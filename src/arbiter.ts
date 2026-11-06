import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { PAAS_DATA_DIR, writeFileAtomic } from "./config.js";
import { getSecrets, timingSafeCompare } from "./vault.js";

// The arbiter is the third vote for automatic failover: a server may take over its peer's data only
// when the arbiter, too, has stopped hearing from that peer. It runs anywhere small (Raspberry, VPS)
// with `paasmcp arbiter serve`, and knows only a key derived from the cluster key (it cannot read
// mirror tokens or vault bundles).
//
// One arbiter can serve several clusters (groups of paired servers): it holds one key per cluster and
// keeps a separate state for each, so node names or epochs of one cluster never affect another. A
// request names its cluster by an id derived from its key (X-Paasmcp-Cluster) and must be signed with
// that key; requests without the header (older servers) are matched to the key that verifies them.

export const DEAD_AFTER_MS = 60_000;
const MAX_CLOCK_SKEW_MS = 60_000;

export const MAX_ARBITER_KEYS = 32;
const KEY_RE = /^[a-f0-9]{64}$/;
const CLUSTER_ID_RE = /^[a-f0-9]{16}$/;
export const ARBITER_ENV_FILE = () => process.env.PAASMCP_ARBITER_ENV_FILE || "/etc/paasmcp-arbiter.env";

/** Public id of a cluster on the arbiter (reveals nothing about the key). */
export const arbiterClusterId = (key: string) => crypto.createHash("sha256").update(`paasmcp-arbiter-cluster:${key}`).digest("hex").slice(0, 16);

/** Keys from --key / PAASMCP_ARBITER_KEY: one or more 64-hex keys separated by commas or spaces. */
export function parseArbiterKeys(raw: string | undefined): string[] {
  const keys = [...new Set(String(raw || "").split(/[\s,]+/).map((k) => k.trim().toLowerCase()).filter(Boolean))];
  for (const k of keys) if (!KEY_RE.test(k)) throw new Error("Each key must be the 64-character output of 'paasmcp arbiter key' (run it on one of the servers of that cluster).");
  if (keys.length > MAX_ARBITER_KEYS) throw new Error(`At most ${MAX_ARBITER_KEYS} clusters per arbiter.`);
  return keys;
}

export interface ArbiterState {
  nodes: Record<string, { lastSeen: number; epoch: number }>;
  /** Who serves the data that originally belongs to each node, and since which epoch. */
  owners: Record<string, { owner: string; epoch: number }>;
}

export function deriveArbiterKey(clusterKeyHex = getSecrets("system").FEDERATION_CLUSTER_KEY): string {
  if (!clusterKeyHex) throw new Error("No cluster key: pair the servers first.");
  return crypto.createHmac("sha256", Buffer.from(clusterKeyHex, "hex")).update("paasmcp-arbiter-v1").digest("hex");
}

const sign = (key: string, body: string) => crypto.createHmac("sha256", key).update(body).digest("hex");

type Op = "heartbeat" | "claim" | "handover";

export function arbiterDecide(state: ArbiterState, req: { op: Op; node: string; epoch: number; dataOf?: string; to?: string }, now: number) {
  const seen = state.nodes[req.node];
  state.nodes[req.node] = { lastSeen: now, epoch: Math.max(req.epoch, seen?.epoch || 0) };
  if (req.op === "claim" && req.dataOf) {
    const target = state.nodes[req.dataOf];
    const current = state.owners[req.dataOf] || { owner: req.dataOf, epoch: 0 };
    const targetDead = !target || now - target.lastSeen > DEAD_AFTER_MS;
    // The owner must look dead to the arbiter too (not just to the claimer), and epochs only go up.
    const ownerDead = current.owner === req.dataOf ? targetDead : !state.nodes[current.owner] || now - state.nodes[current.owner].lastSeen > DEAD_AFTER_MS;
    const granted = current.owner !== req.node && ownerDead && req.epoch > current.epoch;
    if (granted) state.owners[req.dataOf] = { owner: req.node, epoch: req.epoch };
    return { granted, owner: state.owners[req.dataOf] || current, state };
  }
  if (req.op === "handover" && req.dataOf && req.to) {
    const current = state.owners[req.dataOf];
    const granted = !!current && current.owner === req.node && req.epoch > current.epoch;
    if (granted) state.owners[req.dataOf] = { owner: req.to, epoch: req.epoch };
    return { granted, owner: state.owners[req.dataOf], state };
  }
  return { granted: true, state };
}

interface ArbiterFile {
  v: 2;
  clusters: Record<string, ArbiterState>;
}

/** Reads the state file; a single-cluster file from before belongs to the first key. */
export function loadArbiterFile(file: string, firstKey: string | undefined): ArbiterFile {
  if (!fs.existsSync(file)) return { v: 2, clusters: {} };
  const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
  if (raw && raw.v === 2 && raw.clusters && typeof raw.clusters === "object") return raw as ArbiterFile;
  if (!firstKey) return { v: 2, clusters: {} };
  return { v: 2, clusters: { [arbiterClusterId(firstKey)]: { nodes: raw?.nodes || {}, owners: raw?.owners || {} } } };
}

/** Version of the PaaSMCP code running here (package.json next to dist/), or "" when unknown. */
function codeVersion(): string {
  try {
    const dir = path.dirname(new URL(import.meta.url).pathname);
    return String(JSON.parse(fs.readFileSync(path.join(dir, "..", "package.json"), "utf-8")).version || "");
  } catch {
    return "";
  }
}

/** What the arbiter tells the servers of a cluster about itself (signed replies only, never /health). */
export interface ArbiterAbout {
  host: string;
  version: string;
  startedAt: number;
  clusters: number;
}

export function startArbiterServer(opts: { port: number; host: string; keys?: string[]; key?: string; stateFile?: string; keyFile?: string; pairing?: boolean }): http.Server {
  const fixed = [...(opts.keys || []), ...(opts.key ? [opts.key] : [])];
  // With a key file the arbiter re-reads it when it changes (a new pair joins by code or `add-key`),
  // so it may start with no key at all and wait for the first pairing.
  if (!fixed.length && !opts.keyFile) throw new Error("The arbiter needs at least one key.");
  let cache = { mtime: -1, keys: fixed };
  const currentKeys = (): string[] => {
    if (!opts.keyFile) return fixed;
    let mtime = -2;
    try {
      mtime = fs.statSync(opts.keyFile).mtimeMs;
    } catch {
      // no file yet
    }
    if (mtime !== cache.mtime) {
      let fromFile: string[] = [];
      try {
        fromFile = readKeysFile(opts.keyFile);
      } catch {
        // a broken file keeps the keys given on the command line
      }
      cache = { mtime, keys: [...new Set([...fixed, ...fromFile])] };
    }
    return cache.keys;
  };
  const file = opts.stateFile || path.join(PAAS_DATA_DIR, "arbiter.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const startedAt = Date.now();
  const version = codeVersion();
  const server = http.createServer((req, res) => {
    const reply = (code: number, o: unknown) => res.writeHead(code, { "Content-Type": "application/json" }).end(JSON.stringify(o));
    // Unsigned liveness probe for people checking the arbiter by hand (curl / browser), and for
    // servers looking for a PC to pair with. Reveals nothing but whether a pairing is open.
    if (req.method === "GET" && req.url === "/health") {
      const open = opts.pairing && readPairing() !== undefined;
      return reply(200, open ? { ok: true, service: "paasmcp-arbiter", pairing: true } : { ok: true, service: "paasmcp-arbiter" });
    }
    if (req.method !== "POST" || (req.url !== "/arbiter" && !(opts.pairing && req.url === "/pair"))) return res.writeHead(404).end();
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 10_000) req.destroy();
    });
    req.on("end", () => {
      if (req.url === "/pair") {
        const out = handlePairRequest(body, (k) => {
          const target = opts.keyFile || ARBITER_ENV_FILE();
          writeKeysFile(target, parseArbiterKeys([...readKeysFileSafe(target), k].join(",")));
          if (!opts.keyFile && !fixed.includes(k)) fixed.push(k);
        });
        return reply(out.status, out.body);
      }
      const keys = currentKeys();
      const byId = new Map(keys.map((k) => [arbiterClusterId(k), k]));
      const signature = String(req.headers["x-paasmcp-signature"] || "");
      const claimed = String(req.headers["x-paasmcp-cluster"] || "");
      // The cluster comes from the key that signed the request: a named cluster must match its own key.
      let clusterId: string | undefined;
      if (claimed) {
        const key = CLUSTER_ID_RE.test(claimed) ? byId.get(claimed) : undefined;
        if (key && timingSafeCompare(sign(key, body), signature)) clusterId = claimed;
      } else {
        for (const [id, key] of byId) if (timingSafeCompare(sign(key, body), signature)) clusterId = id;
      }
      if (!clusterId) return reply(401, { error: "bad signature" });
      let msg: { op: Op; node: string; epoch: number; ts: number; dataOf?: string; to?: string };
      try {
        msg = JSON.parse(body);
      } catch {
        return reply(400, { error: "bad json" });
      }
      const now = Date.now();
      if (Math.abs(now - msg.ts) > MAX_CLOCK_SKEW_MS) return reply(400, { error: "clock skew or replay" });
      const all = loadArbiterFile(file, keys[0]);
      const state = all.clusters[clusterId] || { nodes: {}, owners: {} };
      const out = arbiterDecide(state, msg, now);
      all.clusters[clusterId] = state;
      writeFileAtomic(file, JSON.stringify(all, null, 2));
      const about: ArbiterAbout = { host: os.hostname(), version, startedAt, clusters: keys.length };
      reply(200, { granted: out.granted, owner: out.owner, owners: state.owners, nodes: state.nodes, now, cluster: clusterId, about });
    });
  });
  server.listen(opts.port, opts.host);
  return server;
}

export async function askArbiter(
  url: string,
  msg: { op: Op; node: string; epoch: number; dataOf?: string; to?: string }
): Promise<{ granted: boolean; owner?: { owner: string; epoch: number }; owners: ArbiterState["owners"]; nodes: ArbiterState["nodes"]; now: number; about?: ArbiterAbout }> {
  const body = JSON.stringify({ ...msg, ts: Date.now() });
  const key = deriveArbiterKey();
  const res = await fetch(`${url.replace(/\/+$/, "")}/arbiter`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Paasmcp-Signature": sign(key, body), "X-Paasmcp-Cluster": arbiterClusterId(key) },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Arbiter answered HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json() as never;
}

/** `paasmcp arbiter serve --host tailscale` binds to this device's Tailscale IPv4. */
export function resolveArbiterHost(host: string): string {
  if (host !== "tailscale") return host;
  return execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8" }).trim().split("\n")[0];
}

/**
 * Keeps the arbiter running on the third device (systemd, survives reboots). The key goes into a
 * root-only environment file, never into the unit or the process arguments.
 */
export function installArbiterService(opts: { host: string; port: number; key: string }): { service: string; envFile: string; clusters: string[] } {
  const newKeys = parseArbiterKeys(opts.key);
  if (!newKeys.length) throw new Error("The key must be the 64-character output of 'paasmcp arbiter key' (run it on one of the servers).");
  if (opts.host !== "tailscale" && !/^[a-zA-Z0-9.:[\]-]+$/.test(opts.host)) throw new Error(`Invalid --host '${opts.host}'.`);
  if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) throw new Error(`Invalid --port '${opts.port}'.`);
  const envFile = ARBITER_ENV_FILE();
  // Reinstalling keeps the clusters already served here.
  const keys = parseArbiterKeys([...readArbiterKeys(), ...newKeys].join(","));
  writeArbiterKeys(keys);
  const service = "/etc/systemd/system/paasmcp-arbiter.service";
  fs.writeFileSync(
    service,
    `[Unit]\nDescription=PaaSMCP arbiter (third vote for automatic failover)\nAfter=network-online.target tailscaled.service\nWants=network-online.target\n\n[Service]\nEnvironment=PAASMCP_ROOT=${process.env.PAASMCP_ROOT || "/opt/homelab"}\nEnvironmentFile=${envFile}\nExecStart=${process.execPath} ${path.resolve(process.argv[1])} arbiter serve --host ${opts.host} --port ${opts.port}\n# The Tailscale address may not exist yet right after boot.\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n`
  );
  execFileSync("systemctl", ["daemon-reload"]);
  execFileSync("systemctl", ["enable", "--now", "paasmcp-arbiter.service"]);
  execFileSync("systemctl", ["restart", "paasmcp-arbiter.service"]);
  return { service, envFile, clusters: keys.map(arbiterClusterId) };
}

function readKeysFile(file: string): string[] {
  if (!fs.existsSync(file)) return [];
  const line = fs.readFileSync(file, "utf-8").split("\n").find((l) => l.startsWith("PAASMCP_ARBITER_KEY="));
  return parseArbiterKeys(line?.slice("PAASMCP_ARBITER_KEY=".length));
}
function readKeysFileSafe(file: string): string[] {
  try {
    return readKeysFile(file);
  } catch {
    return [];
  }
}
const readArbiterKeys = () => readKeysFile(ARBITER_ENV_FILE());

function writeKeysFile(file: string, keys: string[]): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  if (fs.existsSync(file)) fs.chmodSync(file, 0o600); // tighten before the keys go in
  fs.writeFileSync(file, `PAASMCP_ARBITER_KEY=${keys.join(",")}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}
const writeArbiterKeys = (keys: string[]) => writeKeysFile(ARBITER_ENV_FILE(), keys);

const restartArbiter = () => {
  if (process.env.PAASMCP_OFFLINE_TEST === "1") return false;
  try {
    execFileSync("systemctl", ["restart", "paasmcp-arbiter.service"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
};

/** On the arbiter device: serve one more cluster (its key from 'paasmcp arbiter key' on one of its servers). */
export function addArbiterKey(key: string): { cluster: string; clusters: string[]; restarted: boolean } {
  const [k] = parseArbiterKeys(key);
  if (!k) throw new Error("Usage: paasmcp arbiter add-key <key from 'paasmcp arbiter key'>");
  const keys = parseArbiterKeys([...readArbiterKeys(), k].join(","));
  writeArbiterKeys(keys);
  return { cluster: arbiterClusterId(k), clusters: keys.map(arbiterClusterId), restarted: restartArbiter() };
}

/** On the arbiter device: stop serving a cluster (by its id from 'arbiter clusters', or its key). */
export function removeArbiterKey(idOrKey: string): { removed: string; clusters: string[]; restarted: boolean } {
  const want = String(idOrKey || "").trim().toLowerCase();
  const keys = readArbiterKeys();
  const left = keys.filter((k) => k !== want && arbiterClusterId(k) !== want);
  if (left.length === keys.length) {
    const label = CLUSTER_ID_RE.test(want) ? want : KEY_RE.test(want) ? arbiterClusterId(want) : "that value";
    throw new Error(`No cluster '${label}' on this arbiter (see 'paasmcp arbiter clusters').`);
  }
  if (!left.length) throw new Error("That is the last cluster: the arbiter needs at least one key (uninstall it instead).");
  writeArbiterKeys(left);
  return { removed: CLUSTER_ID_RE.test(want) ? want : arbiterClusterId(want), clusters: left.map(arbiterClusterId), restarted: restartArbiter() };
}

/** Ids of the clusters this arbiter serves (never the keys). */
export const listArbiterClusters = () => readArbiterKeys().map(arbiterClusterId);

export const DEFAULT_REPO_URL = "https://github.com/CodeVanzi/paasmcp.git";

/**
 * A git URL the arbiter device can clone without this server's credentials: https only, no user or
 * token in it (a github.com SSH address becomes https). Anything else falls back to the public repo.
 */
export function publicRepoUrl(raw: string | undefined): string {
  let u = String(raw || "").trim();
  const ssh = /^git@github\.com:([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+?)(\.git)?$/.exec(u);
  if (ssh) u = `https://github.com/${ssh[1]}.git`;
  try {
    const p = new URL(u);
    if (p.protocol !== "https:") return DEFAULT_REPO_URL;
    p.username = "";
    p.password = "";
    p.search = "";
    p.hash = "";
    const out = p.toString();
    return /^https:\/\/[A-Za-z0-9.-]+(:\d+)?\/[A-Za-z0-9._~/-]+$/.test(out) ? out : DEFAULT_REPO_URL;
  } catch {
    return DEFAULT_REPO_URL;
  }
}

/**
 * Ready-to-paste commands for the arbiter device: get (or update) the code and install the service with
 * this cluster's key. Re-running it on a device that already judges another pair keeps that pair too
 * (install-service merges keys), so it is the same command in both cases.
 */
export function arbiterInstallCommand(repoUrl: string | undefined, key = deriveArbiterKey()): { key: string; cluster: string; repoUrl: string; command: string } {
  const [k] = parseArbiterKeys(key);
  const repo = publicRepoUrl(repoUrl);
  const command = [
    `test -d paasmcp || git clone ${repo} paasmcp`,
    "cd paasmcp && git pull --ff-only && npm install && npm run build",
    `sudo node dist/cli.js arbiter install-service --key ${k}`,
  ].join("\n");
  return { key: k, cluster: arbiterClusterId(k), repoUrl: repo, command };
}

// ---- Pairing by code: a PC with PaaSMCP becomes the arbiter of another pair from the dashboard ----
//
// On the arbiter PC, a person opens a pairing window: a 6-digit code, valid for 10 minutes and a few
// tries, kept in a root-only file. On one of the servers, the person picks that PC (found on the
// Tailscale network) and types the code. The server first asks the PC to prove it knows the code
// (HMAC over fresh nonces from both sides), so a wrong PC never receives anything; then it sends the
// arbiter key sealed with a key derived from the code (AES-256-GCM). Tailscale already authenticates
// and encrypts the link; the code is the person confirming both ends.

export const ARBITER_DIR = () => process.env.PAASMCP_ARBITER_DIR || path.join(PAAS_DATA_DIR, "arbiter");
const PAIRING_FILE = () => path.join(ARBITER_DIR(), "pairing.json");
export const PAIR_TTL_MS = 10 * 60_000;
export const PAIR_MAX_TRIES = 5;
const NONCE_RE = /^[a-f0-9]{32}$/;

interface PairingWindow {
  code: string;
  expiresAt: number;
  tries: number;
  nonces: string[];
}

function readPairing(): PairingWindow | undefined {
  try {
    const w = JSON.parse(fs.readFileSync(PAIRING_FILE(), "utf-8")) as PairingWindow;
    if (!w || typeof w.code !== "string" || !/^\d{6}$/.test(w.code) || !(w.expiresAt > Date.now()) || w.tries >= PAIR_MAX_TRIES) return undefined;
    return { ...w, nonces: Array.isArray(w.nonces) ? w.nonces : [] };
  } catch {
    return undefined;
  }
}

function writePairing(w: PairingWindow): void {
  fs.mkdirSync(ARBITER_DIR(), { recursive: true, mode: 0o700 });
  writeFileAtomic(PAIRING_FILE(), JSON.stringify(w));
  fs.chmodSync(PAIRING_FILE(), 0o600);
}

export function closeArbiterPairing(): void {
  fs.rmSync(PAIRING_FILE(), { force: true });
}

/** Opens (or renews) the pairing window on this PC and returns its code. */
export function openArbiterPairing(): { code: string; expiresAt: number } {
  const w: PairingWindow = { code: String(crypto.randomInt(0, 1_000_000)).padStart(6, "0"), expiresAt: Date.now() + PAIR_TTL_MS, tries: 0, nonces: [] };
  writePairing(w);
  return { code: w.code, expiresAt: w.expiresAt };
}

/** The open window here, if any (with its code: only for this PC's own dashboard or terminal). */
export function arbiterPairingStatus(): { open: boolean; code?: string; expiresAt?: number; triesLeft?: number } {
  const w = readPairing();
  return w ? { open: true, code: w.code, expiresAt: w.expiresAt, triesLeft: PAIR_MAX_TRIES - w.tries } : { open: false };
}

const pairKey = (code: string) => crypto.scryptSync(code, "paasmcp-arbiter-pair-v1", 32);
const pairProof = (k: Buffer, nonceA: string, nonceC: string) => crypto.createHmac("sha256", k).update(`arbiter|${nonceA}|${nonceC}`).digest("hex");

/** Arbiter side of POST /pair. `addKey` stores a key that arrived sealed with the right code. */
export function handlePairRequest(body: string, addKey: (key: string) => void): { status: number; body: Record<string, unknown> } {
  const w = readPairing();
  if (!w) {
    closeArbiterPairing();
    return { status: 403, body: { error: "not pairing", code: "notPairing" } };
  }
  let msg: { step?: string; nonceA?: string; nonceC?: string; iv?: string; box?: string };
  try {
    msg = JSON.parse(body);
  } catch {
    return { status: 400, body: { error: "bad json" } };
  }
  const nonceA = String(msg.nonceA || "");
  if (!NONCE_RE.test(nonceA)) return { status: 400, body: { error: "bad nonce" } };
  // scrypt only for requests that count as a try or carry a nonce this PC issued.
  if (msg.step === "hello") {
    const k = pairKey(w.code);
    // Each hello is one try: someone guessing the code gets a handful of answers, not a million.
    const nonceC = crypto.randomBytes(16).toString("hex");
    writePairing({ ...w, tries: w.tries + 1, nonces: [...w.nonces, nonceC].slice(-PAIR_MAX_TRIES) });
    return { status: 200, body: { nonceC, proof: pairProof(k, nonceA, nonceC) } };
  }
  if (msg.step === "key") {
    const nonceC = String(msg.nonceC || "");
    if (!w.nonces.includes(nonceC)) return { status: 403, body: { error: "unknown nonce", code: "notPairing" } };
    const k = pairKey(w.code);
    let key: string;
    try {
      const raw = Buffer.from(String(msg.box || ""), "base64");
      const d = crypto.createDecipheriv("aes-256-gcm", k, Buffer.from(String(msg.iv || ""), "hex"));
      d.setAAD(Buffer.from(`${nonceA}|${nonceC}`));
      d.setAuthTag(raw.subarray(raw.length - 16));
      key = Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString("utf-8");
      [key] = parseArbiterKeys(key);
      if (!key) throw new Error("empty");
    } catch {
      writePairing({ ...w, tries: w.tries + 1 });
      return { status: 403, body: { error: "wrong code", code: "wrongCode" } };
    }
    addKey(key);
    closeArbiterPairing();
    return { status: 200, body: { ok: true, cluster: arbiterClusterId(key), host: os.hostname() } };
  }
  return { status: 400, body: { error: "unknown step" } };
}

export type PairErrorCode = "badHost" | "badCode" | "unreachable" | "notArbiter" | "notPairing" | "wrongCode";
export class PairError extends Error {
  constructor(public code: PairErrorCode, message: string) {
    super(message);
  }
}

/** A Tailscale IPv4, or a MagicDNS / host name. */
const PAIR_HOST_RE = /^(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?)$/;

/**
 * Server side: sends this cluster's arbiter key to the PC at `host`, which shows `code`. Returns the
 * arbiter address to save. Nothing is sent before the PC proves it knows the code.
 */
export async function pairWithArbiter(host: string, code: string, opts: { port?: number; key?: string } = {}): Promise<{ url: string; cluster: string; host: string }> {
  const h = String(host || "").trim();
  const c = String(code || "").replace(/\D/g, "");
  if (!PAIR_HOST_RE.test(h)) throw new PairError("badHost", "Invalid address: use the PC's Tailscale IP or name.");
  if (!/^\d{6}$/.test(c)) throw new PairError("badCode", "The code has 6 digits.");
  const port = opts.port || 4097;
  const url = `http://${h}:${port}`;
  const key = opts.key || deriveArbiterKey();
  let health: { service?: string; pairing?: boolean };
  try {
    const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(5000) });
    health = (await r.json()) as never;
  } catch {
    throw new PairError("unreachable", `Nothing answered at ${url}. Is that PC on, on Tailscale, and showing a code?`);
  }
  if (health?.service !== "paasmcp-arbiter") throw new PairError("notArbiter", "Something answered there, but it is not a PaaSMCP arbiter.");
  if (!health.pairing) throw new PairError("notPairing", "That PC is not showing a code (or it expired). Click “Be the arbiter of another pair” there again.");
  const post = async (o: unknown) => {
    const r = await fetch(`${url}/pair`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(o), signal: AbortSignal.timeout(10_000) });
    const j = (await r.json().catch(() => ({}))) as Record<string, string>;
    if (!r.ok) throw new PairError(j.code === "wrongCode" ? "wrongCode" : "notPairing", j.error || `HTTP ${r.status}`);
    return j;
  };
  const nonceA = crypto.randomBytes(16).toString("hex");
  const k = pairKey(c);
  const hello = await post({ step: "hello", nonceA });
  if (!NONCE_RE.test(String(hello.nonceC)) || !timingSafeCompare(pairProof(k, nonceA, hello.nonceC), String(hello.proof || ""))) {
    throw new PairError("wrongCode", "The code does not match the one on that PC.");
  }
  const iv = crypto.randomBytes(12);
  const e = crypto.createCipheriv("aes-256-gcm", k, iv);
  e.setAAD(Buffer.from(`${nonceA}|${hello.nonceC}`));
  const box = Buffer.concat([e.update(key, "utf-8"), e.final(), e.getAuthTag()]).toString("base64");
  const done = await post({ step: "key", nonceA, nonceC: hello.nonceC, iv: iv.toString("hex"), box });
  return { url, cluster: String(done.cluster || arbiterClusterId(key)), host: String(done.host || h) };
}

/**
 * Runs the arbiter in the foreground: `paasmcp arbiter serve` and the arbiter container a PC with
 * PaaSMCP starts from its dashboard. Keys come from --key / PAASMCP_ARBITER_KEY plus the key file,
 * which pairing by code adds to while it runs.
 */
export function serveArbiter(opts: { host: string; port: number; keys?: string[]; stateFile?: string }): http.Server {
  const host = resolveArbiterHost(opts.host);
  return startArbiterServer({
    host,
    port: opts.port,
    keys: opts.keys || [],
    keyFile: ARBITER_ENV_FILE(),
    stateFile: opts.stateFile || process.env.PAASMCP_ARBITER_STATE_FILE || undefined,
    pairing: true,
  });
}
