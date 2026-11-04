import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
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
export function loadArbiterFile(file: string, firstKey: string): ArbiterFile {
  if (!fs.existsSync(file)) return { v: 2, clusters: {} };
  const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
  if (raw && raw.v === 2 && raw.clusters && typeof raw.clusters === "object") return raw as ArbiterFile;
  return { v: 2, clusters: { [arbiterClusterId(firstKey)]: { nodes: raw?.nodes || {}, owners: raw?.owners || {} } } };
}

export function startArbiterServer(opts: { port: number; host: string; keys?: string[]; key?: string; stateFile?: string }): http.Server {
  const keys = [...(opts.keys || []), ...(opts.key ? [opts.key] : [])];
  if (!keys.length) throw new Error("The arbiter needs at least one key.");
  const byId = new Map(keys.map((k) => [arbiterClusterId(k), k]));
  const file = opts.stateFile || path.join(PAAS_DATA_DIR, "arbiter.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const server = http.createServer((req, res) => {
    // Unsigned liveness probe for people checking the arbiter by hand (curl / browser). Reveals nothing.
    if (req.method === "GET" && req.url === "/health") return res.writeHead(200, { "Content-Type": "application/json" }).end('{"ok":true,"service":"paasmcp-arbiter"}');
    if (req.method !== "POST" || req.url !== "/arbiter") return res.writeHead(404).end();
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 10_000) req.destroy();
    });
    req.on("end", () => {
      const reply = (code: number, o: unknown) => res.writeHead(code, { "Content-Type": "application/json" }).end(JSON.stringify(o));
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
      reply(200, { granted: out.granted, owner: out.owner, owners: state.owners, nodes: state.nodes, now, cluster: clusterId });
    });
  });
  server.listen(opts.port, opts.host);
  return server;
}

export async function askArbiter(
  url: string,
  msg: { op: Op; node: string; epoch: number; dataOf?: string; to?: string }
): Promise<{ granted: boolean; owner?: { owner: string; epoch: number }; owners: ArbiterState["owners"]; nodes: ArbiterState["nodes"]; now: number }> {
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

function readArbiterKeys(): string[] {
  const file = ARBITER_ENV_FILE();
  if (!fs.existsSync(file)) return [];
  const line = fs.readFileSync(file, "utf-8").split("\n").find((l) => l.startsWith("PAASMCP_ARBITER_KEY="));
  return parseArbiterKeys(line?.slice("PAASMCP_ARBITER_KEY=".length));
}

function writeArbiterKeys(keys: string[]): void {
  const file = ARBITER_ENV_FILE();
  if (fs.existsSync(file)) fs.chmodSync(file, 0o600); // tighten before the keys go in
  fs.writeFileSync(file, `PAASMCP_ARBITER_KEY=${keys.join(",")}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

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
