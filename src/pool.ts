import { execFileSync, spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AppRecord,
  appServiceUrl,
  DOCKER_NETWORK,
  HOMELAB_ROOT,
  loadState,
  PAAS_DATA_DIR,
  PAAS_DB_DIR,
  PAAS_REDIS_DIR,
  PaaSState,
  PoolConfig,
  PoolCopyRecord,
  PoolHelperRecord,
  CourtesyMode,
  POOL_BALANCER,
  sanitizeSlug,
  saveState,
  tailnetBindIp,
  writeFileAtomic,
  WATCHTOWER_OFF_COMPOSE,
} from "./config.js";
import { audit } from "./guard.js";
import { appendDiary } from "./scale.js";
import {
  CopySpec,
  copyLimits,
  encodeInvite,
  HELPER_TAG,
  helloProof,
  imageFingerprint,
  INVITE_ADD_WINDOW_MS,
  INVITE_TTL_MS,
  isTailscaleIp,
  normalizeArch,
  POOL_IMAGE_REPO,
  sha256,
  sshKeyFingerprint,
  cleanPublicKey,
  validateCopyList,
  validateFacts,
  validateHelperName,
  validateIpv4,
  WORKER_USER,
  WorkerCopy,
  WorkerFacts,
} from "./poolproto.js";
import { getSecrets, setSecretEntries, timingSafeCompare } from "./vault.js";
import { clearWake, noteWakeAnswers, readWake, wakeHelper, wakeOf, wakeStatus } from "./wol.js";

// Helper pool, scale phase 3: the owner's own PCs run extra copies of an app when a person (or the AI,
// within the guard) sets how many, or (phase 4, autoscale.ts) when the decider does, within the app's
// scale rule.
//
// The origin stays the owner of everything: it keeps the vault, builds the image, decides where copies
// run and receives the traffic. Helpers only run stateless copies when told:
//   - orders go over SSH with a key of its own (pool/pool_ed25519) that the helper accepts only from
//     this server's Tailscale IP and only to run `worker.js` (no terminal, no forwarding);
//   - the image travels by `docker save | ssh helper load`, checked by fingerprint on arrival;
//   - the app's variables go with the order and live only in the helper's memory (tmpfs);
//   - copies reach Postgres, Redis and S3 here over Tailscale (the same names as on this server);
//   - visitors still enter here: a small Caddy (paasmcp-pool-lb) splits each pooled app's requests
//     between this server's copy and the helpers', with health checks every 3 s. Cloudflare Tunnel
//     routes those apps to it; a self-hosted edge on this server lists the helpers' copies directly.
// Nothing new runs while idle: SSH orders are one-shot, and the balancer exists only while an app uses
// helpers (it is part of the traffic path, like cloudflared).

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
export const POOL_DIR = path.join(PAAS_DATA_DIR, "pool");
const KEY_PATH = path.join(POOL_DIR, "pool_ed25519");
const KNOWN_HOSTS = path.join(POOL_DIR, "known_hosts");
const SEEN_FILE = path.join(POOL_DIR, "seen.json");
export const LB_DIR = path.join(HOMELAB_ROOT, "paasmcp-pool-lb");
const LB_ADMIN = "unix//data/admin.sock";
/** Seconds a copy keeps its in-flight requests after it leaves the balancer, before it stops. */
const drainMs = () => Math.max(0, Number(process.env.PAASMCP_POOL_DRAIN_SECONDS ?? 30)) * 1000;
export const MAX_COPIES = 20;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const msg = (err: unknown) => (err instanceof Error ? err.message : String(err));

// ---------- state ----------

export function poolOf(state: Pick<PaaSState, "pool">): PoolConfig {
  return { helpers: {}, invites: {}, ...(state.pool || {}) };
}

function savePool(update: (p: PoolConfig) => void): PaaSState {
  const state = loadState();
  const pool = poolOf(state);
  update(pool);
  state.pool = pool;
  saveState(state);
  return state;
}

function patchApp(slug: string, update: (a: AppRecord) => void): AppRecord | undefined {
  const state = loadState();
  const app = state.apps[slug];
  if (!app) return undefined;
  update(app);
  saveState(state);
  return app;
}

function ensurePoolDir(): void {
  fs.mkdirSync(POOL_DIR, { recursive: true, mode: 0o700 });
}

// ---------- keys and invites ----------

/** The pool's own SSH key (never the Git deploy key): created once, private key 0600. */
export function ensurePoolKey(): { publicKey: string; fingerprint: string } {
  ensurePoolDir();
  if (!fs.existsSync(KEY_PATH)) {
    execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-q", "-C", "paasmcp-pool", "-f", KEY_PATH], { stdio: "pipe" });
  }
  fs.chmodSync(KEY_PATH, 0o600);
  const publicKey = cleanPublicKey(fs.readFileSync(`${KEY_PATH}.pub`, "utf-8"));
  return { publicKey, fingerprint: sshKeyFingerprint(publicKey) };
}

function inviteKey(): Buffer {
  let hex = getSecrets("system").POOL_INVITE_KEY;
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) {
    hex = crypto.randomBytes(32).toString("hex");
    setSecretEntries("system", { POOL_INVITE_KEY: hex });
  }
  return Buffer.from(hex, "hex");
}

/** Each invite's proof key is derived from a vault secret, so state.json never holds it. */
export function proofKeyFor(inviteId: string): string {
  return crypto.createHmac("sha256", inviteKey()).update(`pool-invite\n${inviteId}`).digest("hex");
}

function detectTailscaleIp(): string | undefined {
  if (OFFLINE()) return undefined;
  try {
    return validateIpv4(execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0]);
  } catch {
    return undefined;
  }
}

function originName(state: PaaSState): string {
  const n = state.federation?.nodeName;
  return sanitizeSlug(n && n !== "primary-node" ? n : os.hostname());
}

/**
 * Prepares this server for helpers: picks its Tailscale IP and publishes Postgres, Redis and S3 there
 * too (a restart of a few seconds, once). The mirror uses the same address when it exists.
 */
export async function preparePool(opts: { advertise?: string } = {}): Promise<{ bindIp: string; rebound: string[] }> {
  const state = loadState();
  const ip = opts.advertise ? validateIpv4(opts.advertise, "--advertise") : state.pool?.bindIp || state.mirror?.bindIp || detectTailscaleIp();
  if (!ip) throw new Error("This server has no Tailscale IP ('tailscale ip -4' found none). Install Tailscale and log in, or pass --advertise <IP>.");
  if (state.mirror?.bindIp && state.mirror.bindIp !== ip) {
    throw new Error(`The mirror already publishes this server's data on ${state.mirror.bindIp}; helpers must use the same address.`);
  }
  const before = tailnetBindIp(state);
  savePool((p) => (p.bindIp = ip));
  const rebound: string[] = [];
  if (before !== ip && !OFFLINE()) {
    const db = await import("./database.js");
    if (fs.existsSync(path.join(PAAS_DB_DIR, "compose.yaml"))) {
      db.ensureSharedPostgresCluster();
      rebound.push("postgres");
    }
    if (fs.existsSync(path.join(PAAS_REDIS_DIR, "compose.yaml"))) {
      db.ensureSharedRedisCluster();
      rebound.push("redis");
    }
    const storage = await import("./storage.js");
    if (fs.existsSync(path.join(storage.PAAS_GARAGE_DIR, "compose.yaml"))) {
      await storage.ensureGarage();
      rebound.push("garage");
    }
  }
  return { bindIp: ip, rebound };
}

/** One-use invite for one PC (guard "pool.invite", confirm). The PC runs `pool join` with it. */
export async function createInvite(nameIn: string, opts: { advertise?: string; by?: string } = {}) {
  const name = validateHelperName(nameIn);
  if (loadState().pool?.helpers[name]) throw new Error(`A helper named '${name}' already exists. Remove it first ('paasmcp pool remove ${name}') or pick another name.`);
  const prep = await preparePool(opts);
  const key = ensurePoolKey();
  const state = loadState();
  const id = crypto.randomBytes(8).toString("hex");
  const now = Date.now();
  const exp = now + INVITE_TTL_MS;
  const text = encodeInvite({
    v: 1,
    id,
    name,
    originNodeId: state.federation?.nodeId || "primary",
    originName: originName(state),
    originIp: prep.bindIp,
    originKey: key.publicKey,
    proofKey: proofKeyFor(id),
    exp,
  });
  savePool((p) => {
    for (const [k, inv] of Object.entries(p.invites)) {
      if (Date.parse(inv.createdAt) + INVITE_ADD_WINDOW_MS < now || inv.usedAt) delete p.invites[k];
    }
    p.invites[id] = { name, createdAt: new Date(now).toISOString(), expiresAt: new Date(exp).toISOString() };
  });
  audit({ event: "pool.invite", helper: name, by: opts.by || "cli" });
  return {
    name,
    invite: text,
    expiresAt: new Date(exp).toISOString(),
    // Run in the PaaSMCP folder on the PC (sudo does not see a per-user PATH such as ~/.local/bin).
    joinCommand: `sudo node dist/cli.js pool join '${text}'`,
    originIp: prep.bindIp,
    keyFingerprint: key.fingerprint,
    published: prep.rebound,
    next: [
      "On the PC (Linux with Docker, the OpenSSH server, Tailscale and Node.js 20+ for all users, and PaaSMCP built with 'npm install && npm run build', no 'init'), run the join command in the PaaSMCP folder within 15 minutes. Add --cpus <n> --memory <size> to choose how much it gives (default: half).",
      `Then, here: paasmcp pool add ${name} <the PC's Tailscale IP> (the join command prints it).`,
    ],
  };
}

// ---------- talking to helpers ----------

type HelperAddr = Pick<PoolHelperRecord, "name" | "ip" | "sshPort">;

export class HelperOrderError extends Error {}

function sshArgs(h: HelperAddr, opts: { tofu?: boolean; compress?: boolean } = {}): string[] {
  return [
    "-i", KEY_PATH,
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-o", `UserKnownHostsFile=${KNOWN_HOSTS}`,
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", `StrictHostKeyChecking=${opts.tofu ? "accept-new" : "yes"}`,
    "-o", `HostKeyAlias=paasmcp-pool-${h.name}`,
    "-o", "ConnectTimeout=6",
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=3",
    "-o", "LogLevel=ERROR",
    ...(opts.compress ? ["-C"] : []),
    "-T",
    "-p", String(h.sshPort || 22),
    `${WORKER_USER}@${validateIpv4(h.ip, "helper IP")}`,
  ];
}

/**
 * Sends one order to a helper's worker and returns its result. The answer is untrusted: callers
 * validate what they keep. `stdin` may be a string (JSON) or a stream (an image).
 */
export function sshOrder(
  h: HelperAddr,
  order: string,
  opts: { input?: string; stream?: NodeJS.ReadableStream; tofu?: boolean; compress?: boolean; timeoutMs?: number } = {}
): Promise<unknown> {
  if (OFFLINE()) return Promise.reject(new Error("offline test: no SSH"));
  return new Promise((resolve, reject) => {
    const child = spawn("ssh", [...sshArgs(h, opts), order], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => {
      if (out.length < 4 * 1024 * 1024) out += String(d);
    });
    child.stderr.on("data", (d) => (err = (err + String(d)).slice(-4000)));
    const timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs ?? 60_000);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      let parsed: { ok?: boolean; result?: unknown; error?: unknown } | undefined;
      try {
        parsed = JSON.parse(out.trim().split("\n").pop() || "");
      } catch {
        parsed = undefined;
      }
      if (parsed?.ok === true) return resolve(parsed.result);
      if (parsed?.ok === false) return reject(new HelperOrderError(`${h.name}: ${String(parsed.error).slice(0, 600)}`));
      const why = signal === "SIGKILL" ? "timed out" : err.trim().split("\n").pop() || `ssh exited with ${code}`;
      reject(new Error(`${h.name} (${h.ip}) did not answer: ${why}`));
    });
    child.stdin.on("error", () => undefined);
    if (opts.stream) opts.stream.pipe(child.stdin);
    else child.stdin.end(opts.input ?? "");
  });
}

function removeKnownHost(name: string): void {
  if (fs.existsSync(KNOWN_HOSTS)) spawnSync("ssh-keygen", ["-R", `paasmcp-pool-${name}`, "-f", KNOWN_HOSTS], { stdio: "ignore" });
  fs.rmSync(`${KNOWN_HOSTS}.old`, { force: true });
}

interface SeenEntry {
  at?: string;
  ok: boolean;
  failedAt?: string;
  error?: string;
  facts?: WorkerFacts;
  copies?: WorkerCopy[];
}

/** Last answer of each helper (kept apart from state.json so a status read never needs the lock). */
function readSeen(): Record<string, SeenEntry> {
  try {
    return JSON.parse(fs.readFileSync(SEEN_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function writeSeen(update: (s: Record<string, SeenEntry>) => void): void {
  ensurePoolDir();
  const s = readSeen();
  update(s);
  writeFileAtomic(SEEN_FILE, JSON.stringify(s));
}

/** Keeps the last answer's copy list current when this server starts or stops a copy itself. */
function noteCopy(helper: string, copyId: string, app: string, fingerprint: string, running: boolean): void {
  writeSeen((s) => {
    const e = s[helper];
    if (!e?.ok) return;
    const rest = (e.copies || []).filter((c) => c.copyId !== copyId);
    e.copies = running ? [...rest, { copyId, app, running: true, status: "Up", fingerprint }] : rest;
  });
}

export type Listing = { ok: true; facts: WorkerFacts; copies: WorkerCopy[] } | { ok: false; error: string };

/** Asks helpers what they run (in parallel) and records the answers. */
export async function probeHelpers(helpers: PoolHelperRecord[]): Promise<Record<string, Listing>> {
  const results = await Promise.all(
    helpers.map(async (h): Promise<[string, Listing]> => {
      try {
        const r = (await sshOrder(h, "list", { timeoutMs: 15_000 })) as { facts?: unknown; copies?: unknown };
        return [h.name, { ok: true, facts: validateFacts(r?.facts), copies: validateCopyList(r?.copies) }];
      } catch (err) {
        return [h.name, { ok: false, error: msg(err).slice(0, 300) }];
      }
    })
  );
  const now = new Date().toISOString();
  writeSeen((s) => {
    for (const [name, l] of results) {
      s[name] = l.ok ? { at: now, ok: true, facts: l.facts, copies: l.copies } : { ...(s[name] || {}), ok: false, failedAt: now, error: l.error };
    }
  });
  recordWakeAnswers(results.filter(([, l]) => l.ok).map(([n]) => n));
  return Object.fromEntries(results);
}

/** The last answer a helper gave (facts and copies), without asking it again. */
export function lastAnswer(name: string): { at?: string; ok: boolean; facts?: WorkerFacts } | undefined {
  const s = readSeen()[name];
  return s ? { at: s.at, ok: s.ok, facts: s.facts } : undefined;
}

/** Helpers that answer after being woken over the network: each app that needed them hears it in its diary. */
export function recordWakeAnswers(names: string[], now = Date.now()): { helper: string; seconds: number }[] {
  const woke = noteWakeAnswers(names, now);
  for (const w of woke) {
    if (w.gaveUp) continue;
    for (const app of w.apps) appendDiary({ t: new Date(now).toISOString(), app, kind: "woke", p: { helper: w.helper, seconds: w.seconds } });
  }
  return woke.map((w) => ({ helper: w.helper, seconds: w.seconds }));
}

// ---------- courteous mode (the decision itself is in courtesy.ts) ----------

export const COURTESY_DEFAULT: { mode: CourtesyMode; cpuPct: number } = { mode: "auto", cpuPct: 50 };
export const COURTESY_MODES: readonly CourtesyMode[] = ["auto", "warn", "off"];

/** The helper's courteous mode, with the default for PCs that never set it. */
export function courtesyOf(h: Pick<PoolHelperRecord, "courtesy">): { mode: CourtesyMode; cpuPct: number } {
  const c = h.courtesy;
  return c && COURTESY_MODES.includes(c.mode) && Number.isFinite(c.cpuPct) ? { mode: c.mode, cpuPct: c.cpuPct } : { ...COURTESY_DEFAULT };
}

/** The owner is using the PC and asked for it to be left alone: no new copies (warn and auto). */
export function ownerBusy(h: Pick<PoolHelperRecord, "courtesy" | "ownerBusy">): boolean {
  return Boolean(h.ownerBusy) && courtesyOf(h).mode !== "off";
}

/** ...and its copies move away (auto only). */
export function ownerWantsOut(h: Pick<PoolHelperRecord, "courtesy" | "ownerBusy">): boolean {
  return Boolean(h.ownerBusy) && courtesyOf(h).mode === "auto";
}

/** Helpers whose owner is using them right now by their last answer (before the round decides): no new copy goes there. */
function ownerHighNow(state: PaaSState, listings: Record<string, Listing>): Set<string> {
  const out = new Set<string>();
  for (const [name, l] of Object.entries(listings)) {
    const h = state.pool?.helpers[name];
    const pct = l.ok ? l.facts.owner?.cpuPct : null;
    if (h && typeof pct === "number" && courtesyOf(h).mode !== "off" && pct >= courtesyOf(h).cpuPct) out.add(name);
  }
  return out;
}

export function validateCourtesy(modeIn: unknown, cpuIn?: unknown): { mode: CourtesyMode; cpuPct?: number } {
  const mode = String(modeIn ?? "").trim().toLowerCase() as CourtesyMode;
  if (!COURTESY_MODES.includes(mode)) throw new Error("Courteous mode must be auto (copies leave when the owner uses the PC), warn (they stay, no new ones go there) or off.");
  if (cpuIn === undefined || cpuIn === null || cpuIn === "") return { mode };
  const cpuPct = Number(String(cpuIn).replace(/%$/, ""));
  if (!Number.isInteger(cpuPct) || cpuPct < 10 || cpuPct > 95) throw new Error("--cpu must be a whole percentage from 10 to 95 (the owner's share of the whole PC's CPU).");
  return { mode, cpuPct };
}

/**
 * Sets a helper's courteous mode (free, like pause: it only ever takes load off the PC or gives back what
 * the owner's settings allow). The copies follow at once: moving to auto while the owner is busy moves
 * them away; off, or the owner no longer busy, lets missing copies come back.
 */
export async function setCourtesy(nameIn: string, modeIn: unknown, cpuIn?: unknown, opts: { by?: string; log?: (l: string) => void } = {}) {
  const name = validateHelperName(nameIn);
  const want = validateCourtesy(modeIn, cpuIn);
  const before = loadState().pool?.helpers[name];
  if (!before) throw new Error(`Helper '${name}' not found.`);
  const next = { mode: want.mode, cpuPct: want.cpuPct ?? courtesyOf(before).cpuPct };
  savePool((p) => {
    p.helpers[name].courtesy = next;
    // Off: nothing is watched, so nothing is known about the owner any more.
    if (next.mode === "off") delete p.helpers[name].ownerBusy;
  });
  audit({ event: "pool.courtesy", helper: name, mode: next.mode, cpuPct: next.cpuPct, by: opts.by || "cli" });
  const after = loadState().pool!.helpers[name];
  const reports: ReconcileReport[] = [];
  for (const app of pooledApps(loadState())) {
    const there = app.pool!.placed.some((c) => c.helper === name);
    if ((ownerWantsOut(after) && there) || (!ownerBusy(after) && ownerBusy(before) && app.pool!.placed.length < app.pool!.copies - 1)) {
      reports.push(await reconcilePool(app.name, { log: opts.log }));
    }
  }
  return { helper: name, courtesy: next, ownerBusy: after.ownerBusy || null, apps: reports };
}

// ---------- helpers: add, pause, remove ----------

/**
 * Finishes an invite: reaches the PC over SSH (its host key is pinned from now on), checks it holds the
 * invite (HMAC of a fresh nonce) and records it with the facts it reports.
 */
export async function addHelper(nameIn: string, ipIn: string, opts: { sshPort?: number; by?: string } = {}) {
  const name = validateHelperName(nameIn);
  const ip = validateIpv4(ipIn, "helper IP");
  const sshPort = opts.sshPort ?? 22;
  if (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) throw new Error("--ssh-port must be 1-65535.");
  const pool = poolOf(loadState());
  if (pool.helpers[name]) throw new Error(`'${name}' is already a helper.`);
  const now = Date.now();
  const pending = Object.entries(pool.invites).find(([, i]) => i.name === name && !i.usedAt && Date.parse(i.createdAt) + INVITE_ADD_WINDOW_MS > now);
  if (!pending) throw new Error(`No open invite for '${name}' (they last an hour). Create one: paasmcp pool invite ${name}.`);
  const [inviteId] = pending;
  ensurePoolKey();
  removeKnownHost(name);
  const nonce = crypto.randomBytes(16).toString("hex");
  let reply: { name?: unknown; proof?: unknown; facts?: unknown };
  try {
    reply = (await sshOrder({ name, ip, sshPort }, "hello", { input: JSON.stringify({ inviteId, nonce }), tofu: true, timeoutMs: 30_000 })) as typeof reply;
  } catch (err) {
    removeKnownHost(name);
    throw new Error(`Could not finish adding '${name}' at ${ip}: ${msg(err)}`);
  }
  const expected = helloProof(proofKeyFor(inviteId), inviteId, nonce, name);
  if (String(reply?.name) !== name || !timingSafeCompare(expected, String(reply?.proof || ""))) {
    removeKnownHost(name);
    throw new Error(`The PC at ${ip} did not prove it holds the invite for '${name}'. Nothing was added.`);
  }
  const f = validateFacts(reply.facts);
  const rec: PoolHelperRecord = {
    name,
    ip,
    sshPort,
    tier: "own",
    arch: f.arch,
    cpus: f.cpus,
    memMb: f.memMb,
    diskFreeGb: f.diskFreeGb,
    give: f.give,
    dockerVersion: f.dockerVersion || undefined,
    workerVersion: f.workerVersion || undefined,
    addedAt: new Date().toISOString(),
  };
  savePool((p) => {
    p.helpers[name] = rec;
    if (p.invites[inviteId]) p.invites[inviteId].usedAt = rec.addedAt;
  });
  writeSeen((s) => (s[name] = { at: rec.addedAt, ok: true, facts: f, copies: [] }));
  audit({ event: "pool.add", helper: name, ip, by: opts.by || "cli" });
  const warnings: string[] = [];
  if (!f.secretsInMemory) warnings.push("The PC's in-memory folder for app variables is not ready: copies will be refused there until 'sudo systemd-tmpfiles --create' or a new join.");
  if (!isTailscaleIp(ip)) warnings.push(`${ip} is not a Tailscale address (100.64.0.0/10): orders and app traffic would cross that network unencrypted by Tailscale.`);
  if (f.give.cpus <= 0 || f.give.memMb < 128) warnings.push("The PC gives almost nothing to copies (see --cpus and --memory on join).");
  return { helper: rec, warnings };
}

/** Paused helpers get no copies and their copies move to other helpers (or stop when there is none). */
export async function pauseHelper(nameIn: string, paused: boolean, opts: { by?: string; log?: (l: string) => void } = {}) {
  const name = validateHelperName(nameIn);
  const state = loadState();
  if (!state.pool?.helpers[name]) throw new Error(`Helper '${name}' not found.`);
  savePool((p) => {
    if (paused) p.helpers[name].paused = { at: new Date().toISOString(), by: opts.by || "cli" };
    else delete p.helpers[name].paused;
  });
  audit({ event: paused ? "pool.pause" : "pool.resume", helper: name, by: opts.by || "cli" });
  const reports: ReconcileReport[] = [];
  for (const app of pooledApps(loadState())) {
    if (paused ? app.pool!.placed.some((c) => c.helper === name) : app.pool!.placed.length < app.pool!.copies - 1) {
      reports.push(await reconcilePool(app.name, { log: opts.log }));
    }
  }
  return { helper: name, paused, apps: reports };
}

/** Takes a PC out of the pool (guard "pool.remove", confirm): its copies stop and its key is revoked there. */
export async function removeHelper(nameIn: string, opts: { by?: string; log?: (l: string) => void } = {}) {
  const name = validateHelperName(nameIn);
  const state = loadState();
  const h = state.pool?.helpers[name];
  if (!h) throw new Error(`Helper '${name}' not found.`);
  // Copies there leave the balancer first, then the PC forgets everything (and revokes the key).
  const affected = pooledApps(state).filter((a) => a.pool!.placed.some((c) => c.helper === name));
  for (const app of affected) patchApp(app.name, (a) => (a.pool!.placed = a.pool!.placed.filter((c) => c.helper !== name)));
  if (affected.length) {
    await applyBalancer();
    await sleep(drainMs());
  }
  let revoked = false;
  let note: string | undefined;
  try {
    await sshOrder(h, "forget", { timeoutMs: 120_000 });
    revoked = true;
  } catch (err) {
    note = `The PC did not answer (${msg(err)}). Its copies stop by themselves at its next reboot, but its key stays: run 'sudo paasmcp pool leave' on it.`;
  }
  savePool((p) => delete p.helpers[name]);
  removeKnownHost(name);
  writeSeen((s) => delete s[name]);
  clearWake(name);
  audit({ event: "pool.remove", helper: name, revoked, by: opts.by || "cli" });
  const reports: ReconcileReport[] = [];
  for (const app of affected) reports.push(await reconcilePool(app.name, { log: opts.log }));
  return { removed: name, revoked, ...(note ? { note } : {}), apps: reports };
}

// ---------- apps ----------

export function pooledApps(state: PaaSState): AppRecord[] {
  return Object.values(state.apps)
    .filter((a) => a.pool?.enabled && !a.trashedAt)
    .sort((a, b) => a.name.localeCompare(b.name));
}

export interface PoolReadiness {
  app: string;
  ok: boolean;
  problems: string[];
  warnings: string[];
  problemCodes: string[];
  warningCodes: { code: string; value?: string }[];
}

/** PaaSMCP's own variables for reaching the databases from the server's shell (the app uses the others). */
const HOST_ONLY_VARS = new Set(["LOCAL_DATABASE_URL", "LOCAL_REDIS_URL"]);

/** Variables that point at this machine or at containers that only exist here. */
export function localReferences(env: Record<string, string>): string[] {
  const shared = new Set(["paasmcp-postgres", "paasmcp-redis", "paasmcp-garage"]);
  return Object.entries(env)
    .filter(([k, v]) => {
      if (HOST_ONLY_VARS.has(k)) return false;
      if (/(^|[^0-9A-Za-z.-])(localhost|127\.0\.0\.1)([^0-9A-Za-z-]|$)/.test(v)) return true;
      return [...v.matchAll(/(?:^|[/@])(paasmcp-[a-z0-9-]+)/g)].some((m) => !shared.has(m[1]));
    })
    .map(([k]) => k)
    .sort();
}

/** Can this app have copies on helpers? (problems block, warnings inform) */
export function poolReadiness(appName: string, state = loadState(), env?: Record<string, string>): PoolReadiness {
  const slug = sanitizeSlug(appName);
  const app = state.apps[slug];
  const problems: string[] = [];
  const problemCodes: string[] = [];
  const warnings: string[] = [];
  const warningCodes: { code: string; value?: string }[] = [];
  const problem = (code: string, text: string) => (problemCodes.push(code), problems.push(text));
  const warn = (code: string, text: string, value?: string) => (warningCodes.push({ code, value }), warnings.push(text));
  if (!app) {
    problem("notFound", `App '${slug}' not found.`);
    return { app: slug, ok: false, problems, warnings, problemCodes, warningCodes };
  }
  if (slug === "paasmcp-dashboard") problem("dashboard", "The dashboard controls this server and never runs on helpers.");
  if (app.trashedAt) problem("trashed", "The app is in the trash.");
  if (app.originNodeId) problem("fromPeer", "This app came from another server: set its copies there.");
  if (app.activeActive) problem("activeActive", "The app runs on both servers. In this phase helpers only take apps that run on this server alone (turn 'both servers' off first).");
  if (app.composePassThrough) problem("ownCompose", "The app brings its own docker-compose.yml (several services, maybe its own database): only single-container apps can run on helpers.");
  if (app.trusted) problem("trusted", "The app is marked trusted (privileged compose fields): it never runs on helpers.");
  if (app.healthcheckDisabled) problem("noHealthcheck", "The app has no HTTP health check, and the balancer needs one to stop sending visits to a copy that stopped answering.");
  if (!app.lastCommit && app.status !== "running") problem("notDeployed", "Deploy the app first.");
  if (state.mirror?.fenced) problem("fenced", "This server is fenced: another server serves its data now.");
  if (!app.healthcheckDisabled && (!app.healthcheckPath || app.healthcheckPath === "/")) {
    warn("rootHealthPath", "Use a health check path that queries the database (for example /healthz): with '/', a copy that lost the database keeps receiving visits.");
  }
  if (!app.cpuLimit || !app.memoryLimit) {
    warn("noLimits", "The app has no CPU or memory limit: each copy on a helper takes everything that PC gives. Set limits (redeploy with --cpu/--memory) to fit more copies.");
  }
  if (app.domains.some((d) => d.mode === "zero-trust")) {
    warn("zeroTrustBypass", "The app is behind Cloudflare Access (zero-trust). Its copies on helpers are published on their Tailscale IPs, where devices of your Tailnet reach them without that login. Keep the app's own login on, or limit the Tailnet with the access rules ('paasmcp pool acl').");
  }
  const refs = localReferences(env ?? (OFFLINE() ? {} : safeSecrets(slug)));
  if (refs.length) warn("localRefs", `These variables point at this machine or at containers that only exist here, so they will not work on a helper: ${refs.join(", ")}.`, refs.join(", "));
  if (!Object.keys(state.pool?.helpers || {}).length) warn("noHelpers", "No helper PC was added yet ('paasmcp pool invite <name>').");
  return { app: slug, ok: problems.length === 0, problems, warnings, problemCodes, warningCodes };
}

function safeSecrets(slug: string): Record<string, string> {
  try {
    return getSecrets(slug);
  } catch {
    return {};
  }
}

/** The variables a copy runs with: the same as this server's .env.runtime. */
function copyEnv(app: AppRecord): Record<string, string> {
  return { ...getSecrets(app.name), PORT: String(app.internalPort), NODE_ENV: "production" };
}

function configHashOf(app: AppRecord, env: Record<string, string>): string {
  const sorted = Object.keys(env).sort().map((k) => [k, env[k]]);
  return sha256(JSON.stringify({ env: sorted, port: app.localPort, internalPort: app.internalPort })).slice(0, 32);
}

interface OriginImage {
  tag: string;
  poolTag: string;
  fingerprint: string;
  arch: string;
}

function originImage(slug: string): OriginImage {
  if (OFFLINE()) throw new Error("offline test: no Docker");
  const tag = `paasmcp/${slug}:latest`;
  let inspect: { Architecture?: string };
  try {
    inspect = JSON.parse(execFileSync("docker", ["image", "inspect", "--format", "{{json .}}", tag], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }));
  } catch {
    throw new Error(`Image ${tag} not found: deploy the app first.`);
  }
  const fingerprint = imageFingerprint(inspect);
  return { tag, poolTag: `${POOL_IMAGE_REPO}/${slug}:${fingerprint.slice(0, 12)}`, fingerprint, arch: normalizeArch(inspect.Architecture) };
}

/** Sends the image to a helper: `docker save | ssh worker load`, checked against the fingerprint there. */
async function sendImage(h: PoolHelperRecord, img: OriginImage): Promise<void> {
  execFileSync("docker", ["tag", img.tag, img.poolTag], { stdio: "pipe" });
  try {
    const save = spawn("docker", ["save", img.poolTag], { stdio: ["ignore", "pipe", "pipe"] });
    let saveErr = "";
    save.stderr.on("data", (d) => (saveErr = (saveErr + String(d)).slice(-1000)));
    const saved = new Promise<void>((resolve, reject) => save.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`docker save failed: ${saveErr.trim() || code}`)))));
    await Promise.all([sshOrder(h, `load ${img.poolTag} ${img.fingerprint}`, { stream: save.stdout, compress: true, timeoutMs: 60 * 60 * 1000 }), saved]);
  } finally {
    spawnSync("docker", ["image", "rm", img.poolTag], { stdio: "ignore" });
  }
}

/** Polls a copy's health path from here (the balancer's view): 2xx within the time limit. */
export async function waitCopyHealthy(url: string, timeoutMs: number): Promise<{ healthy: boolean; reason: string }> {
  const end = Date.now() + timeoutMs;
  let reason = "no answer";
  while (Date.now() < end) {
    try {
      const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(3000) });
      await res.body?.cancel().catch(() => undefined);
      if (res.status >= 200 && res.status < 300) return { healthy: true, reason: `HTTP ${res.status}` };
      reason = `HTTP ${res.status}`;
    } catch (err) {
      reason = (err as { cause?: { code?: string } }).cause?.code || msg(err);
    }
    await sleep(1000);
  }
  return { healthy: false, reason };
}

/** CPUs and MB the recorded copies take on each helper. */
export function usedOnHelpers(state: PaaSState): Record<string, { cpus: number; memMb: number; apps: string[] }> {
  const used: Record<string, { cpus: number; memMb: number; apps: string[] }> = {};
  for (const app of pooledApps(state)) {
    for (const c of app.pool!.placed) {
      const u = (used[c.helper] ||= { cpus: 0, memMb: 0, apps: [] });
      u.cpus += c.cpus;
      u.memMb += c.memMb;
      u.apps.push(app.name);
    }
  }
  return used;
}

/**
 * Where new copies go (pure): reachable, not paused, its owner not using it (courteous mode), same CPU
 * architecture as the image, no copy of this app yet, and room for its limits. The one with the most free CPU first, so copies spread out.
 */
export function pickHelpers(
  state: PaaSState,
  app: AppRecord,
  arch: string,
  reachable: Set<string>,
  count: number,
  ownerHigh: Set<string> = new Set()
): { picked: PoolHelperRecord[]; skipped: { helper: string; why: string }[] } {
  const used = usedOnHelpers(state);
  const skipped: { helper: string; why: string }[] = [];
  const has = new Set((app.pool?.placed || []).map((c) => c.helper));
  const candidates = Object.values(state.pool?.helpers || {}).filter((h) => {
    const why = h.paused
      ? "paused"
      : ownerBusy(h) || (ownerHigh.has(h.name) && !has.has(h.name))
        ? "its owner is using it"
      : !reachable.has(h.name)
        ? "not answering"
        : h.arch !== arch
          ? `${h.arch} PC, ${arch} image`
          : has.has(h.name)
            ? ""
            : (() => {
                const need = copyLimits(app, h.give);
                const u = used[h.name] || { cpus: 0, memMb: 0 };
                return u.cpus + need.cpus > h.give.cpus + 0.001 || u.memMb + need.memMb > h.give.memMb ? "no room left in what its owner gave" : "";
              })();
    if (why) skipped.push({ helper: h.name, why });
    return !why && !has.has(h.name);
  });
  const free = (h: PoolHelperRecord) => ({ cpus: h.give.cpus - (used[h.name]?.cpus || 0), memMb: h.give.memMb - (used[h.name]?.memMb || 0) });
  candidates.sort((a, b) => free(b).cpus - free(a).cpus || free(b).memMb - free(a).memMb || a.name.localeCompare(b.name));
  return { picked: candidates.slice(0, count), skipped };
}

export interface ReconcileReport {
  app: string;
  wanted: number;
  running: number;
  started: { helper: string; copy: string }[];
  stopped: { helper: string; copy: string; why: string }[];
  errors: { helper?: string; error: string }[];
  warnings: string[];
  /** Helpers woken over the network (or still waking) for this app's copies: they answer within a minute or so. */
  waking: string[];
}

async function startCopy(app: AppRecord, h: PoolHelperRecord, img: OriginImage, bindIp: string, log: (l: string) => void): Promise<PoolCopyRecord> {
  const env = copyEnv(app);
  const limits = copyLimits(app, h.give);
  const present = (await sshOrder(h, `has-image ${img.poolTag} ${img.fingerprint}`, { timeoutMs: 30_000 })) as { present?: boolean };
  if (present?.present !== true) {
    log(`sending the image to ${h.name}...`);
    await sendImage(h, img);
  }
  const copyId = `${app.name}-${crypto.randomBytes(3).toString("hex")}`;
  const spec: CopySpec = {
    app: app.name,
    copyId,
    image: img.poolTag,
    fingerprint: img.fingerprint,
    port: app.localPort,
    internalPort: app.internalPort,
    env,
    memory: `${limits.memMb}m`,
    cpus: String(limits.cpus),
    originIp: bindIp,
    originNodeId: loadState().federation?.nodeId || "primary",
  };
  log(`starting a copy on ${h.name}...`);
  await sshOrder(h, "run", { input: JSON.stringify(spec), timeoutMs: 180_000 });
  const pathOf = app.healthcheckPath || "/";
  const health = await waitCopyHealthy(`http://${h.ip}:${app.localPort}${pathOf}`, Math.max(30, app.healthcheckTimeoutSeconds || 60) * 1000);
  if (!health.healthy) {
    const logs = ((await sshOrder(h, `logs ${copyId}`, { timeoutMs: 30_000 }).catch(() => ({}))) as { logs?: string }).logs;
    await sshOrder(h, `stop ${copyId}`, { timeoutMs: 60_000 }).catch(() => undefined);
    throw new Error(`The copy on ${h.name} did not answer GET ${pathOf} with 2xx (${health.reason}).${logs ? `\nLast lines of its log:\n${String(logs).slice(-2000)}` : ""}`);
  }
  noteCopy(h.name, copyId, app.name, img.fingerprint, true);
  return { id: copyId, helper: h.name, port: app.localPort, fingerprint: img.fingerprint, configHash: configHashOf(app, env), cpus: limits.cpus, memMb: limits.memMb, startedAt: new Date().toISOString() };
}

async function stopCopies(list: { rec: PoolCopyRecord; why: string }[], report: ReconcileReport, log: (l: string) => void): Promise<void> {
  const helpers = loadState().pool?.helpers || {};
  await Promise.all(
    list.map(async ({ rec, why }) => {
      const h = helpers[rec.helper];
      report.stopped.push({ helper: rec.helper, copy: rec.id, why });
      if (!h) return;
      log(`stopping the copy on ${rec.helper} (${why})...`);
      try {
        await sshOrder(h, `stop ${rec.id}`, { timeoutMs: 90_000 });
        noteCopy(rec.helper, rec.id, "", rec.fingerprint, false);
      } catch (err) {
        report.errors.push({ helper: rec.helper, error: `could not stop ${rec.id}: ${msg(err)}` });
      }
    })
  );
}

/**
 * Wakes, over the network, sleeping helpers that would have room for this app's missing copies: Wake-on-LAN
 * on, not answering now, not given up on, and fit for a copy by the same rules as an awake PC (not paused,
 * owner not busy, same architecture, room in what its owner gave). At most one PC per missing copy.
 */
async function wakeForRoom(
  state: PaaSState,
  app: AppRecord,
  arch: string,
  reachable: Set<string>,
  tried: Set<string>,
  missing: number,
  ownerHigh: Set<string>,
  report: ReconcileReport
): Promise<string[]> {
  const now = Date.now();
  const tracks = readWake().helpers;
  const asleep = new Set(
    Object.values(state.pool?.helpers || {})
      .filter((h) => !reachable.has(h.name) && !tried.has(h.name) && wakeOf(h) && wakeStatus(tracks[h.name], now) !== "gave_up")
      .map((h) => h.name)
  );
  if (!asleep.size) return [];
  const { picked } = pickHelpers(state, app, arch, asleep, missing, ownerHigh);
  const woken: string[] = [];
  for (const h of picked) {
    try {
      const w = await wakeHelper(h, { app: app.name, now });
      if (w.state === "sent" || w.state === "waking") woken.push(h.name);
    } catch (err) {
      report.warnings.push(`Could not wake ${h.name} over the network: ${msg(err)}`);
    }
  }
  report.waking.push(...woken.filter((n) => !report.waking.includes(n)));
  return woken;
}

/**
 * Brings an app's copies on helpers to what is wanted, with the image and settings this server runs
 * now. Copies leave the balancer and drain before they stop; a replacement answers its health check
 * before it joins. Called after `scale set`, deploys, rollbacks, start/stop and pool changes; it
 * expects the state lock to be held by the caller.
 */
export async function reconcilePool(appName: string, opts: { log?: (l: string) => void } = {}): Promise<ReconcileReport> {
  const slug = sanitizeSlug(appName);
  const log = (l: string) => (opts.log ?? (() => undefined))(`[${slug}] ${l}`);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const report: ReconcileReport = { app: slug, wanted: app.pool?.copies ?? 1, running: 1, started: [], stopped: [], errors: [], warnings: [], waking: [] };
  const pool = app.pool;
  if (!pool?.enabled) return report;
  // A fenced server (another one serves its data now) keeps no copies anywhere: they would write here.
  const fenced = Boolean(state.mirror?.fenced);
  const wantHelpers = pool.stoppedAt || app.trashedAt || fenced ? 0 : Math.max(0, pool.copies - 1);
  const helpers = state.pool?.helpers || {};
  const listings = await probeHelpers(Object.values(helpers));
  const reachable = new Set(Object.entries(listings).filter(([, l]) => l.ok).map(([n]) => n));
  const ownerHigh = ownerHighNow(state, listings);

  let img: OriginImage | undefined;
  const needImage = wantHelpers > 0 || pool.placed.length > 0;
  if (needImage) {
    try {
      img = originImage(slug);
    } catch (err) {
      // Copies already running keep running; nothing new starts until the image is back.
      if (wantHelpers > 0) report.errors.push({ error: msg(err) });
    }
  }
  const env = needImage ? copyEnv(app) : {};
  const cfgHash = configHashOf(app, env);
  const isCurrent = (rec: PoolCopyRecord, h: PoolHelperRecord) => {
    const limits = copyLimits(app, h.give);
    return Boolean(img) && rec.fingerprint === img!.fingerprint && rec.configHash === cfgHash && rec.cpus === limits.cpus && rec.memMb === limits.memMb;
  };

  const keep: PoolCopyRecord[] = [];
  const outdated: PoolCopyRecord[] = [];
  // PCs that hold a copy we keep but do not answer: the ones that can be woken over the network are.
  const wakeKept: PoolHelperRecord[] = [];
  const toStop: { rec: PoolCopyRecord; why: string }[] = [];
  const dropSilent = (rec: PoolCopyRecord, why: string) => report.stopped.push({ helper: rec.helper, copy: rec.id, why });
  for (const rec of pool.placed) {
    const h = helpers[rec.helper];
    const l = listings[rec.helper];
    if (!h) {
      dropSilent(rec, "helper removed");
      continue;
    }
    if (!l?.ok) {
      // Not answering now (asleep, rebooting, network). A current copy stays listed: the balancer's
      // health checks decide whether it gets visits. Any other leaves the balancer now and stops when
      // the PC answers again (a later round sees it as unknown).
      if (wantHelpers > 0 && !h.paused && !ownerWantsOut(h) && isCurrent(rec, h)) {
        keep.push(rec);
        if (wakeOf(h) && !wakeKept.includes(h)) wakeKept.push(h);
      } else dropSilent(rec, "helper not answering");
      report.warnings.push(`${rec.helper} does not answer now (${l?.ok === false ? l.error : "no answer"}).`);
      continue;
    }
    const live = l.copies.find((c) => c.copyId === rec.id);
    if (!live?.running) {
      toStop.push({ rec, why: live ? `stopped on its own (${live.status})` : "gone from the helper" });
      continue;
    }
    if (h.paused) {
      toStop.push({ rec, why: "helper paused" });
      continue;
    }
    if (ownerWantsOut(h)) {
      toStop.push({ rec, why: "its owner is using the PC" });
      continue;
    }
    if (!isCurrent(rec, h)) {
      outdated.push(rec);
      continue;
    }
    keep.push(rec);
  }
  // Too many (fewer wanted, or helpers paused): copies on PCs that do not answer go first, then the
  // most recent ones.
  keep.sort((a, b) => Number(reachable.has(b.helper)) - Number(reachable.has(a.helper)) || a.startedAt.localeCompare(b.startedAt));
  while (keep.length > wantHelpers) {
    const rec = keep.pop()!;
    if (reachable.has(rec.helper)) toStop.push({ rec, why: "fewer copies wanted" });
    else dropSilent(rec, "fewer copies wanted (the PC does not answer; it stops when it does)");
  }
  while (outdated.length && keep.length + outdated.length > wantHelpers) toStop.push({ rec: outdated.pop()!, why: "fewer copies wanted" });
  for (const h of wakeKept) {
    if (!keep.some((c) => c.helper === h.name)) continue;
    const w = await wakeHelper(h, { app: slug }).catch((err) => ({ state: "error", error: msg(err) }) as const);
    if (w.state === "sent" || w.state === "waking") report.waking.push(h.name);
    else if (w.state === "error") report.warnings.push(`Could not wake ${h.name} over the network: ${w.error}`);
  }

  // Copies of this app on helpers that no record knows (an interrupted order, a PC that came back), and
  // copies of apps that no longer use helpers. Other apps' copies are left to their own rounds.
  const known = new Set([...keep, ...outdated, ...toStop.map((t) => t.rec)].map((c) => c.id));
  const orphans: { rec: PoolCopyRecord; why: string }[] = [];
  for (const [name, l] of Object.entries(listings)) {
    if (!l.ok) continue;
    for (const c of l.copies) {
      const owner = state.apps[c.app];
      if (c.app === slug ? !known.has(c.copyId) : !owner?.pool?.enabled) {
        orphans.push({ rec: { id: c.copyId, helper: name, port: 0, fingerprint: "", configHash: "", cpus: 0, memMb: 0, startedAt: "" }, why: "unknown copy" });
      }
    }
  }

  // 1. Leave the balancer, drain (not when fenced: they must stop now), stop.
  patchApp(slug, (a) => (a.pool!.placed = [...keep, ...outdated]));
  if (toStop.length || report.stopped.length) {
    await applyBalancer();
    if (!fenced && toStop.some((s) => !s.why.startsWith("stopped on its own") && s.why !== "gone from the helper")) {
      log(`waiting ${drainMs() / 1000} s for visits in progress to finish...`);
      await sleep(drainMs());
    }
  }
  await stopCopies([...toStop, ...orphans], report, log);

  // 2. Replace outdated copies one at a time (same helper, same port): the image goes first, then the
  //    old copy drains and stops, then the new one must pass its health check.
  const bindIp = tailnetBindIp(loadState());
  for (const rec of outdated) {
    const h = helpers[rec.helper];
    try {
      if (!img || !bindIp) throw new Error("no image or no Tailscale address for copies");
      const present = (await sshOrder(h, `has-image ${img.poolTag} ${img.fingerprint}`, { timeoutMs: 30_000 })) as { present?: boolean };
      if (present?.present !== true) {
        log(`sending the new image to ${h.name}...`);
        await sendImage(h, img);
      }
      patchApp(slug, (a) => (a.pool!.placed = a.pool!.placed.filter((c) => c.id !== rec.id)));
      await applyBalancer();
      log(`replacing the copy on ${h.name}: draining the old one...`);
      await sleep(drainMs());
      await stopCopies([{ rec, why: "replaced by the current version" }], report, log);
      const fresh = await startCopy(loadState().apps[slug], h, img, bindIp, log);
      patchApp(slug, (a) => a.pool!.placed.push(fresh));
      await applyBalancer();
      report.started.push({ helper: h.name, copy: fresh.id });
    } catch (err) {
      report.errors.push({ helper: rec.helper, error: msg(err) });
    }
  }

  // 3. Add copies until there are enough, on the helpers with the most room.
  let current = loadState().apps[slug];
  let missing = wantHelpers - (current.pool?.placed.length || 0);
  const tried = new Set<string>();
  while (missing > 0 && img && bindIp) {
    const s = loadState();
    const ok = new Set([...reachable].filter((n) => !tried.has(n)));
    const { picked, skipped } = pickHelpers(s, s.apps[slug], img.arch, ok, 1, ownerHigh);
    if (!picked.length) {
      // No awake PC has room: PCs asleep that may be woken over the network, and have room, are.
      const woken = await wakeForRoom(s, s.apps[slug], img.arch, reachable, tried, missing, ownerHigh, report);
      const left = skipped.filter((x) => !tried.has(x.helper) && !woken.includes(x.helper)).map((x) => `${x.helper}: ${x.why}`);
      const short = `Only ${(s.apps[slug].pool?.placed.length || 0) + 1} of ${pool.copies} copies could run.`;
      if (woken.length) {
        report.warnings.push(`${short} Waking ${woken.join(", ")} over the network (Wake-on-LAN): a PC takes 30 s to a minute to answer, then its copy starts.${left.length ? ` Other helpers: ${left.join("; ")}.` : ""}`);
      } else {
        report.warnings.push(`${short}${left.length ? ` Other helpers: ${left.join("; ")}.` : Object.keys(helpers).length ? "" : " No helper PC was added yet."}`);
      }
      break;
    }
    const h = picked[0];
    tried.add(h.name);
    try {
      const fresh = await startCopy(s.apps[slug], h, img, bindIp, log);
      patchApp(slug, (a) => a.pool!.placed.push(fresh));
      await applyBalancer();
      report.started.push({ helper: h.name, copy: fresh.id });
      missing -= 1;
    } catch (err) {
      report.errors.push({ helper: h.name, error: msg(err) });
    }
  }
  if (missing > 0 && !bindIp) report.errors.push({ error: "This server has no Tailscale address for helpers yet (create an invite first)." });

  current = loadState().apps[slug];
  await applyBalancer();
  report.running = 1 + (current.pool?.placed.length || 0);
  const lastError = report.errors.length ? report.errors.map((e) => (e.helper ? `${e.helper}: ` : "") + e.error.split("\n")[0]).join("; ").slice(0, 500) : undefined;
  patchApp(slug, (a) => {
    if (!a.pool) return;
    if (lastError) a.pool.lastError = lastError;
    else delete a.pool.lastError;
  });
  if (report.started.length || report.stopped.length) {
    audit({ event: "pool.reconcile", app: slug, wanted: report.wanted, running: report.running, started: report.started.map((s) => s.helper), stopped: report.stopped.map((s) => s.helper) });
  }
  return report;
}

/**
 * Sets how many copies an app has (manual scale). The first time above one, the caller has checked the
 * guard ("app.pool", confirm): the app's traffic moves to the pool balancer here. With automatic scaling
 * on, only the decider sets the number (`fromDecider`), and it may put the app behind the balancer at one
 * copy, so visits are counted from the start.
 */
export async function setCopies(appName: string, n: number, opts: { by?: string; log?: (l: string) => void; fromDecider?: boolean } = {}) {
  const slug = sanitizeSlug(appName);
  if (!Number.isInteger(n) || n < 1 || n > MAX_COPIES) throw new Error(`Copies must be a whole number from 1 to ${MAX_COPIES}.`);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  if (app.scale?.auto && !opts.fromDecider) {
    throw new Error(
      `Automatic scaling is on for '${slug}': the decider sets its copies within the rule. Change the rule's minimum or maximum ('paasmcp scale rule ${slug} --min 2 --max 4'), turn automatic scaling off ('paasmcp scale auto off ${slug}'), or stop everything ('paasmcp scale off ${slug}').`
    );
  }
  if (!app.pool?.enabled && n === 1 && !opts.fromDecider) return { app: slug, wanted: 1, running: 1, note: "The app already runs only on this server." };
  const enabling = !app.pool?.enabled;
  const warnings: string[] = [];
  if (n > 1 || enabling) {
    const r = poolReadiness(slug, state);
    if (!r.ok) throw new Error(`App '${slug}' cannot have copies on helpers yet:\n- ${r.problems.join("\n- ")}`);
    if (enabling) warnings.push(...r.warnings);
  }
  let tunnel: unknown;
  if (enabling) {
    if (!tailnetBindIp(state)) throw new Error("Prepare this server for helpers first: create an invite ('paasmcp pool invite <name>').");
    if (!OFFLINE()) {
      originImage(slug);
      const local = await waitCopyHealthy(`http://127.0.0.1:${app.localPort}${app.healthcheckPath || "/"}`, 5000);
      if (!local.healthy) {
        throw new Error(`This server's copy must answer GET ${app.healthcheckPath || "/"} with 2xx for the balancer to send it visits (now: ${local.reason}). Pick a health path that answers 200 ('paasmcp deploy ... --healthcheck-path /healthz').`);
      }
    }
    patchApp(slug, (a) => (a.pool = { enabled: true, copies: n, placed: [], enabledAt: new Date().toISOString() }));
    await applyBalancer();
    try {
      tunnel = await routeTunnel(slug, true);
    } catch (err) {
      warnings.push(`Cloudflare Tunnel still sends this app's visits straight to its container, so helpers get none from it: ${msg(err)}`);
    }
    await refreshEdgeQuietly();
  } else {
    patchApp(slug, (a) => (a.pool!.copies = n));
  }
  audit({ event: "scale.copies", app: slug, copies: n, by: opts.by || "cli" });
  const report = await reconcilePool(slug, { log: opts.log });
  return { ...report, warnings: [...warnings, ...report.warnings], ...(enabling ? { balancer: `${POOL_BALANCER}:${app.localPort}` } : {}), ...(tunnel ? { tunnel } : {}) };
}

/**
 * Stop everything: automatic scaling off, back to one copy, here, with no balancer in the way. Automatic
 * scaling goes off first, so the decider takes no step even if the rest fails halfway.
 */
export async function disablePool(appName: string, opts: { by?: string; log?: (l: string) => void } = {}) {
  const slug = sanitizeSlug(appName);
  const app = loadState().apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const wasAuto = Boolean(app.scale?.auto);
  if (wasAuto) {
    patchApp(slug, (a) => delete a.scale!.auto);
    audit({ event: "scale.auto.off", app: slug, by: opts.by || "cli" });
  }
  if (!app.pool) {
    if (wasAuto) appendDiary({ t: new Date().toISOString(), app: slug, kind: "stopped_all", p: { auto: 1 } });
    return { app: slug, disabled: false, note: "The app has no copies on helpers." };
  }
  // The tunnel goes back to the container before the balancer forgets the app.
  let tunnel: unknown;
  try {
    tunnel = await routeTunnel(slug, false);
  } catch (err) {
    throw new Error(`Could not move Cloudflare Tunnel back to the app's container, so the balancer stays: ${msg(err)}`);
  }
  patchApp(slug, (a) => (a.pool!.copies = 1));
  const report = await reconcilePool(slug, { log: opts.log });
  patchApp(slug, (a) => delete a.pool);
  await applyBalancer();
  await refreshEdgeQuietly();
  audit({ event: "scale.off", app: slug, by: opts.by || "cli" });
  appendDiary({ t: new Date().toISOString(), app: slug, kind: "stopped_all", p: wasAuto ? { auto: 1 } : {} });
  return { app: slug, disabled: true, stopped: report.stopped, errors: report.errors, ...(tunnel ? { tunnel } : {}) };
}

/** Stops every copy on helpers at once (this server was fenced: another one serves its data now). */
export async function stopAllPoolCopies(): Promise<{ app: string; stopped: number; error?: string }[]> {
  const out: { app: string; stopped: number; error?: string }[] = [];
  for (const app of pooledApps(loadState())) {
    if (!app.pool!.placed.length) continue;
    try {
      out.push({ app: app.name, stopped: (await reconcilePool(app.name)).stopped.length });
    } catch (err) {
      out.push({ app: app.name, stopped: 0, error: msg(err) });
    }
  }
  return out;
}

/** Keeps helper copies in step with this server's copy after app lifecycle actions. */
export async function poolAfterLifecycle(appName: string, action: string, log?: (l: string) => void): Promise<string | undefined> {
  const slug = sanitizeSlug(appName);
  const app = loadState().apps[slug];
  if (!app?.pool) return undefined;
  try {
    if (action === "destroy") {
      await disablePool(slug, { log });
      return "Its copies on helpers stopped.";
    }
    if (action === "stop") patchApp(slug, (a) => (a.pool!.stoppedAt = new Date().toISOString()));
    else if (action === "start") patchApp(slug, (a) => delete a.pool!.stoppedAt);
    else if (action !== "restart" && action !== "rollback") return undefined;
    const r = await reconcilePool(slug, { log });
    return `Copies on helpers: ${r.running - 1} running${r.errors.length ? ` (problems: ${r.errors.map((e) => e.error.split("\n")[0]).join("; ")})` : ""}.`;
  } catch (err) {
    return `Copies on helpers were not updated: ${msg(err)}`;
  }
}

// ---------- balancer ----------

/** The name of an app's server in the balancer, which labels its request counter (autoscale.ts reads it). */
export function balancerServerName(app: Pick<AppRecord, "name" | "localPort">): string {
  return /^[a-z0-9][a-z0-9-]{0,62}$/.test(app.name) ? app.name : `port-${Number(app.localPort)}`;
}

/**
 * The balancer's Caddyfile (pure): one port per pooled app, the app's own number. Each port is a server
 * named after the app with metrics on, so the admin socket counts each app's visits apart.
 */
export function buildBalancerCaddyfile(state: PaaSState): string {
  const lines = ["{", `\tadmin ${LB_ADMIN}`, "\tauto_https off"];
  for (const app of pooledApps(state)) lines.push(`\tservers :${Number(app.localPort)} {`, `\t\tname ${balancerServerName(app)}`, "\t\tmetrics", "\t}");
  lines.push("}", "");
  const helpers = state.pool?.helpers || {};
  for (const app of pooledApps(state)) {
    const backends = [`${app.containerName}:${app.internalPort}`];
    for (const c of app.pool!.placed) {
      const h = helpers[c.helper];
      if (h && !h.paused) backends.push(`${validateIpv4(h.ip)}:${c.port}`);
    }
    lines.push(`:${Number(app.localPort)} {`, `\treverse_proxy ${backends.join(" ")} {`);
    lines.push("\t\tlb_policy round_robin", "\t\tlb_try_duration 5s", "\t\tfail_duration 30s");
    // Checked again here (state.json can be edited by hand): one plain URL path, no spaces or braces.
    const healthUri = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,511}$/.test(app.healthcheckPath || "") ? app.healthcheckPath : "/";
    lines.push(`\t\thealth_uri ${healthUri}`, "\t\thealth_interval 3s", "\t\thealth_timeout 2s", "\t\thealth_status 2xx", "\t\thealth_fails 2", "\t\thealth_passes 1");
    lines.push("\t}", "}", "");
  }
  return lines.join("\n");
}

const lbCompose = (image: string) => `services:
  lb:
    image: ${image}
    container_name: ${POOL_BALANCER}
    restart: unless-stopped
${WATCHTOWER_OFF_COMPOSE}    mem_limit: 128m
    # No published port: Cloudflare Tunnel reaches it by name on the Docker network.
    volumes:
      - ./conf:/etc/caddy:ro
      - ./data:/data
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`;

export function balancerRunning(): boolean {
  if (OFFLINE()) return Boolean(loadState().pool?.balancerAt);
  try {
    return execFileSync("docker", ["inspect", "--format", "{{.State.Running}}", POOL_BALANCER], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim() === "true";
  } catch {
    return false;
  }
}

/**
 * Writes the balancer for the pooled apps and makes it run (or stops it when none is left). Reloads
 * gracefully: requests in progress finish on the old configuration.
 */
export async function applyBalancer(): Promise<{ running: boolean; changed: boolean }> {
  const state = loadState();
  const apps = pooledApps(state);
  const compose = path.join(LB_DIR, "compose.yaml");
  if (!apps.length) {
    if (state.pool?.balancerAt) {
      if (!OFFLINE() && fs.existsSync(compose)) spawnSync("docker", ["compose", "-f", compose, "down"], { cwd: LB_DIR, stdio: "ignore" });
      savePool((p) => delete p.balancerAt);
      audit({ event: "pool.balancer.stop" });
    }
    return { running: false, changed: Boolean(state.pool?.balancerAt) };
  }
  const conf = path.join(LB_DIR, "conf");
  fs.mkdirSync(conf, { recursive: true, mode: 0o700 });
  const file = path.join(conf, "Caddyfile");
  const next = buildBalancerCaddyfile(state);
  const changed = !fs.existsSync(file) || fs.readFileSync(file, "utf-8") !== next;
  if (changed) {
    writeFileAtomic(file, next);
    fs.chmodSync(file, 0o644);
  }
  const { CADDY_IMAGE } = await import("./edge.js");
  if (!balancerRunning()) {
    fs.writeFileSync(compose, lbCompose(CADDY_IMAGE), { mode: 0o600 });
    if (!OFFLINE()) {
      const { ensureDockerNetwork } = await import("./database.js");
      ensureDockerNetwork();
      execFileSync("docker", ["compose", "-f", compose, "up", "-d"], { cwd: LB_DIR, stdio: "pipe" });
    }
    savePool((p) => (p.balancerAt = p.balancerAt || new Date().toISOString()));
    audit({ event: "pool.balancer.start" });
    return { running: true, changed: true };
  }
  if (changed && !OFFLINE()) {
    try {
      execFileSync("docker", ["exec", POOL_BALANCER, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--address", LB_ADMIN], { stdio: "pipe" });
    } catch {
      execFileSync("docker", ["restart", POOL_BALANCER], { stdio: "pipe" });
    }
  }
  if (changed) await refreshEdgeQuietly();
  return { running: true, changed };
}

async function refreshEdgeQuietly(): Promise<void> {
  try {
    const { refreshEdge } = await import("./edge.js");
    refreshEdge();
  } catch {
    // the edge reports its own state
  }
}

// ---------- Cloudflare Tunnel ----------

type IngressRule = { hostname?: string; service: string; originRequest?: Record<string, unknown>; [k: string]: unknown };

/** Points the app's hostnames at `to` when they point at `from` (pure; other rules are untouched). */
export function rewriteIngress(ingress: IngressRule[], hostnames: string[], from: string, to: string): { ingress: IngressRule[]; changed: string[] } {
  const set = new Set(hostnames);
  const changed: string[] = [];
  const out = ingress.map((r) => {
    if (r.hostname && set.has(r.hostname) && r.service === from) {
      changed.push(r.hostname);
      return { ...r, service: to };
    }
    return r;
  });
  return { ingress: out, changed };
}

/** Moves the app's Cloudflare Tunnel hostnames to the balancer (or back to the container). */
export async function routeTunnel(slug: string, viaBalancer: boolean): Promise<{ changed: string[] } | { skipped: string }> {
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const hostnames = app.domains.filter((d) => d.mode === "public" || d.mode === "zero-trust").map((d) => d.hostname);
  if (!hostnames.length) return { skipped: "the app has no Cloudflare Tunnel address" };
  const { accountId, tunnelId } = state.cloudflare;
  const token = getSecrets("system").CF_API_TOKEN || process.env.CF_API_TOKEN;
  if (!accountId || !tunnelId || !token) return { skipped: "Cloudflare Tunnel is not configured on this server" };
  if (OFFLINE()) return { skipped: "offline test" };
  const direct = appServiceUrl({ ...app, pool: undefined });
  const balancer = appServiceUrl({ ...app, pool: { enabled: true, copies: 1, placed: [], enabledAt: "" } });
  const base = `https://api.cloudflare.com/client/v4/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`;
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  const get = await fetch(base, { headers, signal: AbortSignal.timeout(20_000) });
  if (!get.ok) throw new Error(`reading the tunnel configuration failed (${get.status})`);
  const cfg = (await get.json()) as { result?: { config?: { ingress?: IngressRule[]; [k: string]: unknown } } };
  const config = cfg.result?.config || {};
  const { ingress, changed } = rewriteIngress(config.ingress || [], hostnames, viaBalancer ? direct : balancer, viaBalancer ? balancer : direct);
  if (!changed.length) return { changed };
  const put = await fetch(base, { method: "PUT", headers, body: JSON.stringify({ config: { ...config, ingress } }), signal: AbortSignal.timeout(20_000) });
  if (!put.ok) throw new Error(`updating the tunnel configuration failed (${put.status})`);
  audit({ event: "pool.tunnel", app: slug, viaBalancer, hostnames: changed });
  return { changed };
}

// ---------- reading ----------

/** asleep: not answering, and it can be woken over the network; waking: a magic packet is on its way. */
export type HelperState = "available" | "working" | "paused" | "busy" | "gone" | "asleep" | "waking" | "unknown";

export async function poolStatus(opts: { probe?: boolean } = {}) {
  let state = loadState();
  const helpers = Object.values(state.pool?.helpers || {});
  if (opts.probe !== false && helpers.length) {
    await probeHelpers(helpers);
    state = loadState();
  }
  const seen = readSeen();
  const used = usedOnHelpers(state);
  const tracks = readWake().helpers;
  const now = Date.now();
  const placedOn = (name: string) =>
    pooledApps(state).flatMap((a) => a.pool!.placed.filter((c) => c.helper === name).map((c) => ({ app: a.name, copy: c.id, since: c.startedAt })));
  return {
    bindIp: tailnetBindIp(state) || null,
    balancer: { running: Boolean(state.pool?.balancerAt), since: state.pool?.balancerAt || null },
    helpers: helpers
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((h) => {
        const s = seen[h.name];
        const copies = placedOn(h.name);
        const wake = wakeOf(h);
        const track = tracks[h.name];
        const ws = wakeStatus(track, now);
        const asleep: HelperState = !wake || ws === "gave_up" ? "gone" : track ? "waking" : "asleep";
        const st: HelperState = h.paused ? "paused" : !s ? "unknown" : !s.ok ? asleep : ownerBusy(h) ? "busy" : copies.length ? "working" : "available";
        return {
          name: h.name,
          ip: h.ip,
          state: st,
          arch: h.arch,
          cpus: s?.facts?.cpus ?? h.cpus,
          memMb: s?.facts?.memMb ?? h.memMb,
          diskFreeGb: s?.facts?.diskFreeGb ?? h.diskFreeGb,
          give: h.give,
          used: { cpus: Math.round((used[h.name]?.cpus || 0) * 100) / 100, memMb: used[h.name]?.memMb || 0 },
          load1: s?.facts?.load1 ?? null,
          secretsInMemory: s?.facts?.secretsInMemory ?? null,
          copies,
          lastSeenAt: s?.at || null,
          ...(s && !s.ok ? { lastError: s.error, failedAt: s.failedAt } : {}),
          ...(h.paused ? { paused: h.paused } : {}),
          courtesy: courtesyOf(h),
          ownerBusy: ownerBusy(h) ? h.ownerBusy : null,
          // The owner's CPU at the last answer; null when that answer could not tell, absent on an old worker.
          ...(s?.ok && s.facts ? { owner: s.facts.owner ?? { cpuPct: null, seconds: 0, why: "old_worker" } } : {}),
          // Wake-on-LAN: the settings, the card the PC reported last time it answered, and any wake in progress.
          wake: wake ? { ...wake, since: h.wake!.since, by: h.wake!.by } : null,
          lan: s?.facts?.lan ?? null,
          ...(track ? { waking: { since: new Date(track.firstSentAt).toISOString(), tries: track.tries, ...(ws === "gave_up" ? { gaveUp: true } : {}) } } : {}),
          addedAt: h.addedAt,
        };
      }),
    apps: pooledApps(state).map((a) => {
      // A copy counts as running only if its PC answered last time, is not paused and listed it running.
      const answering = (c: PoolCopyRecord) => {
        const s = seen[c.helper];
        return Boolean(s?.ok && !state.pool?.helpers[c.helper]?.paused && (s.copies || []).some((x) => x.copyId === c.id && x.running));
      };
      return {
      app: a.name,
      wanted: a.pool!.copies,
      running: a.pool!.stoppedAt ? 0 : 1 + a.pool!.placed.filter(answering).length,
      copies: a.pool!.placed.map((c) => ({ helper: c.helper, copy: c.id, since: c.startedAt, answering: answering(c) })),
      ...(a.scale?.auto ? { auto: true } : {}),
      ...(a.pool!.stoppedAt ? { stoppedAt: a.pool!.stoppedAt } : {}),
      ...(a.pool!.lastError ? { lastError: a.pool!.lastError } : {}),
      };
    }),
    invites: Object.entries(state.pool?.invites || {})
      .filter(([, i]) => !i.usedAt && Date.parse(i.createdAt) + INVITE_ADD_WINDOW_MS > Date.now())
      .map(([, i]) => ({ name: i.name, joinBy: i.expiresAt, addBy: new Date(Date.parse(i.createdAt) + INVITE_ADD_WINDOW_MS).toISOString() })),
  };
}

/** Tailscale access rules to paste (HuJSON): helpers reach only the data here; only this server reaches them. */
export function poolAcl(state = loadState()): { tag: string; originIp: string | null; acl: string; steps: string[] } {
  const ip = tailnetBindIp(state) || "<this server's Tailscale IP>";
  const acl = `// PaaSMCP helper pool. Paste into the access controls of your Tailscale admin console
// (Access controls → JSON editor), merging with what you already have. If your policy still
// has the default rule that lets everything reach everything, helpers are not fenced in until
// you replace it with rules like these.
{
  "tagOwners": {
    "${HELPER_TAG}": ["autogroup:admin"]
  },
  "acls": [
    // This server gives orders (SSH) and sends visits (app ports) to the helpers.
    { "action": "accept", "src": ["${ip}"], "dst": ["${HELPER_TAG}:22,4000-4998"] },
    // Helpers reach only Postgres, Redis and S3 on this server, nothing else in your Tailnet.
    { "action": "accept", "src": ["${HELPER_TAG}"], "dst": ["${ip}:5432,6379,3900"] },
    // Your own devices (adjust to what you already allow).
    { "action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"] }
  ]
}`;
  return {
    tag: HELPER_TAG,
    originIp: tailnetBindIp(state) || null,
    acl,
    steps: [
      `On each helper PC: sudo tailscale up --advertise-tags=${HELPER_TAG} (you must be an admin of the Tailnet).`,
      "In the Tailscale admin console, Access controls: merge the rules above, then Save.",
      "If a self-hosted entry (edge) on another server also sends visits to helpers, add its Tailscale IP to the first rule's src.",
    ],
  };
}
