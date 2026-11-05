import crypto from "node:crypto";

/** Keeps Watchtower away from PaaSMCP's containers (re-exported by config.ts; kept here so the worker stays dependency-free). */
export const WATCHTOWER_OFF_LABEL = "com.centurylinklabs.watchtower.enable=false";

// Shared, side-effect-free pieces of the helper pool (scale phase 3). Imported by the origin
// (pool.ts), by the helper's one-time setup (pooljoin.ts) and by the forced SSH command that runs on
// the helper for each order (worker.ts). Nothing here touches the disk, Docker or the network, so it is
// all unit-tested, and the worker loads no more code than it needs.
//
// Trust model: the origin owns the vault and decides; a helper only runs stateless copies when told.
// Whatever a helper sends back (facts, lists) is untrusted data and goes through the validators below
// before it reaches the state, the dashboard or an AI.

export const INVITE_PREFIX = "paasmcp-pool://";
/** A PC must run `pool join` within this time; the origin accepts `pool add` for an hour after the invite. */
export const INVITE_TTL_MS = 15 * 60 * 1000;
export const INVITE_ADD_WINDOW_MS = 60 * 60 * 1000;
export const WORKER_USER = "paasmcp-worker";
export const WORKER_HOME = "/var/lib/paasmcp-worker";
/** tmpfs (wiped on reboot): the only place an app's variables are ever written on a helper. */
export const WORKER_RUN_DIR = "/run/paasmcp-worker";
export const TMPFILES_CONF = "/etc/tmpfiles.d/paasmcp-worker.conf";
export const COPY_CONTAINER_PREFIX = "paasmcp-pool-";
export const POOL_IMAGE_REPO = "paasmcp-pool";
/** Path inside a copy where its variables are mounted (read-only), and the wrapper that loads them. */
export const COPY_ENV_MOUNT = "/run/paasmcp/env";
export const ENV_WRAPPER = `set -a; . ${COPY_ENV_MOUNT}; set +a; exec "$@"`;
/** Names the app reaches on the origin (Postgres, Redis, S3): on a helper they point at the origin's Tailscale IP. */
export const SHARED_HOSTS = ["paasmcp-postgres", "paasmcp-redis", "paasmcp-garage"];
export const HELPER_TAG = "tag:paasmcp-helper";
export const WORKER_OPS = ["hello", "facts", "has-image", "load", "run", "stop", "logs", "list", "forget"] as const;
export type WorkerOp = (typeof WORKER_OPS)[number];

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const SLUG = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const NODE_ID = /^[A-Za-z0-9._-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
export const COPY_ID = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?-[0-9a-f]{6}$/;
export const POOL_IMAGE_TAG = /^paasmcp-pool\/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?:[0-9a-f]{12}$/;
const ED25519_KEY = /^ssh-ed25519 [A-Za-z0-9+/]{68}={0,2}$/;

export const sha256 = (s: string | Buffer) => crypto.createHash("sha256").update(s).digest("hex");

export function validateIpv4(ip: unknown, what = "IP"): string {
  const clean = String(ip ?? "").trim();
  if (!IPV4.test(clean) || clean.startsWith("0.") || clean.startsWith("127.")) throw new Error(`Invalid ${what} '${String(ip ?? "").slice(0, 60)}': use the IPv4 address shown by 'tailscale ip -4'.`);
  return clean;
}

/** True for Tailscale's address range (100.64.0.0/10). Labs use private ranges instead. */
export function isTailscaleIp(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return a === 100 && b >= 64 && b <= 127;
}

export function validateHelperName(name: unknown): string {
  const clean = String(name ?? "").trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/.test(clean)) {
    throw new Error(`Invalid helper name '${String(name ?? "").slice(0, 40)}': use 1-32 lowercase letters, digits or '-', like 'notebook'.`);
  }
  return clean;
}

/** "ssh-ed25519 AAAA... comment" → "ssh-ed25519 AAAA..." (the comment is dropped: it is free text). */
export function cleanPublicKey(line: unknown): string {
  const parts = String(line ?? "").trim().split(/\s+/);
  const key = `${parts[0]} ${parts[1] ?? ""}`;
  if (!ED25519_KEY.test(key)) throw new Error("The invite carries an unexpected SSH key (only ssh-ed25519 is accepted).");
  return key;
}

export function sshKeyFingerprint(publicKey: string): string {
  const b64 = cleanPublicKey(publicKey).split(" ")[1];
  return "SHA256:" + crypto.createHash("sha256").update(Buffer.from(b64, "base64")).digest("base64").replace(/=+$/, "");
}

// ---------- invite ----------

export interface PoolInvite {
  v: 1;
  /** One invite = one PC; the origin remembers the id until it is used or expires. */
  id: string;
  name: string;
  originNodeId: string;
  originName: string;
  /** The origin's Tailscale IP: the only address the helper's key accepts orders from. */
  originIp: string;
  /** The origin's pool public key, installed on the helper behind a forced command. */
  originKey: string;
  /** Lets the helper prove, once, that it is the PC that received this invite (HMAC, never sent back). */
  proofKey: string;
  exp: number;
}

export function encodeInvite(inv: PoolInvite): string {
  return INVITE_PREFIX + Buffer.from(JSON.stringify(inv)).toString("base64url");
}

/** Parses and checks an invite (format, every field, expiry). Throws with a plain message. */
export function decodeInvite(text: unknown, now = Date.now()): PoolInvite {
  const clean = String(text ?? "").trim().replace(/^['"]|['"]$/g, "");
  if (!clean.startsWith(INVITE_PREFIX)) throw new Error(`Not a pool invite (it starts with '${INVITE_PREFIX}').`);
  const body = clean.slice(INVITE_PREFIX.length);
  if (!/^[A-Za-z0-9_-]{1,4000}$/.test(body)) throw new Error("The invite is damaged (copy it again, in one line).");
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
  } catch {
    throw new Error("The invite is damaged (copy it again, in one line).");
  }
  if (!raw || raw.v !== 1) throw new Error("Unknown invite version: update PaaSMCP on this PC.");
  const inv: PoolInvite = {
    v: 1,
    id: String(raw.id ?? ""),
    name: validateHelperName(raw.name),
    originNodeId: String(raw.originNodeId ?? ""),
    originName: String(raw.originName ?? ""),
    originIp: validateIpv4(raw.originIp, "origin IP"),
    originKey: cleanPublicKey(raw.originKey),
    proofKey: String(raw.proofKey ?? ""),
    exp: Number(raw.exp),
  };
  if (!/^[0-9a-f]{16}$/.test(inv.id)) throw new Error("The invite is damaged (bad id).");
  if (!NODE_ID.test(inv.originNodeId)) throw new Error("The invite is damaged (bad server id).");
  if (!/^[a-z0-9-]{1,63}$/.test(inv.originName)) throw new Error("The invite is damaged (bad server name).");
  if (!HEX64.test(inv.proofKey)) throw new Error("The invite is damaged (bad proof key).");
  if (!Number.isFinite(inv.exp)) throw new Error("The invite is damaged (bad expiry).");
  if (inv.exp < now) throw new Error("This invite expired (they last 15 minutes). Create a new one on the server: paasmcp pool invite <name>.");
  if (inv.exp > now + INVITE_TTL_MS + 5 * 60 * 1000) throw new Error("This invite expires too far in the future: check this PC's clock.");
  return inv;
}

/** What the helper sends back on `hello`: proves it holds the invite without revealing the key. */
export function helloProof(proofKey: string, inviteId: string, nonce: string, name: string): string {
  return crypto.createHmac("sha256", Buffer.from(proofKey, "hex")).update(`paasmcp-pool-hello\n${inviteId}\n${nonce}\n${name}`).digest("hex");
}

/**
 * The helper's authorized_keys line: only from the origin's IP, only the worker command, no terminal,
 * no forwarding of any kind (`restrict`).
 */
export function authorizedKeysLine(opts: { originIp: string; command: string; publicKey: string }): string {
  const ip = validateIpv4(opts.originIp, "origin IP");
  if (!/^[A-Za-z0-9/._ +-]{1,400}$/.test(opts.command)) throw new Error("The worker command path has unexpected characters; install PaaSMCP in a plain path.");
  return `from="${ip}",command="${opts.command}",restrict ${cleanPublicKey(opts.publicKey)} paasmcp-pool`;
}

// ---------- orders ----------

/** Parses SSH_ORIGINAL_COMMAND: an order name and at most two plain arguments. Never a shell line. */
export function parseOrder(raw: unknown): { op: WorkerOp; args: string[] } {
  const text = String(raw ?? "").trim();
  if (!text) throw new Error("This access only takes orders from PaaSMCP; it never opens a terminal.");
  if (text.length > 200) throw new Error("Order too long.");
  const parts = text.split(/\s+/);
  const op = parts[0] as WorkerOp;
  if (!(WORKER_OPS as readonly string[]).includes(op)) throw new Error(`Unknown order '${parts[0].slice(0, 20)}'. This access only takes orders from PaaSMCP; it never opens a terminal.`);
  const args = parts.slice(1);
  const want: Record<WorkerOp, RegExp[]> = {
    hello: [], facts: [], list: [], forget: [], run: [],
    "has-image": [POOL_IMAGE_TAG, HEX64],
    load: [POOL_IMAGE_TAG, HEX64],
    stop: [COPY_ID],
    logs: [COPY_ID],
  };
  const rules = want[op];
  if (args.length !== rules.length || args.some((a, i) => !rules[i].test(a))) throw new Error(`Bad arguments for '${op}'.`);
  return { op, args };
}

// ---------- copies ----------

export interface CopySpec {
  app: string;
  copyId: string;
  image: string;
  fingerprint: string;
  /** Port the copy is published on, on the helper's Tailscale IP only. */
  port: number;
  internalPort: number;
  env: Record<string, string>;
  /** Docker formats: "512m" and "0.5". Always set on a helper (the owner's share caps them). */
  memory: string;
  cpus: string;
  originIp: string;
  originNodeId: string;
}

const MAX_ENV_BYTES = 256 * 1024;

export function validateEnvKeyName(k: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(k)) throw new Error(`Invalid variable name '${k.slice(0, 40)}'.`);
  return k;
}

/** Validates a copy order on the helper. Everything comes from the origin, but is still checked field by field. */
export function validateCopySpec(raw: unknown): CopySpec {
  const r = (raw || {}) as Record<string, unknown>;
  const s: CopySpec = {
    app: String(r.app ?? ""),
    copyId: String(r.copyId ?? ""),
    image: String(r.image ?? ""),
    fingerprint: String(r.fingerprint ?? ""),
    port: Number(r.port),
    internalPort: Number(r.internalPort),
    env: {},
    memory: String(r.memory ?? ""),
    cpus: String(r.cpus ?? ""),
    originIp: validateIpv4(r.originIp, "origin IP"),
    originNodeId: String(r.originNodeId ?? ""),
  };
  if (!SLUG.test(s.app)) throw new Error("Bad app name.");
  if (!COPY_ID.test(s.copyId) || !s.copyId.startsWith(`${s.app}-`)) throw new Error("Bad copy id.");
  if (!POOL_IMAGE_TAG.test(s.image) || !s.image.startsWith(`${POOL_IMAGE_REPO}/${s.app}:`)) throw new Error("Bad image tag.");
  if (!HEX64.test(s.fingerprint) || !s.image.endsWith(`:${s.fingerprint.slice(0, 12)}`)) throw new Error("Bad image fingerprint.");
  if (!Number.isInteger(s.port) || s.port < 4000 || s.port > 4998) throw new Error("Bad port (4000-4998).");
  if (!Number.isInteger(s.internalPort) || s.internalPort < 1 || s.internalPort > 65535) throw new Error("Bad internal port.");
  if (!/^\d{1,6}m$/.test(s.memory) || Number(s.memory.slice(0, -1)) < 16) throw new Error("Bad memory limit (whole MB, like 512m).");
  if (!/^\d{1,3}(\.\d{1,2})?$/.test(s.cpus) || Number(s.cpus) <= 0) throw new Error("Bad CPU limit.");
  if (!NODE_ID.test(s.originNodeId)) throw new Error("Bad server id.");
  const env = r.env;
  if (!env || typeof env !== "object" || Array.isArray(env)) throw new Error("Bad variables.");
  let size = 0;
  for (const [k, v] of Object.entries(env as Record<string, unknown>)) {
    s.env[validateEnvKeyName(k)] = String(v ?? "");
    size += k.length + String(v ?? "").length;
  }
  if (size > MAX_ENV_BYTES) throw new Error("Variables too large.");
  return s;
}

/** Single-quotes a value for a POSIX shell (`'` becomes `'\''`). */
export function shellQuote(v: string): string {
  return `'${v.replace(/'/g, `'\\''`)}'`;
}

/**
 * The copy's variables as a file the wrapper sources (`set -a; . file`). Values match the origin's
 * .env.runtime byte for byte: carriage returns dropped and newlines written as the two characters \n.
 */
export function renderEnvFile(env: Record<string, string>): string {
  return Object.entries(env)
    .map(([k, v]) => `${validateEnvKeyName(k)}=${shellQuote(String(v).replace(/\r/g, "").replace(/\n/g, "\\n"))}`)
    .join("\n") + "\n";
}

/** Docker CPU and memory for a copy on a helper: the app's limits, capped by what the owner gave. */
export function copyLimits(app: { cpuLimit?: string; memoryLimit?: string }, give: { cpus: number; memMb: number }): { cpus: number; memMb: number } {
  const appCpu = Number(app.cpuLimit);
  const cpus = Number.isFinite(appCpu) && appCpu > 0 ? Math.min(appCpu, give.cpus) : give.cpus;
  const appMem = parseMemoryMb(app.memoryLimit);
  const memMb = appMem ? Math.min(appMem, give.memMb) : give.memMb;
  return { cpus: Math.round(cpus * 100) / 100, memMb: Math.floor(memMb) };
}

/** "512m" → 512, "2g" → 2048, "1048576k" → 1024. */
export function parseMemoryMb(limit?: string): number | undefined {
  const m = /^(\d+)([kmg])b?$/i.exec(String(limit || "").trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  return unit === "g" ? n * 1024 : unit === "m" ? n : Math.floor(n / 1024);
}

/** `docker run` arguments for a copy (pure). The variables never go on the command line or in the container config. */
export function buildRunArgs(spec: CopySpec, bindIp: string, envFile: string, entrypoint: string[], cmd: string[]): string[] {
  const ip = validateIpv4(bindIp, "helper IP");
  return [
    "run", "-d",
    "--name", `${COPY_CONTAINER_PREFIX}${spec.copyId}`,
    "--label", `paasmcp.pool=${spec.originNodeId}`,
    "--label", `paasmcp.app=${spec.app}`,
    "--label", `paasmcp.copy=${spec.copyId}`,
    "--label", `paasmcp.fingerprint=${spec.fingerprint}`,
    "--label", WATCHTOWER_OFF_LABEL,
    "--restart", "no",
    "--memory", spec.memory,
    "--cpus", spec.cpus,
    "--pids-limit", "1024",
    "--security-opt", "no-new-privileges",
    "--publish", `${ip}:${spec.port}:${spec.internalPort}`,
    ...SHARED_HOSTS.flatMap((h) => ["--add-host", `${h}:${spec.originIp}`]),
    "--mount", `type=bind,source=${envFile},target=${COPY_ENV_MOUNT},readonly`,
    "--entrypoint", "/bin/sh",
    spec.image,
    "-c", ENV_WRAPPER, "paasmcp-copy",
    ...entrypoint, ...cmd,
  ];
}

// ---------- images ----------

const asList = (v: unknown) => (Array.isArray(v) ? v.map(String) : typeof v === "string" ? [v] : []);

/**
 * Store-independent fingerprint of an image (`docker image inspect` JSON): layer digests and the parts of
 * the config a container runs with. `.Id` differs between the classic and the containerd image stores
 * for the same image, so it cannot be compared across machines; these fields can.
 */
export function imageFingerprint(inspect: unknown): string {
  const i = (inspect || {}) as { Architecture?: string; Os?: string; RootFS?: { Layers?: unknown }; Config?: Record<string, unknown> };
  const c = i.Config || {};
  const layers = asList(i.RootFS?.Layers);
  if (!layers.length) throw new Error("The image has no layers to fingerprint.");
  return sha256(
    JSON.stringify({
      arch: String(i.Architecture || ""),
      os: String(i.Os || ""),
      layers,
      entrypoint: asList(c.Entrypoint),
      cmd: asList(c.Cmd),
      env: asList(c.Env),
      user: String(c.User || ""),
      workdir: String(c.WorkingDir || ""),
      ports: Object.keys((c.ExposedPorts as Record<string, unknown>) || {}).sort(),
    })
  );
}

/** Docker's architecture names ("x86_64", "aarch64") as image architectures ("amd64", "arm64"). */
export function normalizeArch(a: unknown): string {
  const s = String(a || "").toLowerCase();
  if (s === "x86_64" || s === "amd64") return "amd64";
  if (s === "aarch64" || s === "arm64") return "arm64";
  if (s.startsWith("armv7") || s === "arm") return "arm";
  return /^[a-z0-9_]{1,16}$/.test(s) ? s : "unknown";
}

// ---------- what helpers send back (untrusted) ----------

export interface WorkerFacts {
  name: string;
  arch: string;
  cpus: number;
  memMb: number;
  diskFreeGb: number;
  give: { cpus: number; memMb: number };
  dockerVersion: string;
  workerVersion: string;
  /** 1-minute load average of the whole PC (the owner's use included). */
  load1: number;
  secretsInMemory: boolean;
  /** Courteous mode: how much CPU the PC used outside the copies (absent on workers older than it). */
  owner?: OwnerReading;
  /** Wake-on-LAN: the PC's network card on its home network (absent on older workers, or when unknown). */
  lan?: LanFacts;
}

export interface WorkerCopy {
  copyId: string;
  app: string;
  running: boolean;
  status: string;
  fingerprint: string;
}

const num = (v: unknown, lo: number, hi: number) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : lo;
};
const text = (v: unknown, max: number, re = /^[A-Za-z0-9 ._:+()-]*$/) => {
  const s = String(v ?? "").slice(0, max);
  return re.test(s) ? s : "";
};

/** Facts a helper reports about itself, clamped and stripped to plain values. */
export function validateFacts(raw: unknown): WorkerFacts {
  const r = (raw || {}) as Record<string, unknown>;
  const give = (r.give || {}) as Record<string, unknown>;
  const lan = validateLan(r.lan);
  return {
    name: validateHelperName(r.name),
    arch: normalizeArch(r.arch),
    cpus: Math.round(num(r.cpus, 0, 1024)),
    memMb: Math.round(num(r.memMb, 0, 16 * 1024 * 1024)),
    diskFreeGb: Math.round(num(r.diskFreeGb, 0, 1_000_000) * 10) / 10,
    give: { cpus: Math.round(num(give.cpus, 0, 1024) * 100) / 100, memMb: Math.round(num(give.memMb, 0, 16 * 1024 * 1024)) },
    dockerVersion: text(r.dockerVersion, 40),
    workerVersion: text(r.workerVersion, 40),
    load1: Math.round(num(r.load1, 0, 10_000) * 100) / 100,
    secretsInMemory: r.secretsInMemory === true,
    ...(r.owner && typeof r.owner === "object" ? { owner: validateOwnerReading(r.owner) } : {}),
    ...(lan ? { lan } : {}),
  };
}

/** The owner's CPU reading a helper sends: a number from 0 to 100, or the code of why there is none. */
export function validateOwnerReading(raw: unknown): OwnerReading {
  const r = (raw || {}) as Record<string, unknown>;
  const seconds = Math.round(num(r.seconds, 0, 3600));
  const pct = Number(r.cpuPct);
  if (r.cpuPct !== null && r.cpuPct !== undefined && Number.isFinite(pct)) return { cpuPct: Math.round(Math.min(100, Math.max(0, pct))), seconds };
  const why = String(r.why ?? "");
  return { cpuPct: null, seconds, why: (OWNER_UNSURE as readonly string[]).includes(why) ? (why as OwnerUnsure) : "unreadable" };
}

// ---------- courteous mode: the owner's use of the PC ----------
//
// A helper PC belongs to someone who also uses it. The worker reports how much CPU the PC used outside
// the copies since the origin last asked (the owner's programs, mostly); the origin decides whether the
// owner is using the PC and moves the copies away (courtesy.ts). Nothing runs on the PC in between: each
// order reads two counters, the whole PC's CPU time and each copy's, and keeps the last reading in a file.

/** Counters read at one moment on the helper: CPU time in microseconds, for the whole PC and per copy. */
export interface OwnerSnapshot {
  at: number;
  totalUs: number;
  /** CPUs the PC has (a CPU quota on the PC's own cgroup counts, as inside a container). */
  cores: number;
  copies: Record<string, number>;
}

export const OWNER_UNSURE = ["short", "stale", "busy_order", "copy_left", "unreadable", "counter_reset"] as const;
export type OwnerUnsure = (typeof OWNER_UNSURE)[number];

export interface OwnerReading {
  /** CPU the PC used outside the copies, in % of all its CPUs; null when this window cannot tell. */
  cpuPct: number | null;
  /** Length of the window measured. */
  seconds: number;
  why?: OwnerUnsure;
}

/** A window shorter than this says little (the worker answers the previous one instead). */
export const OWNER_MIN_WINDOW_MS = 10_000;
/** A window longer than this is too old to describe now. */
export const OWNER_MAX_WINDOW_MS = 15 * 60 * 1000;

/**
 * The owner's share of the PC's CPU between two snapshots (pure). Unsure (null) when the window is too
 * short or too old, when an image load or a copy start ran in it (that CPU belongs to Docker, not to the
 * owner), when a copy left during it (its last CPU time is unknown) or when a counter went back.
 * A copy that started in the window counts with all its CPU time, which is all inside the window.
 */
export function ownerShare(prev: OwnerSnapshot, cur: OwnerSnapshot, heavy?: { at: number; open: boolean }, minMs = OWNER_MIN_WINDOW_MS): OwnerReading {
  const ms = cur.at - prev.at;
  const seconds = Math.max(0, Math.round(ms / 1000));
  const unsure = (why: OwnerUnsure): OwnerReading => ({ cpuPct: null, seconds, why });
  if (ms < minMs) return unsure("short");
  if (ms > OWNER_MAX_WINDOW_MS) return unsure("stale");
  if (heavy && (heavy.at > prev.at || (heavy.open && cur.at - heavy.at < 2 * 60 * 60 * 1000))) return unsure("busy_order");
  if (Object.keys(prev.copies).some((id) => !(id in cur.copies))) return unsure("copy_left");
  const total = cur.totalUs - prev.totalUs;
  let copies = 0;
  for (const [id, us] of Object.entries(cur.copies)) {
    const d = us - (prev.copies[id] ?? 0);
    if (d < 0) return unsure("counter_reset");
    copies += d;
  }
  if (total < 0 || !(cur.cores > 0)) return unsure("counter_reset");
  const ownerCores = Math.max(0, total - copies) / (ms * 1000);
  return { cpuPct: Math.round(Math.min(100, (ownerCores / cur.cores) * 100)), seconds };
}

/**
 * The path of a process's CPU accounting cgroup in /proc/<pid>/cgroup: the "0::" line on cgroup v2,
 * the "cpuacct" controller's line on cgroup v1 (also on hybrid systems, where v2 has no CPU controller).
 */
export function cpuCgroupPath(procCgroup: string, v2: boolean): string | undefined {
  for (const line of String(procCgroup).split("\n")) {
    const m = /^(\d+):([^:]*):(\/.*)$/.exec(line.trim());
    if (!m) continue;
    if (v2 ? m[1] === "0" && m[2] === "" : m[2].split(",").includes("cpuacct")) return m[3];
  }
  return undefined;
}

/** `usage_usec` from a cgroup v2 cpu.stat file. */
export function parseCpuStatUsage(text: string): number | undefined {
  const m = /^usage_usec (\d+)$/m.exec(String(text));
  return m ? Number(m[1]) : undefined;
}

/** Busy CPU time of the whole PC from /proc/stat's first line, in microseconds (USER_HZ 100). */
export function procStatBusyUs(text: string): number | undefined {
  const line = String(text).split("\n").find((l) => /^cpu\s/.test(l));
  if (!line) return undefined;
  // user nice system idle iowait irq softirq steal (guest time is already inside user)
  const f = line.trim().split(/\s+/).slice(1).map(Number);
  if (f.length < 8 || f.some((x) => !Number.isFinite(x))) return undefined;
  return (f[0] + f[1] + f[2] + f[5] + f[6] + f[7]) * 10_000;
}

/** A helper's list of copies: only well-formed entries survive. */
export function validateCopyList(raw: unknown): WorkerCopy[] {
  if (!Array.isArray(raw)) return [];
  const out: WorkerCopy[] = [];
  for (const c of raw.slice(0, 500)) {
    const r = (c || {}) as Record<string, unknown>;
    const copyId = String(r.copyId ?? "");
    const app = String(r.app ?? "");
    if (!COPY_ID.test(copyId) || !SLUG.test(app)) continue;
    out.push({ copyId, app, running: r.running === true, status: text(r.status, 60), fingerprint: HEX64.test(String(r.fingerprint)) ? String(r.fingerprint) : "" });
  }
  return out;
}

// ---------- Wake-on-LAN: the PC's network card ----------
//
// To wake a sleeping PC, the origin sends a "magic packet" (its card's MAC repeated) to the broadcast
// address of the network they share. Helpers are reached over Tailscale, so each worker also reports the
// card of its default route: MAC, address on the home network, and whether `pool wake-setup` armed it.

/** Written by `sudo paasmcp pool wake-setup` on the helper (root, 0644): the card it armed. */
export const WOL_MARKER = "/etc/paasmcp-wol.json";
export const IFACE_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}$/;

export interface LanFacts {
  /** Interface of the default route (eth0, enp5s0...). */
  iface: string;
  mac: string;
  /** IPv4 address and prefix on the home network (the magic packet goes to that network's broadcast). */
  ip: string;
  prefix: number;
  /** False for a Wi-Fi card: Wake-on-LAN almost never works over Wi-Fi. */
  wired: boolean;
  /** `pool wake-setup` armed this card (the worker cannot read the card's setting without root). */
  armed: boolean;
}

/** A unicast MAC, written aa:bb:cc:dd:ee:ff (accepts - or : separators, or 12 hex digits). */
export function normalizeMac(v: unknown): string {
  const raw = String(v ?? "").trim().toLowerCase();
  const hex = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/.test(raw) ? raw.replace(/[:-]/g, "") : /^[0-9a-f]{12}$/.test(raw) ? raw : "";
  if (!hex) throw new Error("A MAC address looks like aa:bb:cc:dd:ee:ff.");
  if (hex === "000000000000" || parseInt(hex.slice(0, 2), 16) & 1) throw new Error("That MAC is not a network card's own address (it is empty, broadcast or multicast).");
  return hex.match(/../g)!.join(":");
}

/** The interface of the default route in /proc/net/route (the main table; Tailscale routes elsewhere). */
export function defaultRouteIface(procNetRoute: string): string | undefined {
  for (const line of String(procNetRoute).split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    // Iface Destination Gateway Flags RefCnt Use Metric Mask: destination and mask 0, flags up (1).
    if (f.length >= 8 && f[1] === "00000000" && f[7] === "00000000" && (parseInt(f[3], 16) & 1) && IFACE_NAME.test(f[0])) return f[0];
  }
  return undefined;
}

/** What a helper says about its card (untrusted): kept only when every part is well formed. */
export function validateLan(raw: unknown): LanFacts | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  try {
    const prefix = Number(r.prefix);
    if (!IFACE_NAME.test(String(r.iface ?? "")) || !Number.isInteger(prefix) || prefix < 8 || prefix > 30) return undefined;
    return { iface: String(r.iface), mac: normalizeMac(r.mac), ip: validateIpv4(r.ip), prefix, wired: r.wired === true, armed: r.armed === true };
  } catch {
    return undefined;
  }
}

/** What `ethtool <card>` says about Wake-on-LAN: the modes it supports and the one set now ("g" = magic packet). */
export function parseEthtoolWake(out: string): { supports: string; current: string } {
  const pick = (re: RegExp) => (re.exec(String(out))?.[1] || "").trim();
  return { supports: pick(/^\s*Supports Wake-on:\s*(\S+)\s*$/m), current: pick(/^\s*Wake-on:\s*(\S+)\s*$/m) };
}
