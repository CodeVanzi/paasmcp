import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { WATCHTOWER_OFF_LABEL } from "./poolproto.js";

export interface AppMetrics {
  cpuPercent: string;
  memUsage: string;
  memPercent: string;
  netIO: string;
  pids: string;
}

export interface AppRecord {
  name: string;
  repoUrl?: string;
  branch: string;
  localPort: number;
  internalPort: number;
  containerName: string;
  appDir: string;
  runtimeType: string;
  databases: string[];
  domains: {
    hostname: string;
    mode: "public" | "zero-trust" | "tailscale" | "local";
    url: string;
  }[];
  createdAt: string;
  updatedAt: string;
  status?: string;
  lastCommit?: string;
  previousImageTag?: string;
  composePassThrough?: boolean;
  memoryLimit?: string;
  cpuLimit?: string;
  lastWebhookAt?: string;
  /** Set only after a strong confirmation: keeps privileged compose fields (see guard.ts). */
  trusted?: boolean;
  /** Set on apps imported from a mirror peer: they run here only after that peer is promoted. */
  originNodeId?: string;
  /** "poll": `paasmcp poll` (systemd timer) redeploys when the branch moves. */
  autoDeploy?: "poll";
  trashedAt?: string;
  trashDir?: string;
  /** When the "will be deleted" notice went out (trashclean.ts); cleared on restore. */
  trashWarnedAt?: string;
  /** Blue/green deploy: path probed on the candidate container (default "/"). */
  healthcheckPath?: string;
  /** Blue/green deploy: seconds to wait for a healthy answer (default 20). */
  healthcheckTimeoutSeconds?: number;
  /** true = deploy without candidate/healthcheck (apps that do not speak HTTP). */
  healthcheckDisabled?: boolean;
  /** Full commit SHA of the running version (lastCommit is the short form). */
  lastCommitSha?: string;
  /**
   * Active-active (active.ts): the app also runs on the mirror peer and both take requests. On the
   * origin server it is set by `paasmcp active on`; on the peer it arrives through the control channel.
   */
  activeActive?: boolean;
  /** Peer side: what was last deployed from the origin's control channel, and the last error. */
  activeSync?: {
    commit?: string;
    configHash?: string;
    at?: string;
    error?: string;
    /** Last refresh of this server's copy of the app's bucket. */
    files?: { at: string; copied?: number; removed?: number; tooLarge?: number; error?: string; pending?: boolean };
  };
  /**
   * Automatic scaling (scale.ts, autoscale.ts). Without `auto`, the rule is only rehearsed: nothing is
   * started or stopped. With `auto` (phase 4), the decider sets the app's copies itself, between the
   * rule's `min` and `max`.
   */
  scale?: {
    rule?: Partial<ScaleRule>;
    capacity?: CapacityResult;
    auto?: { since: string; by: string };
  };
  /**
   * Copies on helper PCs (pool.ts, scale phase 3, set by hand). While `enabled`, the app's traffic goes
   * through the pool balancer on this server, which splits it between this copy and the helpers'.
   */
  pool?: AppPoolConfig;
}

export interface AppPoolConfig {
  enabled: boolean;
  /** Copies wanted in total: one here plus `copies - 1` on helpers. */
  copies: number;
  /** Copies running on helpers, as last started or confirmed. */
  placed: PoolCopyRecord[];
  enabledAt: string;
  /** Set by `stop`: copies on helpers are stopped too and come back on `start`. */
  stoppedAt?: string;
  lastError?: string;
}

export interface PoolCopyRecord {
  id: string;
  helper: string;
  port: number;
  /** Store-independent image fingerprint (poolproto.imageFingerprint). */
  fingerprint: string;
  /** Hash of the variables and limits the copy was started with: a change replaces it. */
  configHash: string;
  cpus: number;
  memMb: number;
  startedAt: string;
}

/** A PC that runs copies when the origin asks (scale phase 3: the owner's own machines). */
export interface PoolHelperRecord {
  name: string;
  /** Tailscale IPv4 (the worker publishes copies only there, and accepts orders only from the origin's). */
  ip: string;
  sshPort: number;
  tier: "own";
  arch: string;
  cpus: number;
  memMb: number;
  diskFreeGb: number;
  /** What the owner gave to copies (set at join). */
  give: { cpus: number; memMb: number };
  dockerVersion?: string;
  workerVersion?: string;
  addedAt: string;
  /** Paused by a person or the AI: gets no copies, and its copies move away. */
  paused?: { at: string; by: string };
  /**
   * Courteous mode (courtesy.ts). auto: when the owner uses the PC, its copies move away; warn: they stay,
   * but no new copy goes there; off: the owner's use is not watched. Absent = auto at 50%.
   */
  courtesy?: { mode: CourtesyMode; cpuPct: number };
  /** Set by the scale round while the owner uses the PC (CPU outside the copies above `courtesy.cpuPct`). */
  ownerBusy?: { since: string; cpuPct: number };
  /**
   * Wake-on-LAN (wol.ts): this server may wake the PC with a magic packet to its card when a copy must run
   * and no awake helper has room. Set by a person (`pool wake <name> on`); absent = never woken.
   */
  wake?: { mac: string; broadcast: string; port: number; since: string; by: string };
}

export type CourtesyMode = "auto" | "warn" | "off";

export interface PoolConfig {
  /** This server's Tailscale IP: Postgres, Redis and S3 are also published there for the copies. */
  bindIp?: string;
  helpers: Record<string, PoolHelperRecord>;
  /** Pending invites (the secret is derived from the system vault, never stored). */
  invites: Record<string, { name: string; createdAt: string; expiresAt: string; usedAt?: string }>;
  balancerAt?: string;
}

/** When the decision rule would add or remove a copy (scale.ts). Numbers are starting points to calibrate. */
export interface ScaleRule {
  /** Copies never go below this (the origin always keeps one). */
  min: number;
  max: number;
  /** CPU per copy, in % of the app's CPU limit (or of one core when it has none). */
  targetCpu: number;
  /** Rounds in a row above the target before adding a copy. */
  upRounds: number;
  /** Seconds below half the target before removing a copy. */
  downAfterSeconds: number;
  /** Seconds to wait after an action before the next one. */
  cooldownSeconds: number;
  /**
   * Visits per second per copy, counted by the pool balancer (0 = not used). A copy is added when either
   * CPU or visits pass their target, and removed only when both stay below half of theirs.
   */
  targetRps: number;
}

/** Result of `paasmcp scale test` (loadtest.ts). */
export interface CapacityResult {
  at: string;
  path: string;
  /** Best requests per second with at most 1% errors, for one copy. */
  rps: number;
  concurrency: number;
  p95Ms: number;
  /** App CPU at that point, in % of its limit (or of one core). */
  cpu: number | null;
  bottleneck: "app_cpu" | "database" | "client" | "errors" | "latency" | "none" | "unknown";
  suggestedTargetRps: number;
  steps: {
    concurrency: number;
    seconds: number;
    requests: number;
    errors: number;
    rps: number;
    p50Ms: number;
    p95Ms: number;
    appCpu: number | null;
    dbCpu: number | null;
    clientCpu: number;
  }[];
}

export interface DatabaseRecord {
  name: string;
  engine: "postgres" | "redis";
  mode: "shared" | "dedicated";
  appName: string;
  dbName: string;
  dbUser: string;
  host: string;
  port: number;
  localPort: number;
  createdAt: string;
  /** Warning size in MB of 1,000,000 bytes (Postgres): the dashboard shows the share used and sends a notice at 80% and 100%. */
  warnSizeMb?: number;
}

export interface BackupRecord {
  id: string;
  appName: string;
  databaseName: string;
  engine: "postgres" | "redis" | "volume";
  filePath: string;
  sizeBytes: number;
  sha256: string;
  encrypted: boolean;
  createdAt: string;
  offsiteKey?: string;
  offsiteAt?: string;
  localPrunedAt?: string;
}

export interface StorageRecord {
  appName: string;
  bucket: string;
  bucketId: string;
  accessKeyId: string;
  createdAt: string;
}

/** A revocable key another computer uses to send its backups into a bucket on this server (offsite.ts). */
export interface BackupGrantRecord {
  name: string;
  bucket: string;
  bucketId: string;
  accessKeyId: string;
  maxGb?: number;
  createdAt: string;
  revokedAt?: string;
}

export interface BackupShareConfig {
  /** Tailscale IP where Garage's S3 API (only S3, not the admin API) is published for the grants. */
  bindIp?: string;
  grants: Record<string, BackupGrantRecord>;
}

export interface MirrorReplicaRecord {
  peerName: string;
  peerNodeId: string;
  peerHost: string;
  slot: string;
  container: string;
  localPort: number;
  dataDir: string;
  acceptedAt: string;
  promotedAt?: string;
  promotedEpoch?: number;
  /** Failback: this server's own Postgres is (temporarily) the read-only copy of the peer. */
  failback?: boolean;
  /** Set on the server that served a peer's data once it hands it back; the copy is then stale. */
  handedBackAt?: string;
  /**
   * Several copies of one server (star): another server took over the data this copy follows, so it
   * is behind for good. It never takes over, its app copies stop, and a new offer rebuilds it.
   */
  supersededBy?: { nodeId: string; epoch: number; at: string };
  /** Last time `mirror watch` saw this copy streaming (refreshed every few minutes, not every round). */
  streamedAt?: string;
  /**
   * The origin is gone and this copy of its data follows the server that took it over (peerHost is that
   * server). Its liveness decides an automatic takeover; the origin's apps run only there meanwhile.
   */
  servedByNodeId?: string;
  servedByName?: string;
}

export interface MirrorConfig {
  /** Raised on every promotion; the side with the higher epoch owns the data (split-brain fence). */
  epoch: number;
  /** Tailscale IP where Postgres / Garage S3 are also published for the peer. */
  bindIp?: string;
  /**
   * What this server sends, keyed by peer name. An offer of a promoted copy to a third server (the data
   * of `dataOf`, served here since a takeover) is keyed "<peer>:<dataOf>" and names its peer in `peer`.
   */
  offers: Record<string, { peerCidr: string; slot: string; offeredAt: string; source?: string; peer?: string; dataOf?: string }>;
  replicas: Record<string, MirrorReplicaRecord>;
  /** Third vote for automatic failover (`paasmcp arbiter serve`). */
  arbiterUrl?: string;
  /** Peers this server may take over automatically (needs arbiterUrl). */
  auto?: string[];
  /** Set when the arbiter says another server now serves this server's data: own apps stay stopped. */
  fenced?: { byNodeId: string; epoch: number; at: string };
  /** Active-active, origin side: hash of the last manifest written to paasmcp_meta (skip identical writes). */
  activePublishedHash?: string;
  activePublishedAt?: string;
}

/** Self-hosted entry (edge.ts): a Caddy on this server that splits requests between both servers. */
export interface ActiveTunnelConfig {
  tunnelId: string;
  name: string;
  createdAt: string;
  /** Hostnames whose DNS points at this tunnel. */
  routes: Record<string, { app: string; at: string }>;
  /** Hash of the ingress last sent to Cloudflare (nothing is sent while it stays the same). */
  ingressHash?: string;
}

export interface EdgeConfig {
  /** ACME account email for Let's Encrypt. */
  email?: string;
  sites: Record<string, { app: string; addedAt: string }>;
  installedAt?: string;
}

export interface FederationPeerRecord {
  nodeId: string;
  name: string;
  endpointUrl: string;
  mode: "active-active-tunnel" | "warm-standby";
  publicKeyFingerprint: string;
  pairedAt: string;
  lastSyncAt?: string;
  status: "online" | "standby" | "unreachable";
}

export interface FederationConfig {
  nodeId: string;
  nodeName: string;
  role: "standalone" | "primary" | "replica";
  redundancyMode: "active-active-tunnel" | "warm-standby";
  peers: Record<string, FederationPeerRecord>;
}

export interface CloudflareConfig {
  accountId: string;
  tunnelId: string;
  baseDomain: string;
  zeroTrustPolicyName?: string;
  zeroTrustEmails?: string[];
}

export interface PaaSState {
  version: number;
  initializedAt: string;
  tailscaleDomain?: string;
  cloudflare: CloudflareConfig;
  apps: Record<string, AppRecord>;
  databases: Record<string, DatabaseRecord>;
  backups?: Record<string, BackupRecord>;
  storage?: Record<string, StorageRecord>;
  /** Other computers that send their backups here (offsite.ts). */
  backupShare?: BackupShareConfig;
  mirror?: MirrorConfig;
  edge?: EdgeConfig;
  /** Origin side: the Cloudflare tunnel used only by apps that run on both servers (activetunnel.ts). */
  activeTunnel?: ActiveTunnelConfig;
  /** Peer side: this server runs the connector of that origin's tunnel. */
  activeTunnelCopy?: { fromNodeId: string; tokenHash: string; at: string; hostnames?: string[] };
  /** Images moved by 'paasmcp update apply' (see updater.ts PINNED). */
  versions?: Partial<Record<"postgres" | "redis" | "garage", string>>;
  federation?: FederationConfig;
  /** PCs that run extra copies of apps (pool.ts). */
  pool?: PoolConfig;
  /** Measuring for automatic scaling (scale.ts). */
  scale?: {
    /** Language of the decision diary in the CLI, the MCP tool and the log (the dashboard follows its own switch). */
    language?: "pt" | "en";
    /** Set by `paasmcp scale install-timer`. */
    timer?: { seconds: number; installedAt: string };
  };
}

export const HOMELAB_ROOT = process.env.PAASMCP_ROOT || "/opt/homelab";
export const PAAS_DATA_DIR = path.join(HOMELAB_ROOT, "paasmcp");
export const PAAS_APPS_DIR = path.join(HOMELAB_ROOT, "apps");
export const PAAS_VAULT_DIR = path.join(PAAS_DATA_DIR, "vault");
export const PAAS_SSH_DIR = path.join(PAAS_DATA_DIR, "ssh");
export const PAAS_BACKUPS_DIR = path.join(PAAS_DATA_DIR, "backups");
export const PAAS_DB_DIR = path.join(HOMELAB_ROOT, "paasmcp-postgres");
export const PAAS_REDIS_DIR = path.join(HOMELAB_ROOT, "paasmcp-redis");
export const PAAS_TRASH_DIR = path.join(PAAS_DATA_DIR, "trash");
export const MASTER_KEY_PATH = path.join(PAAS_DATA_DIR, ".master.key");
export const STATE_FILE_PATH = path.join(PAAS_DATA_DIR, "state.json");
export const HOMEPAGE_SERVICES_YAML = path.join(
  HOMELAB_ROOT,
  "homepage",
  "config",
  "services.yaml"
);

export const DEFAULT_CF_ACCOUNT_ID = process.env.PAASMCP_CF_ACCOUNT_ID || "";
export const DEFAULT_CF_TUNNEL_ID = process.env.PAASMCP_CF_TUNNEL_ID || "";
export const DEFAULT_BASE_DOMAIN = process.env.PAASMCP_BASE_DOMAIN || "example.com";
export const DOCKER_NETWORK = process.env.PAASMCP_DOCKER_NETWORK || "homelab-network";

/**
 * The folder with tailscaled's socket, when this machine (or the container we run in) has it. The
 * dashboard container gets it mounted, so "Tailscale Serve" works from the dashboard too.
 */
export const TAILSCALE_SOCKET_DIR = "/var/run/tailscale";
export function tailscaleSocketDir(): string | undefined {
  return fs.existsSync(path.join(TAILSCALE_SOCKET_DIR, "tailscaled.sock")) ? TAILSCALE_SOCKET_DIR : undefined;
}

/**
 * Every container PaaSMCP creates carries this label so Watchtower (common in homelabs) leaves it alone:
 * PaaSMCP pins and updates its own images, and a surprise restart of Postgres or an app copy looks
 * like an outage to the active-active watch and the scale decider.
 */
export { WATCHTOWER_OFF_LABEL };
/** Adds the label to a compose service's own `labels` (list or map form). */
export function withWatchtowerOff(labels: unknown): string[] | Record<string, string> {
  const [key, value] = WATCHTOWER_OFF_LABEL.split("=");
  if (labels && typeof labels === "object" && !Array.isArray(labels)) {
    return { ...(labels as Record<string, string>), [key]: value };
  }
  const list = Array.isArray(labels) ? labels.map(String).filter((l) => !l.startsWith(`${key}=`)) : [];
  return [...list, WATCHTOWER_OFF_LABEL];
}
/** The same label as a compose `labels:` block, indented for a service at the usual 4 spaces. */
export const WATCHTOWER_OFF_COMPOSE = `    labels:\n      - "${WATCHTOWER_OFF_LABEL}"\n`;

export function ensureDirectories(): void {
  if (!fs.existsSync(PAAS_DATA_DIR)) fs.mkdirSync(PAAS_DATA_DIR, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(PAAS_APPS_DIR)) fs.mkdirSync(PAAS_APPS_DIR, { recursive: true, mode: 0o700 });
  for (const dir of [PAAS_VAULT_DIR, PAAS_SSH_DIR, PAAS_BACKUPS_DIR, PAAS_TRASH_DIR]) ensureDataDir(dir);
}

/**
 * Creates a folder inside the data folder (paasmcp/...). Created as root (the dashboard container, a
 * root timer), it gets the data folder's owner, so the person's own CLI can still use it.
 */
export function ensureDataDir(dir: string): void {
  if (fs.existsSync(dir)) return;
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return;
  const rel = path.relative(PAAS_DATA_DIR, dir);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return;
  try {
    const owner = fs.statSync(PAAS_DATA_DIR);
    if (owner.uid === 0) return;
    // Every folder this call created, from the first missing one down to `dir`.
    let p = PAAS_DATA_DIR;
    for (const part of rel.split(path.sep)) {
      p = path.join(p, part);
      const st = fs.statSync(p);
      if (st.uid === 0) fs.chownSync(p, owner.uid, owner.gid);
    }
  } catch {
    // Ownership is a convenience: never fail because of it.
  }
}

export function loadState(): PaaSState {
  ensureDirectories();
  if (!fs.existsSync(STATE_FILE_PATH)) {
    const initial: PaaSState = {
      version: 2,
      initializedAt: new Date().toISOString(),
      cloudflare: {
        accountId: DEFAULT_CF_ACCOUNT_ID,
        tunnelId: DEFAULT_CF_TUNNEL_ID,
        baseDomain: DEFAULT_BASE_DOMAIN,
        zeroTrustPolicyName: "PaaSMCP Zero Trust",
        zeroTrustEmails: [],
      },
      apps: {},
      databases: {},
      backups: {},
      federation: {
        nodeId: `node-${crypto.randomBytes(4).toString("hex")}`,
        nodeName: "primary-node",
        role: "standalone",
        redundancyMode: "active-active-tunnel",
        peers: {},
      },
    };
    saveState(initial);
    return initial;
  }
  const raw = fs.readFileSync(STATE_FILE_PATH, "utf-8");
  const parsed = JSON.parse(raw) as PaaSState;
  if (!parsed.backups) parsed.backups = {};
  if (!parsed.federation) {
    parsed.federation = {
      nodeId: `node-${crypto.randomBytes(4).toString("hex")}`,
      nodeName: "primary-node",
      role: "standalone",
      redundancyMode: "active-active-tunnel",
      peers: {},
    };
  }
  return parsed;
}

export function saveState(state: PaaSState): void {
  ensureDirectories();
  writeFileAtomic(STATE_FILE_PATH, JSON.stringify(state, null, 2));
}

/**
 * Writes via a temp file + rename so a crash never leaves a half-written file. Run as root (the
 * dashboard container, a root timer), the new file keeps the owner of the one it replaces (or of its
 * folder), so the person's own CLI can still read it.
 */
export function writeFileAtomic(filePath: string, content: string): void {
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  keepOwnerOf(tmp, filePath);
  fs.renameSync(tmp, filePath);
}

function keepOwnerOf(tmp: string, filePath: string): void {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return;
  try {
    let owner: fs.Stats;
    try {
      owner = fs.statSync(filePath);
    } catch {
      owner = fs.statSync(path.dirname(filePath));
    }
    if (owner.uid !== 0) fs.chownSync(tmp, owner.uid, owner.gid);
  } catch {
    // Ownership is a convenience: never fail a write because of it.
  }
}

const LOCK_PATH = path.join(PAAS_DATA_DIR, ".lock");
const LOCK_STALE_MS = 30 * 60 * 1000;
let inProcessQueue: Promise<unknown> = Promise.resolve();

function lockIsStale(): boolean {
  try {
    const info = JSON.parse(fs.readFileSync(LOCK_PATH, "utf-8")) as { pid: number; host: string; at: number };
    if (Date.now() - info.at > LOCK_STALE_MS) return true;
    if (info.host !== os.hostname()) return false; // other machine/container: only age tells
    try {
      process.kill(info.pid, 0);
      return false;
    } catch (err) {
      return (err as NodeJS.ErrnoException).code === "ESRCH";
    }
  } catch {
    return true; // unreadable or vanished lock
  }
}

/** Thrown by withStateLock when another operation kept the lock for longer than the caller would wait. */
export class StateLockBusyError extends Error {
  constructor() {
    super("Another PaaSMCP operation is still running (lock held). Try again later.");
    this.name = "StateLockBusyError";
  }
}

/**
 * Serializes state-changing operations across the MCP server, the CLI and the dashboard
 * (which may run in a container sharing PAASMCP_ROOT). Do not nest calls: it would wait forever.
 */
export function withStateLock<T>(fn: () => T | Promise<T>, timeoutMs = 20 * 60 * 1000): Promise<T> {
  const run = async (): Promise<T> => {
    ensureDirectories();
    const started = Date.now();
    for (;;) {
      try {
        fs.writeFileSync(LOCK_PATH, JSON.stringify({ pid: process.pid, host: os.hostname(), at: Date.now() }), {
          flag: "wx",
          mode: 0o600,
        });
        break;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        if (lockIsStale()) {
          fs.rmSync(LOCK_PATH, { force: true });
          continue;
        }
        if (Date.now() - started > timeoutMs) {
          throw new StateLockBusyError();
        }
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    try {
      return await fn();
    } finally {
      fs.rmSync(LOCK_PATH, { force: true });
    }
  };
  const result = inProcessQueue.then(run, run);
  inProcessQueue = result.catch(() => undefined);
  return result;
}

export function updatePlatformConfig(opts: {
  accountId?: string;
  tunnelId?: string;
  baseDomain?: string;
  zeroTrustEmails?: string[];
  tailscaleDomain?: string;
}): PaaSState {
  const state = loadState();
  if (opts.accountId !== undefined) state.cloudflare.accountId = opts.accountId.trim();
  if (opts.tunnelId !== undefined) state.cloudflare.tunnelId = opts.tunnelId.trim();
  if (opts.baseDomain !== undefined) state.cloudflare.baseDomain = opts.baseDomain.trim();
  if (opts.zeroTrustEmails !== undefined) {
    state.cloudflare.zeroTrustEmails = opts.zeroTrustEmails.map((e) => e.trim()).filter(Boolean);
  }
  if (opts.tailscaleDomain !== undefined) {
    state.tailscaleDomain = opts.tailscaleDomain.trim();
  }
  saveState(state);
  return state;
}

/** 4097: the arbiter's default port; 4099: the dashboard. Never handed to an app. */
export const RESERVED_PORTS = [4097, 4099];

/**
 * TCP ports something already listens on in this host's network namespace (best effort, from /proc).
 * A homelab often has other services; a port they hold would make the app's container fail to start.
 */
export function hostListeningPorts(): number[] {
  if (process.env.PAASMCP_OFFLINE_TEST === "1") return [];
  const ports = new Set<number>();
  for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let text = "";
    try {
      text = fs.readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols.length > 3 && cols[3] === "0A") {
        const port = parseInt(cols[1].split(":").pop() || "", 16);
        if (Number.isInteger(port)) ports.add(port);
      }
    }
  }
  // The dashboard runs in a container, where /proc shows only its own sockets: add Docker's published ports.
  try {
    const out = execFileSync("docker", ["ps", "--format", "{{.Ports}}"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
    for (const m of out.matchAll(/:(\d+)->/g)) ports.add(Number(m[1]));
  } catch {
    // no Docker access: /proc is all we have
  }
  return [...ports];
}

export function allocateAppPort(state: PaaSState, existingAppName?: string): number {
  if (existingAppName && state.apps[existingAppName]) {
    return state.apps[existingAppName].localPort;
  }
  const usedPorts = new Set<number>([
    ...Object.values(state.apps).map((a) => a.localPort),
    ...RESERVED_PORTS,
    ...hostListeningPorts(),
  ]);
  // Allocate 4000-4998 for user apps, skipping PaaSMCP's own ports and anything already listening here
  for (let port = 4000; port <= 4998; port++) {
    if (!usedPorts.has(port)) {
      return port;
    }
  }
  throw new Error("No available ports in range 4000-4998");
}

/**
 * The Tailscale IP where this server also publishes Postgres, Redis and S3: set by the mirror (the peer
 * reaches the data) or by the helper pool (copies on helpers reach it). Both are the same address.
 */
export function tailnetBindIp(state: Pick<PaaSState, "mirror" | "pool">): string | undefined {
  return state.mirror?.bindIp || state.pool?.bindIp;
}

/** The container that splits a pooled app's requests between its copies (pool.ts). */
export const POOL_BALANCER = "paasmcp-pool-lb";

/** Where Cloudflare Tunnel sends an app's requests: its container, or the pool balancer while helpers serve it. */
export function appServiceUrl(app: Pick<AppRecord, "containerName" | "internalPort" | "localPort" | "pool">): string {
  return app.pool?.enabled ? `http://${POOL_BALANCER}:${app.localPort}` : `http://${app.containerName}:${app.internalPort}`;
}

/** Offers of this server's own Postgres (not of a promoted copy of another server's data). */
export function ownOffers(state: Pick<PaaSState, "mirror">): [string, MirrorConfig["offers"][string]][] {
  return Object.entries(state.mirror?.offers || {}).filter(([, o]) => !o.source || o.source === "paasmcp-postgres");
}

export function sanitizeSlug(name: string): string {
  const slug = String(name || "")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 63);
  if (!slug) {
    throw new Error(`Invalid application or database name: "${name}"`);
  }
  return slug;
}

export function validateEnvKey(key: string): string {
  const clean = String(key || "").trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(clean)) {
    throw new Error(
      `Invalid environment variable key "${clean}". Keys must match ^[A-Za-z_][A-Za-z0-9_]*$.`
    );
  }
  return clean;
}

export function validateBranchName(branch: string): string {
  const clean = String(branch || "main").trim();
  if (
    !clean ||
    clean.startsWith("-") ||
    clean.includes("..") ||
    !/^[A-Za-z0-9._/-]+$/.test(clean)
  ) {
    throw new Error(`Invalid Git branch or ref name: "${branch}"`);
  }
  return clean;
}

export function validateResourceLimit(limit?: string, type: "memory" | "cpu" = "memory"): string | undefined {
  if (!limit) return undefined;
  const clean = limit.trim().toLowerCase();
  if (type === "memory") {
    if (!/^\d+[kmg]b?$/.test(clean)) {
      throw new Error(`Invalid memory limit "${limit}". Expected format like "256m", "512m", or "2g".`);
    }
    return clean;
  }
  if (!/^\d+(\.\d+)?$/.test(clean) || Number(clean) <= 0 || Number(clean) > 128) {
    throw new Error(`Invalid CPU limit "${limit}". Expected positive number like "0.5", "1", or "2".`);
  }
  return clean;
}
