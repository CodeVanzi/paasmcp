import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
  trashedAt?: string;
  trashDir?: string;
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
  federation?: FederationConfig;
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

export function ensureDirectories(): void {
  for (const dir of [
    PAAS_DATA_DIR,
    PAAS_APPS_DIR,
    PAAS_VAULT_DIR,
    PAAS_SSH_DIR,
    PAAS_BACKUPS_DIR,
    PAAS_TRASH_DIR,
  ]) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
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

/** Writes via a temp file + rename so a crash never leaves a half-written file. */
export function writeFileAtomic(filePath: string, content: string): void {
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
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
          throw new Error("Another PaaSMCP operation is still running (lock held). Try again later.");
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

export function allocateAppPort(state: PaaSState, existingAppName?: string): number {
  if (existingAppName && state.apps[existingAppName]) {
    return state.apps[existingAppName].localPort;
  }
  const usedPorts = new Set<number>(
    Object.values(state.apps).map((a) => a.localPort)
  );
  // Reserve 4099 for paasmcp-dashboard; allocate 4000-4998 for user apps
  for (let port = 4000; port <= 4998; port++) {
    if (!usedPorts.has(port)) {
      return port;
    }
  }
  throw new Error("No available ports in range 4000-4998");
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
