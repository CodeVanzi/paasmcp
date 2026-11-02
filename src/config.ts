import fs from "node:fs";
import path from "node:path";

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
}

export const HOMELAB_ROOT = process.env.PAASMCP_ROOT || "/opt/homelab";
export const PAAS_DATA_DIR = path.join(HOMELAB_ROOT, "paasmcp");
export const PAAS_APPS_DIR = path.join(HOMELAB_ROOT, "apps");
export const PAAS_VAULT_DIR = path.join(PAAS_DATA_DIR, "vault");
export const PAAS_SSH_DIR = path.join(PAAS_DATA_DIR, "ssh");
export const PAAS_DB_DIR = path.join(HOMELAB_ROOT, "paasmcp-postgres");
export const PAAS_REDIS_DIR = path.join(HOMELAB_ROOT, "paasmcp-redis");
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
  for (const dir of [PAAS_DATA_DIR, PAAS_APPS_DIR, PAAS_VAULT_DIR, PAAS_SSH_DIR]) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }
}

export function loadState(): PaaSState {
  ensureDirectories();
  if (!fs.existsSync(STATE_FILE_PATH)) {
    const initial: PaaSState = {
      version: 1,
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
    };
    saveState(initial);
    return initial;
  }
  const raw = fs.readFileSync(STATE_FILE_PATH, "utf-8");
  return JSON.parse(raw) as PaaSState;
}

export function saveState(state: PaaSState): void {
  ensureDirectories();
  fs.writeFileSync(STATE_FILE_PATH, JSON.stringify(state, null, 2), { mode: 0o600 });
}

export function updatePlatformConfig(opts: {
  accountId?: string;
  tunnelId?: string;
  baseDomain?: string;
  zeroTrustEmails?: string[];
  tailscaleDomain?: string;
}): PaaSState {
  const state = loadState();
  if (opts.accountId !== undefined) state.cloudflare.accountId = opts.accountId;
  if (opts.tunnelId !== undefined) state.cloudflare.tunnelId = opts.tunnelId;
  if (opts.baseDomain !== undefined) state.cloudflare.baseDomain = opts.baseDomain;
  if (opts.zeroTrustEmails !== undefined) {
    state.cloudflare.zeroTrustEmails = opts.zeroTrustEmails;
  }
  if (opts.tailscaleDomain !== undefined) {
    state.tailscaleDomain = opts.tailscaleDomain;
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
  // Start at 4000 to avoid any collision with standard administrative ports
  for (let port = 4000; port <= 4999; port++) {
    if (!usedPorts.has(port)) {
      return port;
    }
  }
  throw new Error("No available ports in range 4000-4999");
}

export function sanitizeSlug(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  if (!slug) {
    throw new Error(`Invalid application or database name: "${name}"`);
  }
  return slug;
}
