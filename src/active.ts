import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import {
  AppRecord,
  loadState,
  MirrorReplicaRecord,
  ownOffers,
  PaaSState,
  PAAS_APPS_DIR,
  PAAS_REDIS_DIR,
  sanitizeSlug,
  saveState,
  validateBranchName,
  validateEnvKey,
  validateResourceLimit,
} from "./config.js";
import { deployApp, manageAppLifecycle, validateHealthcheckPath, validateHealthcheckTimeout } from "./deployer.js";
import { audit } from "./guard.js";
import { FileSyncResult, syncBucket } from "./filesync.js";
import { applyPeerTunnel, routeActiveTunnel, validTunnelToken } from "./activetunnel.js";
import { ensureBucketWithImportedKey, ensureGarage, localS3Url, PAAS_GARAGE_DIR, usesLocalGarage } from "./storage.js";
import { decryptBinaryPayload, encryptBinaryPayload, getSecrets, saveSecrets } from "./vault.js";

// Active-active: an app marked here also runs on the mirror peer, and both servers take requests.
// Writes still go to one Postgres (the origin's): on the peer, the app's container resolves
// paasmcp-postgres / paasmcp-redis / paasmcp-garage to the origin's Tailscale IP, so the vault
// variables are the same on both servers.
//
// Control channel: the origin writes an encrypted manifest (app record, vault scope, commit) into
// its own Postgres (database paasmcp_meta). The peer's live copy receives it within seconds, and the
// peer applies it from a run of `paasmcp active sync` (poll timer / mirror watch). No new port, no
// new daemon: PaaSMCP stays at 0 MB while idle.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
const PRIMARY = "paasmcp-postgres";
export const META_DB = "paasmcp_meta";
/** Shared services whose names point at the origin inside a peer's app container. */
export const SHARED_SERVICE_NAMES = ["paasmcp-postgres", "paasmcp-redis", "paasmcp-garage"];
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

export interface ActiveManifestApp {
  record: Partial<AppRecord>;
  secrets: Record<string, string>;
  /** Full SHA the origin runs. */
  commit: string;
  /** Hash of the secrets and deploy settings: a change redeploys the peer. */
  configHash: string;
}

export interface ActiveManifest {
  v: 1;
  nodeId: string;
  epoch: number;
  apps: Record<string, ActiveManifestApp>;
  /** Tunnel for apps on both servers (activetunnel.ts), when it is on: its token and the hostnames it serves. */
  tunnel?: { token: string; hostnames?: string[] };
  /** The arbiter this server uses: the other server adopts it when it has none yet. */
  arbiterUrl?: string;
}

function clusterKey(): Buffer {
  const hex = getSecrets("system").FEDERATION_CLUSTER_KEY;
  if (!hex || hex.length !== 64) throw new Error("Pair the two servers first: the control channel is encrypted with the cluster key.");
  return Buffer.from(hex, "hex");
}

const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const sortedJson = (o: Record<string, unknown>) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));

/** Deploy settings that travel to the peer. Everything else (paths, image tags, status) stays local. */
const SHARED_FIELDS = [
  "repoUrl", "branch", "localPort", "internalPort", "runtimeType", "databases", "domains", "memoryLimit",
  "cpuLimit", "trusted", "healthcheckPath", "healthcheckTimeoutSeconds", "healthcheckDisabled", "composePassThrough",
] as const;

export function buildActiveManifest(
  state: PaaSState,
  secretsOf: (scope: string) => Record<string, string> = getSecrets
): ActiveManifest {
  const apps: Record<string, ActiveManifestApp> = {};
  for (const app of Object.values(state.apps)) {
    if (!app.activeActive || app.originNodeId || app.trashedAt) continue;
    const record: Partial<AppRecord> = {};
    for (const f of SHARED_FIELDS) if (app[f] !== undefined) (record as Record<string, unknown>)[f] = app[f];
    const secrets = secretsOf(app.name);
    apps[app.name] = {
      record,
      secrets,
      commit: app.lastCommitSha || "",
      configHash: sha256(sortedJson({ ...record, ...Object.fromEntries(Object.entries(secrets).map(([k, v]) => [`env:${k}`, v])) })),
    };
  }
  const token = state.activeTunnel ? secretsOf("system").ACTIVE_TUNNEL_TOKEN : undefined;
  return {
    v: 1, nodeId: state.federation?.nodeId || "primary", epoch: state.mirror?.epoch || 0, apps,
    ...(token ? { tunnel: { token, hostnames: Object.keys(state.activeTunnel?.routes || {}).sort() } } : {}),
    ...(state.mirror?.arbiterUrl ? { arbiterUrl: state.mirror.arbiterUrl } : {}),
  };
}

export const encodeManifest = (m: ActiveManifest, key = clusterKey()) =>
  encryptBinaryPayload(Buffer.from(JSON.stringify(m)), key).toString("base64");

export function decodeManifest(body: string, key = clusterKey()): ActiveManifest {
  let parsed: ActiveManifest;
  try {
    parsed = JSON.parse(decryptBinaryPayload(Buffer.from(body.trim(), "base64"), key).toString("utf-8"));
  } catch {
    throw new Error("The control channel could not be decrypted (different cluster key, or the data was changed).");
  }
  if (parsed.v !== 1 || typeof parsed.nodeId !== "string" || typeof parsed.apps !== "object") throw new Error("Unknown control channel format.");
  return parsed;
}

function psql(container: string, sqlText: string, db = "postgres"): string {
  return execFileSync("docker", ["exec", "-i", container, "psql", "-U", "paasmcp_admin", "-d", db, "-tA", "-v", "ON_ERROR_STOP=1"], {
    input: sqlText,
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  }).trim();
}

function writeMeta(body: string): void {
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) throw new Error("Unexpected manifest encoding.");
  psql(
    PRIMARY,
    `SELECT 'CREATE DATABASE ${META_DB}' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='${META_DB}')\\gexec
REVOKE ALL ON DATABASE ${META_DB} FROM PUBLIC;
\\c ${META_DB}
CREATE TABLE IF NOT EXISTS active_manifest (id int PRIMARY KEY, body text NOT NULL, published_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON active_manifest FROM PUBLIC;
INSERT INTO active_manifest (id, body) VALUES (1, '${body}') ON CONFLICT (id) DO UPDATE SET body = EXCLUDED.body, published_at = now();
`
  );
}

/** Reads the origin's manifest from this server's live copy of its Postgres. */
export function readMetaFromCopy(rec: MirrorReplicaRecord): string | undefined {
  try {
    const out = psql(rec.container, "SELECT body FROM active_manifest WHERE id = 1;", META_DB);
    return out || undefined;
  } catch {
    return undefined; // the origin has not published anything yet
  }
}

/**
 * Origin side: writes the manifest of this server's active apps into its Postgres. Called after
 * every deploy of an active app and by `active on/off`. Skips identical writes; a fenced server
 * never publishes (another server serves its data).
 */
export function publishActiveState(write: (body: string) => void = writeMeta): { published: boolean; apps: string[]; reason?: string } {
  const state = loadState();
  const m = state.mirror;
  const manifest = buildActiveManifest(state);
  const apps = Object.keys(manifest.apps);
  if (m?.fenced) return { published: false, apps, reason: "this server is fenced" };
  if (!m || ownOffers(state).length === 0) {
    return { published: false, apps, reason: apps.length ? "no mirror peer receives a copy of this server yet" : "nothing to publish" };
  }
  const hash = sha256(JSON.stringify(manifest));
  if (hash === m.activePublishedHash) return { published: false, apps, reason: "unchanged" };
  const body = encodeManifest(manifest);
  // Offline tests pass their own writer; the default one needs Docker.
  if (!OFFLINE() || write !== writeMeta) write(body);
  const latest = loadState();
  latest.mirror = { ...(latest.mirror || { epoch: 0, offers: {}, replicas: {} }), activePublishedHash: hash, activePublishedAt: new Date().toISOString() };
  saveState(latest);
  return { published: true, apps };
}

function detectTailscaleIp(): string | undefined {
  if (OFFLINE()) return undefined;
  try {
    const ip = execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0].trim();
    return IPV4.test(ip) ? ip : undefined;
  } catch {
    return undefined;
  }
}

/** The address where this server publishes active apps for the peer and the edge (Tailscale). */
export function activeBindIp(state: PaaSState): string | undefined {
  return state.mirror?.bindIp || detectTailscaleIp();
}

/** The live copy this server keeps of `nodeId`, while that server is still the one serving its data. */
export function liveCopyOf(state: PaaSState, nodeId?: string): MirrorReplicaRecord | undefined {
  if (!nodeId) return undefined;
  return Object.values(state.mirror?.replicas || {}).find((r) => r.peerNodeId === nodeId && !r.promotedAt && !r.failback && !r.supersededBy && !r.servedByNodeId);
}

export interface ActiveComposeExtras {
  /** host:ip entries for every service of the app (peer side: shared services live on the origin). */
  extraHosts: string[];
  /** Extra published ports (the Tailscale IP, so the peer's edge can reach this copy of the app). */
  extraPorts: string[];
  /** Extra runtime variables (DATABASE_REPLICA_URL). */
  extraEnv: Record<string, string>;
  warnings: string[];
}

/** What an active app's containers need on this server; empty for other apps. */
export function activeComposeExtras(
  state: PaaSState,
  app: Pick<AppRecord, "activeActive" | "originNodeId" | "localPort">,
  internalPort: number,
  env: Record<string, string>
): ActiveComposeExtras {
  const out: ActiveComposeExtras = { extraHosts: [], extraPorts: [], extraEnv: {}, warnings: [] };
  if (!app.activeActive) return out;
  const bind = activeBindIp(state);
  if (bind && IPV4.test(bind) && !bind.startsWith("127.")) out.extraPorts.push(`${bind}:${app.localPort}:${internalPort}`);
  else out.warnings.push("No Tailscale IP found: the app is published on 127.0.0.1 only, so a self-hosted entry on the other server cannot reach it.");
  if (!app.originNodeId) {
    if (env.DATABASE_URL) out.extraEnv.DATABASE_REPLICA_URL = env.DATABASE_URL;
    return out;
  }
  const rec = liveCopyOf(state, app.originNodeId);
  if (!rec) return out; // the origin's data is served here now (promoted): everything is local
  if (IPV4.test(rec.peerHost)) {
    out.extraHosts = SHARED_SERVICE_NAMES.map((h) => `${h}:${rec.peerHost}`);
  } else {
    out.warnings.push(`The origin advertised '${rec.peerHost}', not an IP: the app here resolves the shared services by that network instead.`);
  }
  if (env.DATABASE_URL) out.extraEnv.DATABASE_REPLICA_URL = env.DATABASE_URL.replace(`@${PRIMARY}:5432/`, `@${rec.container}:5432/`);
  return out;
}

/** Named volumes in the app's compose file: files written there differ on each server. */
function localVolumes(app: AppRecord): string[] {
  try {
    const parsed = YAML.parse(fs.readFileSync(path.join(app.appDir, "compose.yaml"), "utf-8")) as { volumes?: Record<string, unknown> };
    return Object.keys(parsed?.volumes || {});
  } catch {
    return [];
  }
}

export interface ActiveReadiness {
  app: string;
  ok: boolean;
  problems: string[];
  warnings: string[];
  /** Same items as codes (+ values) the dashboard translates. */
  problemCodes: string[];
  warningCodes: { code: string; value?: string }[];
  peers: string[];
}

/** Checks, on the origin server, whether an app can run on both servers. */
export function activeReadiness(appName: string, state = loadState()): ActiveReadiness {
  const slug = sanitizeSlug(appName);
  const app = state.apps[slug];
  const problems: string[] = [];
  const problemCodes: string[] = [];
  const warnings: string[] = [];
  const warningCodes: { code: string; value?: string }[] = [];
  const problem = (code: string, text: string) => (problemCodes.push(code), problems.push(text));
  const warn = (code: string, text: string, value?: string) => (warningCodes.push({ code, value }), warnings.push(text));
  const m = state.mirror;
  const peers = ownOffers(state).map(([k, o]) => o.peer || k);
  if (!app) {
    problem("notFound", `App '${slug}' not found.`);
    return { app: slug, ok: false, problems, warnings, problemCodes, warningCodes, peers };
  }
  const fromGit = Boolean(app.repoUrl) && !fs.existsSync(app.repoUrl!);
  if (app.trashedAt) problem("trashed", "The app is in the trash.");
  if (app.originNodeId) problem("fromPeer", "This app came from the other server: turn the mode on there, where the app was created.");
  if (app.pool?.enabled) problem("pool", "The app uses helper PCs (copies or automatic scaling): stop everything first ('paasmcp scale off <app>'). In this phase an app uses either helpers or both servers.");
  if (!fromGit) problem("localSource", "The app was deployed from a local folder; the other server needs a git repository to build the same version.");
  if (fromGit && !app.lastCommitSha) problem("noCommit", "Deploy the app once more so this server records the exact commit it runs.");
  if (!peers.length) problem("noMirror", "No server receives a live copy of this one yet: set up the mirror first ('paasmcp mirror offer <peer> --peer-ip <ip>' here, 'paasmcp mirror accept' there).");
  else if (!m?.bindIp) problem("noBindIp", "The mirror was offered without a Tailscale IP, so the other server cannot reach this database. Offer it again with --advertise <this server's Tailscale IP>.");
  if (m?.fenced) problem("fenced", "This server is fenced: another server serves its data now.");
  if (app.healthcheckDisabled) problem("noHealthcheck", "The app has no HTTP health check, and the entry needs one to stop sending requests to a server that is down.");
  else if (!app.healthcheckPath || app.healthcheckPath === "/") {
    warn("rootHealthPath", "Use a health check path that queries the database (for example /healthz). With '/', a server that lost the database keeps receiving requests.");
  }
  if (app.domains.some((d) => d.mode === "zero-trust")) {
    warn("zeroTrustBypass", "The app is behind Cloudflare Access (zero-trust). Running on both servers also publishes its port on the Tailscale IPs, where any device of your Tailnet reaches it without that login. Keep the app's own login on, or limit the Tailnet with ACLs.");
  }
  const vols = localVolumes(app);
  if (vols.length) {
    warn("localVolumes", `The app writes to local volumes (${vols.join(", ")}): files there will differ between the servers. Store uploads in S3 (paas_storage_provision) instead: buckets are copied to the peer.`, vols.join(", "));
  }
  return { app: slug, ok: problems.length === 0, problems, warnings, problemCodes, warningCodes, peers };
}

/** True when the shared Redis exists but is not published on the mirror's Tailscale IP yet. */
export function redisNeedsRebind(state = loadState()): boolean {
  const bind = state.mirror?.bindIp;
  const file = path.join(PAAS_REDIS_DIR, "compose.yaml");
  if (!bind || !fs.existsSync(file)) return false;
  return !fs.readFileSync(file, "utf-8").includes(`${bind}:6379:6379`);
}

/** True when the app has a bucket and Garage's S3 API is not published on the mirror's Tailscale IP yet. */
export function garageNeedsRebind(state: PaaSState, env: Record<string, string>): boolean {
  const bind = state.mirror?.bindIp;
  const file = path.join(PAAS_GARAGE_DIR, "compose.yaml");
  if (!bind || !usesLocalGarage(env) || !fs.existsSync(file)) return false;
  return !fs.readFileSync(file, "utf-8").includes(`${bind}:3900:3900`);
}

/** Origin side: turns the mode on/off for an app. The caller redeploys the app afterwards. */
export async function setActiveActive(appName: string, on: boolean): Promise<{ app: string; activeActive: boolean; warnings: string[]; redisRebound: boolean }> {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  if (!state.apps[slug]) throw new Error(`App '${slug}' not found.`);
  let warnings: string[] = [];
  let redisRebound = false;
  if (on) {
    const r = activeReadiness(slug, state);
    if (!r.ok) throw new Error(`App '${slug}' cannot run on both servers yet:\n- ${r.problems.join("\n- ")}`);
    warnings = r.warnings;
    // Sessions and carts in Redis must be shared: publish Redis on the Tailscale IP too (password kept).
    if (!OFFLINE() && redisNeedsRebind(state)) {
      const { ensureSharedRedisCluster } = await import("./database.js");
      ensureSharedRedisCluster();
      redisRebound = true;
    }
    // The peer copies the app's bucket from this server's S3 API on the Tailscale IP.
    if (!OFFLINE() && garageNeedsRebind(state, getSecrets(slug))) await ensureGarage();
  } else if (state.apps[slug].originNodeId) {
    throw new Error("This app came from the other server: turn the mode off there.");
  }
  state.apps[slug].activeActive = on || undefined;
  saveState(state);
  audit({ event: on ? "active.on" : "active.off", app: slug });
  return { app: slug, activeActive: on, warnings, redisRebound };
}

/**
 * Turns the mode on/off and finishes the job: redeploys the same version (publishes or drops the
 * Tailscale port), tells the other server through the control channel and updates the edge.
 * Callers check readiness and the guard ("app.active") first.
 */
export async function switchActiveActive(appName: string, on: boolean): Promise<Record<string, unknown>> {
  const r = await setActiveActive(appName, on);
  const app = loadState().apps[r.app];
  let redeployed: string | undefined;
  let warning: string | undefined;
  if (app.repoUrl && !OFFLINE()) {
    const d = await deployApp({ appName: app.name, repoSource: app.repoUrl, branch: app.branch, commit: app.lastCommitSha, trigger: "active" });
    redeployed = d.commitHash;
    warning = d.warning;
  }
  const published = publishActiveState();
  const { refreshEdge } = await import("./edge.js");
  refreshEdge();
  // Tunnel for apps on both servers: an app that leaves goes back to the main tunnel now; one that
  // joins moves once its copy on the other server answers (mirror watch / poll retry it).
  let tunnel: unknown;
  if (loadState().activeTunnel && !OFFLINE()) {
    try {
      tunnel = await routeActiveTunnel();
    } catch (err) {
      tunnel = { error: err instanceof Error ? err.message : String(err) };
    }
  }
  return { ...r, redeployed, warning, published, ...(tunnel ? { tunnel } : {}) };
}

/** How often the peer refreshes its copy of each app bucket (it lists both sides each time). */
export const FILES_EVERY_MS = 60_000;

type FilesFn = (rec: MirrorReplicaRecord, app: string, env: Record<string, string>, keepGoing: () => boolean) => Promise<FileSyncResult>;

/** The origin's S3 API as seen from here: its Tailscale IP, port 3900 (labs override it). */
export const peerS3Url = (rec: MirrorReplicaRecord) => process.env.PAASMCP_PEER_S3_URL || `http://${rec.peerHost}:3900`;

/** The app's bucket on both sides, with the app's own key (the same key exists on both Garage nodes). */
export function bucketTargets(rec: MirrorReplicaRecord, env: Record<string, string>) {
  const base = { bucket: env.S3_BUCKET, accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY, region: env.S3_REGION || undefined };
  return { origin: { ...base, endpoint: peerS3Url(rec) }, local: { ...base, endpoint: localS3Url() } };
}

const defaultFiles: FilesFn = async (rec, app, env, keepGoing) => {
  await ensureBucketWithImportedKey(env.S3_BUCKET, env.S3_ACCESS_KEY_ID, env.S3_SECRET_ACCESS_KEY, `paasmcp-${app}`);
  const t = bucketTargets(rec, env);
  return syncBucket(t.origin, t.local, "mirror", keepGoing);
};

export interface ActiveFilesResult {
  peer: string;
  app: string;
  copied: number;
  removed: number;
  partial?: boolean;
  error?: string;
}

/** True while this server still follows that peer (not promoted, no failback): copying may go on. */
const stillFollowing = (peerName: string) => {
  const r = loadState().mirror?.replicas[peerName];
  return !!r && !r.promotedAt && !r.failback && !r.supersededBy;
};

/**
 * Peer side: refreshes this server's copy of each active app's bucket, at most every FILES_EVERY_MS
 * (sooner after an error or an unfinished run). Meant to run OUTSIDE the state lock (`mirror watch`
 * starts it in the background so failover checks never wait for a copy): `lock` wraps the short
 * state writes, and `budgetMs` bounds one run; whatever is left continues on the next one.
 */
export async function syncActiveFiles(
  opts: { files?: FilesFn; now?: number; budgetMs?: number; lock?: (fn: () => void) => Promise<void> | void } = {}
): Promise<ActiveFilesResult[]> {
  const files = opts.files || (OFFLINE() ? undefined : defaultFiles);
  if (!files) return [];
  const now = opts.now ?? Date.now();
  const deadline = Date.now() + (opts.budgetMs ?? 10 * 60 * 1000);
  const lock = opts.lock || ((fn: () => void) => fn());
  const out: ActiveFilesResult[] = [];
  const state = loadState();
  for (const rec of Object.values(state.mirror?.replicas || {})) {
    for (const app of Object.values(state.apps)) {
      if (!stillFollowing(rec.peerName)) break;
      if (app.originNodeId !== rec.peerNodeId || !app.activeActive || app.trashedAt) continue;
      const env = getSecrets(app.name);
      // Files at another provider are reachable from both servers already: nothing to copy.
      if (!usesLocalGarage(env) || !env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY) continue;
      const last = app.activeSync?.files;
      if (last?.at && !last.error && !last.pending && now - Date.parse(last.at) < FILES_EVERY_MS) continue;
      if (Date.now() >= deadline) break;
      const keepGoing = () => Date.now() < deadline && stillFollowing(rec.peerName);
      let record: NonNullable<NonNullable<AppRecord["activeSync"]>["files"]>;
      try {
        const r = await files(rec, app.name, env, keepGoing);
        const error = r.errors.length ? r.errors.slice(0, 3).join("; ") : undefined;
        record = { at: new Date(now).toISOString(), copied: r.copied, removed: r.removed, tooLarge: r.tooLarge.length || undefined, error, pending: r.partial || undefined };
        if (r.copied || r.removed || error || r.partial) {
          out.push({ peer: rec.peerName, app: app.name, copied: r.copied, removed: r.removed, ...(r.partial ? { partial: true } : {}), ...(error ? { error } : {}) });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message.split("\n")[0] : String(err);
        record = { at: new Date(now).toISOString(), error: msg };
        out.push({ peer: rec.peerName, app: app.name, copied: 0, removed: 0, error: msg });
      }
      await lock(() => patchApp(app.name, (a) => (a.activeSync = { ...(a.activeSync || {}), files: record })));
    }
  }
  return out;
}

type DeployFn = (app: AppRecord, commit: string | undefined) => Promise<unknown>;

const defaultDeploy: DeployFn = async (app, commit) => {
  if (!app.repoUrl) throw new Error("no repository recorded");
  return deployApp({ appName: app.name, repoSource: app.repoUrl, branch: app.branch, commit, trusted: app.trusted, trigger: "active" });
};

const defaultStop = (appName: string) => {
  manageAppLifecycle(appName, "stop");
};

function patchApp(slug: string, patch: (a: AppRecord) => void): void {
  const s = loadState();
  if (s.apps[slug]) {
    patch(s.apps[slug]);
    saveState(s);
  }
}

/** Builds the peer-side record from what the origin sent, keeping only known fields with valid values. */
function peerRecord(slug: string, sent: Partial<AppRecord>, existing: AppRecord | undefined, originNodeId: string, appDir: string): AppRecord {
  const port = Number(sent.localPort);
  const internalPort = Number(sent.internalPort);
  if (!Number.isInteger(port) || port < 4000 || port > 4998) throw new Error(`invalid port ${sent.localPort}`);
  if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) throw new Error(`invalid internal port ${sent.internalPort}`);
  const now = new Date().toISOString();
  return {
    ...(existing || {}),
    name: slug,
    repoUrl: typeof sent.repoUrl === "string" && !sent.repoUrl.startsWith("-") ? sent.repoUrl : undefined,
    branch: validateBranchName(sent.branch || "main"),
    localPort: port,
    internalPort,
    containerName: `paasmcp-${slug}`,
    appDir,
    runtimeType: String(sent.runtimeType || existing?.runtimeType || "unknown"),
    databases: Array.isArray(sent.databases) ? sent.databases.map(String) : [],
    domains: (Array.isArray(sent.domains) ? sent.domains : [])
      .filter((d) => d && typeof d.hostname === "string" && /^[a-z0-9.:-]{1,253}$/.test(d.hostname) && ["public", "zero-trust", "tailscale", "local"].includes(d.mode))
      .map((d) => ({ hostname: d.hostname, mode: d.mode, url: String(d.url || "").slice(0, 300) })),
    createdAt: existing?.createdAt || now,
    updatedAt: existing?.updatedAt || now,
    memoryLimit: validateResourceLimit(sent.memoryLimit, "memory"),
    cpuLimit: validateResourceLimit(sent.cpuLimit, "cpu"),
    trusted: sent.trusted === true,
    healthcheckPath: validateHealthcheckPath(sent.healthcheckPath),
    healthcheckTimeoutSeconds: validateHealthcheckTimeout(sent.healthcheckTimeoutSeconds),
    healthcheckDisabled: sent.healthcheckDisabled === true || undefined,
    originNodeId,
    activeActive: true,
  };
}

export interface ActiveSyncResult {
  peer: string;
  status: "applied" | "unchanged" | "no manifest" | "skipped" | "error";
  detail?: string;
  deployed: string[];
  stopped: string[];
  /** What happened to this server's copy of the origin's tunnel connector. */
  tunnel?: "started" | "updated" | "removed";
  /** The arbiter address adopted from the origin. */
  arbiter?: string;
  errors: { app: string; error: string }[];
}

/**
 * Peer side (run by `paasmcp active sync`, the poll timer and `mirror watch`): reads each origin's
 * manifest from the live copy here, imports the app record and its vault scope, and redeploys the
 * exact commit the origin runs when the commit or the settings changed.
 */
export async function syncActivePeers(
  opts: {
    read?: (rec: MirrorReplicaRecord) => string | undefined;
    deploy?: DeployFn;
    stop?: (app: string) => Promise<void> | void;
  } = {}
): Promise<ActiveSyncResult[]> {
  const read = opts.read || readMetaFromCopy;
  const deploy = opts.deploy || defaultDeploy;
  const stop = opts.stop || defaultStop;
  const results: ActiveSyncResult[] = [];
  const state0 = loadState();
  const m = state0.mirror;

  for (const rec of Object.values(m?.replicas || {})) {
    const out: ActiveSyncResult = { peer: rec.peerName, status: "unchanged", deployed: [], stopped: [], errors: [] };
    results.push(out);
    if (rec.promotedAt || rec.failback || rec.supersededBy || rec.servedByNodeId) {
      out.status = "skipped";
      out.detail = rec.promotedAt
        ? "this server serves that peer's data now"
        : rec.failback
          ? "failback in progress"
          : rec.supersededBy
            ? "another server took over that peer's data: this copy waits to be rebuilt"
            : `this copy follows ${rec.servedByName || rec.servedByNodeId}, which took over that peer's data: its apps run only there`;
      continue;
    }
    const body = OFFLINE() && !opts.read ? undefined : read(rec);
    if (!body) {
      out.status = "no manifest";
      continue;
    }
    let manifest: ActiveManifest;
    try {
      manifest = decodeManifest(body);
      if (manifest.nodeId !== rec.peerNodeId) throw new Error(`the manifest comes from '${manifest.nodeId}', not '${rec.peerNodeId}'`);
    } catch (err) {
      out.status = "error";
      out.detail = err instanceof Error ? err.message : String(err);
      continue;
    }
    if (manifest.epoch < (loadState().mirror?.epoch || 0)) {
      out.status = "skipped";
      out.detail = `the manifest is from epoch ${manifest.epoch}, older than this server's`;
      continue;
    }

    // The arbiter the origin uses: this server adopts it when it has none yet (one less step to do by
    // hand). An address already set here is never replaced: changing it stays a person's choice.
    if (typeof manifest.arbiterUrl === "string" && /^https?:\/\/[a-zA-Z0-9.:[\]-]+$/.test(manifest.arbiterUrl)) {
      const now = loadState();
      if (now.mirror && !now.mirror.arbiterUrl) {
        now.mirror.arbiterUrl = manifest.arbiterUrl;
        saveState(now);
        audit({ event: "mirror.arbiter-from-peer", peer: rec.peerName, url: manifest.arbiterUrl });
        out.arbiter = manifest.arbiterUrl;
      }
    }

    // The origin's tunnel for apps on both servers: its connector runs here too (or goes away).
    try {
      const tunnelToken = manifest.tunnel?.token;
      if (tunnelToken !== undefined && !validTunnelToken(tunnelToken)) throw new Error("unexpected tunnel token format");
      const hostnames = (Array.isArray(manifest.tunnel?.hostnames) ? manifest.tunnel!.hostnames : []).filter((h): h is string => typeof h === "string" && /^[a-z0-9.-]{1,253}$/.test(h));
      const t = applyPeerTunnel(rec.peerNodeId, tunnelToken, hostnames);
      if (t !== "unchanged") out.tunnel = t;
    } catch (err) {
      out.errors.push({ app: "tunnel", error: err instanceof Error ? err.message.split("\n")[0] : String(err) });
    }

    // Apps the origin no longer runs on both servers stop here.
    for (const app of Object.values(loadState().apps)) {
      if (app.originNodeId !== rec.peerNodeId || !app.activeActive || manifest.apps[app.name]) continue;
      try {
        if (app.status === "running" || app.activeSync) await stop(app.name);
        patchApp(app.name, (a) => {
          a.activeActive = undefined;
          a.activeSync = undefined;
          a.status = "stopped";
        });
        out.stopped.push(app.name);
      } catch (err) {
        out.errors.push({ app: app.name, error: err instanceof Error ? err.message : String(err) });
      }
    }

    for (const [name, entry] of Object.entries(manifest.apps)) {
      let slug = name;
      try {
        slug = sanitizeSlug(name);
        const state = loadState();
        const existing = state.apps[slug];
        if (existing && existing.originNodeId !== rec.peerNodeId) throw new Error("an app with this name already lives on this server");
        const record = peerRecord(slug, entry.record, existing, rec.peerNodeId, path.join(PAAS_APPS_DIR, slug));
        const clash = Object.values(state.apps).find((a) => a.name !== slug && a.localPort === record.localPort && !a.trashedAt);
        if (clash) throw new Error(`port ${record.localPort} is taken here by '${clash.name}'; both servers must use the same port`);
        if (!/^[0-9a-f]{40}$/.test(entry.commit)) throw new Error("the origin did not send a full commit; redeploy the app there");
        const secrets: Record<string, string> = {};
        for (const [k, v] of Object.entries(entry.secrets || {})) secrets[validateEnvKey(k)] = String(v);
        saveSecrets(slug, secrets);
        state.apps[slug] = record;
        saveState(state);

        if (existing?.activeSync?.commit === entry.commit && existing.activeSync.configHash === entry.configHash && !existing.activeSync.error) continue;
        try {
          await deploy(record, entry.commit);
          patchApp(slug, (a) => {
            a.activeSync = { commit: entry.commit, configHash: entry.configHash, at: new Date().toISOString() };
          });
          out.deployed.push(slug);
          audit({ event: "active.sync-deploy", app: slug, commit: entry.commit.slice(0, 12) });
        } catch (err) {
          const msg = err instanceof Error ? err.message.split("\n")[0] : String(err);
          patchApp(slug, (a) => {
            a.activeSync = { ...(a.activeSync || {}), at: new Date().toISOString(), error: msg };
          });
          throw new Error(msg);
        }
      } catch (err) {
        out.errors.push({ app: slug, error: err instanceof Error ? err.message : String(err) });
      }
    }

    out.status = out.errors.length ? "error" : out.deployed.length || out.stopped.length || out.tunnel ? "applied" : "unchanged";
  }
  return results;
}

export interface ActiveAppStatus {
  app: string;
  role: "origin" | "copy";
  /** Commit running on this server. */
  commit?: string;
  /** Copy side: commit the origin asked for, when it was applied, and the last error. */
  wanted?: string;
  syncedAt?: string;
  error?: string;
  /** Copy side: last refresh of the local copy of the app's bucket. */
  files?: { at: string; copied?: number; removed?: number; tooLarge?: number; error?: string; pending?: boolean };
  entries: { tunnel: string[]; edge: string[] };
}

export function activeStatus(state = loadState()): { apps: ActiveAppStatus[]; publishedAt?: string; bindIp?: string; peers: string[] } {
  const apps = Object.values(state.apps)
    .filter((a) => a.activeActive && !a.trashedAt)
    .map((a): ActiveAppStatus => ({
      app: a.name,
      role: a.originNodeId ? "copy" : "origin",
      commit: a.lastCommit,
      ...(a.originNodeId
        ? { wanted: a.activeSync?.commit?.slice(0, 7), syncedAt: a.activeSync?.at, error: a.activeSync?.error, files: a.activeSync?.files }
        : {}),
      entries: {
        tunnel: a.domains.filter((d) => d.mode === "public" || d.mode === "zero-trust").map((d) => d.hostname),
        edge: Object.entries(state.edge?.sites || {}).filter(([, s]) => s.app === a.name).map(([h]) => h),
      },
    }));
  return {
    apps,
    publishedAt: state.mirror?.activePublishedAt,
    bindIp: state.mirror?.bindIp,
    peers: [...Object.keys(state.mirror?.offers || {}), ...Object.keys(state.mirror?.replicas || {})].filter((v, i, a) => a.indexOf(v) === i),
  };
}
