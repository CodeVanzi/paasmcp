import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  DOCKER_NETWORK,
  loadState,
  MirrorConfig,
  MirrorReplicaRecord,
  PAAS_DATA_DIR,
  PAAS_DB_DIR,
  sanitizeSlug,
  saveState,
} from "./config.js";
import { ensureDockerNetwork, ensureSharedPostgresCluster, ensureSharedRedisCluster } from "./database.js";
import { deployApp, manageAppLifecycle } from "./deployer.js";
import { askArbiter } from "./arbiter.js";
import { bucketTargets } from "./active.js";
import { syncBucket } from "./filesync.js";
import { audit } from "./guard.js";
import { exposeApplication } from "./exposure.js";
import { createBucketWithKey } from "./storage.js";
import { imageFor } from "./updater.js";
import { decryptBinaryPayload, encryptBinaryPayload, getSecrets, setSecretEntries } from "./vault.js";

// Mirror = each server keeps a live, read-only copy of the other's Postgres (physical streaming
// over Tailscale) and receives the other's backups in its Garage. Promotion is manual (part 1).

// Copies run the same pinned Postgres image as the primary (see updater.ts).
const PG_IMAGE_NOW = () => imageFor("postgres");
const PRIMARY = "paasmcp-postgres";
const REPLICATOR = "paasmcp_replicator";
const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
const TOKEN_PREFIX = "pmirror_";
const TOKEN_TTL_MS = 60 * 60 * 1000;

interface MirrorOffer {
  v: 1;
  fromNodeId: string;
  fromName: string;
  host: string;
  port: number;
  slot: string;
  password: string;
  s3?: { endpoint: string; bucket: string; accessKeyId: string; secretAccessKey: string };
  /** Sender's epoch, so a rejoining server never goes back in time. */
  epoch?: number;
  expiresAt: number;
}

function mirrorState(): MirrorConfig {
  return loadState().mirror || { epoch: 0, offers: {}, replicas: {} };
}

function saveMirror(update: (m: MirrorConfig) => void): MirrorConfig {
  const state = loadState();
  state.mirror = state.mirror || { epoch: 0, offers: {}, replicas: {} };
  update(state.mirror);
  saveState(state);
  return state.mirror;
}

function clusterKey(): Buffer {
  const hex = getSecrets("system").FEDERATION_CLUSTER_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error("Pair the two servers first ('paasmcp node invite' on one, 'paasmcp node join' on the other): the mirror token is encrypted with the shared cluster key.");
  }
  return Buffer.from(hex, "hex");
}

function sql(container: string, query: string): string {
  return execFileSync(
    "docker",
    ["exec", "-i", container, "psql", "-U", "paasmcp_admin", "-d", "postgres", "-tA", "-v", "ON_ERROR_STOP=1", "-c", query],
    { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }
  ).trim();
}

function detectTailscaleIp(): string {
  try {
    return execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0].trim();
  } catch {
    throw new Error("Could not read this server's Tailscale IP ('tailscale ip -4'). Pass --advertise <ip-or-host>.");
  }
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

function writeCopyCompose(rec: { container: string; localPort: number; dataDir: string }, bindIp?: string): void {
  const dir = path.dirname(rec.dataDir);
  fs.writeFileSync(
    path.join(dir, "compose.yaml"),
    `services:
  mirror:
    image: ${PG_IMAGE_NOW()}
    container_name: ${rec.container}
    restart: unless-stopped
    ports:
      - "127.0.0.1:${rec.localPort}:5432"${bindIp ? `\n      - "${bindIp}:${rec.localPort}:5432"` : ""}
    volumes:
      - ./data:/var/lib/postgresql/data
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`,
    { mode: 0o600 }
  );
  execFileSync("docker", ["compose", "-f", path.join(dir, "compose.yaml"), "up", "-d"], { cwd: dir, stdio: "pipe" });
}

function basebackup(offer: MirrorOffer, dataDir: string): void {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  execFileSync(
    "docker",
    [
      "run", "--rm", "--network", DOCKER_NETWORK, "-e", `PGPASSWORD=${offer.password}`,
      "-v", `${dataDir}:/var/lib/postgresql/data`, PG_IMAGE_NOW(), "sh", "-c",
      'pg_basebackup -h "$1" -p "$2" -U "$3" -D /var/lib/postgresql/data -R -X stream -S "$4" && chown -R postgres:postgres /var/lib/postgresql/data && chmod 700 /var/lib/postgresql/data',
      "sh", offer.host, String(offer.port), REPLICATOR, offer.slot,
    ],
    { stdio: "pipe", timeout: 6 * 60 * 60 * 1000 }
  );
}

// Old data is renamed, never deleted: it may hold the last writes of a server that died.
function moveAside(dir: string, why: string): string {
  const dest = `${dir}.${why}-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  fs.renameSync(dir, dest);
  return dest;
}

/** Primary side: lets `peerName` stream this server's Postgres and store its backups here. Returns a one-hour token. */
export async function offerMirror(opts: {
  peerName: string;
  peerCidr: string;
  advertiseHost?: string;
  /** Port the peer connects to (default: 5432, or the copy's published port). Labs on one Docker host use 5432 + the container name. */
  advertisePort?: number;
  withBackups?: boolean;
  /** Failback: offer the promoted copy of this peer (it is now where the data lives). */
  fromCopyOf?: string;
}): Promise<{ token: string; slot: string; host: string; backupsBucket?: string; expiresAt: string }> {
  const key = clusterKey();
  const peer = sanitizeSlug(opts.peerName);
  const copy = opts.fromCopyOf ? mirrorState().replicas[sanitizeSlug(opts.fromCopyOf)] : undefined;
  if (opts.fromCopyOf && !copy?.promotedAt) throw new Error(`There is no promoted copy of '${opts.fromCopyOf}' here to offer.`);
  const source = copy ? copy.container : PRIMARY;
  const sourcePort = opts.advertisePort || (copy ? copy.localPort : 5432);
  if (!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(opts.peerCidr)) throw new Error(`Invalid --peer-ip '${opts.peerCidr}' (an IP or CIDR).`);
  const peerCidr = opts.peerCidr.includes("/") ? opts.peerCidr : `${opts.peerCidr}/${opts.peerCidr.includes(":") ? 128 : 32}`;
  const host = opts.advertiseHost || detectTailscaleIp();
  if (!/^[a-zA-Z0-9.:-]+$/.test(host)) throw new Error(`Invalid --advertise '${host}'.`);
  const slot = `mirror_${peer.replace(/-/g, "_")}`.slice(0, 63);

  let password = getSecrets("system").MIRROR_REPLICATOR_PASSWORD;
  if (!password) {
    password = crypto.randomBytes(24).toString("hex");
    setSecretEntries("system", { MIRROR_REPLICATOR_PASSWORD: password });
  }

  const bindIp = IPV4.test(host) && !host.startsWith("127.") ? host : undefined;
  const rebind = bindIp && mirrorState().bindIp !== bindIp;
  saveMirror((m) => {
    if (bindIp) m.bindIp = bindIp;
    m.offers[peer] = { peerCidr, slot, offeredAt: new Date().toISOString(), source };
  });

  if (!OFFLINE()) {
    if (copy && bindIp) writeCopyCompose(copy, bindIp);
    else if (rebind) ensureSharedPostgresCluster(); // republish 5432 on the Tailscale IP
    sql(source, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${REPLICATOR}') THEN CREATE ROLE ${REPLICATOR} WITH REPLICATION LOGIN; END IF; END $$;`);
    sql(source, `ALTER ROLE ${REPLICATOR} WITH PASSWORD '${password}'`);
    sql(source, `SELECT pg_create_physical_replication_slot('${slot}') WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name='${slot}')`);
    // The slot keeps WAL while the peer is offline; cap it so a long outage cannot fill this disk.
    sql(source, "ALTER SYSTEM SET max_slot_wal_keep_size = '10GB'");
    const hbaLine = `host replication ${REPLICATOR} ${peerCidr} scram-sha-256`;
    execFileSync("docker", ["exec", source, "sh", "-c", 'f="$PGDATA/pg_hba.conf"; grep -qxF "$1" "$f" || echo "$1" >> "$f"', "sh", hbaLine]);
    sql(source, "SELECT pg_reload_conf()");
  }

  let s3: MirrorOffer["s3"];
  if (opts.withBackups !== false && !copy) {
    const bucket = `mirror-${peer}`.slice(0, 63);
    const k = await createBucketWithKey(bucket, `mirror-${peer}`);
    s3 = { endpoint: `http://${host}:3900`, bucket, accessKeyId: k.accessKeyId, secretAccessKey: k.secretAccessKey };
  }

  const state = loadState();
  const offer: MirrorOffer = {
    v: 1,
    fromNodeId: state.federation?.nodeId || "primary",
    // The default name is the same on every server; the hostname tells the two apart.
    fromName: sanitizeSlug(state.federation?.nodeName && state.federation.nodeName !== "primary-node" ? state.federation.nodeName : os.hostname()),
    host,
    port: sourcePort,
    slot,
    password,
    s3,
    epoch: mirrorState().epoch,
    expiresAt: Date.now() + TOKEN_TTL_MS,
  };
  const token = TOKEN_PREFIX + encryptBinaryPayload(Buffer.from(JSON.stringify(offer)), key).toString("base64url");
  return { token, slot, host, backupsBucket: s3?.bucket, expiresAt: new Date(offer.expiresAt).toISOString() };
}

/** Replica side: copies the peer's Postgres (pg_basebackup) and keeps it streaming in a read-only container. */
export function acceptMirror(
  token: string,
  opts: { rejoin?: boolean } = {}
): { replica: MirrorReplicaRecord; backupsTarget: string; movedAside?: string } {
  if (!token.startsWith(TOKEN_PREFIX)) throw new Error("Not a mirror token.");
  let offer: MirrorOffer;
  try {
    offer = JSON.parse(decryptBinaryPayload(Buffer.from(token.slice(TOKEN_PREFIX.length), "base64url"), clusterKey()).toString("utf-8"));
  } catch {
    throw new Error("Mirror token could not be decrypted: wrong cluster (pair the servers first) or a damaged copy.");
  }
  if (Date.now() > offer.expiresAt) throw new Error("Mirror token expired (1 hour). Ask for a new one with 'paasmcp mirror offer'.");

  const peer = sanitizeSlug(offer.fromName);
  const existing = mirrorState();
  const previous = existing.replicas[peer];
  let movedAside: string | undefined;
  let container = `paasmcp-mirror-${peer}`;
  let dataDir = path.join(PAAS_DATA_DIR, "mirror", peer, "data");
  const localPort = previous?.localPort || 5433 + Object.keys(existing.replicas).length;

  if (opts.rejoin) {
    // Failback: this server's own Postgres becomes the read-only copy of the peer that took over.
    // Callers need existing.fenced or a person's confirmation (guard "mirror.rejoin").
    container = PRIMARY;
    dataDir = path.join(PAAS_DB_DIR, "data");
    if (!OFFLINE()) {
      execFileSync("docker", ["compose", "-f", path.join(PAAS_DB_DIR, "compose.yaml"), "down"], { cwd: PAAS_DB_DIR, stdio: "pipe" });
      if (fs.existsSync(dataDir)) movedAside = moveAside(dataDir, "before-rejoin");
      basebackup(offer, dataDir);
      ensureSharedPostgresCluster();
    }
  } else {
    if (fs.existsSync(dataDir) && fs.readdirSync(dataDir).length > 0) {
      // Only a copy that was promoted and then handed back is stale; any other copy may be the last one.
      if (!previous?.promotedAt || !previous.handedBackAt) {
        throw new Error(`This server already holds a copy of '${peer}' in ${dataDir}. To rebuild it, stop ${container} and move that folder away first.`);
      }
      if (!OFFLINE()) execFileSync("docker", ["rm", "-f", container], { stdio: "pipe" });
      movedAside = moveAside(dataDir, "stale-after-handback");
    }
    if (!OFFLINE()) {
      ensureDockerNetwork();
      basebackup(offer, dataDir);
      writeCopyCompose({ container, localPort, dataDir });
    }
  }

  let backupsTarget = "not offered";
  if (offer.s3 && !opts.rejoin) {
    if (getSecrets("system").BACKUP_S3_ENDPOINT) {
      backupsTarget = "kept your existing off-site target (BACKUP_S3_*); the peer's bucket was not used";
    } else {
      setSecretEntries("system", {
        BACKUP_S3_ENDPOINT: offer.s3.endpoint,
        BACKUP_S3_BUCKET: offer.s3.bucket,
        BACKUP_S3_ACCESS_KEY_ID: offer.s3.accessKeyId,
        BACKUP_S3_SECRET_ACCESS_KEY: offer.s3.secretAccessKey,
        BACKUP_S3_REGION: "garage",
      });
      backupsTarget = `${offer.s3.endpoint}/${offer.s3.bucket} (run 'paasmcp backup install-timer' if not done yet)`;
    }
  }

  const replica: MirrorReplicaRecord = {
    peerName: peer,
    peerNodeId: offer.fromNodeId,
    peerHost: offer.host,
    slot: offer.slot,
    container,
    localPort: opts.rejoin ? 5432 : localPort,
    dataDir,
    acceptedAt: new Date().toISOString(),
    ...(opts.rejoin ? { failback: true } : {}),
  };
  saveMirror((m) => {
    m.replicas[peer] = replica;
    m.epoch = Math.max(m.epoch, offer.epoch || 0);
  });
  return { replica, backupsTarget, movedAside };
}

export function mirrorStatus(): Record<string, unknown> {
  const m = mirrorState();
  const out: Record<string, unknown> = { epoch: m.epoch, bindIp: m.bindIp, arbiterUrl: m.arbiterUrl, auto: m.auto || [], fenced: m.fenced };
  const safe = <T>(fn: () => T): T | { error: string } => {
    try {
      return fn();
    } catch (err) {
      return { error: err instanceof Error ? err.message.split("\n")[0] : String(err) };
    }
  };
  out.sending = Object.entries(m.offers).map(([peer, o]) => ({
    peer,
    slot: o.slot,
    ...(OFFLINE()
      ? {}
      : safe(() => {
          const [active, retained, walStatus] = sql(
            PRIMARY,
            `SELECT active, pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)), wal_status FROM pg_replication_slots WHERE slot_name='${o.slot}'`
          ).split("|");
          // wal_status 'lost' = the peer was away longer than the 10GB cap and needs a fresh copy.
          return { connected: active === "t", walKeptForPeer: retained, walStatus };
        })),
  }));
  out.receiving = Object.values(m.replicas).map((r) => ({
    peer: r.peerName,
    container: r.container,
    promotedAt: r.promotedAt,
    ...(OFFLINE() || r.promotedAt
      ? {}
      : safe(() => {
          const [recovery, lagSeconds, receiver, caughtUp] = sql(
            r.container,
            "SELECT pg_is_in_recovery(), COALESCE(round(extract(epoch FROM now() - pg_last_xact_replay_timestamp()))::text, ''), COALESCE((SELECT status FROM pg_stat_wal_receiver), 'stopped'), pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn()"
          ).split("|");
          return {
            readOnlyCopy: recovery === "t",
            streaming: receiver === "streaming",
            caughtUp: caughtUp === "t",
            secondsSinceLastChangeApplied: lagSeconds ? Number(lagSeconds) : null,
          };
        })),
  }));
  return out;
}

/** Manual failover: this server takes over `peerName`'s apps with its copy. Needs a strong human confirmation (guard "mirror.promote"). */
export async function promoteMirror(peerName: string, opts: { epoch?: number } = {}): Promise<{
  peer: string;
  epoch: number;
  apps: { app: string; ok: boolean; detail: string }[];
}> {
  const peer = sanitizeSlug(peerName);
  const rec = mirrorState().replicas[peer];
  if (!rec) throw new Error(`This server holds no copy of '${peer}'.`);
  if (rec.promotedAt) throw new Error(`'${peer}' was already promoted here at ${rec.promotedAt} (epoch ${rec.promotedEpoch}).`);

  if (!OFFLINE()) sql(rec.container, "SELECT pg_promote(true, 60)");
  const m = saveMirror((mm) => {
    mm.epoch = Math.max(mm.epoch + 1, opts.epoch || 0);
    mm.replicas[peer].promotedAt = new Date().toISOString();
    mm.replicas[peer].promotedEpoch = mm.epoch;
    if (rec.failback) delete mm.fenced;
  });

  const state = loadState();
  const apps: { app: string; ok: boolean; detail: string }[] = [];
  // Normal failover: the peer's apps start here. Failback: this server's own apps start again.
  const mine = (a: { originNodeId?: string; trashedAt?: string }) =>
    !a.trashedAt && (rec.failback ? !a.originNodeId : a.originNodeId === rec.peerNodeId);
  for (const app of Object.values(state.apps).filter(mine)) {
    try {
      const env = getSecrets(app.name);
      if (env.DATABASE_URL && !rec.failback) {
        setSecretEntries(app.name, { DATABASE_URL: env.DATABASE_URL.replace(`@${PRIMARY}:5432/`, `@${rec.container}:5432/`) });
      }
      // The peer's Redis is gone with it: point the app at this server's Redis (its data, e.g.
      // sessions, starts empty). The URL carried the peer's password.
      if ((env.REDIS_URL || env.LOCAL_REDIS_URL) && !rec.failback) {
        const pass = OFFLINE() ? getSecrets("system").REDIS_ROOT_PASSWORD : ensureSharedRedisCluster().redisPass;
        const withPass = (u?: string) => (u ? u.replace(/^redis:\/\/:[^@]*@/, `redis://:${pass}@`) : undefined);
        if (pass) {
          setSecretEntries(app.name, Object.fromEntries(
            Object.entries({ REDIS_URL: withPass(env.REDIS_URL), LOCAL_REDIS_URL: withPass(env.LOCAL_REDIS_URL) }).filter(([, v]) => v)
          ) as Record<string, string>);
        }
      }
      if (rec.failback) {
        if (!OFFLINE()) manageAppLifecycle(app.name, "start");
      } else {
        if (!app.repoUrl) throw new Error("no repository recorded; deploy it by hand");
        // An active-active app keeps the version it already ran here.
        const commit = app.activeActive && app.activeSync?.commit ? app.activeSync.commit : undefined;
        if (!OFFLINE()) await deployApp({ appName: app.name, repoSource: app.repoUrl, branch: app.branch, trusted: app.trusted, commit });
      }
      // DNS switch: re-exposing points the hostname at this server's tunnel.
      const base = state.cloudflare.baseDomain;
      for (const d of app.domains.filter((x) => x.mode === "public" || x.mode === "zero-trust")) {
        if (!OFFLINE()) {
          await exposeApplication({ appName: app.name, mode: d.mode as "public" | "zero-trust", subdomain: d.hostname.replace(`.${base}`, "") });
        }
      }
      apps.push({ app: app.name, ok: true, detail: "running here" });
    } catch (err) {
      apps.push({ app: app.name, ok: false, detail: err instanceof Error ? err.message : String(err) });
    }
  }
  return { peer, epoch: m.epoch, apps };
}

/**
 * Failback, step on the server that took over: stop the peer's apps here, wait until the peer's
 * rejoined copy has every change, and hand the data back (arbiter too, when configured).
 * Next: on the peer, `paasmcp mirror promote <this server>`.
 */
export async function handbackMirror(
  peerName: string,
  waitMs = 120_000
): Promise<{ peer: string; epoch: number; stoppedApps: string[]; filesBack: { app: string; copied: number }[] }> {
  const peer = sanitizeSlug(peerName);
  const m0 = mirrorState();
  const rec = m0.replicas[peer];
  const offer = m0.offers[peer];
  if (!rec?.promotedAt || !offer) {
    throw new Error(`Nothing to hand back: '${peer}' was not promoted here, or no failback offer was made ('paasmcp mirror offer ${peer} --from-copy-of ${peer} ...').`);
  }
  const stoppedApps: string[] = [];
  for (const app of Object.values(loadState().apps).filter((a) => a.originNodeId === rec.peerNodeId && !a.trashedAt)) {
    if (!OFFLINE()) manageAppLifecycle(app.name, "stop");
    stoppedApps.push(app.name);
  }
  if (!OFFLINE()) {
    const deadline = Date.now() + waitMs;
    for (;;) {
      const lag = sql(rec.container, `SELECT COALESCE((SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) FROM pg_stat_replication s JOIN pg_replication_slots r ON r.active_pid = s.pid WHERE r.slot_name='${offer.slot}'), -1)`);
      if (lag === "0") break;
      if (Date.now() > deadline) {
        for (const a of stoppedApps) manageAppLifecycle(a, "start");
        throw new Error(`The copy on '${peer}' did not catch up in time (lag ${lag === "-1" ? "unknown: not connected" : lag + " bytes"}); apps restarted here, nothing handed back.`);
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  // Files uploaded here while this server served the peer's apps go back first (only additions and
  // newer versions: nothing on the peer is deleted). A failure keeps the data here and the apps running.
  const filesBack: { app: string; copied: number }[] = [];
  if (!OFFLINE()) {
    for (const app of stoppedApps) {
      const env = getSecrets(app);
      if (!loadState().apps[app]?.activeActive || !env.S3_BUCKET || !env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY) continue;
      try {
        const t = bucketTargets(rec, env);
        const r = await syncBucket(t.local, t.origin, "additive");
        if (r.errors.length) throw new Error(r.errors[0]);
        filesBack.push({ app, copied: r.copied });
      } catch (err) {
        for (const a of stoppedApps) manageAppLifecycle(a, "start");
        throw new Error(`Could not copy ${app}'s uploaded files back to '${peer}' (${err instanceof Error ? err.message.split("\n")[0] : String(err)}); apps restarted here, nothing handed back.`);
      }
    }
  }
  const m = saveMirror((mm) => {
    mm.epoch += 1;
    mm.replicas[peer].handedBackAt = new Date().toISOString();
  });
  if (m.arbiterUrl) {
    const me = loadState().federation?.nodeId || "primary";
    const r = await askArbiter(m.arbiterUrl, { op: "handover", node: me, epoch: m.epoch, dataOf: rec.peerNodeId, to: rec.peerNodeId });
    if (!r.granted) throw new Error("The arbiter refused the handover (this server is not the recorded owner). Apps here stay stopped; check 'paasmcp mirror status'.");
  }
  audit({ event: "mirror.handback", peer, epoch: m.epoch, filesBack });
  return { peer, epoch: m.epoch, stoppedApps, filesBack };
}

const ARBITER_URL_RE = /^https?:\/\/[a-zA-Z0-9.:[\]-]+(\/.*)?$/;

/** Saves the arbiter address alone (both servers need it: the one that sends a copy heartbeats and gets fenced). */
export function setArbiterUrl(arbiterUrl: string): MirrorConfig {
  const url = arbiterUrl.trim().replace(/\/+$/, "").replace(/\/arbiter$/, "");
  if (!ARBITER_URL_RE.test(url)) throw new Error(`Invalid arbiter URL '${arbiterUrl}'. Use http://<Tailscale IP of the arbiter>:4097`);
  return saveMirror((m) => {
    m.arbiterUrl = url;
  });
}

export interface ArbiterCheck {
  configured: boolean;
  url?: string;
  ok?: boolean;
  /** Plain-language reason when the arbiter cannot be used, and a code the dashboard translates. */
  error?: string;
  /** The raw cause (HTTP status, network error), for the curious. */
  detail?: string;
  errorCode?: "badUrl" | "badKey" | "clock" | "notPaired" | "notArbiter" | "unreachable";
  /** What the arbiter hears right now: this server and every other server it knows. */
  nodes?: { nodeId: string; name: string; isMe: boolean; secondsAgo: number }[];
  /** Whether `paasmcp mirror watch` (systemd) runs here; null when unknown. */
  watchActive?: boolean | null;
  auto?: string[];
}

/**
 * Talks to the arbiter once (a normal heartbeat, so it is harmless) and explains the result: reachable,
 * right key, clock in sync, which servers it hears. Used by the dashboard's "Test arbiter" button.
 */
export async function checkArbiter(urlOverride?: string): Promise<ArbiterCheck> {
  const m = mirrorState();
  const url = (urlOverride || m.arbiterUrl || "").trim().replace(/\/+$/, "").replace(/\/arbiter$/, "");
  const watchActive = OFFLINE()
    ? null
    : (() => {
        try {
          return execFileSync("systemctl", ["is-active", "paasmcp-mirror-watch.service"], { encoding: "utf-8" }).trim() === "active";
        } catch {
          return false;
        }
      })();
  const base = { watchActive, auto: m.auto || [] };
  if (!url) return { configured: false, ...base };
  if (!ARBITER_URL_RE.test(url)) return { configured: true, url, ok: false, errorCode: "badUrl", error: "Invalid address. Use http://<Tailscale IP of the arbiter>:4097", ...base };
  const state = loadState();
  const me = state.federation?.nodeId || "primary";
  const names: Record<string, string> = { [me]: state.federation?.nodeName || os.hostname() };
  for (const p of Object.values(state.federation?.peers || {})) names[p.nodeId] = p.name;
  for (const r of Object.values(m.replicas)) names[r.peerNodeId] = r.peerName;
  try {
    const r = await askArbiter(url, { op: "heartbeat", node: me, epoch: m.epoch });
    const nodes = Object.entries(r.nodes || {})
      .map(([nodeId, n]) => ({ nodeId, name: names[nodeId] || nodeId, isMe: nodeId === me, secondsAgo: Math.max(0, Math.round((r.now - n.lastSeen) / 1000)) }))
      .sort((a, b) => Number(b.isMe) - Number(a.isMe) || a.secondsAgo - b.secondsAgo);
    return { configured: true, url, ok: true, nodes, ...base };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const [errorCode, error]: [NonNullable<ArbiterCheck["errorCode"]>, string] = /HTTP 401/.test(msg)
      ? ["badKey", "The arbiter answered but refused the key. On the arbiter, use the output of 'paasmcp arbiter key' from one of these servers (both give the same key once they are paired)."]
      : /clock skew/.test(msg)
        ? ["clock", "The arbiter answered but its clock is more than 1 minute off from this server. Turn on automatic time (NTP) on both."]
        : /No cluster key/.test(msg)
          ? ["notPaired", "This server is not paired with the other one yet: pair them in Connections & webhook first."]
          : /HTTP 404/.test(msg)
            ? ["notArbiter", "Something answered at that address, but it is not the arbiter. Check the port (default 4097)."]
            : ["unreachable", `The arbiter did not answer (${msg.split("\n")[0].slice(0, 120)}). Check that it is running on the third device ('systemctl status paasmcp-arbiter'), that the address is its Tailscale IP and that the port is right.`];
    return { configured: true, url, ok: false, errorCode, error, detail: msg.split("\n")[0].slice(0, 160), ...base };
  }
}

/** Turns automatic failover on/off for a peer. On needs an arbiter (guard: forbidden without one, strong with one). */
export function setAutoFailover(peerName: string, on: boolean, arbiterUrl?: string): MirrorConfig {
  const peer = sanitizeSlug(peerName);
  if (on && !mirrorState().replicas[peer]) throw new Error(`This server holds no copy of '${peer}'.`);
  if (arbiterUrl && !ARBITER_URL_RE.test(arbiterUrl)) throw new Error(`Invalid arbiter URL '${arbiterUrl}'.`);
  return saveMirror((m) => {
    if (arbiterUrl) m.arbiterUrl = arbiterUrl;
    const set = new Set(m.auto || []);
    on ? set.add(peer) : set.delete(peer);
    m.auto = [...set];
  });
}

/**
 * One watchdog round (run every ~15 s by `paasmcp mirror watch`): heartbeat to the arbiter, fence this
 * server if another one now serves its data, and take over a peer automatically when both this
 * server and the arbiter have lost it and its copy here stopped streaming.
 */
export async function watchTick(): Promise<Record<string, unknown>> {
  const m = mirrorState();
  if (!m.arbiterUrl) return { skipped: "no arbiter configured" };
  const me = loadState().federation?.nodeId || "primary";
  const beat = await askArbiter(m.arbiterUrl, { op: "heartbeat", node: me, epoch: m.epoch });
  const out: Record<string, unknown> = { epoch: m.epoch };

  const myOwner = beat.owners[me];
  if (myOwner && myOwner.owner !== me && !m.fenced) {
    const stopped: string[] = [];
    for (const app of Object.values(loadState().apps).filter((a) => !a.originNodeId && !a.trashedAt)) {
      try {
        if (!OFFLINE()) manageAppLifecycle(app.name, "stop");
        stopped.push(app.name);
      } catch {
        // keep fencing the others
      }
    }
    saveMirror((mm) => {
      mm.fenced = { byNodeId: myOwner.owner, epoch: myOwner.epoch, at: new Date().toISOString() };
    });
    audit({ event: "mirror.fenced", by: myOwner.owner, epoch: myOwner.epoch, stopped });
    out.fenced = { by: myOwner.owner, epoch: myOwner.epoch, stopped };
  }

  for (const peer of m.auto || []) {
    const rec = m.replicas[peer];
    if (!rec || rec.promotedAt || m.fenced) continue;
    const seen = beat.nodes[rec.peerNodeId]?.lastSeen || 0;
    if (beat.now - seen <= 60_000) continue;
    const streaming = OFFLINE() ? false : (() => {
      try {
        return sql(rec.container, "SELECT COALESCE((SELECT status FROM pg_stat_wal_receiver), 'stopped')") === "streaming";
      } catch {
        return false;
      }
    })();
    if (streaming) continue; // the arbiter lost it but the data link is alive: not a real outage
    const claim = await askArbiter(m.arbiterUrl, { op: "claim", node: me, epoch: m.epoch + 1, dataOf: rec.peerNodeId });
    if (!claim.granted) continue;
    audit({ event: "mirror.auto-promote", peer, epoch: m.epoch + 1 });
    out[`promoted:${peer}`] = await promoteMirror(peer, { epoch: m.epoch + 1 });
  }
  return out;
}

export function installMirrorWatch(): string {
  const unit = "/etc/systemd/system/paasmcp-mirror-watch.service";
  fs.writeFileSync(
    unit,
    `[Unit]\nDescription=PaaSMCP mirror watchdog (arbiter heartbeat, fencing, automatic failover)\nAfter=network-online.target docker.service\n\n[Service]\nEnvironment=PAASMCP_ROOT=${process.env.PAASMCP_ROOT || "/opt/homelab"}\nExecStart=${process.execPath} ${path.resolve(process.argv[1])} mirror watch\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n`
  );
  execFileSync("systemctl", ["daemon-reload"]);
  execFileSync("systemctl", ["enable", "--now", "paasmcp-mirror-watch.service"]);
  return unit;
}
