import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  DOCKER_NETWORK,
  loadState,
  MirrorConfig,
  MirrorReplicaRecord,
  PAAS_DATA_DIR,
  sanitizeSlug,
  saveState,
} from "./config.js";
import { ensureDockerNetwork, ensureSharedPostgresCluster } from "./database.js";
import { deployApp } from "./deployer.js";
import { exposeApplication } from "./exposure.js";
import { createBucketWithKey } from "./storage.js";
import { decryptBinaryPayload, encryptBinaryPayload, getSecrets, setSecretEntries } from "./vault.js";

// Mirror = each server keeps a live, read-only copy of the other's Postgres (physical streaming
// over Tailscale) and receives the other's backups in its Garage. Promotion is manual (part 1).

export const PG_IMAGE = "postgres:16-alpine";
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

/** Primary side: lets `peerName` stream this server's Postgres and store its backups here. Returns a one-hour token. */
export async function offerMirror(opts: {
  peerName: string;
  peerCidr: string;
  advertiseHost?: string;
  withBackups?: boolean;
}): Promise<{ token: string; slot: string; host: string; backupsBucket?: string; expiresAt: string }> {
  const key = clusterKey();
  const peer = sanitizeSlug(opts.peerName);
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
    m.offers[peer] = { peerCidr, slot, offeredAt: new Date().toISOString() };
  });

  if (!OFFLINE()) {
    if (rebind) ensureSharedPostgresCluster(); // republish 5432 on the Tailscale IP
    sql(PRIMARY, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${REPLICATOR}') THEN CREATE ROLE ${REPLICATOR} WITH REPLICATION LOGIN; END IF; END $$;`);
    sql(PRIMARY, `ALTER ROLE ${REPLICATOR} WITH PASSWORD '${password}'`);
    sql(PRIMARY, `SELECT pg_create_physical_replication_slot('${slot}') WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name='${slot}')`);
    // The slot keeps WAL while the peer is offline; cap it so a long outage cannot fill this disk.
    sql(PRIMARY, "ALTER SYSTEM SET max_slot_wal_keep_size = '10GB'");
    const hbaLine = `host replication ${REPLICATOR} ${peerCidr} scram-sha-256`;
    execFileSync("docker", ["exec", PRIMARY, "sh", "-c", 'f="$PGDATA/pg_hba.conf"; grep -qxF "$1" "$f" || echo "$1" >> "$f"', "sh", hbaLine]);
    sql(PRIMARY, "SELECT pg_reload_conf()");
  }

  let s3: MirrorOffer["s3"];
  if (opts.withBackups !== false) {
    const bucket = `mirror-${peer}`.slice(0, 63);
    const k = await createBucketWithKey(bucket, `mirror-${peer}`);
    s3 = { endpoint: `http://${host}:3900`, bucket, accessKeyId: k.accessKeyId, secretAccessKey: k.secretAccessKey };
  }

  const state = loadState();
  const offer: MirrorOffer = {
    v: 1,
    fromNodeId: state.federation?.nodeId || "primary",
    fromName: sanitizeSlug(state.federation?.nodeName || "server"),
    host,
    port: 5432,
    slot,
    password,
    s3,
    expiresAt: Date.now() + TOKEN_TTL_MS,
  };
  const token = TOKEN_PREFIX + encryptBinaryPayload(Buffer.from(JSON.stringify(offer)), key).toString("base64url");
  return { token, slot, host, backupsBucket: s3?.bucket, expiresAt: new Date(offer.expiresAt).toISOString() };
}

/** Replica side: copies the peer's Postgres (pg_basebackup) and keeps it streaming in a read-only container. */
export function acceptMirror(token: string): { replica: MirrorReplicaRecord; backupsTarget: string } {
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
  const container = `paasmcp-mirror-${peer}`;
  const dataDir = path.join(PAAS_DATA_DIR, "mirror", peer, "data");
  const localPort = existing.replicas[peer]?.localPort || 5433 + Object.keys(existing.replicas).length;
  // shortcut: rebuilding an existing copy is manual (move the folder away), so a copy that may be the last one is never wiped by a command.
  if (fs.existsSync(dataDir) && fs.readdirSync(dataDir).length > 0) {
    throw new Error(`This server already holds a copy of '${peer}' in ${dataDir}. To rebuild it, stop ${container} and move that folder away first.`);
  }

  if (!OFFLINE()) {
    ensureDockerNetwork();
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    execFileSync(
      "docker",
      [
        "run", "--rm", "--network", DOCKER_NETWORK, "-e", `PGPASSWORD=${offer.password}`,
        "-v", `${dataDir}:/var/lib/postgresql/data`, PG_IMAGE, "sh", "-c",
        'pg_basebackup -h "$1" -p "$2" -U "$3" -D /var/lib/postgresql/data -R -X stream -S "$4" && chown -R postgres:postgres /var/lib/postgresql/data && chmod 700 /var/lib/postgresql/data',
        "sh", offer.host, String(offer.port), REPLICATOR, offer.slot,
      ],
      { stdio: "pipe", timeout: 6 * 60 * 60 * 1000 }
    );
    const dir = path.dirname(dataDir);
    fs.writeFileSync(
      path.join(dir, "compose.yaml"),
      `services:
  mirror:
    image: ${PG_IMAGE}
    container_name: ${container}
    restart: unless-stopped
    ports:
      - "127.0.0.1:${localPort}:5432"
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

  let backupsTarget = "not offered";
  if (offer.s3) {
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
    localPort,
    dataDir,
    acceptedAt: new Date().toISOString(),
  };
  saveMirror((m) => {
    m.replicas[peer] = replica;
  });
  return { replica, backupsTarget };
}

export function mirrorStatus(): Record<string, unknown> {
  const m = mirrorState();
  const out: Record<string, unknown> = { epoch: m.epoch, bindIp: m.bindIp };
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
export async function promoteMirror(peerName: string): Promise<{
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
    mm.epoch += 1;
    mm.replicas[peer].promotedAt = new Date().toISOString();
    mm.replicas[peer].promotedEpoch = mm.epoch;
  });

  const state = loadState();
  const apps: { app: string; ok: boolean; detail: string }[] = [];
  for (const app of Object.values(state.apps).filter((a) => a.originNodeId === rec.peerNodeId && !a.trashedAt)) {
    try {
      const env = getSecrets(app.name);
      if (env.DATABASE_URL) {
        setSecretEntries(app.name, { DATABASE_URL: env.DATABASE_URL.replace(`@${PRIMARY}:5432/`, `@${rec.container}:5432/`) });
      }
      if (!app.repoUrl) throw new Error("no repository recorded; deploy it by hand");
      if (!OFFLINE()) deployApp({ appName: app.name, repoSource: app.repoUrl, branch: app.branch, trusted: app.trusted });
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
