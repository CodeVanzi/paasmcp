import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  BackupRecord,
  ensureDirectories,
  loadState,
  PAAS_BACKUPS_DIR,
  sanitizeSlug,
  saveState,
} from "./config.js";
import { backupDatabase } from "./database.js";
import { localDate, readNightlyMark, writeNightlyMark } from "./nightly.js";
import { sendNotice } from "./notify.js";
import { decryptBinaryPayload, encryptBinaryPayload, getSecrets } from "./vault.js";

export const VOLUME_HELPER_IMAGE = "alpine:3.20";
const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

// ---------------------------------------------------------------------------
// AWS Signature V4 (S3), native crypto only. Works with R2, B2, Garage, MinIO and AWS.
// ---------------------------------------------------------------------------

const sha256Hex = (data: string | Buffer) => crypto.createHash("sha256").update(data).digest("hex");
const hmac = (key: Buffer | string, data: string) => crypto.createHmac("sha256", key).update(data).digest();

export function signV4(o: {
  method: string;
  url: URL;
  headers: Record<string, string>;
  payloadHash: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  amzDate: string; // YYYYMMDDTHHMMSSZ
}): string {
  const names = Object.keys(o.headers).map((h) => h.toLowerCase()).sort();
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(o.headers)) lower[k.toLowerCase()] = String(v).trim();
  const canonicalHeaders = names.map((h) => `${h}:${lower[h]}\n`).join("");
  const signedHeaders = names.join(";");
  const query = [...o.url.searchParams.entries()]
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .sort()
    .join("&");
  const canonicalRequest = [o.method, o.url.pathname || "/", query, canonicalHeaders, signedHeaders, o.payloadHash].join("\n");
  const day = o.amzDate.slice(0, 8);
  const scope = `${day}/${o.region}/s3/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", o.amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const kSigning = hmac(hmac(hmac(hmac(`AWS4${o.secretAccessKey}`, day), o.region), "s3"), "aws4_request");
  const signature = crypto.createHmac("sha256", kSigning).update(stringToSign).digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${o.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

export interface OffsiteConfig {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  prefix: string;
}

export function getOffsiteConfig(): OffsiteConfig | null {
  const s = getSecrets("system");
  if (!s.BACKUP_S3_ENDPOINT || !s.BACKUP_S3_BUCKET || !s.BACKUP_S3_ACCESS_KEY_ID || !s.BACKUP_S3_SECRET_ACCESS_KEY) {
    return null;
  }
  return {
    endpoint: s.BACKUP_S3_ENDPOINT.replace(/\/+$/, ""),
    bucket: s.BACKUP_S3_BUCKET,
    accessKeyId: s.BACKUP_S3_ACCESS_KEY_ID,
    secretAccessKey: s.BACKUP_S3_SECRET_ACCESS_KEY,
    region: s.BACKUP_S3_REGION || "auto",
    prefix: (s.BACKUP_S3_PREFIX || `paasmcp/${sanitizeSlug(os.hostname())}`).replace(/^\/+|\/+$/g, ""),
  };
}

function requireOffsite(): OffsiteConfig {
  const cfg = getOffsiteConfig();
  if (!cfg) {
    throw new Error(
      "Off-site backup is not configured. Choose where to send them in the dashboard (Databases > Off-server backups) or with 'paasmcp backup target set <provider>'."
    );
  }
  return cfg;
}

export async function s3Request(cfg: OffsiteConfig, method: "PUT" | "GET" | "DELETE", key: string, body?: Buffer): Promise<Buffer> {
  // Path-style addressing: the one style every S3-compatible server accepts.
  const url = new URL(`${cfg.endpoint}/${cfg.bucket}/${key.split("/").map(encodeURIComponent).join("/")}`);
  const payloadHash = sha256Hex(body || "");
  const amzDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const headers: Record<string, string> = {
    host: url.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };
  headers.authorization = signV4({ method, url, headers: { ...headers }, payloadHash, ...cfg, amzDate });
  delete headers.host; // fetch sets it
  const res = await fetch(url, { method, headers, body: body ? new Uint8Array(body) : undefined, signal: AbortSignal.timeout(10 * 60 * 1000) });
  const out = Buffer.from(await res.arrayBuffer());
  if (!res.ok) {
    throw new Error(`Off-site ${method} ${key} failed: HTTP ${res.status} ${out.toString("utf-8").slice(0, 300)}`);
  }
  return out;
}

// ---------------------------------------------------------------------------
// App volume backups
// ---------------------------------------------------------------------------

export function listAppVolumes(appName: string): string[] {
  const slug = sanitizeSlug(appName);
  if (OFFLINE()) return [`${slug}_data`];
  const out = execFileSync(
    "docker",
    ["volume", "ls", "-q", "--filter", `label=com.docker.compose.project=${slug}`],
    { encoding: "utf-8" }
  );
  return out.split("\n").map((v) => v.trim()).filter(Boolean);
}

function writeBackup(slug: string, engine: BackupRecord["engine"], databaseName: string, raw: Buffer): BackupRecord {
  ensureDirectories();
  const encryptedBuf = encryptBinaryPayload(raw);
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const id = `${slug}-${engine}-${databaseName.replace(/[^a-zA-Z0-9_-]/g, "")}-${timestamp}`;
  const filePath = path.join(PAAS_BACKUPS_DIR, `${id}.enc.bak`);
  fs.writeFileSync(filePath, encryptedBuf, { mode: 0o600 });
  const record: BackupRecord = {
    id,
    appName: slug,
    databaseName,
    engine,
    filePath,
    sizeBytes: encryptedBuf.length,
    sha256: sha256Hex(encryptedBuf),
    encrypted: true,
    createdAt: new Date().toISOString(),
  };
  const state = loadState();
  state.backups = state.backups || {};
  state.backups[id] = record;
  saveState(state);
  return record;
}

// shortcut: each volume is tarred into memory (1 GiB cap); big volumes move to restic with the mirror (plan item 5).
export function backupAppVolumes(appName: string): BackupRecord[] {
  const slug = sanitizeSlug(appName);
  return listAppVolumes(slug).map((volume) => {
    const raw = OFFLINE()
      ? Buffer.from(`synthetic tar of ${volume}`, "utf-8")
      : execFileSync(
          "docker",
          ["run", "--rm", "-v", `${volume}:/v:ro`, VOLUME_HELPER_IMAGE, "tar", "czf", "-", "-C", "/v", "."],
          { stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1024 * 1024 * 1024 }
        );
    return writeBackup(slug, "volume", volume, raw);
  });
}

// ---------------------------------------------------------------------------
// Verify and decrypt a backup, from disk or (when pruned locally) after a fetch.
// ---------------------------------------------------------------------------

export function readVerifiedBackup(backupId: string): { backup: BackupRecord; plain: Buffer } {
  const cleanId = backupId.replace(/[^a-zA-Z0-9._-]/g, "");
  const backup = loadState().backups?.[cleanId];
  if (!backup) throw new Error(`Backup '${cleanId}' not found in PaaSMCP state.`);
  const resolved = path.resolve(backup.filePath);
  if (!resolved.startsWith(path.resolve(PAAS_BACKUPS_DIR) + path.sep)) {
    throw new Error("Security violation: backup file path is outside PAAS_BACKUPS_DIR.");
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(
      backup.offsiteKey
        ? `Backup '${cleanId}' is only off-site now. Run 'paasmcp backup fetch ${cleanId}' first.`
        : `Encrypted backup file missing on disk: ${resolved}`
    );
  }
  const enc = fs.readFileSync(resolved);
  if (sha256Hex(enc) !== backup.sha256) {
    throw new Error("Backup SHA-256 integrity check failed! File may have been tampered with.");
  }
  return { backup, plain: decryptBinaryPayload(enc) };
}

export function restoreVolume(backup: BackupRecord, plain: Buffer): { safetyBackupId?: string } {
  if (OFFLINE()) return {};
  const app = loadState().apps[backup.appName];
  // Never skippable: snapshot the volume as it is now so a wrong restore can be undone.
  const safety = backupAppVolumes(backup.appName).find((r) => r.databaseName === backup.databaseName);
  const compose = app ? ["compose", "-f", path.join(app.appDir, "compose.yaml")] : null;
  if (compose) execFileSync("docker", [...compose, "stop"], { cwd: app!.appDir, stdio: "pipe" });
  try {
    execFileSync(
      "docker",
      ["run", "--rm", "-i", "-v", `${backup.databaseName}:/v`, VOLUME_HELPER_IMAGE, "sh", "-c", "find /v -mindepth 1 -delete && tar xzf - -C /v"],
      { input: plain, stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }
    );
  } finally {
    if (compose) execFileSync("docker", [...compose, "start"], { cwd: app!.appDir, stdio: "pipe" });
  }
  return { safetyBackupId: safety?.id };
}

// ---------------------------------------------------------------------------
// Restore test: proves a backup can come back without touching the live data.
// ---------------------------------------------------------------------------

export function testRestore(backupId: string): {
  backupId: string;
  engine: string;
  ok: boolean;
  plainBytes: number;
  detail: string;
  /** For the dashboard's own words: what was checked, and how many tables/entries were found. */
  code: "checked" | "pg_ok" | "volume_ok" | "redis_ok" | "redis_bad";
  count?: number;
} {
  const { backup, plain } = readVerifiedBackup(backupId);
  const base = { backupId: backup.id, engine: backup.engine, plainBytes: plain.length };
  if (OFFLINE()) return { ...base, ok: true, detail: "Checksum and decryption OK (offline test mode).", code: "checked" };

  if (backup.engine === "postgres") {
    const tempDb = `restoretest_${crypto.randomBytes(4).toString("hex")}`;
    const exec = (args: string[], input?: Buffer) =>
      execFileSync("docker", ["exec", "-i", "paasmcp-postgres", ...args], {
        input,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 256 * 1024 * 1024,
      });
    exec(["createdb", "-U", "paasmcp_admin", tempDb]);
    try {
      exec(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-U", "paasmcp_admin", "-d", tempDb], plain);
      const tables = exec([
        "psql", "-tA", "-U", "paasmcp_admin", "-d", tempDb, "-c",
        "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')",
      ]).trim();
      return { ...base, ok: true, detail: `Loaded into a temporary database: ${tables} table(s).`, code: "pg_ok", count: Number(tables) || 0 };
    } finally {
      exec(["dropdb", "-U", "paasmcp_admin", "--if-exists", tempDb]);
    }
  }
  if (backup.engine === "volume") {
    const files = execFileSync("tar", ["tzf", "-"], { input: plain, encoding: "utf-8", maxBuffer: 256 * 1024 * 1024 })
      .split("\n").filter(Boolean).length;
    return { ...base, ok: true, detail: `Archive opens: ${files} entr${files === 1 ? "y" : "ies"}.`, code: "volume_ok", count: files };
  }
  const isRdb = plain.subarray(0, 5).toString("ascii") === "REDIS";
  return { ...base, ok: isRdb, detail: isRdb ? "Redis RDB header OK." : "Not a Redis RDB file.", code: isRdb ? "redis_ok" : "redis_bad" };
}

// ---------------------------------------------------------------------------
// Off-site sync, fetch and local pruning
// ---------------------------------------------------------------------------

export async function syncOffsite(): Promise<{ uploaded: string[]; skipped: number; failed: { id: string; error: string }[] }> {
  const cfg = requireOffsite();
  const uploaded: string[] = [];
  const failed: { id: string; error: string }[] = [];
  let skipped = 0;
  for (const backup of Object.values(loadState().backups || {})) {
    if (backup.offsiteKey || !fs.existsSync(backup.filePath)) {
      skipped++;
      continue;
    }
    const key = `${cfg.prefix}/${backup.id}.enc.bak`;
    try {
      await s3Request(cfg, "PUT", key, fs.readFileSync(backup.filePath));
      const meta = { ...backup, offsiteKey: key, offsiteAt: new Date().toISOString() };
      // Metadata next to the file, so a fresh server can rebuild its backup list.
      await s3Request(cfg, "PUT", `${key}.json`, Buffer.from(JSON.stringify(meta, null, 2)));
      const state = loadState();
      if (state.backups?.[backup.id]) {
        state.backups[backup.id] = { ...state.backups[backup.id], offsiteKey: key, offsiteAt: meta.offsiteAt };
        saveState(state);
      }
      uploaded.push(backup.id);
    } catch (err) {
      failed.push({ id: backup.id, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { uploaded, skipped, failed };
}

export async function fetchOffsite(backupId: string): Promise<BackupRecord> {
  const cfg = requireOffsite();
  const cleanId = backupId.replace(/[^a-zA-Z0-9._-]/g, "");
  const key = loadState().backups?.[cleanId]?.offsiteKey || `${cfg.prefix}/${cleanId}.enc.bak`;
  const meta = JSON.parse((await s3Request(cfg, "GET", `${key}.json`)).toString("utf-8")) as BackupRecord;
  const enc = await s3Request(cfg, "GET", key);
  if (sha256Hex(enc) !== meta.sha256) throw new Error("Downloaded backup failed the SHA-256 check.");
  ensureDirectories();
  const filePath = path.join(PAAS_BACKUPS_DIR, `${cleanId}.enc.bak`);
  fs.writeFileSync(filePath, enc, { mode: 0o600 });
  const record: BackupRecord = { ...meta, id: cleanId, appName: sanitizeSlug(meta.appName), filePath, offsiteKey: key };
  delete record.localPrunedAt;
  const state = loadState();
  state.backups = state.backups || {};
  state.backups[cleanId] = record;
  saveState(state);
  return record;
}

// Only removes local copies that are already off-site, so pruning never loses the last copy.
export function pruneLocalBackups(retentionDays = 7, now = Date.now()): { pruned: string[]; keptNotOffsite: number } {
  const state = loadState();
  const pruned: string[] = [];
  let keptNotOffsite = 0;
  for (const b of Object.values(state.backups || {})) {
    if (!fs.existsSync(b.filePath)) continue;
    if (now - new Date(b.createdAt).getTime() < retentionDays * 86400000) continue;
    if (!b.offsiteKey) {
      keptNotOffsite++;
      continue;
    }
    fs.rmSync(b.filePath, { force: true });
    b.localPrunedAt = new Date(now).toISOString();
    pruned.push(b.id);
  }
  saveState(state);
  return { pruned, keptNotOffsite };
}

// ---------------------------------------------------------------------------
// Nightly run and systemd timer
// ---------------------------------------------------------------------------

export async function runNightlyBackup(retentionDays = 7, opts: { ifDue?: boolean } = {}): Promise<Record<string, unknown>> {
  // The mark is written first, so a systemd timer and the dashboard never both run on the same day.
  const today = localDate(new Date());
  if (opts.ifDue && readNightlyMark()?.date === today) return { skipped: `already ran today (${today})` };
  const startedAt = new Date().toISOString();
  writeNightlyMark({ date: today, startedAt });
  const state = loadState();
  const created: string[] = [];
  const errors: string[] = [];
  const attempt = (label: string, fn: () => BackupRecord | BackupRecord[]) => {
    try {
      const r = fn();
      created.push(...(Array.isArray(r) ? r : [r]).map((x) => x.id));
    } catch (err) {
      errors.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  for (const db of Object.values(state.databases)) {
    if (db.engine === "postgres") attempt(`${db.appName} postgres`, () => backupDatabase(db.appName, "postgres"));
  }
  for (const app of Object.values(state.apps)) {
    if (!app.trashedAt) attempt(`${app.name} volumes`, () => backupAppVolumes(app.name));
  }
  const offsite = getOffsiteConfig() ? await syncOffsite() : "not configured: backups stay only on this server";
  const prune = getOffsiteConfig() ? pruneLocalBackups(retentionDays) : { pruned: [], keptNotOffsite: 0 };
  const offsiteState =
    typeof offsite === "string" ? "not-configured" : offsite.failed.length ? "failed" : "ok";
  const failures = [...errors, ...(typeof offsite === "string" ? [] : offsite.failed.map((f) => `${f.id}: ${f.error}`))];
  writeNightlyMark({ date: today, startedAt, finishedAt: new Date().toISOString(), created: created.length, errors: failures.slice(0, 20), offsite: offsiteState });
  if (failures.length) {
    await sendNotice(
      (lang) =>
        lang === "en"
          ? { title: "Nightly backup had errors", text: `⚠️ The nightly backup had ${failures.length} error(s). First: ${failures[0].slice(0, 300)}\nSee Databases → Backups on the dashboard.` }
          : { title: "Backup da noite com erros", text: `⚠️ O backup da noite teve ${failures.length} erro(s). Primeiro: ${failures[0].slice(0, 300)}\nVeja Bancos → Backups no painel.` },
      "backup.nightly",
      "backup"
    );
  }
  return { created, errors, offsite, prune };
}

export function installBackupTimer(hour = 3): { service: string; timer: string } {
  const unitDir = "/etc/systemd/system";
  const service = path.join(unitDir, "paasmcp-backup.service");
  const timer = path.join(unitDir, "paasmcp-backup.timer");
  const cli = path.resolve(process.argv[1]);
  fs.writeFileSync(
    service,
    `[Unit]\nDescription=PaaSMCP nightly backup\n\n[Service]\nType=oneshot\nEnvironment=PAASMCP_ROOT=${process.env.PAASMCP_ROOT || "/opt/homelab"}\nExecStart=${process.execPath} ${cli} backup nightly\n`
  );
  fs.writeFileSync(
    timer,
    `[Unit]\nDescription=Run PaaSMCP backup daily\n\n[Timer]\nOnCalendar=*-*-* ${String(hour).padStart(2, "0")}:00:00\nRandomizedDelaySec=15m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n`
  );
  execFileSync("systemctl", ["daemon-reload"]);
  execFileSync("systemctl", ["enable", "--now", "paasmcp-backup.timer"]);
  return { service, timer };
}
