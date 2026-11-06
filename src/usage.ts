import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  DatabaseRecord,
  loadState,
  PAAS_APPS_DIR,
  PAAS_BACKUPS_DIR,
  PAAS_DATA_DIR,
  PAAS_DB_DIR,
  PAAS_REDIS_DIR,
  PAAS_TRASH_DIR,
  sanitizeSlug,
  saveState,
  writeFileAtomic,
} from "./config.js";
import { sendNotice } from "./notify.js";
import { parseDockerSize } from "./scale.js";
import { PAAS_GARAGE_DIR } from "./storage.js";
import { getSecrets } from "./vault.js";

/**
 * Disk split and database sizes for the dashboard (Resource usage card, Databases page).
 *
 * Measuring the disk walks folders (du) and asks Docker for volume and image sizes, which takes a
 * while on a big server, so the dashboard does it in the background every 10 minutes and keeps the
 * last result in `usage/latest.json`. Database sizes go to `usage/db-history.ndjson` once an hour
 * (90 days), for the growth charts. A database can have a warning size: a notice at 80% and 100%.
 */

export const USAGE_DIR = path.join(PAAS_DATA_DIR, "usage");
const LATEST_PATH = path.join(USAGE_DIR, "latest.json");
const HISTORY_PATH = path.join(USAGE_DIR, "db-history.ndjson");
const WARNED_PATH = path.join(USAGE_DIR, "db-warned.json");
export const HISTORY_DAYS = 90;
const HOUR = 3600 * 1000;
const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

export interface DiskParts {
  /** Code folders, app volumes and app images (paasmcp/<app>, the part no other image shares). */
  apps: number;
  /** Shared Postgres and Redis data folders. */
  databases: number;
  /** Encrypted backups and the trash. */
  backups: number;
  /** App files (Garage). */
  files: number;
}

export interface DbSize {
  name: string;
  engine: "postgres" | "redis";
  appName: string;
  /** Postgres: pg_database_size. Redis has no size per database: null. */
  bytes: number | null;
  /** Redis: keys in this logical database. */
  keys?: number;
}

export interface UsageSnapshot {
  measuredAt: string;
  disk: { parts: DiskParts; perApp: Record<string, number> } | null;
  databases: DbSize[];
  /** Redis as a whole (memory it holds), when it runs. */
  redis?: { usedMemoryBytes: number } | null;
}

function run(cmd: string, args: string[], input?: string, timeout = 120_000): Promise<string> {
  return new Promise((resolve) => {
    const child = execFile(cmd, args, { encoding: "utf-8", timeout, maxBuffer: 16 * 1024 * 1024 }, (_err, stdout) =>
      // du exits 1 when a folder can't be read but still prints what it could: keep the output.
      resolve(String(stdout || ""))
    );
    if (input !== undefined) {
      child.stdin?.end(input);
    }
  });
}

/** `du -k -x -d 1 <dir>` → total and each child folder, in bytes. */
export function parseDuDepth1(out: string, dir: string): { total: number; children: Record<string, number> } {
  const children: Record<string, number> = {};
  let total = 0;
  const root = path.resolve(dir);
  for (const line of out.split("\n")) {
    const m = /^(\d+)\s+(.+)$/.exec(line.trim());
    if (!m) continue;
    const bytes = Number(m[1]) * 1024;
    const p = path.resolve(m[2]);
    if (p === root) total = bytes;
    else if (path.dirname(p) === root) children[path.basename(p)] = bytes;
  }
  return { total, children };
}

async function duDepth1(dir: string): Promise<{ total: number; children: Record<string, number> }> {
  if (!fs.existsSync(dir)) return { total: 0, children: {} };
  return parseDuDepth1(await run("du", ["-k", "-x", "-d", "1", dir]), dir);
}

async function duTotal(dir: string): Promise<number> {
  return (await duDepth1(dir)).total;
}

/** App volumes and images from `docker system df -v`: bytes per app slug. */
export function dockerBytesPerApp(dfJson: string, slugs: Set<string>): Record<string, number> {
  const per: Record<string, number> = {};
  let d: { Images?: { Repository?: string; UniqueSize?: string }[]; Volumes?: { Labels?: string; Size?: string }[] };
  try {
    d = JSON.parse(dfJson);
  } catch {
    return per;
  }
  for (const img of d.Images || []) {
    const m = /^paasmcp\/([a-z0-9-]+)$/.exec(String(img.Repository || ""));
    if (!m || !slugs.has(m[1])) continue;
    per[m[1]] = (per[m[1]] || 0) + (parseDockerSize(String(img.UniqueSize || "")) || 0);
  }
  for (const v of d.Volumes || []) {
    const m = /(?:^|,)com\.docker\.compose\.project=([a-z0-9-]+)(?:,|$)/.exec(String(v.Labels || ""));
    if (!m || !slugs.has(m[1])) continue;
    per[m[1]] = (per[m[1]] || 0) + (parseDockerSize(String(v.Size || "")) || 0);
  }
  return per;
}

/** `datname|bytes` lines from psql -tA. */
export function parsePgSizes(out: string): Record<string, number> {
  const sizes: Record<string, number> = {};
  for (const line of out.split("\n")) {
    const [name, bytes] = line.trim().split("|");
    if (name && /^\d+$/.test(bytes || "")) sizes[name] = Number(bytes);
  }
  return sizes;
}

/** Keys per logical database and memory held, from redis-cli INFO output. */
export function parseRedisInfo(out: string): { keys: Record<string, number>; usedMemoryBytes: number | null } {
  const keys: Record<string, number> = {};
  for (const m of out.matchAll(/^(db\d+):keys=(\d+)/gm)) keys[m[1]] = Number(m[2]);
  const mem = /^used_memory:(\d+)/m.exec(out);
  return { keys, usedMemoryBytes: mem ? Number(mem[1]) : null };
}

async function measureDatabases(dbs: DatabaseRecord[]): Promise<{ list: DbSize[]; redis: UsageSnapshot["redis"] }> {
  const pg = dbs.filter((d) => d.engine === "postgres");
  const rd = dbs.filter((d) => d.engine === "redis");
  let pgSizes: Record<string, number> = {};
  let redis: UsageSnapshot["redis"] = null;
  let redisKeys: Record<string, number> = {};
  if (!OFFLINE() && pg.length) {
    pgSizes = parsePgSizes(
      await run("docker", [
        "exec", "paasmcp-postgres", "psql", "-U", "paasmcp_admin", "-d", "postgres", "-tAc",
        "SELECT datname, pg_database_size(datname) FROM pg_database WHERE NOT datistemplate",
      ], undefined, 30_000)
    );
  }
  const pass = rd.length && !OFFLINE() ? getSecrets("system").REDIS_ROOT_PASSWORD : "";
  if (pass) {
    // The password goes through stdin (AUTH), never on a command line other users could read.
    const info = parseRedisInfo(await run("docker", ["exec", "-i", "paasmcp-redis", "redis-cli"], `AUTH ${pass}\nINFO keyspace\nINFO memory\n`, 30_000));
    redisKeys = info.keys;
    redis = info.usedMemoryBytes === null ? null : { usedMemoryBytes: info.usedMemoryBytes };
  }
  const list: DbSize[] = [
    ...pg.map((d) => ({ name: d.name, engine: d.engine, appName: d.appName, bytes: pgSizes[d.dbName] ?? null })),
    ...rd.map((d) => ({ name: d.name, engine: d.engine, appName: d.appName, bytes: null, keys: redisKeys[d.dbName] ?? 0 })),
  ];
  return { list, redis };
}

/** One full measurement (async, can take a while). */
export async function measureUsage(): Promise<UsageSnapshot> {
  const state = loadState();
  const slugs = new Set(Object.keys(state.apps).filter((k) => k !== "paasmcp-dashboard"));
  const dbs = await measureDatabases(Object.values(state.databases || {}));
  if (OFFLINE()) return { measuredAt: new Date().toISOString(), disk: null, databases: dbs.list, redis: dbs.redis };

  const [apps, pgDir, redisDir, backups, trash, garage, dfJson] = await Promise.all([
    duDepth1(PAAS_APPS_DIR),
    duTotal(PAAS_DB_DIR),
    duTotal(PAAS_REDIS_DIR),
    duTotal(PAAS_BACKUPS_DIR),
    duTotal(PAAS_TRASH_DIR),
    duTotal(PAAS_GARAGE_DIR),
    run("docker", ["system", "df", "-v", "--format", "{{json .}}"]),
  ]);
  const docker = dockerBytesPerApp(dfJson, slugs);
  const perApp: Record<string, number> = {};
  for (const slug of slugs) {
    const pgBytes = dbs.list
      .filter((d) => d.appName === slug && d.engine === "postgres")
      .reduce((n, d) => n + (d.bytes || 0), 0);
    perApp[slug] = (apps.children[slug] || 0) + (docker[slug] || 0) + pgBytes;
  }
  const dockerTotal = Object.values(docker).reduce((a, b) => a + b, 0);
  return {
    measuredAt: new Date().toISOString(),
    disk: {
      parts: {
        apps: apps.total + dockerTotal,
        databases: pgDir + redisDir,
        backups: backups + trash,
        files: garage,
      },
      perApp,
    },
    databases: dbs.list,
    redis: dbs.redis,
  };
}

export function readLatestUsage(): UsageSnapshot | null {
  try {
    return JSON.parse(fs.readFileSync(LATEST_PATH, "utf-8")) as UsageSnapshot;
  } catch {
    return null;
  }
}

export type HistoryPoint = { t: number; s: Record<string, number> };

export function readDbHistory(now = Date.now()): HistoryPoint[] {
  let text = "";
  try {
    text = fs.readFileSync(HISTORY_PATH, "utf-8");
  } catch {
    return [];
  }
  const from = now - HISTORY_DAYS * 24 * HOUR;
  const out: HistoryPoint[] = [];
  for (const line of text.split("\n")) {
    try {
      const p = JSON.parse(line) as HistoryPoint;
      if (typeof p.t === "number" && p.t >= from && p.s && typeof p.s === "object") out.push(p);
    } catch {
      // ignore a torn line
    }
  }
  return out;
}

/** Adds one point when the last is at least an hour old; drops points older than 90 days. */
export function appendDbHistory(sizes: DbSize[], now = Date.now()): boolean {
  const s: Record<string, number> = {};
  for (const d of sizes) if (d.bytes !== null) s[d.name] = d.bytes;
  if (!Object.keys(s).length) return false;
  const points = readDbHistory(now);
  const last = points[points.length - 1];
  if (last && now - last.t < HOUR - 60_000) return false;
  points.push({ t: now, s });
  fs.mkdirSync(USAGE_DIR, { recursive: true, mode: 0o700 });
  writeFileAtomic(HISTORY_PATH, points.map((p) => JSON.stringify(p)).join("\n") + "\n");
  return true;
}

/** 0, 80 or 100: how far a database is into its warning size. */
export function limitLevel(bytes: number | null, warnSizeMb?: number): 0 | 80 | 100 {
  if (bytes === null || !warnSizeMb) return 0;
  const limit = warnSizeMb * 1e6;
  return bytes >= limit ? 100 : bytes >= limit * 0.8 ? 80 : 0;
}

/** Which databases crossed a new level since the last round (a level that drops resets, so it warns again). */
export function limitEvents(
  sizes: DbSize[],
  dbs: Record<string, Pick<DatabaseRecord, "warnSizeMb">>,
  warned: Record<string, number>
): { events: { name: string; level: 80 | 100; bytes: number; limitMb: number }[]; warned: Record<string, number> } {
  const next: Record<string, number> = {};
  const events: { name: string; level: 80 | 100; bytes: number; limitMb: number }[] = [];
  for (const d of sizes) {
    const limitMb = dbs[d.name]?.warnSizeMb;
    const level = limitLevel(d.bytes, limitMb);
    if (level) next[d.name] = level;
    if (level && level > (warned[d.name] || 0)) events.push({ name: d.name, level, bytes: d.bytes as number, limitMb: limitMb as number });
  }
  return { events, warned: next };
}

export function limitNoticeText(e: { name: string; level: 80 | 100; bytes: number; limitMb: number }, lang: "pt" | "en"): { title: string; text: string } {
  const mb = Math.round(e.bytes / 1e6);
  if (lang === "en") {
    return e.level === 100
      ? { title: `${e.name}: over its size`, text: `🗄️ Database ${e.name} has ${mb} MB, past the ${e.limitMb} MB you set. The app keeps working; raise the size or clean up in the dashboard (Databases).` }
      : { title: `${e.name}: 80% of its size`, text: `🗄️ Database ${e.name} has ${mb} MB, 80% of the ${e.limitMb} MB you set.` };
  }
  return e.level === 100
    ? { title: `${e.name}: passou do tamanho`, text: `🗄️ O banco ${e.name} tem ${mb} MB, mais que os ${e.limitMb} MB que você definiu. O app continua funcionando; aumente o tamanho ou faça uma limpeza (painel → Bancos).` }
    : { title: `${e.name}: 80% do tamanho`, text: `🗄️ O banco ${e.name} tem ${mb} MB, 80% dos ${e.limitMb} MB que você definiu.` };
}

function readWarned(): Record<string, number> {
  try {
    return JSON.parse(fs.readFileSync(WARNED_PATH, "utf-8")) as Record<string, number>;
  } catch {
    return {};
  }
}

/** Sets (or clears, with null) a database's warning size in MB. The caller holds the state lock. */
export function setDatabaseLimit(name: string, sizeMb: number | null): DatabaseRecord {
  if (sizeMb !== null && (!Number.isInteger(sizeMb) || sizeMb < 1 || sizeMb > 10_000_000)) {
    throw new Error("The size must be a whole number of MB between 1 and 10000000.");
  }
  const state = loadState();
  const rec = Object.prototype.hasOwnProperty.call(state.databases, name) ? state.databases[name] : undefined;
  if (!rec) throw new Error(`Database '${sanitizeSlug(String(name))}' not found.`);
  if (rec.engine !== "postgres") throw new Error("Only Postgres databases have a size per database.");
  if (sizeMb === null) delete rec.warnSizeMb;
  else rec.warnSizeMb = sizeMb;
  saveState(state);
  return rec;
}

/** One measurement round: latest.json, hourly history, size notices. */
export async function usageRound(): Promise<UsageSnapshot> {
  const snap = await measureUsage();
  fs.mkdirSync(USAGE_DIR, { recursive: true, mode: 0o700 });
  writeFileAtomic(LATEST_PATH, JSON.stringify(snap));
  appendDbHistory(snap.databases);
  const { events, warned } = limitEvents(snap.databases, loadState().databases || {}, readWarned());
  writeFileAtomic(WARNED_PATH, JSON.stringify(warned));
  for (const e of events) void sendNotice((lang) => limitNoticeText(e, lang), `db.size${e.level}`, e.name);
  return snap;
}

let roundBusy: Promise<UsageSnapshot> | null = null;
/** Runs a round unless one is already running (then waits for that one). */
export function usageRoundOnce(): Promise<UsageSnapshot> {
  if (!roundBusy) roundBusy = usageRound().finally(() => (roundBusy = null));
  return roundBusy;
}

export function startUsageLoop(): () => void {
  if (process.env.PAASMCP_USAGE === "0") return () => {};
  const tick = () => void usageRoundOnce().catch(() => undefined);
  const first = setTimeout(tick, 20_000);
  const timer = setInterval(tick, 10 * 60 * 1000);
  first.unref();
  timer.unref();
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}
