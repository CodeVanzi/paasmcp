import { execFile, spawn } from "node:child_process";
import { Transform } from "node:stream";
import { loadState, sanitizeSlug } from "./config.js";
import { backupDatabase } from "./database.js";
import { imageFor } from "./updater.js";

/**
 * Brings the data of a PostgreSQL database that lives elsewhere (Render, Neon, Supabase, Railway, another
 * server) into the app's database here. Only the `public` schema travels (where Django, Rails, Prisma and
 * most frameworks keep their tables); objects come out owned by the app's own user, so its migrations keep
 * working. The copy runs in one transaction: if anything fails, the database here stays as it was. A backup
 * of the current state is taken first anyway.
 *
 * The source address carries a password: it goes to the dump container as PG* environment variables
 * (never as a command argument, which `ps` would show) and is never written to disk, the state or the audit.
 */

export interface PgSource {
  host: string;
  port: string;
  user: string;
  password: string;
  database: string;
  sslmode: string;
}

const SSL_MODES = new Set(["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]);

/** Reads a postgres:// address. Throws in plain words, never repeating the address (it holds a password). */
export function parsePostgresUrl(raw: string): PgSource {
  const text = String(raw || "").trim();
  if (!text) throw new Error("Paste the address of the database to copy from (postgres://...).");
  if (text.length > 2048 || /[\s\0]/.test(text)) throw new Error("The address has spaces or line breaks; paste only the postgres://... address.");
  let u: URL;
  try {
    u = new URL(text);
  } catch {
    throw new Error("This does not look like a database address. It starts with postgres:// or postgresql://.");
  }
  if (u.protocol !== "postgres:" && u.protocol !== "postgresql:") {
    throw new Error("Only PostgreSQL addresses (postgres:// or postgresql://) can be imported.");
  }
  if (!u.hostname) throw new Error("The address has no server name.");
  const database = decodeURIComponent(u.pathname.replace(/^\//, ""));
  if (!database || database.includes("/")) throw new Error("The address has no database name at the end (…/name).");
  if (!u.username) throw new Error("The address has no user (postgres://user:password@…).");
  const sslmode = (u.searchParams.get("sslmode") || "prefer").toLowerCase();
  if (!SSL_MODES.has(sslmode)) throw new Error("Unknown sslmode in the address.");
  const port = u.port || "5432";
  if (!/^\d{1,5}$/.test(port)) throw new Error("Invalid port in the address.");
  return {
    host: u.hostname.replace(/^\[|\]$/g, ""),
    port,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database,
    sslmode,
  };
}

/** The PG* variables libpq reads, so nothing secret goes on a command line. */
export function pgEnv(src: PgSource): Record<string, string> {
  return {
    PGHOST: src.host,
    PGPORT: src.port,
    PGUSER: src.user,
    PGPASSWORD: src.password,
    PGDATABASE: src.database,
    PGSSLMODE: src.sslmode,
    PGCONNECT_TIMEOUT: "15",
  };
}

const PG_ENV_NAMES = ["PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE", "PGCONNECT_TIMEOUT"];

/** `docker run` arguments that pass the PG* variables by name only (the value comes from our environment). */
function envFlags(): string[] {
  return PG_ENV_NAMES.flatMap((n) => ["-e", n]);
}

/** pg_dump must be at least as new as the source server: 16 for older ones, the source's own version above. */
export function dumpImageFor(serverVersionNum: number): string {
  const major = Math.floor(serverVersionNum / 10000);
  if (!Number.isFinite(major) || major < 10) throw new Error("The source server's PostgreSQL version is too old to import (10 or newer).");
  if (major > 18) throw new Error(`The source server runs PostgreSQL ${major}, newer than this import knows (up to 18).`);
  return major <= 16 ? imageFor("postgres") : `postgres:${major}-alpine`;
}

/**
 * Lines of a plain dump that the app's user cannot run here, or that a 16 server does not know.
 * The `public` schema already exists and belongs to the database; a newer pg_dump adds settings 16 lacks.
 */
const DROPPED_LINE = /^(SET transaction_timeout = |COMMENT ON SCHEMA public IS |ALTER SCHEMA public OWNER TO |CREATE SCHEMA public;|DROP SCHEMA IF EXISTS public;|DROP SCHEMA public;)/;

/** Streams a dump through, dropping the lines above (whole lines only; chunks may split a line). */
export function dumpFilter(): Transform {
  let rest = "";
  return new Transform({
    transform(chunk, _enc, done) {
      const text = rest + chunk.toString("utf-8");
      const lines = text.split("\n");
      rest = lines.pop() ?? "";
      done(null, lines.filter((l) => !DROPPED_LINE.test(l)).map((l) => l + "\n").join(""));
    },
    flush(done) {
      done(null, rest && !DROPPED_LINE.test(rest) ? rest : "");
    },
  });
}

/** Keeps the end of an error output, without anything that looks like an address with a password. */
function tailOf(text: string, src?: PgSource): string {
  let t = text.slice(-1500);
  t = t.replace(/postgres(ql)?:\/\/[^\s]+/gi, "postgres://…");
  if (src?.password) t = t.split(src.password).join("…");
  return t.trim();
}

function run(cmd: string, args: string[], env: Record<string, string>, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { env: { ...process.env, ...env }, timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(Object.assign(new Error(String(stderr || err.message)), { stderr: String(stderr || "") }));
      else resolve(String(stdout));
    });
  });
}

export interface ImportResult {
  app: string;
  database: string;
  sourceVersion: string;
  safetyBackupId: string;
  tables: number;
  seconds: number;
}

/** Copies the source's `public` schema over the app's database here, in one transaction. */
export async function importExternalPostgres(appName: string, sourceUrl: string, opts: { timeoutMs?: number } = {}): Promise<ImportResult> {
  const slug = sanitizeSlug(appName);
  const record = loadState().databases[`${slug}-postgres`];
  if (!record) {
    throw new Error(`App '${slug}' has no PostgreSQL database here yet. Tick PostgreSQL when publishing it, or create one under Databases, then import.`);
  }
  if (!/^[a-z0-9_]{1,63}$/.test(record.dbName) || !/^[a-z0-9_]{1,63}$/.test(record.dbUser)) {
    throw new Error("Unexpected database name in the state.");
  }
  const src = parsePostgresUrl(sourceUrl);
  const env = pgEnv(src);
  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? 30 * 60_000;

  // 1. Reach the source and learn its version (it decides which pg_dump can read it).
  let versionNum: number;
  let versionText: string;
  try {
    const out = await run("docker", ["run", "--rm", ...envFlags(), imageFor("postgres"), "psql", "-XAtq", "-c", "SHOW server_version_num", "-c", "SHOW server_version"], env, 3 * 60_000);
    const [num, text] = out.trim().split("\n");
    versionNum = Number(num);
    versionText = String(text || "").split(" ")[0];
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    throw new Error(`Could not connect to the source database: ${tailOf(e.stderr || e.message || "", src)}`);
  }
  const dumpImage = dumpImageFor(versionNum);

  // 2. A backup of what is here now, so the import can be undone from Backups.
  const safetyBackupId = backupDatabase(slug, "postgres").id;

  // 3. pg_dump there | filter | psql here, as the app's own user, all or nothing.
  await new Promise<void>((resolve, reject) => {
    const dump = spawn("docker", ["run", "--rm", ...envFlags(), dumpImage, "pg_dump", "--schema=public", "--clean", "--if-exists", "--no-owner", "--no-privileges", "--format=plain"], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const load = spawn("docker", ["exec", "-i", "paasmcp-postgres", "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-U", record.dbUser, "-d", record.dbName], {
      stdio: ["pipe", "ignore", "pipe"],
    });
    let dumpErr = "";
    let loadErr = "";
    let dumpCode: number | null = null;
    let loadCode: number | null = null;
    let settled = false;
    const finish = (err?: Error) => {
      if (settled) return;
      if (err) {
        settled = true;
        clearTimeout(timer);
        dump.kill();
        load.kill();
        reject(err);
        return;
      }
      if (dumpCode === null || loadCode === null) return;
      settled = true;
      clearTimeout(timer);
      if (dumpCode !== 0) reject(new Error(`Reading the source database failed: ${tailOf(dumpErr, src)}`));
      else if (loadCode !== 0) reject(new Error(`Writing here failed, nothing was changed: ${tailOf(loadErr, src)}`));
      else resolve();
    };
    const timer = setTimeout(() => finish(new Error(`The import took longer than ${Math.round(timeoutMs / 60000)} minutes and was stopped; nothing was changed.`)), timeoutMs);
    dump.stderr.on("data", (d) => { dumpErr = (dumpErr + d).slice(-8000); });
    load.stderr.on("data", (d) => { loadErr = (loadErr + d).slice(-8000); });
    dump.on("error", (e) => finish(e));
    load.on("error", (e) => finish(e));
    load.stdin.on("error", () => { /* psql stopped early: its exit code tells why */ });
    dump.stdout.pipe(dumpFilter()).pipe(load.stdin);
    dump.on("close", (code) => { dumpCode = code ?? 1; if (code !== 0) load.kill(); finish(); });
    load.on("close", (code) => { loadCode = code ?? 1; finish(); });
  });

  // 4. How many tables arrived (shown to the person as a sanity check).
  let tables = 0;
  try {
    const out = await run("docker", ["exec", "paasmcp-postgres", "psql", "-XAtq", "-U", record.dbUser, "-d", record.dbName, "-c", "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"], {}, 60_000);
    tables = Number(out.trim()) || 0;
  } catch {
    /* the count is only informative */
  }

  return {
    app: slug,
    database: record.dbName,
    sourceVersion: versionText || String(Math.floor(versionNum / 10000)),
    safetyBackupId,
    tables,
    seconds: Math.round((Date.now() - started) / 1000),
  };
}
