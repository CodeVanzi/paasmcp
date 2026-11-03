import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  BackupRecord,
  DatabaseRecord,
  DOCKER_NETWORK,
  ensureDirectories,
  loadState,
  PAAS_BACKUPS_DIR,
  PAAS_DB_DIR,
  PAAS_REDIS_DIR,
  sanitizeSlug,
  saveState,
} from "./config.js";
import {
  encryptBinaryPayload,
  getSecrets,
  setSecretEntries,
} from "./vault.js";
import { readVerifiedBackup, restoreVolume } from "./backup.js";
import { imageFor } from "./updater.js";

function assertSafeSqlIdentifier(id: string): string {
  if (!/^[a-z0-9_]{1,63}$/.test(id)) {
    throw new Error(`Unsafe SQL identifier rejected: "${id}"`);
  }
  return id;
}

export function ensureDockerNetwork(): void {
  try {
    execFileSync("docker", ["network", "inspect", DOCKER_NETWORK], { stdio: "ignore" });
  } catch {
    execFileSync("docker", ["network", "create", DOCKER_NETWORK], { stdio: "ignore" });
  }
}

export function ensureSharedPostgresCluster(): { adminUser: string; adminPass: string } {
  ensureDockerNetwork();
  if (!fs.existsSync(PAAS_DB_DIR)) {
    fs.mkdirSync(PAAS_DB_DIR, { recursive: true, mode: 0o700 });
  }
  const sysSecrets = getSecrets("system");
  let adminPass = sysSecrets.POSTGRES_ROOT_PASSWORD;
  if (!adminPass) {
    adminPass = crypto.randomBytes(24).toString("hex");
    setSecretEntries("system", { POSTGRES_ROOT_PASSWORD: adminPass });
  }

  const envFile = path.join(PAAS_DB_DIR, ".env");
  fs.writeFileSync(envFile, `POSTGRES_PASSWORD=${adminPass}\n`, { mode: 0o600 });

  // Published on the Tailscale IP only when a mirror peer streams from this server (pg_hba still limits who).
  const mirrorBind = loadState().mirror?.bindIp;
  const composeFile = path.join(PAAS_DB_DIR, "compose.yaml");
  const composeContent = `services:
  postgres:
    image: ${imageFor("postgres")}
    container_name: paasmcp-postgres
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - POSTGRES_USER=paasmcp_admin
      - POSTGRES_DB=postgres
    ports:
      - "127.0.0.1:5432:5432"${mirrorBind ? `\n      - "${mirrorBind}:5432:5432"` : ""}
    volumes:
      - ./data:/var/lib/postgresql/data
    networks:
      - ${DOCKER_NETWORK}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U paasmcp_admin -d postgres"]
      interval: 5s
      timeout: 5s
      retries: 10

networks:
  ${DOCKER_NETWORK}:
    external: true
`;
  fs.writeFileSync(composeFile, composeContent, { mode: 0o600 });

  execFileSync("docker", ["compose", "-f", composeFile, "up", "-d"], {
    cwd: PAAS_DB_DIR,
    stdio: "pipe",
  });

  // Wait up to 30s for pg_isready
  for (let i = 0; i < 30; i++) {
    try {
      execFileSync(
        "docker",
        ["exec", "paasmcp-postgres", "pg_isready", "-U", "paasmcp_admin", "-d", "postgres"],
        { stdio: "ignore" }
      );
      break;
    } catch {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
    }
  }

  return { adminUser: "paasmcp_admin", adminPass };
}

export function ensureSharedRedisCluster(): { redisPass: string } {
  ensureDockerNetwork();
  if (!fs.existsSync(PAAS_REDIS_DIR)) {
    fs.mkdirSync(PAAS_REDIS_DIR, { recursive: true, mode: 0o700 });
  }
  const sysSecrets = getSecrets("system");
  let redisPass = sysSecrets.REDIS_ROOT_PASSWORD;
  if (!redisPass) {
    redisPass = crypto.randomBytes(24).toString("hex");
    setSecretEntries("system", { REDIS_ROOT_PASSWORD: redisPass });
  }

  const composeFile = path.join(PAAS_REDIS_DIR, "compose.yaml");
  const composeContent = `services:
  redis:
    image: ${imageFor("redis")}
    container_name: paasmcp-redis
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes", "--requirepass", "${redisPass}"]
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - ./data:/data
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`;
  fs.writeFileSync(composeFile, composeContent, { mode: 0o600 });

  execFileSync("docker", ["compose", "-f", composeFile, "up", "-d"], {
    cwd: PAAS_REDIS_DIR,
    stdio: "pipe",
  });

  return { redisPass };
}

export function provisionDatabase(
  appName: string,
  engine: "postgres" | "redis" = "postgres"
): {
  record: DatabaseRecord;
  injectedKeys: string[];
} {
  const slug = sanitizeSlug(appName);
  const dbIdentifier = assertSafeSqlIdentifier(slug.replace(/-/g, "_"));
  const state = loadState();

  if (engine === "postgres") {
    ensureSharedPostgresCluster();
    const dbName = assertSafeSqlIdentifier(`db_${dbIdentifier}`);
    const dbUser = assertSafeSqlIdentifier(`user_${dbIdentifier}`);
    const dbPass = crypto.randomBytes(20).toString("hex");

    // Create or update role and database idempotently
    const roleSql = `DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${dbUser}') THEN
    CREATE ROLE ${dbUser} WITH LOGIN PASSWORD '${dbPass}';
  ELSE
    ALTER ROLE ${dbUser} WITH LOGIN PASSWORD '${dbPass}';
  END IF;
END
$$;`;
    execFileSync(
      "docker",
      ["exec", "paasmcp-postgres", "psql", "-U", "paasmcp_admin", "-d", "postgres", "-c", roleSql],
      { stdio: "pipe" }
    );

    const existsOut = execFileSync(
      "docker",
      [
        "exec",
        "paasmcp-postgres",
        "psql",
        "-U",
        "paasmcp_admin",
        "-d",
        "postgres",
        "-tAc",
        `SELECT 1 FROM pg_database WHERE datname='${dbName}'`,
      ],
      { encoding: "utf-8" }
    ).trim();

    if (existsOut !== "1") {
      execFileSync(
        "docker",
        [
          "exec",
          "paasmcp-postgres",
          "psql",
          "-U",
          "paasmcp_admin",
          "-d",
          "postgres",
          "-c",
          `CREATE DATABASE ${dbName} OWNER ${dbUser};`,
        ],
        { stdio: "pipe" }
      );
    }

    execFileSync(
      "docker",
      [
        "exec",
        "paasmcp-postgres",
        "psql",
        "-U",
        "paasmcp_admin",
        "-d",
        dbName,
        "-c",
        `GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${dbUser}; GRANT ALL ON SCHEMA public TO ${dbUser};`,
      ],
      { stdio: "pipe" }
    );

    const internalUrl = `postgresql://${dbUser}:${dbPass}@paasmcp-postgres:5432/${dbName}`;
    const localUrl = `postgresql://${dbUser}:${dbPass}@127.0.0.1:5432/${dbName}`;

    const injectedKeys = setSecretEntries(slug, {
      DATABASE_URL: internalUrl,
      POSTGRES_URL: internalUrl,
      LOCAL_DATABASE_URL: localUrl,
    });

    const record: DatabaseRecord = {
      name: `${slug}-postgres`,
      engine: "postgres",
      mode: "shared",
      appName: slug,
      dbName,
      dbUser,
      host: "paasmcp-postgres",
      port: 5432,
      localPort: 5432,
      createdAt: new Date().toISOString(),
    };

    state.databases[record.name] = record;
    if (state.apps[slug] && !state.apps[slug].databases.includes(record.name)) {
      state.apps[slug].databases.push(record.name);
    }
    saveState(state);

    return { record, injectedKeys };
  } else {
    const { redisPass } = ensureSharedRedisCluster();
    const existingRedisCount = Object.values(state.databases).filter(
      (d) => d.engine === "redis"
    ).length;
    const dbIndex = (existingRedisCount % 15) + 1;
    const internalUrl = `redis://:${redisPass}@paasmcp-redis:6379/${dbIndex}`;
    const localUrl = `redis://:${redisPass}@127.0.0.1:6379/${dbIndex}`;

    const injectedKeys = setSecretEntries(slug, {
      REDIS_URL: internalUrl,
      LOCAL_REDIS_URL: localUrl,
    });

    const record: DatabaseRecord = {
      name: `${slug}-redis`,
      engine: "redis",
      mode: "shared",
      appName: slug,
      dbName: `db${dbIndex}`,
      dbUser: "default",
      host: "paasmcp-redis",
      port: 6379,
      localPort: 6379,
      createdAt: new Date().toISOString(),
    };

    state.databases[record.name] = record;
    if (state.apps[slug] && !state.apps[slug].databases.includes(record.name)) {
      state.apps[slug].databases.push(record.name);
    }
    saveState(state);

    return { record, injectedKeys };
  }
}

export function listDatabaseBackups(appName?: string): BackupRecord[] {
  const state = loadState();
  const all = Object.values(state.backups || {});
  const filtered = appName
    ? all.filter((b) => b.appName === sanitizeSlug(appName))
    : all;
  return filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function backupDatabase(
  appName: string,
  engine: "postgres" | "redis" = "postgres"
): BackupRecord {
  ensureDirectories();
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const dbRecordName = `${slug}-${engine}`;
  const dbRecord = state.databases[dbRecordName];

  if (!dbRecord) {
    throw new Error(
      `Database '${dbRecordName}' not found in PaaSMCP state. Provision it first via paas_db_provision.`
    );
  }

  let rawDump: Buffer;
  if (process.env.PAASMCP_OFFLINE_TEST === "1") {
    rawDump = Buffer.from(
      `-- PaaSMCP Synthetic Dump for ${dbRecord.dbName} (${engine}) at ${new Date().toISOString()}\nSELECT 1;\n`,
      "utf-8"
    );
  } else if (engine === "postgres") {
    const safeDbName = assertSafeSqlIdentifier(dbRecord.dbName);
    rawDump = execFileSync(
      "docker",
      [
        "exec",
        "paasmcp-postgres",
        "pg_dump",
        "-U",
        "paasmcp_admin",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        safeDbName,
      ],
      { stdio: ["ignore", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024 }
    );
  } else {
    const sysSecrets = getSecrets("system");
    const redisPass = sysSecrets.REDIS_ROOT_PASSWORD || "";
    execFileSync(
      "docker",
      ["exec", "paasmcp-redis", "redis-cli", "-a", redisPass, "SAVE"],
      { stdio: "ignore" }
    );
    rawDump = execFileSync(
      "docker",
      ["exec", "paasmcp-redis", "cat", "/data/dump.rdb"],
      { stdio: ["ignore", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024 }
    );
  }

  const encryptedBuf = encryptBinaryPayload(rawDump);
  const sha256 = crypto.createHash("sha256").update(encryptedBuf).digest("hex");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupId = `${slug}-${engine}-${timestamp}`;
  const filePath = path.join(PAAS_BACKUPS_DIR, `${backupId}.enc.bak`);

  fs.writeFileSync(filePath, encryptedBuf, { mode: 0o600 });

  const backupRecord: BackupRecord = {
    id: backupId,
    appName: slug,
    databaseName: dbRecord.dbName,
    engine,
    filePath,
    sizeBytes: encryptedBuf.length,
    sha256,
    encrypted: true,
    createdAt: new Date().toISOString(),
  };

  if (!state.backups) state.backups = {};
  state.backups[backupId] = backupRecord;
  saveState(state);

  return backupRecord;
}

export function restoreDatabase(backupId: string): {
  restored: boolean;
  backup: BackupRecord;
  restoredBytes: number;
  safetyBackupId?: string;
} {
  ensureDirectories();
  const { backup, plain: decryptedDump } = readVerifiedBackup(backupId);
  if (backup.engine === "volume") {
    return { restored: true, backup, restoredBytes: decryptedDump.length, ...restoreVolume(backup, decryptedDump) };
  }

  let safetyBackupId: string | undefined;
  if (process.env.PAASMCP_OFFLINE_TEST !== "1") {
    if (backup.engine === "postgres") {
      // Never skippable: snapshot the current state so a wrong restore can be undone.
      safetyBackupId = backupDatabase(backup.appName, "postgres").id;
      const safeDbName = assertSafeSqlIdentifier(backup.databaseName);
      execFileSync(
        "docker",
        ["exec", "-i", "paasmcp-postgres", "psql", "-U", "paasmcp_admin", "-d", safeDbName],
        {
          input: decryptedDump,
          stdio: ["pipe", "pipe", "pipe"],
          maxBuffer: 256 * 1024 * 1024,
        }
      );
    } else {
      throw new Error(
        "Live Redis binary RDB restore requires stopping the shared Redis cluster; use PostgreSQL logical restore or export decrypted RDB manually."
      );
    }
  }

  return {
    restored: true,
    backup,
    restoredBytes: decryptedDump.length,
    safetyBackupId,
  };
}
