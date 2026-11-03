import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DOCKER_NETWORK, HOMELAB_ROOT, loadState, sanitizeSlug, saveState, StorageRecord } from "./config.js";
import { ensureDockerNetwork } from "./database.js";
import { getSecrets, setSecretEntries } from "./vault.js";

// Pinned on purpose: the updater (plan item 8) moves it, never a floating tag.
export const GARAGE_IMAGE = "dxflrs/garage:v1.1.0";
export const PAAS_GARAGE_DIR = path.join(HOMELAB_ROOT, "paasmcp-garage");
export const GARAGE_INTERNAL_ENDPOINT = "http://paasmcp-garage:3900";
export const GARAGE_REGION = "garage";
const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
const adminUrl = () => process.env.PAASMCP_GARAGE_ADMIN_URL || "http://127.0.0.1:3903";

function garageSecrets(): { rpcSecret: string; adminToken: string } {
  const sys = getSecrets("system");
  const rpcSecret = sys.GARAGE_RPC_SECRET || crypto.randomBytes(32).toString("hex");
  const adminToken = sys.GARAGE_ADMIN_TOKEN || crypto.randomBytes(32).toString("base64url");
  if (!sys.GARAGE_RPC_SECRET || !sys.GARAGE_ADMIN_TOKEN) {
    setSecretEntries("system", { GARAGE_RPC_SECRET: rpcSecret, GARAGE_ADMIN_TOKEN: adminToken });
  }
  return { rpcSecret, adminToken };
}

async function admin<T = any>(method: string, route: string, body?: unknown): Promise<T> {
  const res = await fetch(`${adminUrl()}${route}`, {
    method,
    headers: { Authorization: `Bearer ${garageSecrets().adminToken}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Garage admin ${method} ${route}: HTTP ${res.status} ${text.slice(0, 300)}`);
  return (text ? JSON.parse(text) : {}) as T;
}

export async function ensureGarage(capacityGb = Number(process.env.PAASMCP_GARAGE_CAPACITY_GB || 100)): Promise<void> {
  const { rpcSecret, adminToken } = garageSecrets();
  if (!OFFLINE()) {
    ensureDockerNetwork();
    fs.mkdirSync(PAAS_GARAGE_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(PAAS_GARAGE_DIR, "garage.toml"),
      `metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "${rpcSecret}"

[s3_api]
s3_region = "${GARAGE_REGION}"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "${adminToken}"
`,
      { mode: 0o600 }
    );
    const composeFile = path.join(PAAS_GARAGE_DIR, "compose.yaml");
    fs.writeFileSync(
      composeFile,
      `services:
  garage:
    image: ${GARAGE_IMAGE}
    container_name: paasmcp-garage
    restart: unless-stopped
    ports:
      - "127.0.0.1:3900:3900"
      - "127.0.0.1:3903:3903"
    volumes:
      - ./garage.toml:/etc/garage.toml:ro
      - ./meta:/var/lib/garage/meta
      - ./data:/var/lib/garage/data
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`,
      { mode: 0o600 }
    );
    execFileSync("docker", ["compose", "-f", composeFile, "up", "-d"], { cwd: PAAS_GARAGE_DIR, stdio: "pipe" });
  }

  let status: { node: string } | undefined;
  for (let i = 0; i < 30 && !status; i++) {
    try {
      status = await admin("GET", "/v1/status");
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  if (!status) throw new Error("Garage did not answer on its admin API within 30s (see 'docker logs paasmcp-garage').");

  // A fresh node has no layout; give this server one zone. The mirror (plan item 5) adds the second.
  const layout = await admin<{ version: number; roles: { id: string }[] }>("GET", "/v1/layout");
  if (!layout.roles.some((r) => r.id === status!.node)) {
    await admin("POST", "/v1/layout", [{ id: status.node, zone: "z1", capacity: capacityGb * 1e9, tags: ["paasmcp"] }]);
    await admin("POST", "/v1/layout/apply", { version: layout.version + 1 });
  }
}

export async function provisionStorage(appName: string): Promise<{ record: StorageRecord; injectedKeys: string[]; reused: boolean }> {
  const slug = sanitizeSlug(appName);
  const existing = loadState().storage?.[slug];
  const keys = ["S3_ENDPOINT", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_REGION", "AWS_ENDPOINT_URL_S3", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"];
  if (existing && getSecrets(slug).S3_SECRET_ACCESS_KEY) {
    return { record: existing, injectedKeys: keys, reused: true };
  }

  await ensureGarage();
  const bucket = `app-${slug}`.slice(0, 63);
  let bucketInfo: { id: string };
  try {
    bucketInfo = await admin("GET", `/v1/bucket?globalAlias=${encodeURIComponent(bucket)}`);
  } catch {
    bucketInfo = await admin("POST", "/v1/bucket", { globalAlias: bucket });
  }
  const key = await admin<{ accessKeyId: string; secretAccessKey: string }>("POST", "/v1/key", { name: `paasmcp-${slug}` });
  await admin("POST", "/v1/bucket/allow", {
    bucketId: bucketInfo.id,
    accessKeyId: key.accessKeyId,
    permissions: { read: true, write: true, owner: false },
  });

  // S3_* for code that reads it explicitly; AWS_* so boto3 / AWS SDKs pick it up with no code.
  setSecretEntries(slug, {
    S3_ENDPOINT: GARAGE_INTERNAL_ENDPOINT,
    S3_BUCKET: bucket,
    S3_ACCESS_KEY_ID: key.accessKeyId,
    S3_SECRET_ACCESS_KEY: key.secretAccessKey,
    S3_REGION: GARAGE_REGION,
    AWS_ENDPOINT_URL_S3: GARAGE_INTERNAL_ENDPOINT,
    AWS_ACCESS_KEY_ID: key.accessKeyId,
    AWS_SECRET_ACCESS_KEY: key.secretAccessKey,
    AWS_REGION: GARAGE_REGION,
  });

  const record: StorageRecord = {
    appName: slug,
    bucket,
    bucketId: bucketInfo.id,
    accessKeyId: key.accessKeyId,
    createdAt: new Date().toISOString(),
  };
  const state = loadState();
  state.storage = { ...(state.storage || {}), [slug]: record };
  saveState(state);
  return { record, injectedKeys: keys, reused: false };
}

export function listStorage(): StorageRecord[] {
  return Object.values(loadState().storage || {});
}
