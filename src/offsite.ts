import crypto from "node:crypto";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { BackupGrantRecord, loadState, sanitizeSlug, saveState, tailnetBindIp } from "./config.js";
import { getOffsiteConfig, OffsiteConfig, s3Request } from "./backup.js";
import { createBucketWithKey, ensureGarage, GARAGE_INTERNAL_ENDPOINT, GARAGE_REGION, garageAdmin } from "./storage.js";
import { deleteSecretKey, getSecrets, setSecretEntries } from "./vault.js";

/**
 * Where off-site backups go, set in one step (receiving side), and revocable keys for other
 * computers that send their backups into this server's Garage (providing side).
 *
 * Secrets are written only to the 'system' vault and are never returned, except the key of a new
 * grant, which goes back exactly once to the person who created it (dashboard or CLI, never MCP).
 */

export const OFFSITE_PROVIDERS = ["r2", "s3", "gcs", "b2", "wasabi", "paasmcp", "custom"] as const;
export type OffsiteProvider = (typeof OFFSITE_PROVIDERS)[number];

export interface OffsiteInput {
  provider: string;
  /** Cloudflare R2: the account id, or the whole "S3 API" address copied from R2. */
  accountId?: string;
  region?: string;
  endpoint?: string;
  bucket?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  prefix?: string;
  /** provider "paasmcp": the access code another PaaSMCP printed for this server. */
  code?: string;
}

export type OffsiteTarget = OffsiteConfig & { provider: OffsiteProvider; prefixSet: boolean };

const PROVIDER_NAMES: Record<OffsiteProvider, string> = {
  r2: "Cloudflare R2",
  s3: "Amazon S3",
  gcs: "Google Cloud Storage",
  b2: "Backblaze B2",
  wasabi: "Wasabi",
  paasmcp: "PaaSMCP",
  custom: "S3",
};

const BUCKET_RE = /^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$/;
const KEY_ID_RE = /^[A-Za-z0-9._+/=-]{3,128}$/;
const SECRET_RE = /^[\x21-\x7e]{8,256}$/;
const PREFIX_RE = /^[A-Za-z0-9._/-]{0,200}$/;
const REGION_RE = /^[a-z0-9-]{2,40}$/;
const CODE_PREFIX = "paasmcp-backup:1:";

const clean = (v: unknown) => String(v ?? "").trim();

/** Hosts where plain http is acceptable: loopback, private networks, Tailscale (100.64/10), *.ts.net, Docker names. */
export function isPrivateHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h === "::1" || h.endsWith(".ts.net") || h.endsWith(".local") || /^[a-z0-9-]+$/.test(h)) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

function checkEndpoint(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw fail(`'${raw}' is not an address (expected https://...).`, `'${raw}' não é um endereço (esperado https://...).`);
  }
  if (url.username || url.password || url.search || url.hash) throw fail("The address must not carry a user, password or query.", "O endereço não pode ter usuário, senha nem parâmetros.");
  if (url.protocol === "http:" && !isPrivateHost(url.hostname)) {
    throw fail("Use https:// for a server on the internet (http:// only inside your network or Tailscale).", "Use https:// para um servidor na internet (http:// só dentro da sua rede ou da Tailscale).");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw fail("The address must start with https://.", "O endereço precisa começar com https://.");
  return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`;
}

/** The access code another PaaSMCP gives (createBackupGrant). Plain text: treat it like a password. */
export function encodeAccessCode(a: { endpoint: string; bucket: string; accessKeyId: string; secretAccessKey: string; region: string }): string {
  const json = JSON.stringify({ e: a.endpoint, b: a.bucket, k: a.accessKeyId, s: a.secretAccessKey, r: a.region });
  return CODE_PREFIX + Buffer.from(json).toString("base64url");
}

export function decodeAccessCode(code: string): { endpoint: string; bucket: string; accessKeyId: string; secretAccessKey: string; region: string } {
  const c = clean(code).replace(/\s+/g, "");
  if (!c.startsWith(CODE_PREFIX)) throw fail("This is not a PaaSMCP access code (it starts with 'paasmcp-backup:1:').", "Isso não é um código de acesso do PaaSMCP (ele começa com 'paasmcp-backup:1:').");
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(Buffer.from(c.slice(CODE_PREFIX.length), "base64url").toString("utf-8"));
  } catch {
    throw fail("The access code is incomplete. Copy it again, whole.", "O código está incompleto. Copie de novo, inteiro.");
  }
  if (!o || typeof o !== "object") throw fail("The access code is incomplete. Copy it again, whole.", "O código está incompleto. Copie de novo, inteiro.");
  return { endpoint: clean(o.e), bucket: clean(o.b), accessKeyId: clean(o.k), secretAccessKey: clean(o.s), region: clean(o.r) || GARAGE_REGION };
}

/** Pure: turns what the person typed for a provider into a complete, validated S3 destination. */
export function buildOffsiteTarget(input: OffsiteInput): OffsiteTarget {
  const provider = clean(input.provider) as OffsiteProvider;
  if (!OFFSITE_PROVIDERS.includes(provider)) throw fail(`Unknown provider '${input.provider}'. Use one of: ${OFFSITE_PROVIDERS.join(", ")}.`, `Serviço desconhecido '${input.provider}'. Use um destes: ${OFFSITE_PROVIDERS.join(", ")}.`);
  let endpoint = "";
  // People often paste the whole endpoint (s3.us-west-004.backblazeb2.com) where the region goes.
  let region = clean(input.region)
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^s3[.-]/, "")
    .replace(/\.(backblazeb2|wasabisys|amazonaws)\.com.*$/, "");
  let bucket = clean(input.bucket);
  let accessKeyId = clean(input.accessKeyId);
  let secretAccessKey = clean(input.secretAccessKey);

  const needRegion = (example: string) => {
    if (!REGION_RE.test(region)) throw fail(`Fill in the region (for example ${example}).`, `Preencha a região (por exemplo ${example}).`);
  };
  switch (provider) {
    case "r2": {
      const raw = clean(input.accountId);
      const id = (raw.match(/^(?:https:\/\/)?([a-f0-9]{32})(?:\.(?:eu\.|fedramp\.)?r2\.cloudflarestorage\.com)?(?:\/([a-z0-9._-]+))?\/?$/i) || []) as string[];
      if (!id[1]) throw fail("Fill in the R2 account id (32 letters and numbers, on the R2 page of the Cloudflare dashboard).", "Preencha o ID da conta do R2 (32 letras e números, na página do R2 no painel da Cloudflare).");
      const jurisdiction = raw.match(/\.(eu|fedramp)\.r2\./i)?.[1]?.toLowerCase();
      endpoint = `https://${id[1].toLowerCase()}.${jurisdiction ? jurisdiction + "." : ""}r2.cloudflarestorage.com`;
      if (!bucket && id[2]) bucket = id[2];
      region = "auto";
      break;
    }
    case "s3":
      needRegion("us-east-1");
      endpoint = `https://s3.${region}.amazonaws.com`;
      break;
    case "gcs":
      endpoint = "https://storage.googleapis.com";
      region = "auto";
      break;
    case "b2":
      needRegion("us-west-004");
      endpoint = `https://s3.${region}.backblazeb2.com`;
      break;
    case "wasabi":
      needRegion("us-east-1");
      endpoint = `https://s3.${region}.wasabisys.com`;
      break;
    case "paasmcp": {
      const c = decodeAccessCode(input.code || "");
      endpoint = checkEndpoint(c.endpoint);
      ({ bucket, accessKeyId, secretAccessKey, region } = c);
      break;
    }
    case "custom":
      if (!clean(input.endpoint)) throw fail("Fill in the server address (for example https://minio.example.com).", "Preencha o endereço do servidor (por exemplo https://minio.exemplo.com).");
      endpoint = checkEndpoint(clean(input.endpoint));
      region = region || "us-east-1";
      if (!REGION_RE.test(region)) throw fail("The region has only letters, numbers and dashes (for example us-east-1).", "A região só tem letras, números e traços (por exemplo us-east-1).");
      break;
  }
  if (!BUCKET_RE.test(bucket)) throw fail("Fill in the bucket name (3 to 63 lowercase letters, numbers, dots or dashes).", "Preencha o nome do bucket (3 a 63 letras minúsculas, números, pontos ou traços).");
  if (!KEY_ID_RE.test(accessKeyId)) throw fail("Fill in the access key id.", "Preencha o ID da chave de acesso.");
  if (!SECRET_RE.test(secretAccessKey)) throw fail("Fill in the secret key (copy it whole, without spaces).", "Preencha a chave secreta (copie inteira, sem espaços).");
  const prefixIn = clean(input.prefix).replace(/^\/+|\/+$/g, "");
  if (!PREFIX_RE.test(prefixIn) || prefixIn.includes("..")) throw fail("The folder has only letters, numbers, dots, dashes and slashes.", "A pasta só tem letras, números, pontos, traços e barras.");
  const prefix = prefixIn || getOffsiteConfigPrefixDefault();
  return { provider, endpoint, bucket, accessKeyId, secretAccessKey, region, prefix, prefixSet: Boolean(prefixIn) };
}

function getOffsiteConfigPrefixDefault(): string {
  // Same default as backup.ts getOffsiteConfig.
  return `paasmcp/${sanitizeSlug(os.hostname())}`;
}

/** Writes, reads back and deletes a small file, so a wrong key or bucket shows up now, not at night. */
export async function testOffsiteTarget(cfg: OffsiteConfig): Promise<{ ok: true; deleted: boolean }> {
  const key = `${cfg.prefix}/.paasmcp-test-${crypto.randomBytes(6).toString("hex")}`;
  const body = Buffer.from(`paasmcp destination test ${new Date().toISOString()}\n`);
  try {
    await s3Request(cfg, "PUT", key, body);
  } catch (err) {
    throw s3Fail("Could not save a test file:", "Não deu para gravar o arquivo de teste:", err);
  }
  let back: Buffer;
  try {
    back = await s3Request(cfg, "GET", key);
  } catch (err) {
    throw s3Fail("The test file was saved but could not be read back:", "O arquivo de teste foi gravado, mas não deu para ler de volta:", err);
  }
  if (!back.equals(body)) throw fail("The test file came back different from what was sent.", "O arquivo de teste voltou diferente do que foi enviado.");
  let deleted = true;
  try {
    await s3Request(cfg, "DELETE", key);
  } catch {
    deleted = false; // Some keys can write but not delete; backups still work.
  }
  return { ok: true, deleted };
}

/** An error with a Portuguese version for the dashboard (the CLI and the API keep the English one). */
export class OffsiteError extends Error {
  constructor(message: string, public pt: string) {
    super(message);
  }
}
const fail = (en: string, pt: string) => new OffsiteError(en, pt);

function s3Fail(en: string, pt: string, err: unknown): OffsiteError {
  const m = err instanceof Error ? err.message : String(err);
  const why: [string, string] = /HTTP 403/.test(m)
    ? ["the key was refused (check the access key, the secret and that the key can use this bucket).", "a chave foi recusada (confira o ID, a chave secreta e se a chave pode usar esse bucket)."]
    : /HTTP 404|NoSuchBucket/.test(m)
      ? ["the bucket was not found (check its name and the region).", "o bucket não foi encontrado (confira o nome e a região)."]
      : /HTTP 301|PermanentRedirect|AuthorizationHeaderMalformed/.test(m)
        ? ["the bucket is in another region.", "o bucket está em outra região."]
        : /fetch failed|ENOTFOUND|ECONNREFUSED|timeout|EHOSTUNREACH|aborted/i.test(m)
          ? ["the server did not answer (check the address, and Tailscale for another PaaSMCP).", "o servidor não respondeu (confira o endereço e, para outro PaaSMCP, a Tailscale)."]
          : [m.slice(0, 300), m.slice(0, 300)];
  return fail(`${en} ${why[0]}`, `${pt} ${why[1]}`);
}

const describe = (t: Pick<OffsiteTarget, "provider" | "bucket" | "endpoint">) =>
  `${PROVIDER_NAMES[t.provider] || "S3"} (${t.bucket} @ ${new URL(t.endpoint).host})`;

function currentProvider(): OffsiteProvider {
  const p = getSecrets("system").BACKUP_S3_PROVIDER as OffsiteProvider;
  return OFFSITE_PROVIDERS.includes(p) ? p : "custom";
}

/** What the dashboard shows about the destination. No secret, and only the start of the key id. */
export function offsiteSummary() {
  const cfg = getOffsiteConfig();
  if (!cfg) return { configured: false as const };
  const provider = currentProvider();
  let host = cfg.endpoint;
  try {
    host = new URL(cfg.endpoint).host;
  } catch {
    /* keep raw */
  }
  return {
    configured: true as const,
    provider,
    providerName: PROVIDER_NAMES[provider],
    host,
    bucket: cfg.bucket,
    region: cfg.region,
    prefix: cfg.prefix,
    accessKeyHint: cfg.accessKeyId.slice(0, 4) + "…",
    testedAt: getSecrets("system").BACKUP_S3_TESTED_AT || null,
  };
}

/**
 * Tests the destination first and saves it only when the test passes. `authorize` runs the guard
 * (the caller passes authorizeHuman with its confirmation); replacing a working destination is confirmed.
 */
export async function saveOffsiteTarget(input: OffsiteInput, authorize: (params: Record<string, unknown>) => void | Promise<void>, opts: { skipTest?: boolean } = {}) {
  const target = buildOffsiteTarget(input);
  const before = getOffsiteConfig();
  const replacing = Boolean(before && (before.endpoint !== target.endpoint || before.bucket !== target.bucket));
  // Test first, so a person is never asked to confirm a destination that does not work.
  const test = opts.skipTest ? null : await testOffsiteTarget(target);
  await authorize({
    replacing,
    target: describe(target),
    previous: before ? describe({ provider: currentProvider(), bucket: before.bucket, endpoint: before.endpoint }) : "",
  });
  const entries: Record<string, string> = {
    BACKUP_S3_PROVIDER: target.provider,
    BACKUP_S3_ENDPOINT: target.endpoint,
    BACKUP_S3_BUCKET: target.bucket,
    BACKUP_S3_ACCESS_KEY_ID: target.accessKeyId,
    BACKUP_S3_SECRET_ACCESS_KEY: target.secretAccessKey,
    BACKUP_S3_REGION: target.region,
  };
  if (test) entries.BACKUP_S3_TESTED_AT = new Date().toISOString();
  if (target.prefixSet) entries.BACKUP_S3_PREFIX = target.prefix;
  setSecretEntries("system", entries);
  if (!target.prefixSet) deleteSecretKey("system", "BACKUP_S3_PREFIX");
  if (!test) deleteSecretKey("system", "BACKUP_S3_TESTED_AT");
  return { summary: offsiteSummary(), test };
}

export async function retestOffsiteTarget() {
  const cfg = getOffsiteConfig();
  if (!cfg) throw fail("No destination yet: choose where to send the backups first.", "Ainda não há destino: escolha primeiro para onde mandar as cópias.");
  const test = await testOffsiteTarget(cfg);
  setSecretEntries("system", { BACKUP_S3_TESTED_AT: new Date().toISOString() });
  return { summary: offsiteSummary(), test };
}

export async function clearOffsiteTarget(authorize: (params: Record<string, unknown>) => void | Promise<void>) {
  if (!getOffsiteConfig()) return { summary: offsiteSummary() };
  await authorize({});
  for (const k of ["BACKUP_S3_PROVIDER", "BACKUP_S3_ENDPOINT", "BACKUP_S3_BUCKET", "BACKUP_S3_ACCESS_KEY_ID", "BACKUP_S3_SECRET_ACCESS_KEY", "BACKUP_S3_REGION", "BACKUP_S3_PREFIX", "BACKUP_S3_TESTED_AT"]) {
    deleteSecretKey("system", k);
  }
  return { summary: offsiteSummary() };
}

// ---------------------------------------------------------------------------
// Providing side: a revocable key for another computer, into a bucket here
// ---------------------------------------------------------------------------

function detectTailscaleIp(): string | undefined {
  if (process.env.PAASMCP_SHARE_BIND_IP) return process.env.PAASMCP_SHARE_BIND_IP;
  try {
    const ip = execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0].trim();
    return /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/.test(ip) ? ip : undefined;
  } catch {
    return undefined;
  }
}

/** The address other computers use to reach this server's S3. Publishes Garage's S3 port on Tailscale if needed. */
async function shareEndpoint(): Promise<string> {
  const state = loadState();
  const existing = tailnetBindIp(state) || state.backupShare?.bindIp;
  if (existing) return `http://${existing}:3900`;
  const ip = detectTailscaleIp();
  if (!ip) {
    throw fail(
      "Other computers reach this server's storage through Tailscale, and Tailscale is not running here. Install it (https://tailscale.com/download), sign in with the same account on both computers, and try again.",
      "Os outros computadores chegam ao armazenamento deste servidor pela Tailscale, e a Tailscale não está rodando aqui. Instale (https://tailscale.com/download), entre com a mesma conta nos dois computadores e tente de novo."
    );
  }
  const s = loadState();
  s.backupShare = { grants: {}, ...(s.backupShare || {}), bindIp: ip };
  saveState(s);
  await ensureGarage(); // recreates Garage with its S3 port (only) also on the Tailscale IP
  return `http://${ip}:3900`;
}

export function validateGrantName(raw: string): string {
  const name = sanitizeSlug(raw);
  if (!name || name.length > 40) throw fail("Give the computer or app a short name (letters, numbers and dashes).", "Dê um nome curto ao computador ou app (letras, números e traços).");
  return name;
}

export async function createBackupGrant(rawName: string, opts: { maxGb?: number }, authorize: (params: Record<string, unknown>) => void | Promise<void>) {
  const name = validateGrantName(rawName);
  const maxGb = opts.maxGb === undefined || opts.maxGb === null || Number(opts.maxGb) === 0 ? undefined : Number(opts.maxGb);
  if (maxGb !== undefined && !(Number.isInteger(maxGb) && maxGb >= 1 && maxGb <= 100000)) throw fail("The limit is a whole number of GB (1 or more), or empty for no limit.", "O limite é um número inteiro de GB (1 ou mais), ou vazio para sem limite.");
  const current = loadState().backupShare?.grants?.[name];
  if (current && !current.revokedAt) throw fail(`'${name}' already has a key. Revoke it first to make a new one.`, `'${name}' já tem uma chave. Revogue antes de gerar outra.`);
  await authorize({ name, maxGb: maxGb || 0 });

  const endpoint = await shareEndpoint();
  const bucket = current?.bucket || `backup-${name}`.slice(0, 63);
  const key = await createBucketWithKey(bucket, `backup-grant-${name}`);
  if (maxGb) {
    await garageAdmin("PUT", `/v1/bucket?id=${encodeURIComponent(key.bucketId)}`, { quotas: { maxSize: maxGb * 1e9, maxObjects: null } });
  }
  const record: BackupGrantRecord = {
    name,
    bucket,
    bucketId: key.bucketId,
    accessKeyId: key.accessKeyId,
    ...(maxGb ? { maxGb } : {}),
    createdAt: new Date().toISOString(),
  };
  const s = loadState();
  s.backupShare = { grants: {}, ...(s.backupShare || {}) };
  s.backupShare.grants = { ...s.backupShare.grants, [name]: record };
  saveState(s);
  const access = { endpoint, bucket, accessKeyId: key.accessKeyId, secretAccessKey: key.secretAccessKey, region: GARAGE_REGION };
  return {
    grant: record,
    access,
    code: encodeAccessCode(access),
    // Apps on this server reach Garage by its container name, without Tailscale.
    internalEndpoint: GARAGE_INTERNAL_ENDPOINT,
  };
}

export async function revokeBackupGrant(rawName: string) {
  const name = validateGrantName(rawName);
  const grant = loadState().backupShare?.grants?.[name];
  if (!grant) throw fail(`No key named '${name}'.`, `Não há chave com o nome '${name}'.`);
  if (!grant.revokedAt) {
    try {
      await garageAdmin("DELETE", `/v1/key?id=${encodeURIComponent(grant.accessKeyId)}`);
    } catch (err) {
      // Already gone in Garage is fine; anything else must not be reported as revoked.
      if (!/HTTP 404/.test(err instanceof Error ? err.message : String(err))) throw err;
    }
    const s = loadState();
    if (s.backupShare?.grants?.[name]) s.backupShare.grants[name] = { ...s.backupShare.grants[name], revokedAt: new Date().toISOString() };
    saveState(s);
  }
  return { grant: loadState().backupShare!.grants[name] };
}

/** Grants with how much each one stores (best effort: Garage may be stopped). */
export async function listBackupGrants() {
  const grants = Object.values(loadState().backupShare?.grants || {});
  return Promise.all(
    grants.map(async (g) => {
      let bytes: number | null = null;
      try {
        const info = await garageAdmin<{ bytes?: number }>("GET", `/v1/bucket?id=${encodeURIComponent(g.bucketId)}`);
        bytes = typeof info.bytes === "number" ? info.bytes : null;
      } catch {
        /* unknown */
      }
      return { ...g, bytes };
    })
  );
}
