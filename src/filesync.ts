import crypto from "node:crypto";
import { signV4 } from "./backup.js";
import { GARAGE_REGION } from "./storage.js";

// Copies of app buckets between the two servers' Garage nodes (active-active, active.ts).
// The peer keeps the same bucket name and the same access key as the origin, so after a failover the
// app's S3_* variables keep working on the peer's own Garage. Objects travel through memory, one at a
// time, signed with the app's own key (SigV4): no admin token ever leaves its server.

const sha256Hex = (data: string | Buffer) => crypto.createHash("sha256").update(data).digest("hex");
/** RFC 3986 encoding, the one SigV4 expects (encodeURIComponent leaves !'()* alone). */
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
/** Objects above this size are reported and skipped (they would go through memory). */
export const MAX_OBJECT_BYTES = 512 * 1024 * 1024;

export interface S3Target {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

export interface S3Object {
  key: string;
  etag: string;
  size: number;
  lastModified: string;
}

/** One signed S3 call (exported for the files lab). */
export async function s3Request(
  t: S3Target,
  method: "GET" | "PUT" | "DELETE" | "HEAD",
  key: string,
  opts: { query?: Record<string, string>; body?: Buffer; contentType?: string; timeoutMs?: number } = {}
): Promise<Response> {
  const path = `/${enc(t.bucket)}${key ? "/" + key.split("/").map(enc).join("/") : ""}`;
  const url = new URL(`${t.endpoint.replace(/\/+$/, "")}${path}`);
  const q = Object.entries(opts.query || {}).sort(([a], [b]) => a.localeCompare(b));
  if (q.length) url.search = q.map(([k, v]) => `${enc(k)}=${enc(v)}`).join("&");
  const payloadHash = sha256Hex(opts.body || "");
  const amzDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const headers: Record<string, string> = { host: url.host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate };
  if (opts.contentType) headers["content-type"] = opts.contentType;
  headers.authorization = signV4({
    method, url, headers: { ...headers }, payloadHash, accessKeyId: t.accessKeyId, secretAccessKey: t.secretAccessKey,
    region: t.region || GARAGE_REGION, amzDate,
  });
  delete headers.host;
  try {
    return await fetch(url, { method, headers, body: opts.body ? new Uint8Array(opts.body) : undefined, signal: AbortSignal.timeout(opts.timeoutMs ?? 10 * 60 * 1000) });
  } catch (err) {
    const cause = (err as { cause?: { code?: string } }).cause?.code || (err instanceof Error ? err.message : String(err));
    throw new Error(`S3 at ${url.host} did not answer (${cause}).`);
  }
}

const xmlText = (s: string) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&amp;/g, "&");

/** Parses one ListObjectsV2 page (exported for tests). */
export function parseListObjects(xml: string): { objects: S3Object[]; next?: string } {
  const objects: S3Object[] = [];
  for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
    const get = (tag: string) => xmlText((m[1].match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`)) || [])[1] || "");
    objects.push({ key: get("Key"), etag: get("ETag").replace(/"/g, ""), size: Number(get("Size")) || 0, lastModified: get("LastModified") });
  }
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
  const next = (xml.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/) || [])[1];
  return { objects, next: truncated && next ? xmlText(next) : undefined };
}

export async function listObjects(t: S3Target): Promise<S3Object[]> {
  const all: S3Object[] = [];
  let token: string | undefined;
  for (let page = 0; page < 10_000; page++) {
    const res = await s3Request(t, "GET", "", {
      query: { "list-type": "2", ...(token ? { "continuation-token": token } : {}) },
      timeoutMs: 20_000, // a server that went away must not hold the caller for minutes
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`List ${t.bucket} on ${t.endpoint}: HTTP ${res.status} ${text.slice(0, 200)}`);
    const { objects, next } = parseListObjects(text);
    all.push(...objects);
    if (!next) break;
    token = next;
  }
  return all;
}

async function copyObject(from: S3Target, to: S3Target, o: S3Object): Promise<void> {
  const res = await s3Request(from, "GET", o.key);
  const body = Buffer.from(await res.arrayBuffer());
  if (!res.ok) throw new Error(`GET ${o.key}: HTTP ${res.status}`);
  const put = await s3Request(to, "PUT", o.key, { body, contentType: res.headers.get("content-type") || undefined });
  if (!put.ok) throw new Error(`PUT ${o.key}: HTTP ${put.status} ${(await put.text()).slice(0, 200)}`);
}

export interface FileSyncPlan {
  copy: S3Object[];
  remove: string[];
  tooLarge: string[];
  /** Keys with "." or ".." segments: a URL would resolve them to another path, so they are never touched. */
  unsafe: string[];
}

const unsafeKey = (k: string) => !k || k.split("/").some((seg) => seg === "." || seg === "..");

/**
 * What to do so `to` matches `from` (pure; tested). `mirror`: also delete what `from` no longer has.
 * Without it (handback), only objects missing on `to`, or newer on `from`, are copied.
 */
export function planFileSync(from: S3Object[], to: S3Object[], mode: "mirror" | "additive"): FileSyncPlan {
  const there = new Map(to.map((o) => [o.key, o]));
  const plan: FileSyncPlan = { copy: [], remove: [], tooLarge: [], unsafe: [] };
  for (const o of from) {
    if (unsafeKey(o.key)) {
      plan.unsafe.push(o.key);
      continue;
    }
    const t = there.get(o.key);
    // A multipart upload's ETag ("<hash>-<parts>") is not the MD5 of the content, and the copy is one PUT:
    // there, the same size and a copy at least as recent count as the same object (no endless re-copy).
    const multipart = !!t && (o.etag.includes("-") || t.etag.includes("-"));
    const same = !!t && t.size === o.size && (t.etag === o.etag || (multipart && t.lastModified >= o.lastModified));
    if (same) continue;
    if (mode === "additive" && t && t.lastModified >= o.lastModified) continue;
    if (o.size > MAX_OBJECT_BYTES) plan.tooLarge.push(o.key);
    else plan.copy.push(o);
  }
  if (mode === "mirror") {
    const here = new Set(from.map((o) => o.key));
    plan.remove = to.filter((o) => !here.has(o.key) && !unsafeKey(o.key)).map((o) => o.key);
  }
  return plan;
}

export interface FileSyncResult {
  copied: number;
  removed: number;
  tooLarge: string[];
  /** Keys with dot segments, never copied (not an error: retrying would not change them). */
  unsafe: string[];
  errors: string[];
  /** Stopped early because `keepGoing` said so; the rest is done on the next run. */
  partial?: boolean;
}

/**
 * Makes `to` follow `from`. `keepGoing` is asked before each object: the caller's time budget, or
 * "this server has not taken over in the meantime".
 */
export async function syncBucket(
  from: S3Target,
  to: S3Target,
  mode: "mirror" | "additive",
  keepGoing: () => boolean = () => true
): Promise<FileSyncResult> {
  const source = await listObjects(from);
  const target = await listObjects(to);
  // An empty source next to a full copy looks like a reinstalled or wrong bucket, not like a shop
  // that deleted every photo at once: keep the copy and say so.
  if (mode === "mirror" && !source.length && target.length) {
    throw new Error(`The bucket '${from.bucket}' at ${from.endpoint} is empty while the copy here has ${target.length} file(s); nothing was deleted.`);
  }
  const plan = planFileSync(source, target, mode);
  const out: FileSyncResult = { copied: 0, removed: 0, tooLarge: plan.tooLarge, unsafe: plan.unsafe, errors: [] };
  for (const o of plan.copy) {
    if (!keepGoing()) return { ...out, partial: true };
    try {
      await copyObject(from, to, o);
      out.copied++;
    } catch (err) {
      out.errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  for (const key of plan.remove) {
    if (!keepGoing()) return { ...out, partial: true };
    const res = await s3Request(to, "DELETE", key);
    if (res.ok || res.status === 404) out.removed++;
    else out.errors.push(`DELETE ${key}: HTTP ${res.status}`);
  }
  return out;
}
