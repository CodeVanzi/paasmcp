import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PAAS_DATA_DIR, ensureDirectories, sanitizeSlug, writeFileAtomic } from "./config.js";
import { audit } from "./guard.js";
import { timingSafeCompare } from "./vault.js";

/**
 * Personal access tokens for the MCP HTTP endpoint.
 * - read: status, logs, diagnostics, lists.
 * - deploy: also deploy, provision, back up, restart, expose privately.
 * - destroy: also risky actions (they still need a person's approval, see guard.ts).
 * Only a SHA-256 hash is stored; the token is shown once at creation.
 */
export type TokenLevel = "read" | "deploy" | "destroy";
export const TOKEN_LEVELS: TokenLevel[] = ["read", "deploy", "destroy"];

export interface TokenRecord {
  id: string;
  name: string;
  level: TokenLevel;
  hash: string;
  createdAt: string;
  lastUsedAt?: string;
}

const TOKENS_PATH = path.join(PAAS_DATA_DIR, "tokens.json");

function loadTokens(): Record<string, TokenRecord> {
  if (!fs.existsSync(TOKENS_PATH)) return {};
  return JSON.parse(fs.readFileSync(TOKENS_PATH, "utf-8")) as Record<string, TokenRecord>;
}

function saveTokens(all: Record<string, TokenRecord>): void {
  ensureDirectories();
  writeFileAtomic(TOKENS_PATH, JSON.stringify(all, null, 2));
}

function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

export function levelAllows(have: TokenLevel, need: TokenLevel): boolean {
  return TOKEN_LEVELS.indexOf(have) >= TOKEN_LEVELS.indexOf(need);
}

export function createToken(name: string, level: TokenLevel = "deploy"): { token: string; record: TokenRecord } {
  if (!TOKEN_LEVELS.includes(level)) throw new Error(`Invalid token level '${level}'. Use read, deploy or destroy.`);
  const all = loadTokens();
  const id = crypto.randomBytes(4).toString("hex");
  const secret = crypto.randomBytes(24).toString("base64url");
  const record: TokenRecord = { id, name: sanitizeSlug(name), level, hash: hashSecret(secret), createdAt: new Date().toISOString() };
  all[id] = record;
  saveTokens(all);
  audit({ event: "token.created", id, name: record.name, level });
  return { token: `pmcp_${id}_${secret}`, record };
}

export function listTokens(): Omit<TokenRecord, "hash">[] {
  return Object.values(loadTokens()).map(({ hash: _hash, ...rest }) => rest);
}

export function revokeToken(id: string): boolean {
  const all = loadTokens();
  if (!all[id]) return false;
  delete all[id];
  saveTokens(all);
  audit({ event: "token.revoked", id });
  return true;
}

/** Returns the token record when the bearer value is valid. */
export function verifyToken(bearer: string): TokenRecord | null {
  const match = /^pmcp_([0-9a-f]{8})_([A-Za-z0-9_-]+)$/.exec(String(bearer || "").trim());
  if (!match) return null;
  const all = loadTokens();
  const rec = all[match[1]];
  if (!rec || !timingSafeCompare(hashSecret(match[2]), rec.hash)) return null;
  // Touch at most once a minute to avoid rewriting the file on every call.
  if (!rec.lastUsedAt || Date.now() - Date.parse(rec.lastUsedAt) > 60_000) {
    rec.lastUsedAt = new Date().toISOString();
    saveTokens(all);
  }
  return rec;
}

/**
 * Notes that an AI really used the MCP server (any tool call, stdio or HTTP), so the dashboard can
 * tell "Connect your AI" is done even with no personal token (stdio on the server needs none).
 * Stores only the time and the transport, never arguments. Best effort: a read-only data dir
 * must not break the tool call. Written at most once a minute.
 */
export type McpVia = "stdio" | "http";
export interface McpUse {
  lastUsedAt: string;
  via: McpVia;
}
const MCP_USE_PATH = path.join(PAAS_DATA_DIR, "mcp-usage.json");
let lastMcpNote = 0;

export function noteMcpUse(via: McpVia, now = Date.now()): void {
  if (now - lastMcpNote < 60_000) return;
  lastMcpNote = now;
  try {
    ensureDirectories();
    writeFileAtomic(MCP_USE_PATH, JSON.stringify({ lastUsedAt: new Date(now).toISOString(), via }));
  } catch {
    /* ignore: usage marks are only a hint for the tutorial */
  }
}

export function readMcpUse(): McpUse | null {
  try {
    const raw = JSON.parse(fs.readFileSync(MCP_USE_PATH, "utf-8")) as Partial<McpUse>;
    if (typeof raw.lastUsedAt !== "string" || Number.isNaN(Date.parse(raw.lastUsedAt))) return null;
    return { lastUsedAt: raw.lastUsedAt, via: raw.via === "http" ? "http" : "stdio" };
  } catch {
    return null;
  }
}

/** Test hook: forget the once-a-minute throttle. */
export function resetMcpUseThrottle(): void {
  lastMcpNote = 0;
}
