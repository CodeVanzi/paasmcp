import crypto from "node:crypto";
import { getSecrets, setSecretEntries, timingSafeCompare } from "./vault.js";

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), compatible with Google Authenticator, Aegis, 1Password etc. */

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = "";
  for (const byte of buf) bits += byte.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += BASE32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=]/g, "").toUpperCase();
  let bits = "";
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 secret");
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function totpCode(secretBase32: string, timeMs = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(timeMs / 30000)));
  const hmac = crypto.createHmac("sha1", base32Decode(secretBase32)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const value = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(value).padStart(6, "0");
}

/** Accepts the current code and one step before/after (clock drift). */
export function verifyTotp(secretBase32: string, code: string, timeMs = Date.now()): boolean {
  const clean = String(code || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) return false;
  return [-1, 0, 1].some((step) => timingSafeCompare(totpCode(secretBase32, timeMs + step * 30000), clean));
}

export function newTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

export function getDashboardTotpSecret(): string | undefined {
  return getSecrets("system").DASHBOARD_TOTP_SECRET || undefined;
}

export function isDashboardTwoFactorEnabled(): boolean {
  return Boolean(getDashboardTotpSecret());
}

/** Activates 2FA only after a valid first code, so a wrong setup never locks the person out. */
export function enableDashboardTwoFactor(secretBase32: string, firstCode: string): void {
  if (!verifyTotp(secretBase32, firstCode)) {
    throw new Error("The code does not match. Check the phone's clock and try again.");
  }
  setSecretEntries("system", { DASHBOARD_TOTP_SECRET: secretBase32 });
}

export function otpauthUri(secretBase32: string, label = "PaaSMCP dashboard"): string {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secretBase32}&issuer=PaaSMCP&algorithm=SHA1&digits=6&period=30`;
}
