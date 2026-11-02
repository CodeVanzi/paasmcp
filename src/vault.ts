import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  ensureDirectories,
  MASTER_KEY_PATH,
  PAAS_VAULT_DIR,
  sanitizeSlug,
  validateEnvKey,
} from "./config.js";

interface EncryptedPayload {
  version: 1;
  iv: string;
  authTag: string;
  ciphertext: string;
  updatedAt: string;
}

export function getOrCreateMasterKey(): Buffer {
  ensureDirectories();
  if (!fs.existsSync(MASTER_KEY_PATH)) {
    const key = crypto.randomBytes(32);
    fs.writeFileSync(MASTER_KEY_PATH, key.toString("hex"), { mode: 0o600 });
    return key;
  }
  const hex = fs.readFileSync(MASTER_KEY_PATH, "utf-8").trim();
  return Buffer.from(hex, "hex");
}

function getVaultFilePath(scope: string): string {
  const safeScope = sanitizeSlug(scope);
  return path.join(PAAS_VAULT_DIR, `${safeScope}.enc.json`);
}

export function timingSafeCompare(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || !a || !b) {
    return false;
  }
  const digestA = crypto.createHash("sha256").update(a, "utf-8").digest();
  const digestB = crypto.createHash("sha256").update(b, "utf-8").digest();
  return crypto.timingSafeEqual(digestA, digestB) && a.length === b.length;
}

export function encryptBinaryPayload(plainBuffer: Buffer, customKey?: Buffer): Buffer {
  const key = customKey || getOrCreateMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Binary wire format: [4-byte magic "PMCP"][1-byte version=1][12-byte IV][16-byte AuthTag][Ciphertext]
  const header = Buffer.from([0x50, 0x4d, 0x43, 0x50, 0x01]);
  return Buffer.concat([header, iv, authTag, encrypted]);
}

export function decryptBinaryPayload(packedBuffer: Buffer, customKey?: Buffer): Buffer {
  if (packedBuffer.length < 33) {
    throw new Error("Invalid encrypted binary payload (too short).");
  }
  const magic = packedBuffer.subarray(0, 4).toString("ascii");
  const version = packedBuffer[4];
  if (magic !== "PMCP" || version !== 1) {
    throw new Error("Unsupported or corrupted PaaSMCP encrypted binary header.");
  }
  const key = customKey || getOrCreateMasterKey();
  const iv = packedBuffer.subarray(5, 17);
  const authTag = packedBuffer.subarray(17, 33);
  const ciphertext = packedBuffer.subarray(33);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function getSecrets(scope: string): Record<string, string> {
  ensureDirectories();
  const filePath = getVaultFilePath(scope);
  if (!fs.existsSync(filePath)) {
    return {};
  }
  const masterKey = getOrCreateMasterKey();
  const payload = JSON.parse(fs.readFileSync(filePath, "utf-8")) as EncryptedPayload;
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    masterKey,
    Buffer.from(payload.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(payload.authTag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "hex")),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf-8")) as Record<string, string>;
}

export function saveSecrets(scope: string, secrets: Record<string, string>): void {
  ensureDirectories();
  const masterKey = getOrCreateMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, iv);
  const plaintext = Buffer.from(JSON.stringify(secrets), "utf-8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const payload: EncryptedPayload = {
    version: 1,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
    ciphertext: encrypted.toString("hex"),
    updatedAt: new Date().toISOString(),
  };

  const filePath = getVaultFilePath(scope);
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), { mode: 0o600 });
}

export function setSecretEntries(
  scope: string,
  entries: Record<string, string>
): string[] {
  const current = getSecrets(scope);
  const savedKeys: string[] = [];
  for (const [k, v] of Object.entries(entries)) {
    const validKey = validateEnvKey(k);
    current[validKey] = String(v);
    savedKeys.push(validKey);
  }
  saveSecrets(scope, current);
  return savedKeys;
}

export function setSecretFromFile(
  scope: string,
  keyName: string,
  filePath: string,
  deleteAfterRead = false
): void {
  const validKey = validateEnvKey(keyName);
  const value = fs.readFileSync(filePath, "utf-8").trim();
  setSecretEntries(scope, { [validKey]: value });
  if (deleteAfterRead) {
    try {
      fs.unlinkSync(filePath);
    } catch {
      // ignore
    }
  }
}

export function importDotEnvFile(scope: string, envFilePath: string): string[] {
  const raw = fs.readFileSync(envFilePath, "utf-8");
  const parsed: Record<string, string> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;
    const key = validateEnvKey(trimmed.slice(0, eqIndex));
    let val = trimmed.slice(eqIndex + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    parsed[key] = val;
  }
  return setSecretEntries(scope, parsed);
}

export function deleteSecretKey(scope: string, keyName: string): boolean {
  const current = getSecrets(scope);
  if (!(keyName in current)) {
    return false;
  }
  delete current[keyName];
  saveSecrets(scope, current);
  return true;
}

export function maskSecretValue(val: string): string {
  if (!val) return "(empty)";
  if (val.length <= 8) return "********";
  return `${val.slice(0, 4)}****${val.slice(-3)}`;
}

export function listMaskedSecrets(scope: string): Record<string, string> {
  const current = getSecrets(scope);
  const masked: Record<string, string> = {};
  for (const [k, v] of Object.entries(current)) {
    masked[k] = maskSecretValue(v);
  }
  return masked;
}

export function writeRuntimeEnvFile(
  scope: string,
  targetPath: string,
  extraEnv: Record<string, string> = {}
): void {
  const secrets = { ...getSecrets(scope), ...extraEnv };
  const lines = Object.entries(secrets).map(([k, v]) => {
    const validKey = validateEnvKey(k);
    const escaped = String(v).replace(/\r/g, "").replace(/\n/g, "\\n");
    return `${validKey}=${escaped}`;
  });
  fs.writeFileSync(targetPath, lines.join("\n") + "\n", { mode: 0o600 });
}
