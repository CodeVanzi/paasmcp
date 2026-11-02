import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensureDirectories, MASTER_KEY_PATH, PAAS_VAULT_DIR, sanitizeSlug } from "./config.js";

interface EncryptedPayload {
  version: 1;
  iv: string;
  authTag: string;
  ciphertext: string;
  updatedAt: string;
}

function getOrCreateMasterKey(): Buffer {
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
  for (const [k, v] of Object.entries(entries)) {
    current[k.trim()] = v;
  }
  saveSecrets(scope, current);
  return Object.keys(entries);
}

export function setSecretFromFile(
  scope: string,
  keyName: string,
  filePath: string,
  deleteAfterRead = false
): void {
  const value = fs.readFileSync(filePath, "utf-8").trim();
  setSecretEntries(scope, { [keyName]: value });
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
    const key = trimmed.slice(0, eqIndex).trim();
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

export function writeRuntimeEnvFile(scope: string, targetPath: string, extraEnv: Record<string, string> = {}): void {
  const secrets = { ...getSecrets(scope), ...extraEnv };
  const lines = Object.entries(secrets).map(([k, v]) => {
    const escaped = String(v).replace(/\n/g, "\\n");
    return `${k}=${escaped}`;
  });
  fs.writeFileSync(targetPath, lines.join("\n") + "\n", { mode: 0o600 });
}
