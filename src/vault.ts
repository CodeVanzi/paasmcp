import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  ensureDirectories,
  MASTER_KEY_PATH,
  PAAS_VAULT_DIR,
  sanitizeSlug,
  validateEnvKey,
  writeFileAtomic,
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

// kind ".deleted" holds removed values and ".meta" each key's description and dates; sanitizeSlug never
// produces a dot, so neither can collide with a scope.
type VaultKind = "" | ".deleted" | ".meta";
function getVaultFilePath(scope: string, kind: VaultKind = ""): string {
  const safeScope = sanitizeSlug(scope);
  return path.join(PAAS_VAULT_DIR, `${safeScope}${kind}.enc.json`);
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

function readEncryptedJson<T>(filePath: string, empty: T): T {
  ensureDirectories();
  if (!fs.existsSync(filePath)) {
    return empty;
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
  return JSON.parse(decrypted.toString("utf-8")) as T;
}

function writeEncryptedJson(filePath: string, data: unknown): void {
  ensureDirectories();
  const masterKey = getOrCreateMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf-8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const payload: EncryptedPayload = {
    version: 1,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
    ciphertext: encrypted.toString("hex"),
    updatedAt: new Date().toISOString(),
  };

  writeFileAtomic(filePath, JSON.stringify(payload, null, 2));
}

export function getSecrets(scope: string, kind: "" | ".deleted" = ""): Record<string, string> {
  return readEncryptedJson<Record<string, string>>(getVaultFilePath(scope, kind), {});
}

export function saveSecrets(
  scope: string,
  secrets: Record<string, string>,
  kind: "" | ".deleted" = ""
): void {
  writeEncryptedJson(getVaultFilePath(scope, kind), secrets);
}

/**
 * What a person wrote about a key, and when it was created and last changed. Kept in its own file
 * (scope.meta.enc.json), encrypted with the same master key, so a description never sits in plain text
 * and never shares a file with the value. Keys saved before this existed have no dates: they show as
 * unknown instead of a guessed date.
 */
export interface SecretMeta {
  description?: string;
  createdAt?: string;
  updatedAt?: string;
}

export const SECRET_DESCRIPTION_MAX = 300;

export function getSecretMeta(scope: string): Record<string, SecretMeta> {
  try {
    return readEncryptedJson<Record<string, SecretMeta>>(getVaultFilePath(scope, ".meta"), {});
  } catch {
    // Metadata is a convenience: a damaged file must never stop the values themselves from loading.
    return {};
  }
}

function saveSecretMeta(scope: string, meta: Record<string, SecretMeta>): void {
  writeEncryptedJson(getVaultFilePath(scope, ".meta"), meta);
}

/** Sets (or, with an empty text, clears) a key's description. The key must already exist. */
export function setSecretDescription(scope: string, keyName: string, description: string): SecretMeta {
  const validKey = validateEnvKey(keyName);
  const current = getSecrets(scope);
  if (!(validKey in current)) {
    throw new Error(`No key '${validKey}' in this scope.`);
  }
  const text = String(description ?? "")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim();
  if (text.length > SECRET_DESCRIPTION_MAX) {
    throw new Error(`The description is too long (${SECRET_DESCRIPTION_MAX} characters at most).`);
  }
  // A description is shown in clear on the screen: refuse one that carries the value itself.
  const value = current[validKey];
  if (value && value.length >= 6 && text.includes(value)) {
    throw new Error("The description contains the key's own value. Describe what it is for, without the value.");
  }
  const meta = getSecretMeta(scope);
  const entry: SecretMeta = { ...(meta[validKey] || {}) };
  if (text) entry.description = text;
  else delete entry.description;
  meta[validKey] = entry;
  saveSecretMeta(scope, meta);
  return entry;
}

export function setSecretEntries(
  scope: string,
  entries: Record<string, string>
): string[] {
  const current = getSecrets(scope);
  const savedKeys: string[] = [];
  const now = new Date().toISOString();
  const meta = getSecretMeta(scope);
  let metaChanged = false;
  for (const [k, v] of Object.entries(entries)) {
    const validKey = validateEnvKey(k);
    const value = String(v);
    const isNew = !(validKey in current);
    // Saving the same value again (a redeploy re-applying its variables) is not a change.
    if (isNew || current[validKey] !== value) {
      const entry: SecretMeta = { ...(meta[validKey] || {}) };
      if (isNew) {
        // A key removed and added again starts over; an old description would describe something else.
        delete entry.description;
        entry.createdAt = now;
      }
      entry.updatedAt = now;
      meta[validKey] = entry;
      metaChanged = true;
    }
    current[validKey] = value;
    savedKeys.push(validKey);
  }
  saveSecrets(scope, current);
  if (metaChanged) saveSecretMeta(scope, meta);
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
  const archive = getSecrets(scope, ".deleted");
  archive[`${keyName}@${new Date().toISOString()}`] = current[keyName];
  saveSecrets(scope, archive, ".deleted");
  delete current[keyName];
  saveSecrets(scope, current);
  const meta = getSecretMeta(scope);
  if (keyName in meta) {
    delete meta[keyName];
    saveSecretMeta(scope, meta);
  }
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


/**
 * Reads a pasted `.env` file (the format Railway, Render, Vercel and docker compose use): `KEY=value`
 * lines, `export KEY=value`, `#` comments, single or double quotes (double quotes understand \n).
 * Lines that are not a variable come back in `skipped` (line numbers only, never their text, since
 * they may hold a secret).
 */
export function parseDotenv(text: string): { entries: Record<string, string>; skipped: number[] } {
  const entries: Record<string, string> = {};
  const skipped: number[] = [];
  const lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const m = line.replace(/^export\s+/, "").match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) {
      skipped.push(i + 1);
      return;
    }
    let value = m[2];
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    } else if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    entries[m[1]] = value;
  });
  return { entries, skipped };
}
