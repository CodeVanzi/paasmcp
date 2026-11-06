import crypto from "node:crypto";
import os from "node:os";
import {
  allocateAppPort,
  AppRecord,
  FederationPeerRecord,
  loadState,
  sanitizeSlug,
  saveState,
  hostName,
} from "./config.js";
import { deployApp } from "./deployer.js";
import { getOrCreateSshDeployKey } from "./github.js";
import {
  decryptBinaryPayload,
  encryptBinaryPayload,
  getSecrets,
  saveSecrets,
  setSecretEntries,
  timingSafeCompare,
} from "./vault.js";

export function getOrCreateWebhookSecret(): string {
  const sys = getSecrets("system");
  if (sys.WEBHOOK_SECRET) {
    return sys.WEBHOOK_SECRET;
  }
  const secret = crypto.randomBytes(24).toString("hex");
  setSecretEntries("system", { WEBHOOK_SECRET: secret });
  return secret;
}

export function verifyGitHubWebhookSignature(
  rawBody: string,
  signatureHeader?: string,
  customSecret?: string
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
    return false;
  }
  const secret = customSecret || getOrCreateWebhookSecret();
  const expectedSig =
    "sha256=" +
    crypto.createHmac("sha256", secret).update(rawBody, "utf-8").digest("hex");
  return timingSafeCompare(expectedSig, signatureHeader.trim());
}

export async function handleGitHubPushWebhook(payload: {
  ref?: string;
  after?: string;
  repository?: { full_name?: string; clone_url?: string; ssh_url?: string };
}): Promise<{
  matchedApps: string[];
  rebuiltApps: string[];
  errors: Record<string, string>;
}> {
  const state = loadState();
  const ref = String(payload.ref || "");
  const pushedBranch = ref.startsWith("refs/heads/")
    ? ref.slice("refs/heads/".length)
    : "";
  const repoFullName = String(payload.repository?.full_name || "").toLowerCase();
  const pushedSha = /^[0-9a-f]{40}$/.test(String(payload.after || "")) ? String(payload.after) : undefined;

  const matchedApps: string[] = [];
  const rebuiltApps: string[] = [];
  const errors: Record<string, string> = {};

  if (!repoFullName || !pushedBranch) {
    return { matchedApps, rebuiltApps, errors };
  }

  for (const app of Object.values(state.apps)) {
    if (!app.repoUrl) continue;
    const normalizedAppRepo = app.repoUrl
      .replace(/^https?:\/\/github\.com\//i, "")
      .replace(/^git@github\.com:/i, "")
      .replace(/\.git$/i, "")
      .toLowerCase();

    if (normalizedAppRepo === repoFullName && app.branch === pushedBranch) {
      matchedApps.push(app.name);
      if (process.env.PAASMCP_OFFLINE_TEST === "1") {
        app.lastWebhookAt = new Date().toISOString();
        rebuiltApps.push(app.name);
      } else {
        try {
          await deployApp({
            appName: app.name,
            repoSource: app.repoUrl,
            branch: app.branch,
            trigger: "webhook",
            announcedCommit: pushedSha,
          });
          const latest = loadState();
          if (latest.apps[app.name]) {
            latest.apps[app.name].lastWebhookAt = new Date().toISOString();
            saveState(latest);
          }
          rebuiltApps.push(app.name);
        } catch (err) {
          errors[app.name] = err instanceof Error ? err.message : String(err);
        }
      }
    }
  }

  if (process.env.PAASMCP_OFFLINE_TEST === "1" && matchedApps.length > 0) {
    saveState(state);
  }

  return { matchedApps, rebuiltApps, errors };
}

// ============================================================================
// Multi-Server Federation & Handshake (HA / Redundancy)
// ============================================================================

export function getOrCreateFederationClusterKey(): Buffer {
  const sys = getSecrets("system");
  if (sys.FEDERATION_CLUSTER_KEY && sys.FEDERATION_CLUSTER_KEY.length === 64) {
    return Buffer.from(sys.FEDERATION_CLUSTER_KEY, "hex");
  }
  const key = crypto.randomBytes(32);
  setSecretEntries("system", { FEDERATION_CLUSTER_KEY: key.toString("hex") });
  return key;
}

export interface FederationJoinTokenPayload {
  v: 1;
  primaryNodeId: string;
  primaryName: string;
  endpointUrl: string;
  mode: "active-active-tunnel" | "warm-standby";
  clusterKeyHex: string;
  fingerprint: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

export function generateFederationJoinToken(opts: {
  endpointUrl: string;
  mode?: "active-active-tunnel" | "warm-standby";
  ttlSeconds?: number;
  nodeName?: string;
}): {
  joinToken: string;
  expiresAtIso: string;
  mode: "active-active-tunnel" | "warm-standby";
  primaryNodeId: string;
} {
  const state = loadState();
  const keyInfo = getOrCreateSshDeployKey();
  const clusterKey = getOrCreateFederationClusterKey();
  const mode = opts.mode || "active-active-tunnel";
  const ttlMs = (opts.ttlSeconds || 900) * 1000;
  const now = Date.now();

  if (!state.federation) {
    state.federation = {
      nodeId: `node-${crypto.randomBytes(4).toString("hex")}`,
      nodeName: opts.nodeName || hostName(),
      role: "primary",
      redundancyMode: mode,
      peers: {},
    };
  } else {
    state.federation.role = "primary";
    state.federation.redundancyMode = mode;
    if (opts.nodeName) state.federation.nodeName = opts.nodeName;
  }
  saveState(state);

  const payload: FederationJoinTokenPayload = {
    v: 1,
    primaryNodeId: state.federation.nodeId,
    primaryName: state.federation.nodeName,
    endpointUrl: opts.endpointUrl.replace(/\/+$/, ""),
    mode,
    clusterKeyHex: clusterKey.toString("hex"),
    fingerprint: keyInfo.fingerprint,
    issuedAt: now,
    expiresAt: now + ttlMs,
    nonce: crypto.randomBytes(12).toString("hex"),
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString("base64url");
  const sig = crypto
    .createHmac("sha256", clusterKey)
    .update(payloadB64, "utf-8")
    .digest("base64url");

  return {
    joinToken: `paasmcp-join://${payloadB64}.${sig}`,
    expiresAtIso: new Date(payload.expiresAt).toISOString(),
    mode,
    primaryNodeId: state.federation.nodeId,
  };
}

export function parseAndVerifyFederationJoinToken(joinToken: string): FederationJoinTokenPayload {
  const clean = joinToken.trim();
  if (!clean.startsWith("paasmcp-join://")) {
    throw new Error("Invalid Join Token prefix. Expected 'paasmcp-join://...'.");
  }
  const body = clean.slice("paasmcp-join://".length);
  const dotIdx = body.indexOf(".");
  if (dotIdx === -1) {
    throw new Error("Malformed Join Token structure.");
  }
  const payloadB64 = body.slice(0, dotIdx);
  const providedSig = body.slice(dotIdx + 1);

  const parsed = JSON.parse(
    Buffer.from(payloadB64, "base64url").toString("utf-8")
  ) as FederationJoinTokenPayload;

  if (parsed.v !== 1 || !parsed.clusterKeyHex || parsed.clusterKeyHex.length !== 64) {
    throw new Error("Invalid Join Token version or cluster key.");
  }

  const clusterKey = Buffer.from(parsed.clusterKeyHex, "hex");
  const expectedSig = crypto
    .createHmac("sha256", clusterKey)
    .update(payloadB64, "utf-8")
    .digest("base64url");

  if (!timingSafeCompare(expectedSig, providedSig)) {
    throw new Error("Federation Join Token HMAC signature verification failed.");
  }

  if (Date.now() > parsed.expiresAt) {
    throw new Error("Federation Join Token has expired. Generate a fresh token on the primary node.");
  }

  return parsed;
}

export function registerFederationPeer(peer: {
  nodeId: string;
  name: string;
  endpointUrl: string;
  mode: "active-active-tunnel" | "warm-standby";
  publicKeyFingerprint: string;
}): FederationPeerRecord {
  const state = loadState();
  if (!state.federation) {
    state.federation = {
      nodeId: `node-${crypto.randomBytes(4).toString("hex")}`,
      nodeName: hostName(),
      role: "primary",
      redundancyMode: peer.mode,
      peers: {},
    };
  }
  const safeId = sanitizeSlug(peer.nodeId);
  const record: FederationPeerRecord = {
    nodeId: safeId,
    name: sanitizeSlug(peer.name),
    endpointUrl: peer.endpointUrl.replace(/\/+$/, ""),
    mode: peer.mode,
    publicKeyFingerprint: peer.publicKeyFingerprint,
    pairedAt: new Date().toISOString(),
    status: peer.mode === "active-active-tunnel" ? "online" : "standby",
  };
  state.federation.peers[safeId] = record;
  saveState(state);
  return record;
}

export interface FederationSyncBundle {
  sourceNodeId: string;
  exportedAt: string;
  cloudflare: {
    accountId: string;
    tunnelId: string;
    baseDomain: string;
  };
  apps: Record<string, AppRecord>;
  vaultScopes: Record<string, Record<string, string>>;
}

export function buildEncryptedFederationSyncBundle(): {
  encryptedBase64: string;
  hmacSignature: string;
  appsCount: number;
  scopesCount: number;
} {
  const state = loadState();
  const clusterKey = getOrCreateFederationClusterKey();

  const vaultScopes: Record<string, Record<string, string>> = {};
  for (const appSlug of Object.keys(state.apps)) {
    if (appSlug === "paasmcp-dashboard") continue;
    vaultScopes[appSlug] = getSecrets(appSlug);
  }

  const bundle: FederationSyncBundle = {
    sourceNodeId: state.federation?.nodeId || "primary",
    exportedAt: new Date().toISOString(),
    cloudflare: {
      accountId: state.cloudflare.accountId,
      tunnelId: state.cloudflare.tunnelId,
      baseDomain: state.cloudflare.baseDomain,
    },
    apps: state.apps,
    vaultScopes,
  };

  const plainBuf = Buffer.from(JSON.stringify(bundle), "utf-8");
  const encryptedBuf = encryptBinaryPayload(plainBuf, clusterKey);
  const encryptedBase64 = encryptedBuf.toString("base64");
  const hmacSignature = crypto
    .createHmac("sha256", clusterKey)
    .update(encryptedBase64, "utf-8")
    .digest("hex");

  return {
    encryptedBase64,
    hmacSignature,
    appsCount: Object.keys(state.apps).length,
    scopesCount: Object.keys(vaultScopes).length,
  };
}

export function applyEncryptedFederationSyncBundle(
  encryptedBase64: string,
  hmacSignature: string
): {
  importedApps: string[];
  importedScopes: string[];
  skippedConflicts: string[];
  sourceNodeId: string;
} {
  const clusterKey = getOrCreateFederationClusterKey();
  const expectedSig = crypto
    .createHmac("sha256", clusterKey)
    .update(encryptedBase64, "utf-8")
    .digest("hex");

  if (!timingSafeCompare(expectedSig, hmacSignature)) {
    throw new Error("Federation Sync Bundle HMAC signature verification failed!");
  }

  const encryptedBuf = Buffer.from(encryptedBase64, "base64");
  const decryptedBuf = decryptBinaryPayload(encryptedBuf, clusterKey);
  const bundle = JSON.parse(decryptedBuf.toString("utf-8")) as FederationSyncBundle;

  const state = loadState();
  // An app that already lives here (ours, or from another peer) is never overwritten by a peer's copy.
  const conflicts = Object.keys(bundle.apps || {})
    .map((slug) => sanitizeSlug(slug))
    .filter((slug) => state.apps[slug] && state.apps[slug].originNodeId !== bundle.sourceNodeId);
  const importedScopes: string[] = [];
  for (const [scope, secrets] of Object.entries(bundle.vaultScopes || {})) {
    const safeScope = sanitizeSlug(scope);
    if (conflicts.includes(safeScope) || safeScope === "system") continue;
    saveSecrets(safeScope, secrets);
    importedScopes.push(safeScope);
  }

  const importedApps: string[] = [];
  for (const [slug, appRec] of Object.entries(bundle.apps || {})) {
    if (slug === "paasmcp-dashboard") continue;
    const safeSlug = sanitizeSlug(slug);
    if (conflicts.includes(safeSlug)) continue;
    const others = Object.values(state.apps).filter((a) => a.name !== safeSlug);
    const portTaken = others.some((a) => a.localPort === appRec.localPort);
    state.apps[safeSlug] = {
      ...appRec,
      name: safeSlug,
      originNodeId: bundle.sourceNodeId,
      localPort: portTaken ? allocateAppPort({ ...state, apps: Object.fromEntries(others.map((a) => [a.name, a])) }) : appRec.localPort,
    };
    importedApps.push(safeSlug);
  }

  if (bundle.cloudflare?.baseDomain && state.cloudflare.baseDomain === "example.com") {
    state.cloudflare.accountId = bundle.cloudflare.accountId;
    state.cloudflare.tunnelId = bundle.cloudflare.tunnelId;
    state.cloudflare.baseDomain = bundle.cloudflare.baseDomain;
  }

  saveState(state);
  return {
    importedApps,
    importedScopes,
    skippedConflicts: conflicts,
    sourceNodeId: bundle.sourceNodeId,
  };
}
