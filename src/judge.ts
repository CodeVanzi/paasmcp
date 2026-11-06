import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { HOMELAB_ROOT, loadState, WATCHTOWER_OFF_LABEL } from "./config.js";
import { ARBITER_DIR, arbiterClusterId, arbiterPairingStatus, closeArbiterPairing, openArbiterPairing, parseArbiterKeys } from "./arbiter.js";
import { audit } from "./guard.js";

// A PC that already runs PaaSMCP can be the arbiter (third vote) of another pair of servers, set up
// from its own dashboard: the arbiter runs in a small container (host network, so it answers on the
// PC's Tailscale address) that comes back after a reboot. Its code is a copy of the few compiled
// files the arbiter needs, kept next to its keys, so a dashboard update never pulls it from under it.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
export const JUDGE_CONTAINER = "paasmcp-arbiter";
export const JUDGE_PORT = () => Number(process.env.PAASMCP_ARBITER_PORT || 4097);
const JUDGE_IMAGE = "node:22.11.0-alpine3.20";
/** Compiled files the arbiter imports (arbiter.js and what it pulls in). A test keeps this list honest. */
export const JUDGE_FILES = ["arbiter.js", "config.js", "vault.js", "poolproto.js"];
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

const keyFile = () => path.join(ARBITER_DIR(), "keys.env");
const stateFile = () => path.join(ARBITER_DIR(), "state.json");

/** This PC's Tailscale IPv4 (PAASMCP_ARBITER_HOST overrides it, for tests and odd setups). */
export function tailscaleIp(): string | undefined {
  const forced = process.env.PAASMCP_ARBITER_HOST;
  if (forced) return forced;
  if (OFFLINE()) return undefined;
  try {
    const ip = execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0].trim();
    return IPV4.test(ip) ? ip : undefined;
  } catch {
    return undefined;
  }
}

async function health(url: string, ms = 2000): Promise<{ service?: string; pairing?: boolean } | undefined> {
  try {
    const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(ms) });
    return (await r.json()) as never;
  } catch {
    return undefined;
  }
}

/** Copies the arbiter's compiled files into the arbiter folder (replaced as a whole). */
export function writeJudgeBundle(fromDist = path.dirname(new URL(import.meta.url).pathname)): string {
  const codeDir = path.join(ARBITER_DIR(), "code");
  const tmp = `${codeDir}.tmp`;
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(path.join(tmp, "dist"), { recursive: true, mode: 0o700 });
  for (const f of JUDGE_FILES) fs.copyFileSync(path.join(fromDist, f), path.join(tmp, "dist", f));
  let version = "";
  try {
    version = String(JSON.parse(fs.readFileSync(path.join(fromDist, "..", "package.json"), "utf-8")).version || "");
  } catch {
    // unknown version
  }
  fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "paasmcp-arbiter", version, type: "module", private: true }));
  fs.writeFileSync(
    path.join(tmp, "judge.js"),
    `import { serveArbiter } from "./dist/arbiter.js";\nconst srv = serveArbiter({ host: process.env.PAASMCP_ARBITER_HOST, port: Number(process.env.PAASMCP_ARBITER_PORT || 4097) });\nsrv.on("listening", () => console.error("Arbiter listening on", srv.address()));\nsrv.on("error", (e) => { console.error(e.message); process.exit(1); });\n`
  );
  fs.rmSync(codeDir, { recursive: true, force: true });
  fs.renameSync(tmp, codeDir);
  return codeDir;
}

/** Keys this PC serves as an arbiter, as cluster ids (never the keys). */
function servedClusters(): string[] {
  const ids = new Set<string>();
  for (const f of [keyFile(), process.env.PAASMCP_ARBITER_ENV_FILE || "/etc/paasmcp-arbiter.env"]) {
    try {
      const line = fs.readFileSync(f, "utf-8").split("\n").find((l) => l.startsWith("PAASMCP_ARBITER_KEY="));
      for (const k of parseArbiterKeys(line?.slice("PAASMCP_ARBITER_KEY=".length))) ids.add(arbiterClusterId(k));
    } catch {
      // not readable here
    }
  }
  return [...ids];
}

function containerRunning(): boolean {
  if (OFFLINE()) return false;
  try {
    return execFileSync("docker", ["inspect", "-f", "{{.State.Running}}", JUDGE_CONTAINER], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim() === "true";
  } catch {
    return false;
  }
}

export interface LocalJudge {
  /** This PC's arbiter answers on its Tailscale address. */
  running: boolean;
  /** The arbiter runs in the container this dashboard started (and can stop). */
  container: boolean;
  ip?: string;
  url?: string;
  /** Pairs of servers it serves (cluster ids). */
  clusters: string[];
  pairing: { open: boolean; code?: string; expiresAt?: number; triesLeft?: number };
  /** Why it cannot run here, when it cannot. */
  problem?: "noTailscale";
}

export async function localJudgeStatus(): Promise<LocalJudge> {
  const ip = tailscaleIp();
  const url = ip ? `http://${ip}:${JUDGE_PORT()}` : undefined;
  const h = url ? await health(url) : undefined;
  return {
    running: h?.service === "paasmcp-arbiter",
    container: containerRunning(),
    ...(ip ? { ip, url } : { problem: "noTailscale" as const }),
    clusters: servedClusters(),
    pairing: arbiterPairingStatus(),
  };
}

/** Starts the arbiter container here unless an arbiter (container or service) already answers. */
export async function ensureLocalJudge(run: (args: string[]) => void = (a) => execFileSync("docker", a, { stdio: "pipe" })): Promise<{ url: string; started: boolean }> {
  const ip = tailscaleIp();
  if (!ip) throw new Error("This PC has no Tailscale address: install Tailscale and sign in with the same account as the servers.");
  const url = `http://${ip}:${JUDGE_PORT()}`;
  if ((await health(url))?.service === "paasmcp-arbiter") return { url, started: false };
  const codeDir = writeJudgeBundle();
  const dir = ARBITER_DIR();
  run(["rm", "-f", JUDGE_CONTAINER]);
  run([
    "run", "-d", "--name", JUDGE_CONTAINER, "--restart", "unless-stopped", "--network", "host",
    "--label", WATCHTOWER_OFF_LABEL, "--memory", "128m",
    "-e", `PAASMCP_ROOT=${HOMELAB_ROOT}`,
    "-e", `PAASMCP_ARBITER_DIR=${dir}`,
    "-e", `PAASMCP_ARBITER_ENV_FILE=${keyFile()}`,
    "-e", `PAASMCP_ARBITER_STATE_FILE=${stateFile()}`,
    "-e", `PAASMCP_ARBITER_HOST=${ip}`,
    "-e", `PAASMCP_ARBITER_PORT=${JUDGE_PORT()}`,
    "-v", `${dir}:${dir}`,
    "-w", codeDir,
    JUDGE_IMAGE, "node", "judge.js",
  ]);
  for (let i = 0; i < 30; i++) {
    if ((await health(url, 1000))?.service === "paasmcp-arbiter") {
      audit({ event: "judge.started", url });
      return { url, started: true };
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`The arbiter container started but does not answer at ${url}. See 'docker logs ${JUDGE_CONTAINER}'.`);
}

/** “Be the arbiter of another pair”: makes sure the arbiter runs here and opens a pairing window. */
export async function beJudge(run?: (args: string[]) => void): Promise<{ url: string; code: string; expiresAt: number; host: string }> {
  const { url } = await ensureLocalJudge(run);
  const w = openArbiterPairing();
  audit({ event: "judge.pairing-opened", url });
  return { url, code: w.code, expiresAt: w.expiresAt, host: os.hostname() };
}

export function cancelJudgePairing(): void {
  closeArbiterPairing();
}

/** Stops the arbiter container (the pairs it served lose their arbiter: no automatic takeover until another one). */
export function stopLocalJudge(run: (args: string[]) => void = (a) => execFileSync("docker", a, { stdio: "pipe" })): void {
  closeArbiterPairing();
  run(["rm", "-f", JUDGE_CONTAINER]);
  audit({ event: "judge.stopped" });
}

export interface TailscalePeer {
  name: string;
  /** Tailscale IPv4 ("" when the device has none). */
  ip: string;
  os?: string;
  online: boolean;
  /** Shared into this network from another account (not one of the owner's own devices). */
  shared?: boolean;
  /** Belongs to another user of the network (a tagged device has no user and is not "other"). */
  otherOwner?: boolean;
  /** Tailscale tags (tag:...), when the device has any. */
  tags?: string[];
  /** SSH host keys the device told Tailscale about (only while its Tailscale SSH is on). */
  sshHostKeys?: string[];
}

type RawPeer = {
  HostName?: string; DNSName?: string; OS?: string; Online?: boolean; TailscaleIPs?: string[];
  UserID?: number; ShareeNode?: boolean; Tags?: string[]; sshHostKeys?: string[];
};
const TAG_RE = /^tag:[A-Za-z0-9-]{1,60}$/;
const HOST_KEY_RE = /^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) [A-Za-z0-9+/]{40,1000}={0,3}$/;

/**
 * The other devices of this Tailscale network, from `tailscale status --json` (`statusJson` in tests).
 * Every device is listed, online or not, with or without PaaSMCP.
 */
export function listTailscalePeers(statusJson?: string): { peers: TailscalePeer[]; selfIp?: string; error?: "noTailscale" | "offline" } {
  let raw = statusJson;
  if (raw === undefined) {
    if (OFFLINE()) return { peers: [], error: "offline" };
    try {
      raw = execFileSync("tailscale", ["status", "--json"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 8 * 1024 * 1024 });
    } catch {
      return { peers: [], error: "noTailscale" };
    }
  }
  let parsed: { Self?: { TailscaleIPs?: string[]; UserID?: number }; Peer?: Record<string, RawPeer> };
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { peers: [], error: "noTailscale" };
  }
  const peers = Object.values(parsed.Peer || {})
    .map((p) => ({
      name: String(p.HostName || String(p.DNSName || "").split(".")[0] || "?").slice(0, 80),
      ip: (p.TailscaleIPs || []).find((x) => IPV4.test(x)) || "",
      ...(p.OS ? { os: String(p.OS).slice(0, 20) } : {}),
      online: p.Online !== false,
      ...(p.ShareeNode === true ? { shared: true } : {}),
      ...(!(p.Tags || []).length && typeof p.UserID === "number" && typeof parsed.Self?.UserID === "number" && p.UserID !== parsed.Self.UserID ? { otherOwner: true } : {}),
      ...((p.Tags || []).length ? { tags: (p.Tags || []).filter((t) => TAG_RE.test(String(t))).slice(0, 20) } : {}),
      ...((p.sshHostKeys || []).length ? { sshHostKeys: (p.sshHostKeys || []).map((k) => String(k).trim().split(/\s+/).slice(0, 2).join(" ")).filter((k) => HOST_KEY_RE.test(k)).slice(0, 10) } : {}),
    }))
    .slice(0, 200);
  return { peers, selfIp: (parsed.Self?.TailscaleIPs || []).find((x) => IPV4.test(x)) };
}

/** Whether a device answers as a PaaSMCP arbiter on the usual port, and shows a pairing code. */
export async function probeArbiter(ip: string, ms = 1500): Promise<{ arbiter: boolean; pairing: boolean }> {
  const h = await health(`http://${ip}:${JUDGE_PORT()}`, ms);
  const arbiter = h?.service === "paasmcp-arbiter";
  return { arbiter, pairing: arbiter && h?.pairing === true };
}

export interface JudgeCandidate extends TailscalePeer {
  /** Answers as a PaaSMCP arbiter. */
  arbiter: boolean;
  /** Shows a pairing code right now. */
  pairing: boolean;
  /** One of the servers of this pair: it cannot be their arbiter. */
  inPair: boolean;
}

/** Online devices of this Tailscale network for the Arbiter tab, those showing a code first. */
export async function findJudgeCandidates(statusJson?: string): Promise<{ devices: JudgeCandidate[]; error?: string }> {
  const { peers, error } = listTailscalePeers(statusJson);
  if (error) return { devices: [], error };
  const state = loadState();
  const pairIps = new Set<string>();
  for (const r of Object.values(state.mirror?.replicas || {})) if (r.peerHost) pairIps.add(r.peerHost);
  for (const o of Object.values(state.mirror?.offers || {})) if (o.peerCidr) pairIps.add(o.peerCidr.split("/")[0]);
  const online = peers.filter((p) => p.online && p.ip).slice(0, 100);
  const devices = await Promise.all(online.map(async (p) => ({ ...p, ...(await probeArbiter(p.ip)), inPair: pairIps.has(p.ip) })));
  devices.sort((a, b) => Number(b.pairing) - Number(a.pairing) || Number(b.arbiter) - Number(a.arbiter) || Number(a.inPair) - Number(b.inPair) || a.name.localeCompare(b.name));
  return { devices };
}
