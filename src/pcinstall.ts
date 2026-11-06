import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { loadState, PAAS_DATA_DIR } from "./config.js";
import { listTailscalePeers, probeArbiter, TailscalePeer } from "./judge.js";

// "PCs of your Tailscale" (Connections > PCs): every device of the Tailscale network, marked with
// whether it already runs PaaSMCP and whether PaaSMCP could be installed on it from here.
//
// The list only reads: `tailscale status`, what this server already knows (helpers, the other server
// of a pair, federation peers, PCs installed from this dashboard), and two harmless probes per online
// Linux device: the arbiter's /health on 4097 and the first line the SSH port sends (which says
// whether Tailscale SSH or OpenSSH answers there). Nothing logs in anywhere.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

export type PcState = "paasmcp" | "installable" | "offline" | "unsupported";
/** Why a device cannot get PaaSMCP from here. */
export type PcWhyNot = "notLinux" | "shared" | "otherOwner" | "noIp";
/** How PaaSMCP shows up on a device: what this server knows it as, or what answered. */
export type PcRole = "pair" | "helper" | "federation" | "arbiter" | "installed";
/** What answers on the device's SSH port: Tailscale SSH (no password), OpenSSH, or nothing. */
export type PcSsh = "tailscale" | "openssh" | "other" | "closed";

export interface TailnetPc {
  name: string;
  ip: string;
  os?: string;
  online: boolean;
  state: PcState;
  why?: PcWhyNot;
  roles: PcRole[];
  ssh?: PcSsh;
  /** Its Tailscale SSH host keys are known (the identity check needs no question). */
  hostKeysKnown?: boolean;
}

/** PCs installed from this dashboard (kept so the list knows them even before anything answers). */
export const INSTALLS_FILE = () => path.join(PAAS_DATA_DIR, "pcinstall", "installs.json");

export interface InstallRecord {
  name: string;
  ip: string;
  role: string;
  commit?: string;
  at: string;
  by: string;
}

export function readInstalls(): InstallRecord[] {
  try {
    const raw = JSON.parse(fs.readFileSync(INSTALLS_FILE(), "utf-8"));
    return Array.isArray(raw) ? (raw as InstallRecord[]).slice(-200) : [];
  } catch {
    return [];
  }
}

/** Tailscale IPs this server already knows as PaaSMCP, with how. */
export function knownPaasmcpIps(state = loadState()): Map<string, Set<PcRole>> {
  const out = new Map<string, Set<PcRole>>();
  const add = (ip: string | undefined, role: PcRole) => {
    const v = String(ip || "").trim();
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return;
    if (!out.has(v)) out.set(v, new Set());
    out.get(v)!.add(role);
  };
  for (const h of Object.values(state.pool?.helpers || {})) add(h.ip, "helper");
  for (const r of Object.values(state.mirror?.replicas || {})) add(r.peerHost, "pair");
  for (const o of Object.values(state.mirror?.offers || {})) add(o.peerCidr?.split("/")[0], "pair");
  for (const p of Object.values(state.federation?.peers || {})) {
    try {
      add(new URL(p.endpointUrl).hostname, "federation");
    } catch {
      /* not a URL */
    }
  }
  for (const i of readInstalls()) add(i.ip, "installed");
  return out;
}

/** The first line an SSH server sends ("SSH-2.0-Tailscale", "SSH-2.0-OpenSSH_9.6p1 ..."). */
export function sshBanner(ip: string, port = 22, ms = 1500): Promise<string | undefined> {
  return new Promise((resolve) => {
    let buf = "";
    const done = (v: string | undefined) => {
      sock.destroy();
      resolve(v);
    };
    const sock = net.connect({ host: ip, port });
    sock.setTimeout(ms, () => done(buf ? buf.split(/\r?\n/)[0] : undefined));
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      if (buf.includes("\n") || buf.length > 255) done(buf.split(/\r?\n/)[0].slice(0, 255));
    });
    sock.on("error", () => done(undefined));
    sock.on("end", () => done(buf ? buf.split(/\r?\n/)[0] : undefined));
  });
}

export function sshKind(banner: string | undefined): PcSsh {
  if (!banner) return "closed";
  if (/^SSH-2\.0-Tailscale/i.test(banner)) return "tailscale";
  if (/^SSH-2\.0-OpenSSH/i.test(banner)) return "openssh";
  return "other";
}

/** Linux and not a phone: Tailscale reports "linux" for Linux PCs and servers. */
const isLinux = (os?: string) => String(os || "").toLowerCase() === "linux";

export function classifyPc(p: TailscalePeer, known: Set<PcRole> | undefined): Pick<TailnetPc, "state" | "why"> {
  if (known?.size) return { state: "paasmcp" };
  if (!p.ip) return { state: "unsupported", why: "noIp" };
  if (p.shared) return { state: "unsupported", why: "shared" };
  if (p.otherOwner) return { state: "unsupported", why: "otherOwner" };
  if (!isLinux(p.os)) return { state: "unsupported", why: "notLinux" };
  if (!p.online) return { state: "offline" };
  return { state: "installable" };
}

const ORDER: Record<PcState, number> = { installable: 0, paasmcp: 1, offline: 2, unsupported: 3 };

/**
 * Every device of the Tailscale network for Connections > PCs. `statusJson` and `probe` are for tests
 * (probe=false skips the network probes).
 */
export async function listTailnetPcs(opts: { statusJson?: string; probe?: boolean } = {}): Promise<{ pcs: TailnetPc[]; selfIp?: string; error?: string }> {
  const { peers, selfIp, error } = listTailscalePeers(opts.statusJson);
  if (error) return { pcs: [], error };
  const known = knownPaasmcpIps();
  const probe = opts.probe ?? !OFFLINE();
  const pcs = await Promise.all(
    peers.slice(0, 100).map(async (p): Promise<TailnetPc> => {
      const roles = new Set<PcRole>(known.get(p.ip) || []);
      let ssh: PcSsh | undefined;
      // Only online Linux devices of the owner are probed: phones and other people's devices never are.
      if (probe && p.online && p.ip && isLinux(p.os) && !p.shared && !p.otherOwner) {
        const [arb, banner] = await Promise.all([probeArbiter(p.ip), sshBanner(p.ip, 22, 3000)]);
        if (arb.arbiter) roles.add("arbiter");
        ssh = sshKind(banner);
      }
      const c = classifyPc(p, roles);
      return {
        name: p.name,
        ip: p.ip,
        ...(p.os ? { os: p.os } : {}),
        online: p.online,
        ...c,
        roles: [...roles].sort(),
        ...(ssh ? { ssh } : {}),
        ...(p.sshHostKeys?.length ? { hostKeysKnown: true } : {}),
      };
    })
  );
  pcs.sort((a, b) => ORDER[a.state] - ORDER[b.state] || a.name.localeCompare(b.name));
  return { pcs, selfIp };
}
