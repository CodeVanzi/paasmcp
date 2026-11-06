import { execFileSync } from "node:child_process";
import { loadState, saveState, WakeTargetRecord } from "./config.js";
import { audit } from "./guard.js";
import { normalizeMac } from "./poolproto.js";
import { sendMagicPacket, validateBroadcast, validateWakePort, WakeConfig } from "./wol.js";

// Turning on a PC of the same home network by Wake-on-LAN, by hand ("Ligar" in Connections > PCs,
// `paasmcp wake <name>`). Unlike the helper pool (wol.ts / wake.ts), nothing decides here: a person
// asks, this server sends the magic packet. Typical use: a server at home that sleeps or is off, woken
// from the dashboard of another PaaSMCP server on the same network, reached from anywhere.
//
// Nothing secret travels (anyone on the network can send the same packet): adding a PC and waking it
// are free actions, recorded in the audit log. The packet only goes to a broadcast address of a private
// network (validateBroadcast), never to the internet.

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function validateWakeTargetName(v: unknown): string {
  const name = String(v ?? "").trim().toLowerCase();
  if (!NAME_RE.test(name)) throw new Error("The PC name is its Tailscale name: lowercase letters, digits and dashes (for example labserver).");
  return name;
}

/** A saved PC, checked again (state.json can be edited by hand). */
export function wakeTargetConfig(rec: Pick<WakeTargetRecord, "mac" | "broadcast" | "port"> | undefined): WakeConfig | undefined {
  if (!rec) return undefined;
  try {
    return { mac: normalizeMac(rec.mac), broadcast: validateBroadcast(rec.broadcast), port: validateWakePort(rec.port) };
  } catch {
    return undefined;
  }
}

export function listWakeTargets(): { name: string; mac: string; broadcast: string; port: number; addedAt: string }[] {
  return Object.entries(loadState().wakeTargets || {})
    .map(([name, r]) => ({ name, mac: r.mac, broadcast: r.broadcast, port: r.port, addedAt: r.addedAt }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Saves (or replaces) how to turn on `name`. The broadcast defaults to 255.255.255.255: this server's own network. */
export function addWakeTarget(nameIn: unknown, opts: { mac: unknown; broadcast?: unknown; port?: unknown; by?: string }): WakeTargetRecord & { name: string } {
  const name = validateWakeTargetName(nameIn);
  const rec: WakeTargetRecord = {
    mac: normalizeMac(opts.mac),
    broadcast: validateBroadcast(opts.broadcast === undefined || opts.broadcast === "" ? "255.255.255.255" : opts.broadcast),
    port: validateWakePort(opts.port),
    addedAt: new Date().toISOString(),
  };
  const state = loadState();
  state.wakeTargets = { ...(state.wakeTargets || {}), [name]: rec };
  saveState(state);
  audit({ event: "wake.add", pc: name, by: opts.by || "cli" });
  return { name, ...rec };
}

export function removeWakeTarget(nameIn: unknown, by = "cli"): { name: string; removed: boolean } {
  const name = validateWakeTargetName(nameIn);
  const state = loadState();
  const removed = Boolean(state.wakeTargets?.[name]);
  if (removed) {
    delete state.wakeTargets![name];
    saveState(state);
    audit({ event: "wake.remove", pc: name, by });
  }
  return { name, removed };
}

/**
 * docker run arguments that send the packet from the host's network. Inside the dashboard container a
 * broadcast stays on the Docker bridge, so the dashboard sends it from a short-lived container on the
 * host network (its own image, nothing mounted). Every value is validated first and passed as argv.
 */
export function hostSenderArgs(cfg: WakeConfig, image: string): string[] {
  const mac = normalizeMac(cfg.mac);
  const broadcast = validateBroadcast(cfg.broadcast);
  const port = validateWakePort(cfg.port);
  const script =
    "const d=require('dgram');const [m,b,p]=process.argv.slice(1);" +
    "const mac=Buffer.from(m.replace(/:/g,''),'hex');const pk=Buffer.concat([Buffer.alloc(6,255),...Array(16).fill(mac)]);" +
    "const s=d.createSocket('udp4');s.bind(0,()=>{s.setBroadcast(true);s.send(pk,+p,b,()=>setTimeout(()=>s.send(pk,+p,b,()=>s.close()),100));});";
  return ["run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL", "--memory", "64m", image, "node", "-e", script, mac, broadcast, String(port)];
}

/** Sends the magic packet to a saved PC. */
export async function wakeTarget(nameIn: unknown, opts: { by?: string; dashboardImage?: string } = {}): Promise<{ name: string; sent: true; mac: string; to: string }> {
  const name = validateWakeTargetName(nameIn);
  const cfg = wakeTargetConfig(loadState().wakeTargets?.[name]);
  if (!cfg) throw new Error(`'${name}' is not set up to be turned on from here: paasmcp wake add ${name} --mac <its card's MAC>`);
  if (process.env.PAASMCP_IN_DASHBOARD === "1" && process.env.PAASMCP_OFFLINE_TEST !== "1") {
    if (!opts.dashboardImage) throw new Error("Unknown dashboard image.");
    execFileSync("docker", hostSenderArgs(cfg, opts.dashboardImage), { stdio: "pipe", timeout: 60_000 });
  } else {
    await sendMagicPacket(cfg);
  }
  audit({ event: "wake.now", pc: name, by: opts.by || "cli" });
  return { name, sent: true, mac: cfg.mac, to: `${cfg.broadcast}:${cfg.port}` };
}
