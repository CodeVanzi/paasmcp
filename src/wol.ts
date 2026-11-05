import dgram from "node:dgram";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PAAS_DATA_DIR, PoolHelperRecord, writeFileAtomic } from "./config.js";
import { audit } from "./guard.js";
import { normalizeMac, validateIpv4 } from "./poolproto.js";

// Wake-on-LAN, the low-level part: the magic packet, where it goes, and what was sent to whom.
//
// A helper PC on the same home network as this server can sleep (or be off) while nobody needs it. When
// a copy must run and no awake helper has room, this server sends its card a magic packet: 6 bytes 0xff
// and its MAC 16 times, by UDP to the network's broadcast address. The PC takes 30 s to a minute to
// answer, so this helps load that lasts, not short peaks. Nothing secret travels: anyone on the network
// can send the same packet; what decides whether a PC may be woken is the person who turns it on for it.
//
// Each PC gets a few tries (one per `wakeWaitMs`); after `WAKE_TRIES` without an answer it is left alone
// until it answers again or a person wakes it by hand. The record of tries lives in pool/wake.json, apart
// from state.json, so sending never needs the state lock. The decisions that use it are in pool.ts
// (placement) and wake.ts (the follow-up of every scale round).

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
const WAKE_FILE = () => path.join(PAAS_DATA_DIR, "pool", "wake.json");
/** Tries before a PC that never answers is left alone. */
export const WAKE_TRIES = 3;
/** How long a PC gets to answer after a magic packet before another is sent. */
export const wakeWaitMs = () => Math.max(5, Number(process.env.PAASMCP_WAKE_WAIT_SECONDS ?? 180) || 180) * 1000;
/** How soon the decider tries a step again after waking a PC for it. */
export const wakeRecheckMs = () => Math.max(5, Number(process.env.PAASMCP_WAKE_RECHECK_SECONDS ?? 60) || 60) * 1000;
/** A PC that answered stays on the follow-up list this long while the state is busy. */
const FOLLOW_MAX_MS = 30 * 60 * 1000;

export interface WakeConfig {
  mac: string;
  broadcast: string;
  port: number;
}

// ---------- the packet and where it goes (pure) ----------

/** The magic packet: 6 bytes 0xff, then the MAC 16 times (102 bytes). */
export function magicPacket(macIn: string): Buffer {
  const mac = Buffer.from(normalizeMac(macIn).replace(/:/g, ""), "hex");
  return Buffer.concat([Buffer.alloc(6, 0xff), ...Array.from({ length: 16 }, () => mac)]);
}

const ipNum = (ip: string) => validateIpv4(ip).split(".").reduce((n, o) => n * 256 + Number(o), 0);
const numIp = (n: number) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");

/** The broadcast address of `ip/prefix` (prefix 8 to 30). */
export function broadcastFor(ip: string, prefix: number): string {
  if (!Number.isInteger(prefix) || prefix < 8 || prefix > 30) throw new Error("The network prefix must be 8 to 30.");
  const host = 2 ** (32 - prefix);
  return numIp(Math.floor(ipNum(ip) / host) * host + host - 1);
}

/** 10/8, 172.16/12, 192.168/16: a home or office network. */
export function isPrivateIpv4(ip: string): boolean {
  const [a, b] = validateIpv4(ip).split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * Where magic packets may go: a broadcast address on a private network, or 255.255.255.255 (the network
 * of this server's default route). Never a public address: this is not a way to send UDP to the internet.
 */
export function validateBroadcast(v: unknown): string {
  const ip = validateIpv4(String(v ?? "").trim(), "broadcast address");
  if (ip === "255.255.255.255") return ip;
  if (!isPrivateIpv4(ip)) {
    throw new Error("Wake-on-LAN works only inside a home or office network: the broadcast address must be in 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16 (or 255.255.255.255).");
  }
  // The last address of a network (/30 or larger) ends in binary 11: a single machine's address would
  // turn the packet into plain UDP aimed at it.
  if (ipNum(ip) % 4 !== 3) throw new Error(`${ip} is not a broadcast address: it is the last address of the network, for example 192.168.1.255 for 192.168.1.0/24.`);
  return ip;
}

/** Magic packets go to UDP port 9 (discard), or 7 (echo) for cards that listen there; nothing else. */
export function validateWakePort(v: unknown): number {
  if (v === undefined || v === null || v === "") return 9;
  const port = Number(v);
  if (port !== 9 && port !== 7) throw new Error("The Wake-on-LAN port is 9 (the usual one) or 7.");
  return port;
}

/** This server's own address on the network of `broadcast`, if it has one (magic packets do not cross routers). */
export function originAddressFor(broadcast: string, ifaces: NodeJS.Dict<os.NetworkInterfaceInfo[]> = os.networkInterfaces()): string | undefined {
  for (const list of Object.values(ifaces)) {
    for (const a of list || []) {
      if (a.family !== "IPv4" || a.internal || !a.cidr) continue;
      const prefix = Number(a.cidr.split("/")[1]);
      if (broadcast === "255.255.255.255" || (prefix >= 8 && prefix <= 30 && broadcastFor(a.address, prefix) === broadcast)) return a.address;
    }
  }
  return undefined;
}

/** A helper's Wake-on-LAN settings, checked again (state.json can be edited by hand). */
export function wakeOf(h: Pick<PoolHelperRecord, "wake">): WakeConfig | undefined {
  const w = h.wake;
  if (!w) return undefined;
  try {
    return { mac: normalizeMac(w.mac), broadcast: validateBroadcast(w.broadcast), port: validateWakePort(w.port) };
  } catch {
    return undefined;
  }
}

/** Packets "sent" while testing offline (nothing leaves the machine then). */
export const offlineSent: { mac: string; broadcast: string; port: number }[] = [];

/** Sends the magic packet (twice, 100 ms apart: UDP may lose one). */
export async function sendMagicPacket(cfg: WakeConfig): Promise<void> {
  const packet = magicPacket(cfg.mac);
  if (OFFLINE()) {
    offlineSent.push({ ...cfg });
    return;
  }
  const sock = dgram.createSocket("udp4");
  try {
    await new Promise<void>((resolve, reject) => {
      sock.once("error", reject);
      sock.bind(0, () => resolve());
    });
    sock.setBroadcast(true);
    for (let i = 0; i < 2; i++) {
      if (i) await new Promise((r) => setTimeout(r, 100));
      await new Promise<void>((resolve, reject) => sock.send(packet, cfg.port, cfg.broadcast, (err) => (err ? reject(err) : resolve())));
    }
  } finally {
    sock.close();
  }
}

// ---------- what was sent (pool/wake.json) ----------

export interface WakeTrack {
  /** The first packet of this series, and the last one. */
  firstSentAt: number;
  sentAt: number;
  tries: number;
  /** Apps that needed the PC (their diary hears whether it woke). */
  apps: string[];
  /** Set when the tries ran out: no more packets until it answers or a person wakes it. */
  gaveUpAt?: number;
}

interface WakeFile {
  v: 1;
  helpers: Record<string, WakeTrack>;
  /** PCs that answered after a packet: the next round puts back the copies they should run. */
  follow: Record<string, number>;
}

export function readWake(): WakeFile {
  try {
    const f = JSON.parse(fs.readFileSync(WAKE_FILE(), "utf-8"));
    if (f && f.v === 1 && f.helpers && typeof f.helpers === "object") return { v: 1, helpers: f.helpers, follow: f.follow && typeof f.follow === "object" ? f.follow : {} };
  } catch {
    // nothing sent yet
  }
  return { v: 1, helpers: {}, follow: {} };
}

export function writeWake(update: (f: WakeFile) => void): WakeFile {
  const f = readWake();
  update(f);
  fs.mkdirSync(path.dirname(WAKE_FILE()), { recursive: true, mode: 0o700 });
  writeFileAtomic(WAKE_FILE(), JSON.stringify(f));
  return f;
}

export type WakeStatus = "idle" | "waking" | "retry" | "gave_up";

/**
 * Where a PC stands (pure): never sent (idle), waiting for its answer (waking), time for another try
 * (retry), or the tries ran out (gave_up).
 */
export function wakeStatus(t: WakeTrack | undefined, now: number, waitMs = wakeWaitMs(), tries = WAKE_TRIES): WakeStatus {
  if (!t) return "idle";
  if (t.gaveUpAt !== undefined) return "gave_up";
  if (now >= t.sentAt && now - t.sentAt < waitMs) return "waking";
  return t.tries >= tries ? "gave_up" : "retry";
}

/**
 * Wakes a helper unless a packet is already on its way: sends when it never was, or its wait ran out with
 * tries left (or `force`, a person's "wake now", which starts the tries over). `app` is noted so its diary
 * hears the result.
 */
export async function wakeHelper(
  h: Pick<PoolHelperRecord, "name" | "wake">,
  opts: { app?: string; now?: number; force?: boolean; by?: string } = {}
): Promise<{ state: "sent" | "waking" | "gave_up" | "off"; tries?: number }> {
  const cfg = wakeOf(h);
  if (!cfg) return { state: "off" };
  const now = opts.now ?? Date.now();
  const before = readWake().helpers[h.name];
  const st = opts.force ? "idle" : wakeStatus(before, now);
  // The apps that needed it stay listed across a person's "wake now" (a new series): they still want to know.
  const apps = [...new Set([...(before?.apps || []), ...(opts.app ? [opts.app] : [])])].slice(-20);
  if (st === "waking" || st === "gave_up") {
    if (opts.app && !before!.apps.includes(opts.app)) writeWake((f) => f.helpers[h.name] && (f.helpers[h.name].apps = apps));
    return { state: st, tries: before!.tries };
  }
  await sendMagicPacket(cfg);
  const tries = st === "retry" ? before!.tries + 1 : 1;
  writeWake((f) => {
    f.helpers[h.name] = { firstSentAt: st === "retry" ? before!.firstSentAt : now, sentAt: now, tries, apps };
  });
  audit({ event: "pool.wake.sent", helper: h.name, mac: cfg.mac, to: `${cfg.broadcast}:${cfg.port}`, tries, by: opts.by || (opts.app ? `decider:${opts.app}` : "pool") });
  return { state: "sent", tries };
}

/**
 * Helpers that answered: their record of tries ends, and they go on the follow-up list so the next round
 * puts back the copies they should run. Returns those that were being woken (and how long it took).
 */
export function noteWakeAnswers(names: string[], now = Date.now()): { helper: string; seconds: number; apps: string[]; gaveUp: boolean }[] {
  const f = readWake();
  const woke = names.filter((n) => f.helpers[n]);
  if (!woke.length) return [];
  const out = woke.map((n) => {
    const t = f.helpers[n];
    return { helper: n, seconds: Math.max(0, Math.round((now - t.firstSentAt) / 1000)), apps: t.apps || [], gaveUp: t.gaveUpAt !== undefined };
  });
  writeWake((w) => {
    for (const n of woke) {
      delete w.helpers[n];
      w.follow[n] = now;
    }
  });
  return out;
}

/** Forgets what was sent to a PC (wake turned off, the PC removed). */
export function clearWake(name: string): void {
  const f = readWake();
  if (f.helpers[name] || f.follow[name]) {
    writeWake((w) => {
      delete w.helpers[name];
      delete w.follow[name];
    });
  }
}

/** Follow-ups older than half an hour are dropped (the state stayed busy that long: other rounds reconciled). */
export function freshFollowUps(f: WakeFile, now: number): string[] {
  return Object.entries(f.follow)
    .filter(([, at]) => typeof at === "number" && now - at < FOLLOW_MAX_MS)
    .map(([n]) => n);
}
