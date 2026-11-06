import fs from "node:fs";
import os from "node:os";
import { HOMELAB_ROOT } from "./config.js";
import type { RawStats } from "./scale.js";

/**
 * Server resources for the dashboard's "Resource usage" card: how much the server has,
 * how much PaaSMCP's own containers use (apps, shared databases, the dashboard) and how much
 * everything else uses (other programs, other containers, the system).
 *
 * Works the same on the host and inside the dashboard container: /proc/stat and /proc/meminfo
 * are not namespaced, so they describe the whole server, and the data folder (PAASMCP_ROOT)
 * is mounted from the host, so its disk is the server's disk.
 */

/** Cumulative CPU time of every core, from os.cpus() (milliseconds). */
export interface CpuSample {
  busy: number;
  total: number;
  at: number;
}

export function cpuSample(cpus: os.CpuInfo[] = os.cpus(), at = Date.now()): CpuSample {
  let busy = 0;
  let total = 0;
  for (const c of cpus) {
    const t = c.times;
    const sum = t.user + t.nice + t.sys + t.idle + t.irq;
    total += sum;
    busy += sum - t.idle;
  }
  return { busy, total, at };
}

/** Share of the whole server's CPU in use between two samples (0..100), or null when too close. */
export function cpuPercentBetween(a: CpuSample, b: CpuSample): number | null {
  const dt = b.total - a.total;
  if (!(dt > 0)) return null;
  const pct = ((b.busy - a.busy) / dt) * 100;
  return Math.min(100, Math.max(0, pct));
}

/** MemAvailable from /proc/meminfo (what can be used without swapping), in bytes. */
export function memAvailableBytes(meminfo?: string): number | null {
  let text = meminfo;
  if (text === undefined) {
    try {
      text = fs.readFileSync("/proc/meminfo", "utf-8");
    } catch {
      return null;
    }
  }
  const m = /^MemAvailable:\s+(\d+)\s*kB/m.exec(text);
  return m ? Number(m[1]) * 1024 : null;
}

export interface ResourceSplit {
  /** Everything PaaSMCP runs: containers named paasmcp-* (apps, copies, databases, dashboard). */
  paasmcp: number;
  /** Other programs, other containers and the system. */
  others: number;
}

export interface HostResources {
  cpu: {
    cores: number;
    /** Whole server, 0..100; null while the first measurement is not ready. */
    usedPercent: number | null;
    /** Same scale as usedPercent (share of the whole server), null when unknown. */
    split: ResourceSplit | null;
    load1: number;
  };
  memory: {
    totalBytes: number;
    usedBytes: number;
    availableBytes: number;
    split: ResourceSplit | null;
  };
  disk: {
    path: string;
    totalBytes: number;
    usedBytes: number;
    freeBytes: number;
    usedPercent: number;
  } | null;
  /** Containers counted under PaaSMCP, largest memory first (at most 5). */
  top: { name: string; cpuPercent: number | null; memBytes: number | null }[];
}

export function diskUsage(dir: string = HOMELAB_ROOT): HostResources["disk"] {
  // The data folder may not exist yet on a fresh install: measure the nearest existing parent.
  let p = dir;
  while (!fs.existsSync(p) && p !== "/" && p) p = p.replace(/\/[^/]+\/?$/, "") || "/";
  try {
    const s = fs.statfsSync(p);
    const total = s.blocks * s.bsize;
    const free = s.bavail * s.bsize;
    const used = (s.blocks - s.bfree) * s.bsize;
    // Like df: the share of the space ordinary programs can use.
    const usable = used + free;
    return {
      path: p,
      totalBytes: total,
      usedBytes: used,
      freeBytes: free,
      usedPercent: usable > 0 ? Math.round((used / usable) * 100) : 0,
    };
  } catch {
    return null;
  }
}

/** Remembered between calls so a status without `docker stats` still has a fresh CPU reading. */
let previousSample: CpuSample | null = null;

/** Only for tests. */
export function resetCpuMemory(): void {
  previousSample = null;
}

export function hostResources(opts: {
  /** CPU sample taken just before `docker stats` ran (aligns the two readings). */
  cpuBefore?: CpuSample;
  /** Parsed `docker stats` (scale.parseDockerStats); empty when Docker was not asked. */
  stats?: Record<string, RawStats>;
  statsRan?: boolean;
  now?: CpuSample;
  totalMem?: number;
  availableMem?: number | null;
  disk?: HostResources["disk"];
  load1?: number;
}): HostResources {
  const now = opts.now || cpuSample();
  const cores = Math.max(1, os.cpus().length);

  // The reading over the docker stats window lines up with the containers' numbers; when that
  // window was too short (no Docker), use the time since the previous status instead.
  let usedPercent: number | null = null;
  if (opts.cpuBefore && now.at - opts.cpuBefore.at >= 500) usedPercent = cpuPercentBetween(opts.cpuBefore, now);
  if (usedPercent === null && previousSample && now.at - previousSample.at <= 120_000) {
    usedPercent = cpuPercentBetween(previousSample, now);
  }
  previousSample = now;

  const total = opts.totalMem ?? os.totalmem();
  const avail = opts.availableMem !== undefined ? opts.availableMem : memAvailableBytes();
  const available = Math.min(total, Math.max(0, avail ?? os.freemem()));
  const used = total - available;

  const rows = Object.entries(opts.stats || {}).filter(([name]) => name.startsWith("paasmcp-"));
  let paasCpuCores = 0;
  let paasMem = 0;
  for (const [, r] of rows) {
    paasCpuCores += (r.cpu ?? 0) / 100;
    paasMem += (r.mem ?? 0) * 1024 * 1024;
  }

  let cpuSplit: ResourceSplit | null = null;
  let memSplit: ResourceSplit | null = null;
  if (opts.statsRan) {
    // The two readings come from different sources a moment apart: never let PaaSMCP exceed the total.
    if (usedPercent !== null) {
      const paas = Math.min(usedPercent, (paasCpuCores / cores) * 100);
      cpuSplit = { paasmcp: paas, others: usedPercent - paas };
    }
    const paas = Math.min(used, paasMem);
    memSplit = { paasmcp: paas, others: used - paas };
  }

  const top = rows
    .map(([name, r]) => ({ name, cpuPercent: r.cpu, memBytes: r.mem === null ? null : r.mem * 1024 * 1024 }))
    .sort((a, b) => (b.memBytes ?? 0) - (a.memBytes ?? 0))
    .slice(0, 5);

  const round1 = (n: number) => Math.round(n * 10) / 10;
  return {
    cpu: {
      cores,
      usedPercent: usedPercent === null ? null : round1(usedPercent),
      split: cpuSplit && { paasmcp: round1(cpuSplit.paasmcp), others: round1(cpuSplit.others) },
      load1: round1(opts.load1 ?? os.loadavg()[0]),
    },
    memory: { totalBytes: total, usedBytes: used, availableBytes: available, split: memSplit },
    disk: opts.disk !== undefined ? opts.disk : diskUsage(),
    top,
  };
}
