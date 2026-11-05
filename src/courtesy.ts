import fs from "node:fs";
import path from "node:path";
import { ensureDataDir, loadState, saveState, StateLockBusyError, withStateLock, writeFileAtomic } from "./config.js";
import { audit } from "./guard.js";
import { courtesyOf, Listing, POOL_DIR, pooledApps, probeHelpers, reconcilePool } from "./pool.js";
import type { PoolHelperRecord } from "./config.js";
import { readDiary } from "./scale.js";

// Courteous mode: a helper PC belongs to someone who also uses it, and the copies must never make it slow.
//
// Each order the origin sends, the helper's worker reports how much CPU the PC used outside the copies
// since the last one (worker.ts, poolproto.ownerShare): the owner's programs, mostly. Nothing runs on the
// PC in between. The scale round (scale.ts) asks every helper once a minute and decides here:
//   - the owner's share at or above the PC's limit (50% by default) twice in a row: the owner is using
//     the PC. In "auto" mode its copies leave the balancer, finish the visits in progress and stop, and
//     the same reconcile as a pause looks for another PC with room; in "warn" mode they stay, the diary
//     says so, and no new copy goes there;
//   - below 80% of the limit for 5 minutes: the PC is free again and missing copies come back.
// Readings the worker cannot trust (an image load, a copy that left, a window too short) count neither
// way. Changes are made under the state lock, waiting at most 2 s for it (busy: the next check redoes it).

const FILE = path.join(POOL_DIR, "courtesy.json");
/** Readings in a row at or above the limit before the copies move. */
export const BUSY_READINGS = 2;
/** Below this share of the limit the PC counts as free (between the two, nothing changes). */
export const CALM_SHARE = 0.8;
export const checkEveryMs = () => Math.max(5, Number(process.env.PAASMCP_COURTESY_EVERY_SECONDS ?? 60) || 60) * 1000;
export const calmForMs = () => Math.max(0, Number(process.env.PAASMCP_COURTESY_CALM_SECONDS ?? 300) || 0) * 1000;

export interface CourtesyTrack {
  /** Readings in a row at or above the limit. */
  high: number;
  /** Since when the readings stay below the calm line, while the owner is marked busy. */
  calmSince?: number;
  lastPct?: number;
  lastAt?: number;
}

interface CourtesyFile {
  v: 1;
  lastCheckAt?: number;
  helpers: Record<string, CourtesyTrack>;
}

/**
 * One reading of a helper (pure). `pct` is the owner's share of the PC's CPU, or null when the worker
 * could not tell (or did not answer): then nothing changes.
 */
export function courtesyObserve(
  track: CourtesyTrack,
  pct: number | null,
  limit: number,
  busy: boolean,
  now: number,
  calmMs: number
): { track: CourtesyTrack; change?: "busy" | "calm" } {
  if (pct === null || !Number.isFinite(pct)) return { track };
  const t: CourtesyTrack = { ...track, high: track.high || 0, lastPct: pct, lastAt: now };
  if (pct >= limit) {
    t.high += 1;
    delete t.calmSince;
    return !busy && t.high >= BUSY_READINGS ? { track: t, change: "busy" } : { track: t };
  }
  t.high = 0;
  if (pct >= limit * CALM_SHARE || !busy) {
    delete t.calmSince;
    return { track: t };
  }
  t.calmSince ??= now;
  if (now - t.calmSince >= calmMs) {
    delete t.calmSince;
    return { track: t, change: "calm" };
  }
  return { track: t };
}

function readFile(): CourtesyFile {
  try {
    const f = JSON.parse(fs.readFileSync(FILE, "utf-8"));
    if (f && f.v === 1 && f.helpers && typeof f.helpers === "object") return f;
  } catch {
    // first check
  }
  return { v: 1, helpers: {} };
}

function writeFile(f: CourtesyFile): void {
  ensureDataDir(POOL_DIR);
  writeFileAtomic(FILE, JSON.stringify(f));
}

export type Note = (app: string, kind: "owner_busy" | "owner_calm", p: Record<string, number | string>) => string;

export interface CourtesyChange {
  helper: string;
  change: "busy" | "calm";
  cpuPct: number;
  /** Done, or why not (busy: another operation held the state; the next check tries again). */
  done: boolean;
  held?: "busy" | "changed";
  apps: { app: string; started: string[]; stopped: number; running: number }[];
}

/**
 * The courteous check, at most once every `checkEveryMs` (called by every scale round). Asks the helpers
 * in courteous mode how much their owner uses them, then moves copies away from, or back to, the PCs
 * whose state changed.
 */
export async function courtesyRound(opts: {
  now?: number;
  log?: (l: string) => void;
  note: Note;
  /** Injectable for tests (default: ask each helper over SSH). */
  probe?: (helpers: PoolHelperRecord[]) => Promise<Record<string, Listing>>;
}): Promise<CourtesyChange[]> {
  const now = opts.now ?? Date.now();
  const log = opts.log ?? (() => undefined);
  const state = loadState();
  const helpers = Object.values(state.pool?.helpers || {});
  if (!helpers.length) return [];
  const pooled = pooledApps(state).length > 0;
  // With no app on the pool there is nothing to move; a PC still marked busy is followed until it is free.
  const watch = helpers.filter((h) => !h.paused && courtesyOf(h).mode !== "off" && (pooled || h.ownerBusy));
  if (!watch.length) return [];
  const file = readFile();
  if (file.lastCheckAt !== undefined && now >= file.lastCheckAt && now - file.lastCheckAt < checkEveryMs()) return [];
  file.lastCheckAt = now;
  writeFile(file);

  const listings = await (opts.probe ?? probeHelpers)(watch);
  const changes: { helper: string; change: "busy" | "calm"; cpuPct: number }[] = [];
  for (const h of watch) {
    const l = listings[h.name];
    const pct = l?.ok ? (l.facts.owner?.cpuPct ?? null) : null;
    const o = courtesyObserve(file.helpers[h.name] || { high: 0 }, pct, courtesyOf(h).cpuPct, Boolean(h.ownerBusy), now, calmForMs());
    file.helpers[h.name] = o.track;
    if (o.change) changes.push({ helper: h.name, change: o.change, cpuPct: pct as number });
  }
  for (const name of Object.keys(file.helpers)) if (!state.pool?.helpers[name]) delete file.helpers[name];
  writeFile(file);

  const out: CourtesyChange[] = [];
  for (const c of changes) {
    try {
      out.push(await withStateLock(() => applyChange(c, now, log, opts.note), 2000));
    } catch (err) {
      if (!(err instanceof StateLockBusyError)) throw err;
      log(`[${c.helper}] courteous mode: the state is busy, checking again at the next round`);
      out.push({ ...c, done: false, held: "busy", apps: [] });
    }
  }
  return out;
}

/** True when the app's diary last said this PC's owner was using it (so "free again" is worth a line). */
function toldBusy(app: string, helper: string): boolean {
  const last = readDiary({ app, limit: 500 })
    .filter((e) => (e.kind === "owner_busy" || e.kind === "owner_calm") && e.p.helper === helper)
    .pop();
  return last?.kind === "owner_busy";
}

/** Marks the owner busy (or free) and moves the copies. Runs under the state lock. */
async function applyChange(
  c: { helper: string; change: "busy" | "calm"; cpuPct: number },
  now: number,
  log: (l: string) => void,
  note: Note
): Promise<CourtesyChange> {
  const state = loadState();
  const h = state.pool?.helpers[c.helper];
  const result: CourtesyChange = { ...c, done: false, apps: [] };
  const mode = h ? courtesyOf(h).mode : "off";
  // A person changed the PC meanwhile (paused, removed, mode off, or already marked).
  if (!h || h.paused || mode === "off" || Boolean(h.ownerBusy) === (c.change === "busy")) return { ...result, held: "changed" };
  const limit = courtesyOf(h).cpuPct;
  if (c.change === "busy") h.ownerBusy = { since: new Date(now).toISOString(), cpuPct: c.cpuPct };
  else delete h.ownerBusy;
  saveState(state);
  audit({ event: c.change === "busy" ? "pool.owner.busy" : "pool.owner.free", helper: c.helper, cpuPct: c.cpuPct, mode });
  result.done = true;
  const say = (l: string) => log(`[${c.helper}] ${l}`);

  for (const app of pooledApps(loadState())) {
    const there = app.pool!.placed.some((p) => p.helper === c.helper);
    const missing = app.pool!.placed.length < app.pool!.copies - 1;
    const base = { helper: c.helper, cpu: c.cpuPct, limit };
    if (c.change === "busy") {
      if (!there) continue;
      if (mode === "warn") {
        note(app.name, "owner_busy", { ...base, mode: "warn" });
        result.apps.push({ app: app.name, started: [], stopped: 0, running: 1 + app.pool!.placed.length });
        continue;
      }
      say(`its owner is using it: moving the copies of ${app.name} away`);
      const r = await reconcilePool(app.name, { log });
      const to = r.started.map((x) => x.helper).filter((x) => x !== c.helper);
      note(app.name, "owner_busy", { ...base, mode: "auto", ...(to[0] ? { to: to[0] } : {}), running: r.running, wanted: r.wanted });
      result.apps.push({ app: app.name, started: to, stopped: r.stopped.length, running: r.running });
    } else {
      const minutes = Math.max(1, Math.round(calmForMs() / 60_000));
      const below = Math.round(limit * CALM_SHARE);
      if (missing && !app.pool!.stoppedAt) {
        const r = await reconcilePool(app.name, { log });
        if (r.started.length || there || toldBusy(app.name, c.helper)) note(app.name, "owner_calm", { helper: c.helper, below, minutes, started: r.started.length });
        result.apps.push({ app: app.name, started: r.started.map((x) => x.helper), stopped: r.stopped.length, running: r.running });
      } else if (there || toldBusy(app.name, c.helper)) {
        note(app.name, "owner_calm", { helper: c.helper, below, minutes, started: 0 });
      }
    }
  }
  return result;
}
