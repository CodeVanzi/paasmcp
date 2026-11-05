import { loadState, PoolHelperRecord, saveState, StateLockBusyError, withStateLock } from "./config.js";
import { audit } from "./guard.js";
import { lastAnswer, Listing, pooledApps, probeHelpers, reconcilePool, recordWakeAnswers } from "./pool.js";
import { normalizeMac, validateHelperName } from "./poolproto.js";
import {
  broadcastFor,
  clearWake,
  freshFollowUps,
  originAddressFor,
  readWake,
  validateBroadcast,
  validateWakePort,
  WAKE_TRIES,
  wakeHelper,
  wakeOf,
  wakeStatus,
  wakeWaitMs,
  writeWake,
} from "./wol.js";

// Wake-on-LAN, the parts that need the pool: a person turns it on or off for a PC (or wakes it by hand),
// and every scale round follows up on the PCs woken earlier.
//
// Who wakes a PC: placement (pool.ts reconcilePool), when a copy must run and no awake helper has room, or
// when a PC holding a copy stops answering. The decider waits about a minute and tries its step again
// (scale.ts holdStep "waking"). This round asks the PCs on their way up whether they answer: those that do
// get the copies they should run (a copy asked by hand, one lost to a reboot); the others get another
// packet after `wakeWaitMs`, up to WAKE_TRIES; then the diary says the PC did not wake and it is left alone.

export type WakeNote = (app: string, kind: "wake_failed", p: Record<string, number | string>) => string;

export interface WakeChange {
  helper: string;
  change: "woke" | "sent" | "gave_up";
  apps: { app: string; started: string[]; running: number }[];
}

/** One follow-up, called by every scale round. Does nothing (and asks nobody) when no PC is being woken. */
export async function wakeRound(opts: {
  now?: number;
  log?: (l: string) => void;
  note: WakeNote;
  /** Injectable for tests (default: ask each helper over SSH). */
  probe?: (helpers: PoolHelperRecord[]) => Promise<Record<string, Listing>>;
}): Promise<WakeChange[]> {
  const now = opts.now ?? Date.now();
  const log = opts.log ?? (() => undefined);
  const state = loadState();
  const helpers = state.pool?.helpers || {};
  let file = readWake();
  // Records of PCs removed, or whose Wake-on-LAN was turned off, are dropped.
  const stale = [...Object.keys(file.helpers), ...Object.keys(file.follow)].filter((n) => !helpers[n] || !wakeOf(helpers[n]));
  if (stale.length) for (const n of new Set(stale)) clearWake(n);
  file = readWake();
  const pending = Object.entries(file.helpers)
    .filter(([n, t]) => helpers[n] && !helpers[n].paused && t.gaveUpAt === undefined)
    .map(([n]) => helpers[n]);
  const out: WakeChange[] = [];

  if (pending.length) {
    const listings = await (opts.probe ?? probeHelpers)(pending);
    const answered = pending.filter((h) => listings[h.name]?.ok).map((h) => h.name);
    // probeHelpers already noted them; a test's probe did not (noting twice does nothing).
    recordWakeAnswers(answered, now);
    for (const h of pending) {
      if (answered.includes(h.name)) continue;
      const t = readWake().helpers[h.name];
      const st = wakeStatus(t, now);
      if (st === "retry") {
        const w = await wakeHelper(h, { now }).catch((err) => {
          log(`[${h.name}] could not send the wake-up: ${err instanceof Error ? err.message : String(err)}`);
          return undefined;
        });
        if (w?.state === "sent") {
          log(`[${h.name}] still not answering: sent another wake-up (try ${w.tries})`);
          out.push({ helper: h.name, change: "sent", apps: [] });
        }
      } else if (st === "gave_up" && t) {
        writeWake((f) => f.helpers[h.name] && (f.helpers[h.name].gaveUpAt = now));
        audit({ event: "pool.wake.failed", helper: h.name, tries: t.tries });
        const minutes = Math.max(1, Math.round((now - t.firstSentAt) / 60_000));
        for (const app of t.apps) if (loadState().apps[app]) opts.note(app, "wake_failed", { helper: h.name, tries: t.tries, minutes });
        out.push({ helper: h.name, change: "gave_up", apps: [] });
      }
    }
  }

  // PCs that answered after a wake-up (here or in any other probe): the copies they should run come back.
  const follow = freshFollowUps(readWake(), now);
  const expired = Object.keys(readWake().follow).filter((n) => !follow.includes(n));
  if (expired.length) writeWake((f) => expired.forEach((n) => delete f.follow[n]));
  for (const name of follow) {
    const change: WakeChange = { helper: name, change: "woke", apps: [] };
    try {
      await withStateLock(async () => {
        for (const app of pooledApps(loadState())) {
          const p = app.pool!;
          if (p.stoppedAt || (p.placed.length >= p.copies - 1 && !p.placed.some((c) => c.helper === name))) continue;
          log(`[${name}] answers again: checking the copies of ${app.name}`);
          const r = await reconcilePool(app.name, { log });
          change.apps.push({ app: app.name, started: r.started.map((x) => x.helper), running: r.running });
        }
      }, 2000);
    } catch (err) {
      if (!(err instanceof StateLockBusyError)) throw err;
      log(`[${name}] answers again; the state is busy, its copies are checked at the next round`);
      continue;
    }
    writeWake((f) => delete f.follow[name]);
    out.push(change);
  }
  return out;
}

// ---------- a person's settings ----------

export const WAKE_ACTIONS = ["on", "off", "now"] as const;
export type WakeAction = (typeof WAKE_ACTIONS)[number];

export function validateWakeAction(v: unknown): WakeAction {
  const a = String(v ?? "").trim().toLowerCase() as WakeAction;
  if (!WAKE_ACTIONS.includes(a)) throw new Error("Wake-on-LAN: use on (this server may wake the PC when it needs room), off, or now (wake it once, to test).");
  return a;
}

/**
 * Turns Wake-on-LAN on or off for a helper, or wakes it now (free, audited "pool.wake": the PC is the
 * owner's and already in the pool; this only lets the server wake it when a copy needs room).
 *
 * On: the MAC and the network come from what the PC reported the last time it answered (its card on the
 * default route), unless given. This server must have an address on that network, since magic packets do
 * not cross routers; with `broadcast` given by hand it is only a warning.
 */
export async function setWake(
  nameIn: string,
  actionIn: unknown,
  opts: { mac?: unknown; broadcast?: unknown; port?: unknown; by?: string } = {}
): Promise<Record<string, unknown>> {
  const name = validateHelperName(nameIn);
  const action = validateWakeAction(actionIn);
  const by = opts.by || "cli";
  const state = loadState();
  const h = state.pool?.helpers[name];
  if (!h) throw new Error(`Helper '${name}' not found.`);

  if (action === "off") {
    const was = Boolean(h.wake);
    delete h.wake;
    saveState(state);
    clearWake(name);
    if (was) audit({ event: "pool.wake", helper: name, on: false, by });
    return { helper: name, wake: null, ...(was ? {} : { note: "Wake-on-LAN was already off." }) };
  }

  if (action === "now") {
    const cfg = wakeOf(h);
    if (!cfg) throw new Error(`Wake-on-LAN is off for '${name}'. Turn it on first: paasmcp pool wake ${name} on`);
    await wakeHelper(h, { force: true, by });
    audit({ event: "pool.wake.now", helper: name, by });
    return {
      helper: name,
      sent: true,
      mac: cfg.mac,
      to: `${cfg.broadcast}:${cfg.port}`,
      note: `A PC that wakes usually answers within a minute; the next scale rounds check it (or run 'paasmcp pool status'). After ${Math.round(wakeWaitMs() / 60_000)} min without an answer another packet goes, ${WAKE_TRIES} at most.`,
    };
  }

  const lan = lastAnswer(name)?.facts?.lan;
  const warnings: string[] = [];
  const mac = opts.mac !== undefined && opts.mac !== "" ? normalizeMac(opts.mac) : lan?.mac;
  if (!mac) {
    throw new Error(
      `'${name}' has not reported its network card yet: update its worker ('sudo paasmcp pool update-worker' on the PC), check it with 'paasmcp pool status', or give the card's MAC (--mac) and the network's broadcast address (--broadcast).`
    );
  }
  const byHand = opts.broadcast !== undefined && opts.broadcast !== "";
  let broadcast: string;
  if (byHand) broadcast = validateBroadcast(opts.broadcast);
  else if (lan) broadcast = validateBroadcast(broadcastFor(lan.ip, lan.prefix));
  else throw new Error(`Give the broadcast address of the network '${name}' is on (--broadcast, for example 192.168.1.255).`);
  const port = validateWakePort(opts.port);
  const here = originAddressFor(broadcast);
  if (!here) {
    const net = lan && !byHand ? `${lan.ip}/${lan.prefix}` : broadcast;
    if (!byHand) {
      throw new Error(
        `This server has no address on ${name}'s network (${net}). Magic packets do not cross routers, so it could not wake that PC. Wake-on-LAN works between machines on the same home network; give --broadcast only if you know the router forwards it.`
      );
    }
    warnings.push(`This server has no address on the network of ${broadcast}: the packet leaves by its default route and most routers drop it.`);
  }
  if (lan && mac !== lan.mac) warnings.push(`The PC reports its card as ${lan.mac} (${lan.iface}); you gave ${mac}.`);
  if (lan && !lan.wired) warnings.push(`${name} reaches the network by Wi-Fi (${lan.iface}). Wake-on-LAN almost never works over Wi-Fi: connect it by cable.`);
  if (lan && !lan.armed) warnings.push(`Run 'sudo paasmcp pool wake-setup' once on ${name}: it turns Wake-on-LAN on in its network card and keeps it on after reboots. Also allow it in the PC's BIOS/UEFI if it should wake from power off, not only from sleep.`);
  if (!lan) warnings.push(`${name} has not reported its network card (older worker), so nothing could be checked. Update it: 'sudo paasmcp pool update-worker' on the PC.`);

  const fresh = loadState();
  const rec = fresh.pool?.helpers[name];
  if (!rec) throw new Error(`Helper '${name}' not found.`);
  rec.wake = { mac, broadcast, port, since: rec.wake?.since || new Date().toISOString(), by };
  saveState(fresh);
  clearWake(name);
  audit({ event: "pool.wake", helper: name, on: true, mac, to: `${broadcast}:${port}`, by });
  return { helper: name, wake: { mac, broadcast, port }, ...(here ? { from: here } : {}), warnings };
}
