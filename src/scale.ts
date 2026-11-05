import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AppRecord,
  CapacityResult,
  HOMELAB_ROOT,
  loadState,
  PAAS_DATA_DIR,
  PaaSState,
  sanitizeSlug,
  saveState,
  ScaleRule,
  writeFileAtomic,
} from "./config.js";
import { audit } from "./guard.js";
import { wakeRecheckMs } from "./wol.js";

// Automatic scaling: measure, rehearse and (phase 4) act.
//
// `paasmcp scale tick` (a systemd oneshot timer, so nothing stays in memory between rounds) reads
// every running app's CPU, memory and network traffic from `docker stats`, probes its health path
// to time an answer, reads the visits per second the pool balancer counted for apps behind it, and keeps:
//   - the last 10 minutes at full resolution, plus the decision state, in scale/<app>.json;
//   - one point per minute for 24 hours in scale/<app>.history.ndjson (appended once a minute).
// Apps without automatic scaling only get a rehearsal: the rule runs on those numbers as if the app
// could have more copies, and what it would do goes to the decision diary (scale/diary.ndjson). Apps
// with automatic scaling on (autoscale.ts) get the same rule acting for real, within their min and max.
// The diary is stored as codes and numbers and rendered in Portuguese or English when read.

export const SCALE_DIR = path.join(PAAS_DATA_DIR, "scale");
const LOCK_FILE = path.join(SCALE_DIR, ".tick.lock");
const DIARY_FILE = path.join(SCALE_DIR, "diary.ndjson");
const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

export const RECENT_MS = 10 * 60 * 1000;
export const HISTORY_MS = 24 * 60 * 60 * 1000;
const HISTORY_MAX_LINES = 1440;
const DIARY_KEEP_MS = 7 * 24 * 60 * 60 * 1000;
const DIARY_MAX_LINES = 2000;
const PROBE_TIMEOUT_MS = 3000;
export const DEFAULT_INTERVAL_SECONDS = 15;

export const DEFAULT_RULE: ScaleRule = {
  min: 1,
  max: 3,
  targetCpu: 70,
  upRounds: 3,
  downAfterSeconds: 600,
  cooldownSeconds: 120,
  targetRps: 0,
};

const RULE_LIMITS: Record<keyof ScaleRule, [number, number]> = {
  min: [1, 20],
  max: [1, 20],
  targetCpu: [10, 95],
  upRounds: [1, 20],
  downAfterSeconds: [60, 86400],
  cooldownSeconds: [0, 3600],
  targetRps: [0, 100000],
};
/** After a step that could not happen (no room on helpers, a copy that failed), wait at least this, doubling. */
const RETRY_MIN_MS = 60_000;
const RETRY_MAX_MS = 30 * 60_000;

export type DiaryLang = "pt" | "en";

/** One measurement of one app. cpu is in % of one core (as docker stats shows it). */
export interface Sample {
  t: number;
  cpu: number | null;
  /** MiB */
  mem: number | null;
  /** Bytes per second received / sent by the app's container. */
  rx: number | null;
  tx: number | null;
  /** Milliseconds for the health path to answer (null when not probed or no answer). */
  lat: number | null;
  /** true: answered below 500; false: no answer or 5xx; null: not probed (health check off). */
  ok: boolean | null;
  /** Visits per second through the pool balancer, all copies together (absent or null: not counted). */
  rps?: number | null;
  /** Copies the balancer found healthy (absent or null: unknown). */
  serving?: number | null;
  /** Copies running (or asked for, with automatic scaling) when measured. */
  copies?: number;
}

/** One minute of samples, averaged. */
export interface MinutePoint {
  t: number;
  n: number;
  cpu: number | null;
  cpuMax: number | null;
  mem: number | null;
  rx: number | null;
  tx: number | null;
  lat: number | null;
  latMax: number | null;
  fail: number;
  /** Visits per second through the pool balancer (absent in points written before phase 4). */
  rps?: number | null;
  rpsMax?: number | null;
  /** Most copies running in that minute. */
  copies?: number | null;
}

/** The decision state of one app: the rehearsal's, or the real one when automatic scaling is on. */
export interface RehearsalState {
  copies: number;
  aboveStreak: number;
  aboveSince?: number;
  belowSince?: number;
  lastActionAt?: number;
  lastSampleAt?: number;
  atMaxNoted?: boolean;
  failing: number;
  failNoted?: boolean;
  /** Automatic scaling: a step that could not happen is tried again only after this time. */
  retryAt?: number;
  /** Steps in a row that could not happen (the wait doubles each time). */
  heldCount?: number;
  /** Why the last step could not happen (written to the diary once until something changes). */
  heldNoted?: string;
  /** Rounds in a row in which the balancer found a helper copy unhealthy. */
  unhealthyRounds?: number;
  lastRepairAt?: number;
}

interface AppScaleFile {
  v: 1;
  container?: string;
  counters?: { t: number; rx: number; tx: number };
  /** The pool balancer's request counter for this app at the last round. */
  lb?: { t: number; total: number };
  recent: Sample[];
  /** Start of the first minute not yet written to the history. */
  flushedUntil?: number;
  rehearsal: RehearsalState;
}

export type DiaryKind =
  | "would_up"
  | "would_down"
  | "at_max"
  | "no_answer"
  | "answered_again"
  | "rule_changed"
  | "capacity"
  // Phase 4: automatic scaling acting for real.
  | "up"
  | "down"
  | "held"
  | "auto_on"
  | "auto_off"
  | "stopped_all"
  | "repaired"
  // Courteous mode (courtesy.ts): the owner of a helper PC started or stopped using it.
  | "owner_busy"
  | "owner_calm"
  // Wake-on-LAN (wol.ts, wake.ts): a sleeping helper woke up, or did not.
  | "woke"
  | "wake_failed";

export interface DiaryEntry {
  t: string;
  app: string;
  kind: DiaryKind;
  p: Record<string, number | string>;
}

// ---------- small helpers ----------

function ensureScaleDir(): void {
  fs.mkdirSync(SCALE_DIR, { recursive: true, mode: 0o700 });
}

function appFile(slug: string): string {
  return path.join(SCALE_DIR, `${sanitizeSlug(slug)}.json`);
}

function historyFile(slug: string): string {
  return path.join(SCALE_DIR, `${sanitizeSlug(slug)}.history.ndjson`);
}

const round1 = (n: number) => Math.round(n * 10) / 10;

/** Parses docker sizes: "12.3MiB", "1.2kB", "0B", "3.4GB". */
export function parseDockerSize(s: string): number | null {
  const m = /^\s*([\d.]+)\s*([kKMGTP]?i?B)\s*$/.exec(String(s || ""));
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  const unit = m[2];
  const base = unit.includes("i") ? 1024 : 1000;
  const pow = { B: 0, K: 1, k: 1, M: 2, G: 3, T: 4, P: 5 }[unit[0] as "B"] ?? 0;
  return n * Math.pow(base, pow);
}

export interface RawStats {
  cpu: number | null;
  mem: number | null;
  rxTotal: number | null;
  txTotal: number | null;
}

/** Parses `docker stats --no-stream --format '{{json .}}'` output, keyed by container name. */
export function parseDockerStats(out: string): Record<string, RawStats> {
  const result: Record<string, RawStats> = {};
  for (const line of out.split("\n")) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line) as { Name?: string; CPUPerc?: string; MemUsage?: string; NetIO?: string };
      if (!row.Name) continue;
      const cpu = Number(String(row.CPUPerc || "").replace("%", ""));
      const mem = parseDockerSize(String(row.MemUsage || "").split("/")[0]);
      const [rx, tx] = String(row.NetIO || "").split("/");
      result[row.Name] = {
        cpu: Number.isFinite(cpu) && row.CPUPerc ? cpu : null,
        mem: mem === null ? null : mem / (1024 * 1024),
        rxTotal: parseDockerSize(rx || ""),
        txTotal: parseDockerSize(tx || ""),
      };
    } catch {
      // ignore malformed row
    }
  }
  return result;
}

/** One `docker stats` call for every container (async: probes run at the same time). */
export function dockerStats(): Promise<Record<string, RawStats>> {
  if (OFFLINE()) return Promise.resolve({});
  return new Promise((resolve) => {
    // All running containers: naming them would fail the whole call when one is stopped.
    execFile(
      "docker",
      ["stats", "--no-stream", "--format", "{{json .}}"],
      { encoding: "utf-8", timeout: 15_000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout) => resolve(parseDockerStats(err && !stdout ? "" : String(stdout || "")))
    );
  });
}

/** Times one answer of the app's health path on its loopback port. */
export async function probeApp(url: string): Promise<{ ok: boolean; ms: number | null }> {
  const started = performance.now();
  try {
    const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    await res.body?.cancel().catch(() => undefined);
    const ms = Math.round(performance.now() - started);
    return { ok: res.status < 500, ms };
  } catch {
    return { ok: false, ms: null };
  }
}

/** CPU reference for an app: its CPU limit in cores, or one core when it has none. */
export function cpuReference(app: Pick<AppRecord, "cpuLimit">): number {
  const n = Number(app.cpuLimit);
  return Number.isFinite(n) && n > 0 ? n : 1;
}

// ---------- rule ----------

export function ruleFor(app: Pick<AppRecord, "scale">): ScaleRule {
  const r = { ...DEFAULT_RULE, ...(app.scale?.rule || {}) };
  r.max = Math.max(r.max, r.min);
  return r;
}

/** Validates a partial rule from the CLI, the dashboard or the MCP tool. */
export function validateRule(input: Record<string, unknown>): Partial<ScaleRule> {
  const out: Partial<ScaleRule> = {};
  for (const key of Object.keys(RULE_LIMITS) as (keyof ScaleRule)[]) {
    const raw = input[key];
    if (raw === undefined || raw === null || raw === "") continue;
    const n = Number(raw);
    const [lo, hi] = RULE_LIMITS[key];
    if (!Number.isInteger(n) || n < lo || n > hi) throw new Error(`'${key}' must be a whole number from ${lo} to ${hi}.`);
    out[key] = n;
  }
  const unknown = Object.keys(input).filter((k) => !(k in RULE_LIMITS));
  if (unknown.length) throw new Error(`Unknown rule field(s): ${unknown.join(", ")}.`);
  return out;
}

/** Changes an app's scale rule. The caller checked the guard "scale.rule" (raising the maximum of an app that scales by itself asks a person). */
export function setScaleRule(appName: string, input: Record<string, unknown>, by = "cli"): { app: string; rule: ScaleRule } {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const patch = validateRule(input);
  const next = { ...ruleFor(app), ...patch };
  if (next.max < next.min) throw new Error(`'max' (${next.max}) cannot be below 'min' (${next.min}).`);
  app.scale = { ...(app.scale || {}), rule: { ...(app.scale?.rule || {}), ...patch } };
  saveState(state);
  audit({ event: "scale.rule", app: slug, rule: next, by });
  appendDiary({
    t: new Date().toISOString(),
    app: slug,
    kind: "rule_changed",
    p: { min: next.min, max: next.max, target: next.targetCpu, ...(next.targetRps ? { targetRps: next.targetRps } : {}), ...(app.scale.auto ? { auto: 1 } : {}) },
  });
  return { app: slug, rule: next };
}

/**
 * What the guard sees when a rule changes (action "scale.rule"): raising the maximum of an app that
 * scales by itself asks a person, since the decider may then run more copies without asking.
 */
export function ruleRiskParams(appName: string, input: Record<string, unknown>, state: PaaSState = loadState()): Record<string, unknown> {
  const slug = sanitizeSlug(appName);
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const now = ruleFor(app);
  const next = { ...now, ...validateRule(input) };
  return { appName: slug, max: next.max, previousMax: now.max, auto: Boolean(app.scale?.auto) };
}

export function diaryLanguage(state: Pick<PaaSState, "scale"> = loadState()): DiaryLang {
  return state.scale?.language === "en" ? "en" : "pt";
}

export function setDiaryLanguage(lang: string): { language: DiaryLang } {
  if (lang !== "pt" && lang !== "en") throw new Error("Language must be 'pt' or 'en'.");
  const state = loadState();
  state.scale = { ...(state.scale || {}), language: lang };
  saveState(state);
  return { language: lang };
}

// ---------- decision rule (pure) ----------

export function freshRehearsal(rule: ScaleRule): RehearsalState {
  return { copies: rule.min, aboveStreak: 0, failing: 0 };
}

export type Signal = "cpu" | "rps";

/** Load on each copy, before comparing it with the rule. */
export interface Reading {
  /** CPU per copy, in % of the app's CPU limit (or of one core). */
  cpu: number | null;
  /** Visits per second per copy (pool balancer), null when not counted. */
  rps: number | null;
}

export interface Pressure {
  /** Load as a fraction of its target: above 1 is over the target, below 0.5 is under half of it. */
  value: number;
  /** The signal that is highest against its target. */
  signal: Signal;
  cpu: number | null;
  rps: number | null;
}

/** CPU and (when the rule has a visits target) visits, each against its target; the highest wins. */
export function pressureOf(rule: ScaleRule, r: Reading): Pressure | null {
  const parts: { value: number; signal: Signal }[] = [];
  if (r.cpu !== null && Number.isFinite(r.cpu)) parts.push({ value: r.cpu / rule.targetCpu, signal: "cpu" });
  if (rule.targetRps > 0 && r.rps !== null && Number.isFinite(r.rps)) parts.push({ value: r.rps / rule.targetRps, signal: "rps" });
  if (!parts.length) return null;
  const top = parts.reduce((a, b) => (b.value > a.value ? b : a));
  return { ...top, cpu: r.cpu, rps: r.rps };
}

export interface Observation {
  state: RehearsalState;
  /** The rule says to add or remove one copy now (nothing is changed in `state` yet: see commitStep). */
  want?: "up" | "down";
  pressure?: Pressure;
  /** Rounds in a row and seconds the load has been over the target (for the diary). */
  rounds?: number;
  seconds?: number;
  event?: { kind: DiaryKind; p: Record<string, number | string> };
}

const clampCopies = (rule: ScaleRule, n: number) => Math.min(rule.max, Math.max(rule.min, n || rule.min));

/**
 * One round of the rule on one app (pure). It keeps the streaks and says whether a copy should be added
 * or removed now; the caller commits the step (commitStep) once it happened, so a step that could not
 * happen (automatic scaling with no room, or another operation holding the state) is asked again.
 */
export function observe(
  rule: ScaleRule,
  prev: RehearsalState,
  s: Pick<Sample, "t" | "ok" | "lat">,
  reading: Reading,
  opts: { gapMs: number; path?: string; auto?: boolean }
): Observation {
  const st: RehearsalState = { ...prev };
  st.copies = clampCopies(rule, st.copies);
  const auto: Record<string, number> = opts.auto ? { auto: 1 } : {};
  const resetStreaks = () => {
    st.aboveStreak = 0;
    delete st.aboveSince;
    delete st.belowSince;
  };
  // A hole in the data (timer stopped, server off) breaks any streak: never decide on stale numbers.
  if (st.lastSampleAt !== undefined && s.t - st.lastSampleAt > opts.gapMs) resetStreaks();
  st.lastSampleAt = s.t;

  if (s.ok === false) {
    st.failing = (st.failing || 0) + 1;
    resetStreaks();
    if (st.failing >= 3 && !st.failNoted) {
      st.failNoted = true;
      return { state: st, event: { kind: "no_answer", p: { rounds: st.failing, path: opts.path || "/", ...auto } } };
    }
    return { state: st };
  }
  st.failing = 0;
  let recovered: Observation["event"];
  if (st.failNoted) {
    st.failNoted = false;
    recovered = { kind: "answered_again", p: { ms: s.lat ?? 0 } };
  }
  const pr = pressureOf(rule, reading);
  if (!pr) return { state: st, event: recovered };

  const waiting =
    (st.lastActionAt !== undefined && s.t - st.lastActionAt < rule.cooldownSeconds * 1000) || (st.retryAt !== undefined && s.t < st.retryAt);

  if (pr.value > 1) {
    st.aboveStreak += 1;
    st.aboveSince ??= s.t;
  } else {
    st.aboveStreak = 0;
    delete st.aboveSince;
    st.atMaxNoted = false;
    // The load eased: a later step that cannot happen is worth writing down again.
    if (st.copies >= rule.min) delete st.heldNoted;
  }
  if (pr.value < 0.5) st.belowSince ??= s.t;
  else delete st.belowSince;

  if (st.aboveStreak >= rule.upRounds && !waiting) {
    if (st.copies < rule.max) return { state: st, want: "up", pressure: pr, rounds: st.aboveStreak, seconds: Math.round((s.t - (st.aboveSince ?? s.t)) / 1000) };
    if (!st.atMaxNoted) {
      st.atMaxNoted = true;
      return { state: st, pressure: pr, event: { kind: "at_max", p: { max: rule.max, ...overParams(rule, pr), ...auto } } };
    }
  }
  if (st.belowSince !== undefined && s.t - st.belowSince >= rule.downAfterSeconds * 1000 && st.copies > rule.min && !waiting) {
    return { state: st, want: "down", pressure: pr };
  }
  return { state: st, pressure: pr, event: recovered };
}

/** Records a step that happened: `to` copies from now, and the wait before the next one. */
export function commitStep(prev: RehearsalState, dir: "up" | "down", t: number, to?: number): RehearsalState {
  const st: RehearsalState = { ...prev, copies: to ?? prev.copies + (dir === "up" ? 1 : -1), lastActionAt: t };
  if (dir === "up") {
    st.aboveStreak = 0;
    delete st.aboveSince;
    delete st.belowSince;
  } else {
    // The next removal needs another full period below half the target.
    st.belowSince = t;
  }
  delete st.retryAt;
  delete st.heldCount;
  delete st.heldNoted;
  return st;
}

/** Records a step that could not happen: the next try waits (at least a minute, doubling, up to 30). */
export function holdStep(prev: RehearsalState, why: string, t: number, rule: ScaleRule, copies?: number): { state: RehearsalState; note: boolean } {
  // A PC is waking up for this step: try again soon (it answers within a minute or so), without the
  // growing wait of a step that found no room.
  if (why === "waking") {
    const st: RehearsalState = { ...prev, retryAt: t + wakeRecheckMs(), heldNoted: why, ...(copies !== undefined ? { copies } : {}) };
    return { state: st, note: prev.heldNoted !== why };
  }
  const heldCount = (prev.heldCount || 0) + 1;
  const wait = Math.min(RETRY_MAX_MS, Math.max(RETRY_MIN_MS, rule.cooldownSeconds * 1000) * 2 ** (heldCount - 1));
  const st: RehearsalState = { ...prev, heldCount, retryAt: t + wait, heldNoted: why, ...(copies !== undefined ? { copies } : {}) };
  return { state: st, note: prev.heldNoted !== why };
}

function overParams(rule: ScaleRule, pr: Pressure): Record<string, number | string> {
  return {
    cpu: Math.round(pr.cpu ?? 0),
    target: rule.targetCpu,
    ...(pr.signal === "rps" ? { signal: "rps", rps: round1(pr.rps ?? 0), targetRps: rule.targetRps } : {}),
  };
}

/** Diary numbers for one step (the same for the rehearsal and for automatic scaling). */
export function stepParams(rule: ScaleRule, dir: "up" | "down", from: number, to: number, o: Pick<Observation, "pressure" | "rounds" | "seconds">): Record<string, number | string> {
  const pr = o.pressure;
  // The real streak: after a wait (cooldown, a held step) it can be longer than the rule's minimum.
  if (dir === "up") return { from, to, ...(pr ? overParams(rule, pr) : {}), rounds: o.rounds ?? rule.upRounds, seconds: o.seconds ?? 0 };
  return {
    from,
    to,
    cpu: Math.round(pr?.cpu ?? 0),
    below: Math.round(rule.targetCpu / 2),
    minutes: Math.round(rule.downAfterSeconds / 60),
    ...(rule.targetRps > 0 ? { belowRps: round1(rule.targetRps / 2), rps: round1(pr?.rps ?? 0) } : {}),
  };
}

/** The reading of one sample: CPU and visits spread over the copies. */
export function readingOf(
  s: Pick<Sample, "cpu">,
  copies: number,
  opts: { cpuRefCores: number; realCopies?: number; rps?: number | null; serving?: number | null }
): Reading {
  return {
    // This server's copy carries its share of the visits: the whole load is its CPU times the copies running.
    cpu: s.cpu === null ? null : (s.cpu * Math.max(1, opts.realCopies ?? 1)) / opts.cpuRefCores / copies,
    rps: opts.rps === null || opts.rps === undefined ? null : opts.rps / Math.max(1, opts.serving || copies),
  };
}

/**
 * Runs the decision rule on one sample as if the app could have more copies. `copies` is how many
 * copies the rule would be running by now; the measured CPU (of this server's copy) is spread over them.
 * With copies on helper PCs (`realCopies`), this server's copy carries only its share of the visits, so the
 * whole load is estimated as its CPU times the real copies; visits counted by the balancer (`rps`) are
 * spread the same way. Pure: returns the next state and, when something would happen, a diary event.
 */
export function rehearse(
  rule: ScaleRule,
  prev: RehearsalState,
  s: Pick<Sample, "t" | "cpu" | "ok" | "lat">,
  opts: { gapMs: number; cpuRefCores: number; path?: string; realCopies?: number; rps?: number | null }
): { state: RehearsalState; event?: { kind: DiaryKind; p: Record<string, number | string> } } {
  const copies = clampCopies(rule, prev.copies);
  const o = observe(rule, prev, s, readingOf(s, copies, opts), opts);
  if (!o.want) return { state: o.state, event: o.event };
  const to = o.state.copies + (o.want === "up" ? 1 : -1);
  return {
    state: commitStep(o.state, o.want, s.t, to),
    event: { kind: o.want === "up" ? "would_up" : "would_down", p: stepParams(rule, o.want, o.state.copies, to, o) },
  };
}

// ---------- history ----------

/** Averages the samples of one minute. */
export function aggregateMinute(t: number, samples: Sample[]): MinutePoint {
  const avg = (vals: (number | null | undefined)[]) => {
    const v = vals.filter((x): x is number => typeof x === "number");
    return v.length ? round1(v.reduce((a, b) => a + b, 0) / v.length) : null;
  };
  const max = (vals: (number | null | undefined)[]) => {
    const v = vals.filter((x): x is number => typeof x === "number");
    return v.length ? round1(Math.max(...v)) : null;
  };
  return {
    t,
    n: samples.length,
    cpu: avg(samples.map((s) => s.cpu)),
    cpuMax: max(samples.map((s) => s.cpu)),
    mem: avg(samples.map((s) => s.mem)),
    rx: avg(samples.map((s) => s.rx)),
    tx: avg(samples.map((s) => s.tx)),
    lat: avg(samples.map((s) => s.lat)),
    latMax: max(samples.map((s) => s.lat)),
    fail: samples.filter((s) => s.ok === false).length,
    rps: avg(samples.map((s) => s.rps)),
    rpsMax: max(samples.map((s) => s.rps)),
    copies: max(samples.map((s) => s.copies)),
  };
}

function isMinutePoint(x: unknown): x is MinutePoint {
  const p = x as MinutePoint;
  return Boolean(p) && typeof p.t === "number" && typeof p.n === "number";
}

/** Minute points of the last 24 h (oldest first). Unreadable lines are skipped. */
export function readHistory(appName: string, now = Date.now()): MinutePoint[] {
  const file = historyFile(appName);
  if (!fs.existsSync(file)) return [];
  const out: MinutePoint[] = [];
  for (const line of fs.readFileSync(file, "utf-8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const p = JSON.parse(line);
      if (isMinutePoint(p) && p.t >= now - HISTORY_MS && p.t <= now) out.push(p);
    } catch {
      // skip
    }
  }
  return out.sort((a, b) => a.t - b.t);
}

/** Groups minute points into buckets of `minutes` (for charts and the MCP answer). */
export function downsample(points: MinutePoint[], minutes: number): MinutePoint[] {
  if (minutes <= 1) return points;
  const size = minutes * 60_000;
  const groups = new Map<number, MinutePoint[]>();
  for (const p of points) {
    const k = Math.floor(p.t / size) * size;
    groups.set(k, [...(groups.get(k) || []), p]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a - b)
    .map(([t, ps]) => {
      const n = ps.reduce((a, p) => a + p.n, 0);
      // Points written before a field existed have it missing: they count as "not measured".
      const wavg = (f: (p: MinutePoint) => number | null | undefined) => {
        const v = ps.filter((p) => typeof f(p) === "number");
        const w = v.reduce((a, p) => a + p.n, 0);
        return w ? round1(v.reduce((a, p) => a + (f(p) as number) * p.n, 0) / w) : null;
      };
      const mx = (f: (p: MinutePoint) => number | null | undefined) => {
        const v = ps.map(f).filter((x): x is number => typeof x === "number");
        return v.length ? Math.max(...v) : null;
      };
      return {
        t,
        n,
        cpu: wavg((p) => p.cpu),
        cpuMax: mx((p) => p.cpuMax),
        mem: wavg((p) => p.mem),
        rx: wavg((p) => p.rx),
        tx: wavg((p) => p.tx),
        lat: wavg((p) => p.lat),
        latMax: mx((p) => p.latMax),
        fail: ps.reduce((a, p) => a + p.fail, 0),
        rps: wavg((p) => p.rps),
        rpsMax: mx((p) => p.rpsMax),
        copies: mx((p) => p.copies),
      };
    });
}

function appendHistory(slug: string, points: MinutePoint[], now: number): void {
  if (!points.length) return;
  const file = historyFile(slug);
  fs.appendFileSync(file, points.map((p) => JSON.stringify(p)).join("\n") + "\n", { mode: 0o600 });
  // Trim rarely (every ~2 hours of data) so the file stays one point per minute for 24 h.
  const lines = fs.readFileSync(file, "utf-8").split("\n").filter(Boolean).length;
  if (lines > HISTORY_MAX_LINES + 120) {
    writeFileAtomic(file, readHistory(slug, now).slice(-HISTORY_MAX_LINES).map((p) => JSON.stringify(p)).join("\n") + "\n");
  }
}

// ---------- diary ----------

export function appendDiary(entry: DiaryEntry): void {
  ensureScaleDir();
  fs.appendFileSync(DIARY_FILE, JSON.stringify(entry) + "\n", { mode: 0o600 });
  const raw = fs.readFileSync(DIARY_FILE, "utf-8").split("\n").filter(Boolean);
  if (raw.length > DIARY_MAX_LINES + 200) {
    const keep = readDiary({ limit: DIARY_MAX_LINES });
    writeFileAtomic(DIARY_FILE, keep.map((e) => JSON.stringify(e)).join("\n") + "\n");
  }
}

const DIARY_KINDS = new Set<DiaryKind>([
  "would_up",
  "would_down",
  "at_max",
  "no_answer",
  "answered_again",
  "rule_changed",
  "capacity",
  "up",
  "down",
  "held",
  "auto_on",
  "auto_off",
  "stopped_all",
  "repaired",
  "owner_busy",
  "owner_calm",
  "woke",
  "wake_failed",
]);

/** Diary entries, oldest first (last 7 days), optionally for one app. */
export function readDiary(opts: { app?: string; limit?: number; now?: number } = {}): DiaryEntry[] {
  if (!fs.existsSync(DIARY_FILE)) return [];
  const since = (opts.now ?? Date.now()) - DIARY_KEEP_MS;
  const app = opts.app ? sanitizeSlug(opts.app) : undefined;
  const out: DiaryEntry[] = [];
  for (const line of fs.readFileSync(DIARY_FILE, "utf-8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line) as DiaryEntry;
      if (!e || typeof e.t !== "string" || typeof e.app !== "string" || !DIARY_KINDS.has(e.kind) || typeof e.p !== "object") continue;
      if (Date.parse(e.t) < since) continue;
      if (app && e.app !== app) continue;
      out.push(e);
    } catch {
      // skip
    }
  }
  return out.slice(-(opts.limit ?? 200));
}

const BOTTLENECK_TEXT: Record<DiaryLang, Record<string, string>> = {
  pt: {
    app_cpu: "a CPU do app",
    database: "o banco de dados",
    client: "o próprio teste (o servidor não conseguiu gerar mais carga)",
    errors: "erros do app",
    latency: "o tempo de resposta",
    none: "não travou até o máximo testado",
    unknown: "não identificado (talvez disco, rede ou um limite do próprio app)",
  },
  en: {
    app_cpu: "the app's CPU",
    database: "the database",
    client: "the test itself (the server could not generate more load)",
    errors: "app errors",
    latency: "response time",
    none: "it did not choke up to the highest load tested",
    unknown: "not identified (maybe disk, network or a limit inside the app)",
  },
};

export function bottleneckText(code: string, lang: DiaryLang): string {
  return BOTTLENECK_TEXT[lang][code] || code;
}

/** Turns a diary entry into a sentence. Only numbers, slugs and codes go in, so the text is safe to show. */
export function renderDiary(e: DiaryEntry, lang: DiaryLang): string {
  const p = e.p;
  const pt = lang === "pt";
  const num = (k: string) => Number(p[k]) || 0;
  const n = (k: string) => String(num(k));
  // One decimal at most, with the language's decimal mark.
  const dec = (k: string) => {
    const v = String(Math.round(num(k) * 10) / 10);
    return pt ? v.replace(".", ",") : v;
  };
  const s = (k: string) => String(p[k] ?? "");
  // Helper PC names are validated slugs; anything else in the file is not shown.
  const name = (k: string) => (/^[a-z0-9][a-z0-9-]{0,39}$/.test(s(k)) ? s(k) : "");
  const copies = (k: string) => {
    const v = num(k);
    return pt ? `${v} ${v === 1 ? "cópia" : "cópias"}` : `${v} ${v === 1 ? "copy" : "copies"}`;
  };
  const auto = Boolean(p.auto);
  // "CPU per copy was 92% (target 70%)" or, when visits drove it, "visits per copy were 34/s (target 20/s)".
  const over = (verbPt: string, verbEn: string) =>
    p.signal === "rps"
      ? pt
        ? `as visitas por cópia ${verbPt === "ficou" ? "ficaram" : "seguem"} em ${dec("rps")}/s (alvo ${n("targetRps")}/s)`
        : `visits per copy ${verbEn === "was" ? "were" : "are still"} ${dec("rps")}/s (target ${n("targetRps")}/s)`
      : pt
        ? `a CPU por cópia ${verbPt} em ${n("cpu")}% (alvo ${n("target")}%)`
        : `CPU per copy ${verbEn} ${n("cpu")}% (target ${n("target")}%)`;
  const under = () =>
    pt
      ? `a CPU por cópia ficou abaixo de ${n("below")}%${p.belowRps !== undefined ? ` e as visitas abaixo de ${dec("belowRps")}/s por cópia` : ""} por ${n("minutes")} min`
      : `CPU per copy stayed below ${n("below")}%${p.belowRps !== undefined ? ` and visits below ${dec("belowRps")}/s per copy` : ""} for ${n("minutes")} min`;
  const cap = (t: string) => t.charAt(0).toUpperCase() + t.slice(1);
  const count = (k: string, ptOne: string, ptMany: string, enOne: string, enMany: string) =>
    `${n(k)} ${pt ? (num(k) === 1 ? ptOne : ptMany) : num(k) === 1 ? enOne : enMany}`;
  const wait = () => {
    const m = Math.max(1, Math.round(num("waitSeconds") / 60));
    return pt ? `${m} min` : `${m} min`;
  };

  switch (e.kind) {
    case "would_up":
      return pt
        ? `Ensaio: subiria de ${n("from")} para ${copies("to")}. ${cap(over("ficou", "was"))} por ${n("rounds")} rodadas seguidas (${n("seconds")} s).`
        : `Rehearsal: would go from ${n("from")} to ${copies("to")}. ${cap(over("ficou", "was"))} for ${n("rounds")} rounds in a row (${n("seconds")} s).`;
    case "would_down":
      return pt
        ? `Ensaio: desceria de ${n("from")} para ${copies("to")}. ${cap(under())}.`
        : `Rehearsal: would go from ${n("from")} to ${copies("to")}. ${cap(under())}.`;
    case "at_max":
      if (auto) {
        return pt
          ? `Está no máximo de ${copies("max")} e ${over("segue", "is still")}. Vale aumentar o máximo ou o limite de CPU.`
          : `At the maximum of ${copies("max")} and ${over("segue", "is still")}. Consider a higher maximum or CPU limit.`;
      }
      return pt
        ? `Ensaio: já está no máximo de ${copies("max")} e ${over("segue", "is still")}. Vale aumentar o máximo ou o limite de CPU.`
        : `Rehearsal: already at the maximum of ${copies("max")} and ${over("segue", "is still")}. Consider a higher maximum or CPU limit.`;
    case "no_answer":
      return pt
        ? `O app não respondeu em ${s("path")} por ${n("rounds")} rodadas seguidas. ${auto ? "O decisor não muda as cópias" : "O ensaio não decide nada"} enquanto isso.`
        : `The app did not answer on ${s("path")} for ${n("rounds")} rounds in a row. ${auto ? "The decider leaves the copies as they are" : "The rehearsal decides nothing"} meanwhile.`;
    case "answered_again":
      return pt ? `O app voltou a responder (${n("ms")} ms).` : `The app answers again (${n("ms")} ms).`;
    case "rule_changed": {
      const rps = p.targetRps ? (pt ? `, alvo de visitas ${n("targetRps")}/s por cópia` : `, visits target ${n("targetRps")}/s per copy`) : "";
      return pt
        ? `Regra ${auto ? "da escala" : "do ensaio"} alterada: mínimo ${n("min")}, máximo ${n("max")}, alvo de CPU ${n("target")}%${rps}.`
        : `${auto ? "Scaling" : "Rehearsal"} rule changed: minimum ${n("min")}, maximum ${n("max")}, CPU target ${n("target")}%${rps}.`;
    }
    case "capacity":
      return pt
        ? `Teste de capacidade: uma cópia aguentou ${n("rps")} visitas por segundo em ${s("path")} (p95 ${n("p95")} ms). Limite: ${bottleneckText(s("bottleneck"), "pt")}.`
        : `Capacity test: one copy handled ${n("rps")} requests per second on ${s("path")} (p95 ${n("p95")} ms). Limit: ${bottleneckText(s("bottleneck"), "en")}.`;
    case "up": {
      const where = name("helper") ? (pt ? ` A nova cópia roda em ${name("helper")}.` : ` The new copy runs on ${name("helper")}.`) : "";
      if (p.why === "min") {
        return pt
          ? `Subi de ${n("from")} para ${copies("to")} para cumprir o mínimo da regra.${where}`
          : `Went from ${n("from")} to ${copies("to")} to meet the rule's minimum.${where}`;
      }
      return pt
        ? `Subi de ${n("from")} para ${copies("to")}: ${over("ficou", "was")} por ${n("rounds")} rodadas seguidas (${n("seconds")} s).${where}`
        : `Went from ${n("from")} to ${copies("to")}: ${over("ficou", "was")} for ${n("rounds")} rounds in a row (${n("seconds")} s).${where}`;
    }
    case "down": {
      const which = name("helper") ? (pt ? ` Saiu a cópia de ${name("helper")}.` : ` The copy on ${name("helper")} left.`) : "";
      if (p.why === "max") {
        return pt
          ? `Desci de ${n("from")} para ${copies("to")} para respeitar o máximo da regra.${which}`
          : `Went from ${n("from")} to ${copies("to")} to respect the rule's maximum.${which}`;
      }
      return pt
        ? `Desci de ${n("from")} para ${copies("to")}: ${under()}.${which}`
        : `Went from ${n("from")} to ${copies("to")}: ${under()}.${which}`;
    }
    case "held":
      if (p.why === "db_busy") {
        return pt
          ? `Não subi para ${copies("to")}: o Postgres já usa ${n("used")} de ${n("limit")} conexões, e mais cópias abririam mais. Tento de novo em ${wait()}.`
          : `Did not go to ${copies("to")}: Postgres already uses ${n("used")} of ${n("limit")} connections, and more copies would open more. Trying again in ${wait()}.`;
      }
      if (p.why === "start_failed") {
        return pt
          ? `Tentei subir para ${copies("to")}, mas a cópia nova não chegou a rodar (o motivo aparece em Ajudantes). Sigo com ${copies("running")} e tento de novo em ${wait()}.`
          : `Tried to go to ${copies("to")}, but the new copy did not get to run (the reason shows on the Helpers screen). Staying at ${copies("running")} and trying again in ${wait()}.`;
      }
      if (p.why === "waking") {
        return pt
          ? `Precisava de ${copies("to")} e nenhum ajudante acordado tinha espaço. Mandei acordar ${name("helper")} pela rede (Wake-on-LAN), o que leva de 30 s a 1 min. Sigo com ${copies("running")} e tento de novo em ${wait()}.`
          : `Needed ${copies("to")} and no awake helper had room. Sent ${name("helper")} a wake-up over the network (Wake-on-LAN), which takes 30 s to a minute. Staying at ${copies("running")} and trying again in ${wait()}.`;
      }
      if (p.why === "stop_failed") {
        return pt
          ? `Tentei descer para ${copies("to")}, mas não deu (o motivo aparece em Ajudantes). Sigo com ${copies("running")} e tento de novo em ${wait()}.`
          : `Tried to go down to ${copies("to")}, but it did not work (the reason shows on the Helpers screen). Staying at ${copies("running")} and trying again in ${wait()}.`;
      }
      return pt
        ? `Precisava de ${copies("to")}, mas nenhum PC ajudante tinha espaço livre ou respondeu. Sigo com ${copies("running")} e tento de novo em ${wait()}.`
        : `Needed ${copies("to")}, but no helper PC had room or answered. Staying at ${copies("running")} and trying again in ${wait()}.`;
    case "auto_on":
      return pt
        ? `Escala automática ligada: entre ${n("min")} e ${copies("max")}, decididas pela regra a cada medição.`
        : `Automatic scaling on: between ${n("min")} and ${copies("max")}, decided by the rule at every round.`;
    case "auto_off":
      return pt
        ? `Escala automática desligada. O app fica com ${copies("copies")} até alguém mudar.`
        : `Automatic scaling off. The app keeps ${copies("copies")} until someone changes it.`;
    case "stopped_all":
      return pt
        ? `Parar tudo: o app voltou a uma cópia, só neste servidor${auto ? ", e a escala automática foi desligada" : ""}.`
        : `Stop everything: the app is back to one copy, on this server only${auto ? ", and automatic scaling is off" : ""}.`;
    case "repaired": {
      const what = pt
        ? `${count("started", "cópia iniciada", "cópias iniciadas", "", "")}, ${count("stopped", "parada", "paradas", "", "")}`
        : `${count("started", "", "", "copy started", "copies started")}, ${count("stopped", "", "", "stopped", "stopped")}`;
      if (p.why === "unhealthy") {
        return pt
          ? `Uma cópia num ajudante não respondia ao balanceador havia ${n("minutes")} min. Conferi os ajudantes: ${what}.`
          : `A copy on a helper PC had not answered the balancer for ${n("minutes")} min. Checked the helpers: ${what}.`;
      }
      return pt
        ? `Uma mudança de cópias foi interrompida no meio (o servidor reiniciou?). Conferi os ajudantes: ${what}.`
        : `A change of copies was interrupted halfway (did the server restart?). Checked the helpers: ${what}.`;
    }
    case "owner_busy": {
      const pc = name("helper");
      const using = pt
        ? `O dono de ${pc} está usando o PC (CPU fora das cópias em ${n("cpu")}%, limite ${n("limit")}%).`
        : `The owner of ${pc} is using it (CPU outside the copies at ${n("cpu")}%, limit ${n("limit")}%).`;
      if (p.mode === "warn") {
        return pt
          ? `${using} Modo com aviso: a cópia fica lá, mas nenhuma nova vai para esse PC até ele liberar.`
          : `${using} Warn mode: the copy stays there, but no new one goes to that PC until it is free.`;
      }
      if (name("to")) {
        return pt
          ? `${using} A cópia saiu de lá depois de terminar as visitas em curso e foi para ${name("to")}.`
          : `${using} The copy left after finishing the visits in progress and went to ${name("to")}.`;
      }
      return pt
        ? `${using} A cópia saiu de lá depois de terminar as visitas em curso. Nenhum outro PC tinha espaço, então o app segue com ${n("running")} de ${copies("wanted")} até ele liberar.`
        : `${using} The copy left after finishing the visits in progress. No other PC had room, so the app runs ${n("running")} of ${copies("wanted")} until it is free.`;
    }
    case "owner_calm": {
      const free = pt
        ? `${name("helper")} está livre de novo (CPU do dono abaixo de ${n("below")}% por ${n("minutes")} min).`
        : `${name("helper")} is free again (the owner's CPU below ${n("below")}% for ${n("minutes")} min).`;
      if (num("started") > 0) {
        return pt
          ? `${free} ${num("started") === 1 ? "Voltou 1 cópia" : `Voltaram ${n("started")} cópias`} que faltavam.`
          : `${free} ${num("started") === 1 ? "1 missing copy is back" : `${n("started")} missing copies are back`}.`;
      }
      return pt ? `${free} Ele volta a receber cópias.` : `${free} It takes copies again.`;
    }
    case "woke":
      return pt
        ? `${name("helper")} acordou pela rede: respondeu ${n("seconds")} s depois do primeiro pedido.`
        : `${name("helper")} woke up over the network: it answered ${n("seconds")} s after the first request.`;
    case "wake_failed":
      return pt
        ? `Pedi ${n("tries")} vezes para ${name("helper")} acordar pela rede e ele não respondeu em ${n("minutes")} min. Paro de tentar até ele responder de novo ou alguém usar "Acordar agora" na tela Ajudantes.`
        : `Asked ${name("helper")} ${n("tries")} times to wake up over the network and it did not answer in ${n("minutes")} min. No more tries until it answers again or someone uses "Wake now" on the Helpers screen.`;
  }
  return e.kind;
}

// ---------- per-app file ----------

function readAppFile(slug: string): AppScaleFile | undefined {
  try {
    const f = JSON.parse(fs.readFileSync(appFile(slug), "utf-8")) as AppScaleFile;
    if (f && f.v === 1 && Array.isArray(f.recent) && f.rehearsal && typeof f.rehearsal.copies === "number") return f;
  } catch {
    // missing or unreadable: start over
  }
  return undefined;
}

/** Removes an app's measurements (called when the app is purged). */
export function forgetScaleData(appName: string): void {
  for (const f of [appFile(appName), historyFile(appName), intentFile(appName)]) fs.rmSync(f, { force: true });
}

// ---------- automatic scaling: steps ----------

/** A change of copies the decider asks for (autoscale.ts carries it out under the state lock). */
export interface StepDecision {
  app: string;
  kind: "up" | "down" | "repair";
  from: number;
  to: number;
  /** load: the rule's numbers; min / max: the rule's bounds changed; interrupted / unhealthy: a repair. */
  why: "load" | "min" | "max" | "interrupted" | "unhealthy";
  /** Numbers for the diary. */
  p: Record<string, number | string>;
}

export interface StepOutcome {
  /** The step happened: the app now runs `running` copies (this server's included). */
  done: boolean;
  running: number;
  /**
   * Why it did not happen. busy (another operation holds the state) and changed (a person changed the
   * app meanwhile) are asked again next round; no_room, start_failed and db_busy wait before trying again;
   * waking (a sleeping helper was woken over the network for it) tries again after about a minute.
   */
  held?: "busy" | "changed" | "no_room" | "start_failed" | "stop_failed" | "db_busy" | "waking";
  started?: string[];
  stopped?: string[];
  p?: Record<string, number | string>;
}

/** What the pool balancer counted: requests per app (counters since it started) and each copy's health. */
export interface BalancerReading {
  requests: Record<string, number>;
  healthy: Record<string, boolean>;
}

/** The parts of autoscale.ts a round uses (injectable for tests). */
export interface AutoHooks {
  readBalancer(): Promise<BalancerReading | null>;
  /** Rewrites the balancer when its configuration differs from the state (an update, a hand edit). */
  syncBalancer(): Promise<void>;
  apply(d: StepDecision, opts: { log: (l: string) => void }): Promise<StepOutcome>;
}

/** Automatic scaling acts on this app now (it is on, the app uses the pool balancer, runs, and this server owns its data). */
export function autoActive(app: AppRecord, state: Pick<PaaSState, "mirror">): boolean {
  return Boolean(app.scale?.auto && app.pool?.enabled && !app.pool.stoppedAt && !app.trashedAt && !app.originNodeId && !state.mirror?.fenced);
}

function intentFile(slug: string): string {
  return path.join(SCALE_DIR, `${sanitizeSlug(slug)}.step.json`);
}

/** Written before a step changes anything, removed after: one left behind means the step was cut short. */
export function writeIntent(d: StepDecision): void {
  ensureScaleDir();
  writeFileAtomic(intentFile(d.app), JSON.stringify({ app: d.app, kind: d.kind, from: d.from, to: d.to, pid: process.pid, host: os.hostname(), at: Date.now() }));
}

export function clearIntent(appName: string): void {
  fs.rmSync(intentFile(appName), { force: true });
}

function processGone(pid: unknown, host: unknown, at: unknown, maxAgeMs: number): boolean {
  if (typeof at !== "number" || Date.now() - at > maxAgeMs) return true;
  if (host !== os.hostname()) return false;
  try {
    process.kill(Number(pid), 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ESRCH";
  }
}

/** Steps whose process died halfway (the server restarted, the round was killed): each becomes a repair. */
export function interruptedSteps(): StepDecision[] {
  if (!fs.existsSync(SCALE_DIR)) return [];
  const out: StepDecision[] = [];
  for (const f of fs.readdirSync(SCALE_DIR)) {
    if (!f.endsWith(".step.json")) continue;
    let rec: { app?: unknown; pid?: unknown; host?: unknown; at?: unknown };
    try {
      rec = JSON.parse(fs.readFileSync(path.join(SCALE_DIR, f), "utf-8"));
    } catch {
      rec = {};
    }
    const slug = f.slice(0, -".step.json".length);
    if (rec.app !== slug) {
      fs.rmSync(path.join(SCALE_DIR, f), { force: true });
      continue;
    }
    if (processGone(rec.pid, rec.host, rec.at, 2 * 60 * 60 * 1000)) out.push({ app: slug, kind: "repair", from: 0, to: 0, why: "interrupted", p: { why: "interrupted" } });
  }
  return out;
}

// ---------- the round ----------

const LOCK_STALE_MS = 2 * 60 * 60 * 1000;

/** One round at a time. A round that adds or removes copies can take minutes, so the lock names its process. */
function takeLock(): boolean {
  ensureScaleDir();
  try {
    const fd = fs.openSync(LOCK_FILE, "wx", 0o600);
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, host: os.hostname(), at: Date.now() }));
    fs.closeSync(fd);
    return true;
  } catch {
    try {
      let rec: { pid?: unknown; host?: unknown; at?: unknown } = {};
      try {
        rec = JSON.parse(fs.readFileSync(LOCK_FILE, "utf-8"));
      } catch {
        // an older round wrote only its pid, or the file is being written
        rec = { pid: Number(fs.readFileSync(LOCK_FILE, "utf-8")), host: os.hostname(), at: fs.statSync(LOCK_FILE).mtimeMs };
      }
      if (processGone(rec.pid, rec.host, rec.at, LOCK_STALE_MS)) {
        fs.rmSync(LOCK_FILE, { force: true });
        return takeLock();
      }
    } catch {
      // vanished: try once more next round
    }
    return false;
  }
}

/** Copies of the app running now: this server's plus those on helper PCs (pool.ts). */
export function realCopies(app: Pick<AppRecord, "pool">): number {
  if (!app.pool?.enabled || app.pool.stoppedAt) return 1;
  return 1 + app.pool.placed.length;
}

/** Apps that can be measured here (only those whose container is running get a sample). */
export function measuredApps(state: PaaSState): AppRecord[] {
  return Object.values(state.apps).filter((a) => !a.trashedAt);
}

/** The addresses the pool balancer checks for an app: this server's container and each helper copy. */
function balancerAddresses(app: AppRecord, state: PaaSState): { origin: string; helpers: string[] } {
  const helpers = (app.pool?.placed || [])
    .map((c) => ({ c, h: state.pool?.helpers[c.helper] }))
    .filter(({ h }) => h && !h.paused)
    .map(({ c, h }) => `${h!.ip}:${c.port}`);
  return { origin: `${app.containerName}:${app.internalPort}`, helpers };
}

export interface TickResult {
  at: string;
  skipped?: string;
  apps: Record<
    string,
    { cpu: number | null; mem: number | null; lat: number | null; ok: boolean | null; rps?: number | null; copies: number; auto?: boolean; event?: string; step?: string }
  >;
  /** Courteous mode: helpers whose owner started or stopped using them in this round. */
  courtesy?: { helper: string; change: "busy" | "calm"; cpuPct: number; done: boolean; held?: string; apps: { app: string; started: string[]; stopped: number; running: number }[] }[];
  /** Wake-on-LAN: helpers that answered after a wake-up, got another try, or were given up on. */
  wake?: { helper: string; change: "woke" | "sent" | "gave_up"; apps: { app: string; started: string[]; running: number }[] }[];
}

/** Rounds in a row a helper copy must look unhealthy to the balancer before the helpers are checked. */
const UNHEALTHY_ROUNDS = 8;
const REPAIR_EVERY_MS = 10 * 60 * 1000;

/**
 * One round for every running app: measure, run the rule, and for apps with automatic scaling on, carry
 * out the step the rule asks for (one at a time, each under the state lock). `stats`, `probe` and `auto`
 * are injectable for tests.
 */
export async function scaleTick(
  opts: {
    now?: number;
    stats?: () => Promise<Record<string, RawStats>>;
    probe?: (url: string) => Promise<{ ok: boolean; ms: number | null }>;
    log?: (line: string) => void;
    auto?: AutoHooks;
    courtesy?: (o: { now?: number; log?: (l: string) => void; note: (app: string, kind: "owner_busy" | "owner_calm", p: Record<string, number | string>) => string }) => Promise<NonNullable<TickResult["courtesy"]>>;
    wake?: (o: { now?: number; log?: (l: string) => void; note: (app: string, kind: "wake_failed", p: Record<string, number | string>) => string }) => Promise<NonNullable<TickResult["wake"]>>;
  } = {}
): Promise<TickResult> {
  const now = opts.now ?? Date.now();
  const result: TickResult = { at: new Date(now).toISOString(), apps: {} };
  const log = opts.log ?? ((l: string) => console.log(l));
  if (!takeLock()) return { ...result, skipped: "another round is still running" };
  try {
    const state = loadState();
    const lang = diaryLanguage(state);
    const interval = state.scale?.timer?.seconds || DEFAULT_INTERVAL_SECONDS;
    const gapMs = Math.max(90_000, interval * 3 * 1000);
    const pooled = Object.values(state.apps).some((a) => a.pool?.enabled && !a.trashedAt);
    const steps: StepDecision[] = interruptedSteps();
    // The pool's code is loaded only when something uses it.
    const hooks: AutoHooks | undefined = pooled || steps.length ? opts.auto ?? (await import("./autoscale.js")).autoHooks() : undefined;
    const note = (app: string, kind: DiaryKind, p: Record<string, number | string>) => {
      const entry: DiaryEntry = { t: new Date(now).toISOString(), app, kind, p };
      appendDiary(entry);
      const text = renderDiary(entry, lang);
      log(`[${app}] ${text}`);
      return text;
    };

    if (measuredApps(state).length) {
      if (pooled && hooks) await hooks.syncBalancer().catch(() => undefined);
      const statsFn = opts.stats ?? (() => dockerStats());
      const probeFn = opts.probe ?? probeApp;
      const [stats, lb] = await Promise.all([statsFn(), pooled && hooks ? hooks.readBalancer().catch(() => null) : Promise.resolve(null)]);
      // Only apps whose container runs here get a sample; their health paths are probed in parallel.
      const apps = measuredApps(state).filter((a) => stats[a.containerName]);
      const probes = await Promise.all(
        apps.map((a) => (a.healthcheckDisabled ? Promise.resolve(null) : probeFn(`http://127.0.0.1:${a.localPort}${a.healthcheckPath || "/"}`)))
      );
      apps.forEach((app, i) => {
        const raw = stats[app.containerName];
        const probe = probes[i];
        const rule = ruleFor(app);
        const auto = autoActive(app, state);
        const file: AppScaleFile = readAppFile(app.name) || { v: 1, recent: [], rehearsal: freshRehearsal(rule) };
        // Network counters restart with the container: only a growing counter gives a rate.
        let rx: number | null = null;
        let tx: number | null = null;
        const c = file.counters;
        if (c && file.container === app.containerName && raw.rxTotal !== null && raw.txTotal !== null && now > c.t) {
          const secs = (now - c.t) / 1000;
          if (raw.rxTotal >= c.rx && raw.txTotal >= c.tx && now - c.t <= gapMs) {
            rx = round1((raw.rxTotal - c.rx) / secs);
            tx = round1((raw.txTotal - c.tx) / secs);
          }
        }
        file.container = app.containerName;
        if (raw.rxTotal !== null && raw.txTotal !== null) file.counters = { t: now, rx: raw.rxTotal, tx: raw.txTotal };

        // Visits through the pool balancer: its counter for this app, the same way (a restart resets it).
        let rps: number | null = null;
        let serving: number | null = null;
        const total = app.pool?.enabled ? lb?.requests[app.name] : undefined;
        if (typeof total === "number" && Number.isFinite(total)) {
          const prev = file.lb;
          if (prev && total >= prev.total && now > prev.t && now - prev.t <= gapMs) rps = round1((total - prev.total) / ((now - prev.t) / 1000));
          file.lb = { t: now, total };
        } else delete file.lb;
        const addrs = balancerAddresses(app, state);
        if (lb && app.pool?.enabled) {
          const known = [addrs.origin, ...addrs.helpers].filter((a) => typeof lb.healthy[a] === "boolean");
          serving = known.length ? known.filter((a) => lb.healthy[a]).length : null;
        }

        const sample: Sample = {
          t: now,
          cpu: raw.cpu === null ? null : round1(raw.cpu),
          mem: raw.mem === null ? null : round1(raw.mem),
          rx,
          tx,
          lat: probe ? probe.ms : null,
          ok: probe ? probe.ok : null,
          ...(app.pool?.enabled ? { rps, serving } : {}),
          copies: realCopies(app),
        };
        file.recent = [...file.recent.filter((s) => s.t > now - RECENT_MS && s.t < now), sample].slice(-200);

        // Close every finished minute into the 24 h history.
        const thisMinute = Math.floor(now / 60_000) * 60_000;
        // Only minutes still inside the recent window can be closed (a long gap has nothing to close).
        const oldest = Math.floor((now - RECENT_MS) / 60_000) * 60_000;
        const from = Math.max(file.flushedUntil ?? oldest, oldest);
        const done: MinutePoint[] = [];
        for (let m = from; m < thisMinute; m += 60_000) {
          const inMinute = file.recent.filter((s) => s.t >= m && s.t < m + 60_000);
          if (inMinute.length) done.push(aggregateMinute(m, inMinute));
        }
        file.flushedUntil = thisMinute;
        ensureScaleDir();
        appendHistory(app.name, done, now);

        const base = { cpuRefCores: cpuReference(app), gapMs, path: app.healthcheckPath || "/", realCopies: realCopies(app), rps };
        let eventText: string | undefined;
        if (!auto) {
          const r = rehearse(rule, file.rehearsal, sample, base);
          file.rehearsal = r.state;
          if (r.event) eventText = note(app.name, r.event.kind, r.event.p);
        } else if (!steps.some((d) => d.app === app.name)) {
          // The real number of copies, as asked for (a person may have changed it, or a step was cut short).
          const copies = app.pool!.copies;
          file.rehearsal.copies = copies;
          const o = observe(rule, file.rehearsal, sample, readingOf(sample, clampCopies(rule, copies), { ...base, serving }), { gapMs, path: base.path, auto: true });
          file.rehearsal = o.state;
          if (o.event) eventText = note(app.name, o.event.kind, o.event.p);
          const st = file.rehearsal;
          const waiting = (st.lastActionAt !== undefined && now - st.lastActionAt < rule.cooldownSeconds * 1000) || (st.retryAt !== undefined && now < st.retryAt);
          const bounded = clampCopies(rule, copies);
          // Helper copies the balancer has found unhealthy for a while: the helpers are asked what they run.
          const sick = lb ? addrs.helpers.filter((a) => lb.healthy[a] === false).length : 0;
          st.unhealthyRounds = sick ? (st.unhealthyRounds || 0) + 1 : 0;
          // Nothing changes while the app's health path fails (observe asks for no step then either).
          if (bounded !== copies && !waiting && !st.failing) {
            const dir = bounded > copies ? "up" : "down";
            steps.push({ app: app.name, kind: dir, from: copies, to: bounded, why: dir === "up" ? "min" : "max", p: { from: copies, to: bounded, why: dir === "up" ? "min" : "max" } });
          } else if (o.want) {
            const to = copies + (o.want === "up" ? 1 : -1);
            steps.push({ app: app.name, kind: o.want, from: copies, to, why: "load", p: stepParams(rule, o.want, copies, to, o) });
          } else if (st.unhealthyRounds >= UNHEALTHY_ROUNDS && (st.lastRepairAt === undefined || now - st.lastRepairAt >= REPAIR_EVERY_MS)) {
            steps.push({ app: app.name, kind: "repair", from: copies, to: copies, why: "unhealthy", p: { why: "unhealthy", minutes: Math.max(1, Math.round((st.unhealthyRounds * interval) / 60)) } });
          }
        }
        writeFileAtomic(appFile(app.name), JSON.stringify(file));
        result.apps[app.name] = {
          cpu: sample.cpu,
          mem: sample.mem,
          lat: sample.lat,
          ok: sample.ok,
          ...(app.pool?.enabled ? { rps } : {}),
          copies: auto ? app.pool!.copies : file.rehearsal.copies,
          ...(auto ? { auto: true } : {}),
          ...(eventText ? { event: eventText } : {}),
        };
      });
    }

    // Carry out the steps, one app at a time. Each takes the state lock (briefly waiting for it): when
    // another operation holds it, the step is asked again next round.
    for (const d of steps) {
      if (!hooks) break;
      let outcome: StepOutcome;
      try {
        outcome = await hooks.apply(d, { log: (l) => log(`[${d.app}] ${l}`) });
      } catch (err) {
        log(`[${d.app}] step failed: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      const text = settleStep(d, outcome, now, note);
      if (result.apps[d.app]) {
        result.apps[d.app].copies = outcome.running;
        if (text) result.apps[d.app].step = text;
      }
    }

    // Courteous mode: once a minute, the helpers say how much their owner uses them (courtesy.ts).
    if (Object.keys(loadState().pool?.helpers || {}).length) {
      try {
        const { courtesyRound } = await (opts.courtesy ? Promise.resolve({ courtesyRound: opts.courtesy }) : import("./courtesy.js"));
        const changes = await courtesyRound({ now, log, note });
        if (changes.length) result.courtesy = changes;
        for (const c of changes) for (const a of c.apps) if (result.apps[a.app]) result.apps[a.app].copies = a.running;
      } catch (err) {
        log(`courteous mode: ${err instanceof Error ? err.message : String(err)}`);
      }
      // Wake-on-LAN: PCs woken earlier are asked whether they answer now; those that do get their copies
      // back, the others another try, until the tries run out (wake.ts).
      try {
        const { wakeRound } = await (opts.wake ? Promise.resolve({ wakeRound: opts.wake }) : import("./wake.js"));
        const changes = await wakeRound({ now, log, note });
        if (changes.length) result.wake = changes;
        for (const c of changes) for (const a of c.apps) if (result.apps[a.app]) result.apps[a.app].copies = a.running;
      } catch (err) {
        log(`Wake-on-LAN: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return result;
  } finally {
    fs.rmSync(LOCK_FILE, { force: true });
  }
}

/** Records what a step did in the app's decision state and the diary. Returns the diary sentence, if any. */
function settleStep(
  d: StepDecision,
  outcome: StepOutcome,
  now: number,
  note: (app: string, kind: DiaryKind, p: Record<string, number | string>) => string
): string | undefined {
  const app = loadState().apps[d.app];
  if (!app) return undefined;
  const rule = ruleFor(app);
  const file: AppScaleFile = readAppFile(d.app) || { v: 1, recent: [], rehearsal: freshRehearsal(rule) };
  let text: string | undefined;
  if (d.kind === "repair") {
    file.rehearsal = { ...file.rehearsal, lastRepairAt: now, unhealthyRounds: 0, ...(outcome.done ? { copies: outcome.running } : {}) };
    if (outcome.done && (outcome.started?.length || outcome.stopped?.length)) {
      text = note(d.app, "repaired", { ...d.p, started: outcome.started?.length || 0, stopped: outcome.stopped?.length || 0 });
    }
  } else if (outcome.done) {
    file.rehearsal = commitStep(file.rehearsal, d.kind, now, outcome.running);
    const helper = d.kind === "up" ? outcome.started?.[0] : outcome.stopped?.[0];
    text = note(d.app, d.kind, { ...d.p, to: outcome.running, ...(helper ? { helper } : {}) });
  } else if (outcome.held && outcome.held !== "busy" && outcome.held !== "changed") {
    const h = holdStep(file.rehearsal, outcome.held, now, rule, outcome.running);
    file.rehearsal = h.state;
    if (h.note) {
      text = note(d.app, "held", {
        why: outcome.held,
        from: d.from,
        to: d.to,
        running: outcome.running,
        waitSeconds: Math.round(((h.state.retryAt ?? now) - now) / 1000),
        ...(outcome.p || {}),
      });
    }
  }
  writeFileAtomic(appFile(d.app), JSON.stringify(file));
  return text;
}

// ---------- reading ----------

export interface AppScaleStatus {
  app: string;
  measuring: boolean;
  last?: Sample;
  /** CPU of the last sample in % of the app's limit (or of one core). */
  cpuOfLimit: number | null;
  cpuReferenceCores: number;
  cpuLimited: boolean;
  /** Copies the rehearsal would be running now (with automatic scaling on: the copies the decider asks for). */
  rehearsalCopies: number;
  /** Copies really running now (this server's plus those on helper PCs). */
  copies: number;
  /** Copies asked for (by hand, or by the decider); absent when the app runs only here. */
  wantedCopies?: number;
  poolError?: string;
  /** Automatic scaling: on since when, and whether it acts now (it waits while the app is stopped or the server fenced). */
  auto?: { since: string; by: string; acting: boolean };
  /** Visits per second through the pool balancer at the last round (only for apps behind it). */
  rps?: number | null;
  /** Copies the balancer found healthy at the last round. */
  serving?: number | null;
  rule: ScaleRule;
  capacity?: CapacityResult;
  lastEvent?: { t: string; text: string };
}

export function scaleStatus(opts: { app?: string; lang?: DiaryLang; now?: number } = {}): {
  timer: { seconds: number; installedAt: string } | null;
  language: DiaryLang;
  apps: AppScaleStatus[];
} {
  const state = loadState();
  const now = opts.now ?? Date.now();
  const lang = opts.lang ?? diaryLanguage(state);
  const interval = state.scale?.timer?.seconds || DEFAULT_INTERVAL_SECONDS;
  const only = opts.app ? sanitizeSlug(opts.app) : undefined;
  if (only && !state.apps[only]) throw new Error(`App '${only}' not found.`);
  const diary = readDiary({ now });
  const apps = measuredApps(state)
    .filter((a) => !only || a.name === only)
    .map((app) => {
      const file = readAppFile(app.name);
      const last = file?.recent[file.recent.length - 1];
      const ref = cpuReference(app);
      const ev = [...diary].reverse().find((e) => e.app === app.name);
      return {
        app: app.name,
        measuring: Boolean(last && now - last.t <= Math.max(90_000, interval * 3000)),
        last,
        cpuOfLimit: last?.cpu == null ? null : Math.round(last.cpu / ref),
        cpuReferenceCores: ref,
        cpuLimited: Boolean(app.cpuLimit),
        rehearsalCopies: file?.rehearsal.copies ?? ruleFor(app).min,
        copies: realCopies(app),
        ...(app.pool?.enabled ? { wantedCopies: app.pool.copies } : {}),
        ...(app.pool?.lastError ? { poolError: app.pool.lastError } : {}),
        ...(app.scale?.auto ? { auto: { ...app.scale.auto, acting: autoActive(app, state) } } : {}),
        ...(app.pool?.enabled ? { rps: last?.rps ?? null, serving: last?.serving ?? null } : {}),
        rule: ruleFor(app),
        ...(app.scale?.capacity ? { capacity: app.scale.capacity } : {}),
        ...(ev ? { lastEvent: { t: ev.t, text: renderDiary(ev, lang) } } : {}),
      };
    });
  // `language` is the server's setting (CLI, log, MCP); the sentences above use `lang`.
  return { timer: state.scale?.timer || null, language: diaryLanguage(state), apps };
}

/** Everything one app's chart needs: 24 h of points (in buckets of `bucketMinutes`) and the last 10 minutes. */
export function scaleHistory(appName: string, opts: { bucketMinutes?: number; now?: number } = {}) {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const now = opts.now ?? Date.now();
  const bucket = Math.min(60, Math.max(1, Math.round(opts.bucketMinutes ?? 5)));
  return {
    app: slug,
    bucketMinutes: bucket,
    cpuReferenceCores: cpuReference(app),
    points: downsample(readHistory(slug, now), bucket),
    recent: readAppFile(slug)?.recent || [],
  };
}

/** Diary sentences in one language (newest last). */
export function scaleDiary(opts: { app?: string; lang?: DiaryLang; limit?: number } = {}) {
  const lang = opts.lang ?? diaryLanguage();
  const limit = Math.min(500, Math.max(1, Math.round(opts.limit ?? 50)));
  return readDiary({ app: opts.app, limit }).map((e) => ({ t: e.t, app: e.app, kind: e.kind, text: renderDiary(e, lang) }));
}

// ---------- timer ----------

const SERVICE = "/etc/systemd/system/paasmcp-scale.service";
const TIMER = "/etc/systemd/system/paasmcp-scale.timer";

/** A systemd oneshot timer: one round every `seconds`, nothing in memory in between. */
export function installScaleTimer(seconds = DEFAULT_INTERVAL_SECONDS): { service: string; timer: string; seconds: number } {
  if (!Number.isInteger(seconds) || seconds < 10 || seconds > 300) throw new Error("--seconds must be a whole number from 10 to 300.");
  fs.writeFileSync(
    SERVICE,
    // A round that adds or removes copies can take minutes (an image to send, 30 s of draining); a
    // round cut short is repaired by the next one.
    `[Unit]\nDescription=PaaSMCP scale round (measures and rehearses; adds or removes copies only for apps with automatic scaling on)\nAfter=docker.service\n\n[Service]\nType=oneshot\nNice=10\nTimeoutStartSec=45min\nEnvironment=PAASMCP_ROOT=${process.env.PAASMCP_ROOT || HOMELAB_ROOT}\nExecStart=${process.execPath} ${path.resolve(process.argv[1])} scale tick --quiet\n`
  );
  fs.writeFileSync(
    TIMER,
    `[Unit]\nDescription=Run the PaaSMCP scale round every ${seconds} s\n\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=${seconds}s\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n`
  );
  if (!OFFLINE()) {
    execFileSync("systemctl", ["daemon-reload"]);
    execFileSync("systemctl", ["enable", "--now", "paasmcp-scale.timer"]);
  }
  const state = loadState();
  state.scale = { ...(state.scale || {}), timer: { seconds, installedAt: new Date().toISOString() } };
  saveState(state);
  audit({ event: "scale.timer.install", seconds });
  return { service: SERVICE, timer: TIMER, seconds };
}

export function uninstallScaleTimer(): { removed: boolean } {
  if (!OFFLINE()) {
    try {
      execFileSync("systemctl", ["disable", "--now", "paasmcp-scale.timer"], { stdio: "pipe" });
    } catch {
      // not installed
    }
  }
  const existed = fs.existsSync(TIMER);
  fs.rmSync(TIMER, { force: true });
  fs.rmSync(SERVICE, { force: true });
  if (!OFFLINE()) execFileSync("systemctl", ["daemon-reload"]);
  const state = loadState();
  if (state.scale) delete state.scale.timer;
  saveState(state);
  audit({ event: "scale.timer.uninstall" });
  return { removed: existed };
}
