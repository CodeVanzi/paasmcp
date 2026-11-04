import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
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

// Automatic scaling, phase 1: measure and rehearse, never act.
//
// `paasmcp scale tick` (a systemd oneshot timer, so nothing stays in memory between rounds) reads
// every running app's CPU, memory and network traffic from `docker stats`, probes its health path
// to time an answer, and keeps:
//   - the last 10 minutes at full resolution, plus the rehearsal state, in scale/<app>.json;
//   - one point per minute for 24 hours in scale/<app>.history.ndjson (appended once a minute).
// The rehearsal runs the decision rule on those numbers as if the app could have more copies, and
// writes what it would do, with the reason, to the decision diary (scale/diary.ndjson). The diary is
// stored as codes and numbers and rendered in Portuguese or English when read.

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
};

const RULE_LIMITS: Record<keyof ScaleRule, [number, number]> = {
  min: [1, 20],
  max: [1, 20],
  targetCpu: [10, 95],
  upRounds: [1, 20],
  downAfterSeconds: [60, 86400],
  cooldownSeconds: [0, 3600],
};

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
}

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
}

interface AppScaleFile {
  v: 1;
  container?: string;
  counters?: { t: number; rx: number; tx: number };
  recent: Sample[];
  /** Start of the first minute not yet written to the history. */
  flushedUntil?: number;
  rehearsal: RehearsalState;
}

export type DiaryKind = "would_up" | "would_down" | "at_max" | "no_answer" | "answered_again" | "rule_changed" | "capacity";

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

/** Changes an app's rehearsal rule (free: phase 1 never starts or stops anything). */
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
  appendDiary({ t: new Date().toISOString(), app: slug, kind: "rule_changed", p: { min: next.min, max: next.max, target: next.targetCpu } });
  return { app: slug, rule: next };
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

// ---------- rehearsal (pure) ----------

export function freshRehearsal(rule: ScaleRule): RehearsalState {
  return { copies: rule.min, aboveStreak: 0, failing: 0 };
}

/**
 * Runs the decision rule on one sample as if the app could have more copies. `copies` is how many
 * copies the rule would be running by now; the measured CPU (of this server's copy) is spread over them.
 * With copies on helper PCs (`realCopies`, set by hand in phase 3), this server's copy carries only its
 * share of the visits, so the whole load is estimated as its CPU times the real copies. Pure: returns the next state and, when something would happen, a diary event.
 */
export function rehearse(
  rule: ScaleRule,
  prev: RehearsalState,
  s: Pick<Sample, "t" | "cpu" | "ok" | "lat">,
  opts: { cpuRefCores: number; gapMs: number; path?: string; realCopies?: number }
): { state: RehearsalState; event?: { kind: DiaryKind; p: Record<string, number | string> } } {
  const st: RehearsalState = { ...prev };
  st.copies = Math.min(rule.max, Math.max(rule.min, st.copies || rule.min));
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
      return { state: st, event: { kind: "no_answer", p: { rounds: st.failing, path: opts.path || "/" } } };
    }
    return { state: st };
  }
  st.failing = 0;
  let recovered: { kind: DiaryKind; p: Record<string, number | string> } | undefined;
  if (st.failNoted) {
    st.failNoted = false;
    recovered = { kind: "answered_again", p: { ms: s.lat ?? 0 } };
  }
  if (s.cpu === null) return { state: st, event: recovered };

  const perCopy = (s.cpu * Math.max(1, opts.realCopies ?? 1)) / opts.cpuRefCores / st.copies;
  const inCooldown = st.lastActionAt !== undefined && s.t - st.lastActionAt < rule.cooldownSeconds * 1000;

  if (perCopy > rule.targetCpu) {
    st.aboveStreak += 1;
    st.aboveSince ??= s.t;
  } else {
    st.aboveStreak = 0;
    delete st.aboveSince;
    st.atMaxNoted = false;
  }
  if (perCopy < rule.targetCpu / 2) st.belowSince ??= s.t;
  else delete st.belowSince;

  if (st.aboveStreak >= rule.upRounds && !inCooldown) {
    if (st.copies < rule.max) {
      const from = st.copies;
      const seconds = Math.round((s.t - (st.aboveSince ?? s.t)) / 1000);
      st.copies += 1;
      st.lastActionAt = s.t;
      resetStreaks();
      return {
        state: st,
        event: { kind: "would_up", p: { from, to: st.copies, cpu: Math.round(perCopy), target: rule.targetCpu, rounds: rule.upRounds, seconds } },
      };
    }
    if (!st.atMaxNoted) {
      st.atMaxNoted = true;
      return { state: st, event: { kind: "at_max", p: { max: rule.max, cpu: Math.round(perCopy), target: rule.targetCpu } } };
    }
  }

  if (st.belowSince !== undefined && s.t - st.belowSince >= rule.downAfterSeconds * 1000 && st.copies > rule.min && !inCooldown) {
    const from = st.copies;
    st.copies -= 1;
    st.lastActionAt = s.t;
    st.belowSince = s.t;
    return {
      state: st,
      event: {
        kind: "would_down",
        p: { from, to: st.copies, cpu: Math.round(perCopy), below: Math.round(rule.targetCpu / 2), minutes: Math.round(rule.downAfterSeconds / 60) },
      },
    };
  }
  return { state: st, event: recovered };
}

// ---------- history ----------

/** Averages the samples of one minute. */
export function aggregateMinute(t: number, samples: Sample[]): MinutePoint {
  const avg = (vals: (number | null)[]) => {
    const v = vals.filter((x): x is number => x !== null);
    return v.length ? round1(v.reduce((a, b) => a + b, 0) / v.length) : null;
  };
  const max = (vals: (number | null)[]) => {
    const v = vals.filter((x): x is number => x !== null);
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
      const wavg = (f: (p: MinutePoint) => number | null) => {
        const v = ps.filter((p) => f(p) !== null);
        const w = v.reduce((a, p) => a + p.n, 0);
        return w ? round1(v.reduce((a, p) => a + (f(p) as number) * p.n, 0) / w) : null;
      };
      const mx = (f: (p: MinutePoint) => number | null) => {
        const v = ps.map(f).filter((x): x is number => x !== null);
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

const DIARY_KINDS = new Set<DiaryKind>(["would_up", "would_down", "at_max", "no_answer", "answered_again", "rule_changed", "capacity"]);

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

/** Turns a diary entry into a sentence. Only numbers and app slugs go in, so the text is safe to show. */
export function renderDiary(e: DiaryEntry, lang: DiaryLang): string {
  const p = e.p;
  const n = (k: string) => String(Number(p[k]) || 0);
  const s = (k: string) => String(p[k] ?? "");
  const copies = (k: string) => {
    const v = Number(p[k]) || 0;
    return lang === "en" ? `${v} ${v === 1 ? "copy" : "copies"}` : `${v} ${v === 1 ? "cópia" : "cópias"}`;
  };
  if (lang === "en") {
    switch (e.kind) {
      case "would_up":
        return `Rehearsal: would go from ${n("from")} to ${copies("to")}. CPU per copy was ${n("cpu")}% (target ${n("target")}%) for ${n("rounds")} rounds in a row (${n("seconds")} s).`;
      case "would_down":
        return `Rehearsal: would go from ${n("from")} to ${copies("to")}. CPU per copy stayed below ${n("below")}% for ${n("minutes")} min.`;
      case "at_max":
        return `Rehearsal: already at the maximum of ${copies("max")} and CPU per copy is still ${n("cpu")}% (target ${n("target")}%). Consider a higher maximum or CPU limit.`;
      case "no_answer":
        return `The app did not answer on ${s("path")} for ${n("rounds")} rounds in a row. The rehearsal decides nothing meanwhile.`;
      case "answered_again":
        return `The app answers again (${n("ms")} ms).`;
      case "rule_changed":
        return `Rehearsal rule changed: minimum ${n("min")}, maximum ${n("max")}, CPU target ${n("target")}%.`;
      case "capacity":
        return `Capacity test: one copy handled ${n("rps")} requests per second on ${s("path")} (p95 ${n("p95")} ms). Limit: ${bottleneckText(s("bottleneck"), "en")}.`;
    }
  }
  switch (e.kind) {
    case "would_up":
      return `Ensaio: subiria de ${n("from")} para ${copies("to")}. A CPU por cópia ficou em ${n("cpu")}% (alvo ${n("target")}%) por ${n("rounds")} rodadas seguidas (${n("seconds")} s).`;
    case "would_down":
      return `Ensaio: desceria de ${n("from")} para ${copies("to")}. A CPU por cópia ficou abaixo de ${n("below")}% por ${n("minutes")} min.`;
    case "at_max":
      return `Ensaio: já está no máximo de ${copies("max")} e a CPU por cópia segue em ${n("cpu")}% (alvo ${n("target")}%). Vale aumentar o máximo ou o limite de CPU.`;
    case "no_answer":
      return `O app não respondeu em ${s("path")} por ${n("rounds")} rodadas seguidas. O ensaio não decide nada enquanto isso.`;
    case "answered_again":
      return `O app voltou a responder (${n("ms")} ms).`;
    case "rule_changed":
      return `Regra do ensaio alterada: mínimo ${n("min")}, máximo ${n("max")}, alvo de CPU ${n("target")}%.`;
    case "capacity":
      return `Teste de capacidade: uma cópia aguentou ${n("rps")} visitas por segundo em ${s("path")} (p95 ${n("p95")} ms). Limite: ${bottleneckText(s("bottleneck"), "pt")}.`;
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
  for (const f of [appFile(appName), historyFile(appName)]) fs.rmSync(f, { force: true });
}

// ---------- the round ----------

function takeLock(): boolean {
  ensureScaleDir();
  try {
    const fd = fs.openSync(LOCK_FILE, "wx", 0o600);
    fs.writeSync(fd, String(process.pid));
    fs.closeSync(fd);
    return true;
  } catch {
    try {
      if (Date.now() - fs.statSync(LOCK_FILE).mtimeMs > 120_000) {
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

export interface TickResult {
  at: string;
  skipped?: string;
  apps: Record<string, { cpu: number | null; mem: number | null; lat: number | null; ok: boolean | null; copies: number; event?: string }>;
}

/**
 * One measuring round for every running app. `stats` and `probe` are injectable for tests.
 * Never starts or stops anything.
 */
export async function scaleTick(
  opts: {
    now?: number;
    stats?: () => Promise<Record<string, RawStats>>;
    probe?: (url: string) => Promise<{ ok: boolean; ms: number | null }>;
    log?: (line: string) => void;
  } = {}
): Promise<TickResult> {
  const now = opts.now ?? Date.now();
  const result: TickResult = { at: new Date(now).toISOString(), apps: {} };
  if (!takeLock()) return { ...result, skipped: "another round is still running" };
  try {
    const state = loadState();
    const lang = diaryLanguage(state);
    const interval = state.scale?.timer?.seconds || DEFAULT_INTERVAL_SECONDS;
    const gapMs = Math.max(90_000, interval * 3 * 1000);
    if (!measuredApps(state).length) return result;
    const statsFn = opts.stats ?? (() => dockerStats());
    const probeFn = opts.probe ?? probeApp;
    const stats = await statsFn();
    // Only apps whose container runs here get a sample; their health paths are probed in parallel.
    const apps = measuredApps(state).filter((a) => stats[a.containerName]);
    const probes = await Promise.all(
      apps.map((a) => (a.healthcheckDisabled ? Promise.resolve(null) : probeFn(`http://127.0.0.1:${a.localPort}${a.healthcheckPath || "/"}`)))
    );
    apps.forEach((app, i) => {
      const raw = stats[app.containerName];
      const probe = probes[i];
      const rule = ruleFor(app);
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
      const sample: Sample = {
        t: now,
        cpu: raw.cpu === null ? null : round1(raw.cpu),
        mem: raw.mem === null ? null : round1(raw.mem),
        rx,
        tx,
        lat: probe ? probe.ms : null,
        ok: probe ? probe.ok : null,
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

      const r = rehearse(rule, file.rehearsal, sample, { cpuRefCores: cpuReference(app), gapMs, path: app.healthcheckPath || "/", realCopies: realCopies(app) });
      file.rehearsal = r.state;
      let eventText: string | undefined;
      if (r.event) {
        const entry: DiaryEntry = { t: new Date(now).toISOString(), app: app.name, kind: r.event.kind, p: r.event.p };
        appendDiary(entry);
        eventText = renderDiary(entry, lang);
        (opts.log ?? ((l: string) => console.log(l)))(`[${app.name}] ${eventText}`);
      }
      writeFileAtomic(appFile(app.name), JSON.stringify(file));
      result.apps[app.name] = { cpu: sample.cpu, mem: sample.mem, lat: sample.lat, ok: sample.ok, copies: file.rehearsal.copies, ...(eventText ? { event: eventText } : {}) };
    });
    return result;
  } finally {
    fs.rmSync(LOCK_FILE, { force: true });
  }
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
  /** Copies the rehearsal would be running now. */
  rehearsalCopies: number;
  /** Copies really running now (this server's plus those on helper PCs, set by hand). */
  copies: number;
  /** Copies asked for by hand (`scale set`); absent when the app runs only here. */
  wantedCopies?: number;
  poolError?: string;
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
    `[Unit]\nDescription=PaaSMCP scale measuring round (measures and rehearses, never starts or stops apps)\nAfter=docker.service\n\n[Service]\nType=oneshot\nNice=10\nEnvironment=PAASMCP_ROOT=${process.env.PAASMCP_ROOT || HOMELAB_ROOT}\nExecStart=${process.execPath} ${path.resolve(process.argv[1])} scale tick --quiet\n`
  );
  fs.writeFileSync(
    TIMER,
    `[Unit]\nDescription=Run the PaaSMCP scale measuring round every ${seconds} s\n\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=${seconds}s\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n`
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
