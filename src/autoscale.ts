import { execFile } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { loadState, PaaSState, sanitizeSlug, saveState, StateLockBusyError, withStateLock } from "./config.js";
import { audit } from "./guard.js";
import { applyBalancer, balancerRunning, balancerServerName, buildBalancerCaddyfile, LB_DIR, MAX_COPIES, poolReadiness, pooledApps, reconcilePool, setCopies } from "./pool.js";
import {
  appendDiary,
  AutoHooks,
  BalancerReading,
  clearIntent,
  realCopies,
  ruleFor,
  setScaleRule,
  StepDecision,
  StepOutcome,
  validateRule,
  writeIntent,
} from "./scale.js";

// Automatic scaling, phase 4: the decision rule rehearsed in phase 1 now acts, within each app's minimum
// and maximum, on the helper pool of phase 3.
//
// The measuring round (scale.ts, a systemd oneshot timer) decides; this file carries the step out:
//   - it reads how many visits each app got from the pool balancer's metrics (admin unix socket, no port);
//   - a step changes the copies asked for and runs the same reconcile as `scale set`, under the state lock;
//   - a file in scale/ marks a step in progress, so a step cut short (the server restarted) is repaired by
//     the next round: the helpers are asked what they run, and copies nobody knows are stopped;
//   - nothing new stays in memory: the round ends when its steps end.
// Turning automatic scaling on asks a person (guard "scale.auto"); so does raising the maximum of an app
// that scales by itself (guard "scale.rule"). Steps within the limits a person set are free.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
/** Above this share of Postgres's connections, no copy is added (each copy opens its own). */
const DB_BUSY_SHARE = 0.8;
/** Longest Unix socket path (sun_path is 108 bytes on Linux, with the final zero). */
const MAX_SOCKET_PATH = 107;
const msg = (err: unknown) => (err instanceof Error ? err.message : String(err));
const SERVER_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
const UPSTREAM = /^[a-z0-9][a-z0-9.-]{0,252}:\d{1,5}$/;

// ---------- the balancer's numbers ----------

/** Reads one Prometheus label set (`a="x",b="y"`), with its escapes. */
function parseLabels(text: string): Record<string, string> | null {
  const out: Record<string, string> = {};
  let i = 0;
  while (i < text.length) {
    const m = /^\s*([a-zA-Z_][a-zA-Z0-9_]*)="/.exec(text.slice(i));
    if (!m) return null;
    i += m[0].length;
    let v = "";
    for (;;) {
      if (i >= text.length) return null;
      const ch = text[i];
      if (ch === "\\") {
        const nx = text[i + 1];
        v += nx === "n" ? "\n" : nx;
        i += 2;
        continue;
      }
      if (ch === '"') break;
      v += ch;
      i += 1;
    }
    out[m[1]] = v;
    i += 1;
    const rest = /^\s*,?/.exec(text.slice(i));
    i += rest ? rest[0].length : 0;
  }
  return out;
}

/**
 * The two series the decider uses from the balancer's metrics (pure): requests the proxy handled per server
 * (one server per app, see balancerServerName) and each copy's health. Everything else is ignored.
 */
export function parseCaddyMetrics(text: string): BalancerReading {
  const requests: Record<string, number> = {};
  const healthy: Record<string, boolean> = {};
  for (const line of String(text).split("\n")) {
    const m = /^(caddy_http_requests_total|caddy_reverse_proxy_upstreams_healthy)\{(.*)\}\s+(\S+)\s*$/.exec(line);
    if (!m) continue;
    const labels = parseLabels(m[2]);
    const value = Number(m[3]);
    if (!labels || !Number.isFinite(value)) continue;
    // Each handler of a route counts the same request: only the proxy's count is the visit. Names are the
    // ones this server wrote (app slugs, `port-<n>`, `<host>:<port>`); anything else is skipped.
    if (m[1] === "caddy_http_requests_total" && labels.handler === "reverse_proxy" && SERVER_NAME.test(labels.server || "")) {
      requests[labels.server] = (requests[labels.server] || 0) + value;
    }
    if (m[1] === "caddy_reverse_proxy_upstreams_healthy" && UPSTREAM.test(labels.upstream || "")) healthy[labels.upstream] = value === 1;
  }
  return { requests, healthy };
}

/** Asks the balancer for its metrics on its admin socket (root only, nothing listens on a port). */
export function readBalancer(socketPath = path.join(LB_DIR, "data", "admin.sock")): Promise<BalancerReading | null> {
  if (OFFLINE() || socketPath.length > MAX_SOCKET_PATH || !fs.existsSync(socketPath)) return Promise.resolve(null);
  return new Promise((resolve) => {
    // Caddy's admin API on a Unix socket accepts only an empty Host.
    const req = http.request({ socketPath, path: "/metrics", method: "GET", setHost: false, headers: { Host: "" }, timeout: 3000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve(null);
      }
      let body = "";
      res.setEncoding("utf-8");
      res.on("data", (d) => {
        body += d;
        if (body.length > 8 * 1024 * 1024) req.destroy();
      });
      res.on("end", () => resolve(parseCaddyMetrics(body)));
      res.on("error", () => resolve(null));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
    req.end();
  });
}

/** Writes the balancer again when it differs from the state (an update of PaaSMCP, a hand edit) or is down. */
async function syncBalancer(): Promise<void> {
  const state = loadState();
  if (!pooledApps(state).length) return;
  const file = path.join(LB_DIR, "conf", "Caddyfile");
  const current = fs.existsSync(file) ? fs.readFileSync(file, "utf-8") : "";
  if (current === buildBalancerCaddyfile(state) && balancerRunning()) return;
  try {
    await withStateLock(() => applyBalancer(), 2000);
  } catch {
    // busy: next round
  }
}

// ---------- Postgres ----------

/** Connections in use and the most Postgres accepts, when the app uses the shared Postgres. */
export function postgresConnections(appName: string, state: PaaSState = loadState()): Promise<{ used: number; limit: number } | null> {
  const app = state.apps[appName];
  const usesPg = (app?.databases || []).some((d) => state.databases[d]?.engine === "postgres" && state.databases[d]?.host === "paasmcp-postgres");
  if (!usesPg || OFFLINE()) return Promise.resolve(null);
  // Only connections from clients (apps, people), not this question's own nor Postgres's background workers.
  const sql =
    "select count(*) filter (where backend_type = 'client backend' and pid <> pg_backend_pid()), " +
    "current_setting('max_connections')::int - current_setting('superuser_reserved_connections')::int from pg_stat_activity";
  return new Promise((resolve) => {
    execFile(
      "docker",
      ["exec", "paasmcp-postgres", "psql", "-U", "paasmcp_admin", "-d", "postgres", "-Atc", sql],
      { encoding: "utf-8", timeout: 8000 },
      (err, stdout) => {
        const m = /^(\d+)\|(\d+)\s*$/.exec(String(stdout || "").trim());
        resolve(err || !m ? null : { used: Number(m[1]), limit: Number(m[2]) });
      }
    );
  });
}

// ---------- steps ----------

/**
 * Carries out one step under the state lock (waiting at most `lockWaitMs` for it). The app is checked
 * again inside the lock: a person may have changed it since the round measured.
 */
export async function applyStep(d: StepDecision, opts: { log?: (l: string) => void; lockWaitMs?: number } = {}): Promise<StepOutcome> {
  const slug = sanitizeSlug(d.app);
  const log = opts.log ?? (() => undefined);
  if (d.kind === "up" && d.why === "load") {
    const db = await postgresConnections(slug);
    if (db && db.limit > 0 && db.used >= db.limit * DB_BUSY_SHARE) return { done: false, running: d.from, held: "db_busy", p: { used: db.used, limit: db.limit } };
  }
  try {
    return await withStateLock(async () => {
      const state = loadState();
      const app = state.apps[slug];
      if (d.kind === "repair") {
        // A step cut short, or a helper copy the balancer has found unhealthy for a while: the helpers
        // are asked what they run, missing copies come back and copies nobody knows stop.
        if (!app?.pool?.enabled) {
          clearIntent(slug);
          return { done: false, running: app ? realCopies(app) : 1, held: "changed" };
        }
        writeIntent(d);
        try {
          const r = await reconcilePool(slug, { log });
          return { done: true, running: r.running, started: r.started.map((x) => x.helper), stopped: r.stopped.map((x) => x.helper) };
        } finally {
          clearIntent(slug);
        }
      }
      if (!app?.scale?.auto || !app.pool?.enabled || app.pool.stoppedAt || state.mirror?.fenced) return { done: false, running: app ? realCopies(app) : 1, held: "changed" };
      if (app.pool.copies !== d.from) return { done: false, running: app.pool.copies, held: "changed" };
      const rule = ruleFor(app);
      const to = Math.min(MAX_COPIES, rule.max, Math.max(rule.min, d.to));
      if (to === d.from) return { done: false, running: d.from, held: "changed" };
      writeIntent({ ...d, to });
      try {
        let running: number;
        let started: string[] = [];
        let stopped: string[] = [];
        let waking: string[] = [];
        try {
          const r = await setCopies(slug, to, { by: "decider", log, fromDecider: true });
          running = r.running;
          started = "started" in r ? r.started.map((x) => x.helper) : [];
          stopped = "stopped" in r ? r.stopped.map((x) => x.helper) : [];
          waking = "waking" in r ? r.waking : [];
        } catch (err) {
          log(msg(err));
          running = realCopies(loadState().apps[slug]);
          patchCopies(slug, running, msg(err));
          return { done: false, running, held: to > d.from ? "start_failed" : "stop_failed" };
        }
        if (to > d.from && running < to) {
          // Fewer copies could run than asked: ask only for those, and try again after a wait (short when
          // a sleeping PC is waking up for it: Wake-on-LAN).
          patchCopies(slug, Math.max(running, d.from));
          const last = loadState().apps[slug]?.pool?.lastError;
          if (waking.length && !last) return { done: false, running: Math.max(running, d.from), held: "waking", started, p: { helper: waking[0] } };
          return { done: false, running: Math.max(running, d.from), held: last ? "start_failed" : "no_room", started };
        }
        return { done: true, running, started, stopped };
      } finally {
        clearIntent(slug);
      }
    }, opts.lockWaitMs ?? 2000);
  } catch (err) {
    if (err instanceof StateLockBusyError) return { done: false, running: d.from, held: "busy" };
    throw err;
  }
}

/** Sets the copies asked for without touching what runs (after a step that could not fully happen). */
function patchCopies(slug: string, n: number, error?: string): void {
  const state = loadState();
  const app = state.apps[slug];
  if (!app?.pool) return;
  app.pool.copies = Math.max(1, n);
  if (error) app.pool.lastError = error.split("\n")[0].slice(0, 500);
  saveState(state);
}

export function autoHooks(): AutoHooks {
  return { readBalancer: () => readBalancer(), syncBalancer, apply: (d, o) => applyStep(d, o) };
}

// ---------- turning it on and off ----------

/** What the guard sees when automatic scaling is turned on (action "scale.auto"). */
export function autoRiskParams(appName: string, input: { min?: unknown; max?: unknown } = {}, state: PaaSState = loadState()): Record<string, unknown> {
  const slug = sanitizeSlug(appName);
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  const rule = { ...ruleFor(app), ...validateRule(ruleInput(input)) };
  return { appName: slug, min: rule.min, max: rule.max, enabling: !app.pool?.enabled };
}

function ruleInput(input: { min?: unknown; max?: unknown }): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (input.min !== undefined && input.min !== null && input.min !== "") out.min = input.min;
  if (input.max !== undefined && input.max !== null && input.max !== "") out.max = input.max;
  return out;
}

/**
 * Turns automatic scaling on (the caller checked the guard "scale.auto") or off. On: the rule's minimum
 * and maximum may be set at the same time; the app goes behind the pool balancer (at the copies it has,
 * kept within the limits) so its visits are counted, and from the next round the decider adds or removes
 * copies by itself. Off: the copies stay as they are, set by hand from then on.
 */
export async function setAutoScale(
  appName: string,
  on: boolean,
  opts: { min?: unknown; max?: unknown; by?: string; log?: (l: string) => void } = {}
): Promise<Record<string, unknown>> {
  const slug = sanitizeSlug(appName);
  const by = opts.by || "cli";
  let state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`App '${slug}' not found.`);
  if (!on) {
    if (!app.scale?.auto) return { app: slug, auto: false, note: "Automatic scaling was already off." };
    delete app.scale.auto;
    saveState(state);
    audit({ event: "scale.auto.off", app: slug, by });
    const copies = realCopies(app);
    appendDiary({ t: new Date().toISOString(), app: slug, kind: "auto_off", p: { copies } });
    return { app: slug, auto: false, copies, note: "The copies stay as they are. Set them by hand, or stop everything ('scale off') to go back to one copy here." };
  }
  // Checked before anything changes.
  const next = { ...ruleFor(app), ...validateRule(ruleInput(opts)) };
  if (next.max < next.min) throw new Error(`'max' (${next.max}) cannot be below 'min' (${next.min}).`);
  if (next.max < 2) throw new Error("With a maximum of 1 copy there is nothing to decide. Raise the maximum (for example --max 3).");
  const ready = poolReadiness(slug, state);
  if (!ready.ok) throw new Error(`App '${slug}' cannot have copies on helpers yet:\n- ${ready.problems.join("\n- ")}`);
  // Only a real change of the limits goes to the rule (and its diary line).
  const now = ruleFor(app);
  if (next.min !== now.min || next.max !== now.max) setScaleRule(slug, ruleInput(opts), by);

  state = loadState();
  const wasAuto = Boolean(state.apps[slug].scale?.auto);
  state.apps[slug].scale = { ...(state.apps[slug].scale || {}), auto: { since: state.apps[slug].scale?.auto?.since || new Date().toISOString(), by } };
  saveState(state);
  const current = state.apps[slug].pool?.enabled ? state.apps[slug].pool!.copies : 1;
  const wanted = Math.min(next.max, Math.max(next.min, current));
  let report: Awaited<ReturnType<typeof setCopies>>;
  try {
    report = await setCopies(slug, wanted, { by, log: opts.log, fromDecider: true });
  } catch (err) {
    // Not even the balancer could start: nothing scales by itself.
    if (!wasAuto) {
      const s = loadState();
      if (s.apps[slug]?.scale) delete s.apps[slug].scale!.auto;
      saveState(s);
    }
    throw err;
  }
  if (!wasAuto) {
    audit({ event: "scale.auto.on", app: slug, min: next.min, max: next.max, by });
    appendDiary({ t: new Date().toISOString(), app: slug, kind: "auto_on", p: { min: next.min, max: next.max } });
  }
  const warnings = [...("warnings" in report ? report.warnings : [])];
  if (!loadState().scale?.timer) warnings.push("Measuring is not on, so nothing decides yet: run 'sudo paasmcp scale install-timer' on this server.");
  if (!Object.keys(loadState().pool?.helpers || {}).length) warnings.push("No helper PC was added yet: the decider can only keep this server's copy until one is ('paasmcp pool invite <name>').");
  return { ...report, app: slug, auto: true, rule: { min: next.min, max: next.max, targetCpu: next.targetCpu, targetRps: next.targetRps }, warnings };
}
