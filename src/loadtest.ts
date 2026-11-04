import http from "node:http";
import { CapacityResult, loadState, sanitizeSlug, saveState } from "./config.js";
import { audit } from "./guard.js";
import { appendDiary, cpuReference, dockerStats } from "./scale.js";

// Capacity test (`paasmcp scale test <app>`): sends GET requests to one app's loopback port, doubling
// the number of parallel requests each step, and finds how many requests per second one copy
// handles before it chokes, and on what (its CPU, the database, errors or response time). Only the
// app's own 127.0.0.1 port is ever targeted, only GET, with hard limits on load and duration.

const MAX_CONCURRENCY = 64;
const PATH_RE = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/;
const REQUEST_TIMEOUT_MS = 10_000;

export function validateTestPath(p: string): string {
  const clean = String(p || "/").trim();
  if (clean.length > 200 || !PATH_RE.test(clean)) throw new Error(`Invalid path '${p}'. Use a path on the app such as / or /api/health.`);
  return clean;
}

export interface CapacityOptions {
  path?: string;
  stepSeconds?: number;
  maxConcurrency?: number;
  onStep?: (step: CapacityResult["steps"][number]) => void;
}

function percentile(sorted: number[], q: number): number {
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
}

/** Runs `concurrency` request loops against `url` for `ms` milliseconds. */
async function runStep(url: string, concurrency: number, ms: number, agent: http.Agent) {
  const latencies: number[] = [];
  let errors = 0;
  const end = Date.now() + ms;
  const one = () =>
    new Promise<void>((resolve) => {
      const started = performance.now();
      const req = http.get(url, { agent, timeout: REQUEST_TIMEOUT_MS }, (res) => {
        res.resume();
        res.on("end", () => {
          if ((res.statusCode || 0) >= 500) errors++;
          else latencies.push(performance.now() - started);
          resolve();
        });
        res.on("error", () => {
          errors++;
          resolve();
        });
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", () => {
        errors++;
        resolve();
      });
    });
  const loop = async () => {
    while (Date.now() < end) await one();
  };
  const started = Date.now();
  await Promise.all(Array.from({ length: concurrency }, loop));
  return { latencies: latencies.sort((a, b) => a - b), errors, seconds: (Date.now() - started) / 1000 };
}

/** Classifies what limited the app (pure; tested). */
export function classifyBottleneck(input: {
  appCpuOfLimit: number | null;
  dbCpu: number | null;
  clientCpu: number;
  stoppedBy?: "errors" | "latency";
  saturated: boolean;
}): CapacityResult["bottleneck"] {
  if (input.appCpuOfLimit !== null && input.appCpuOfLimit >= 85) return "app_cpu";
  if (input.dbCpu !== null && input.dbCpu >= 80) return "database";
  if (input.clientCpu >= 90) return "client";
  if (input.stoppedBy) return input.stoppedBy;
  return input.saturated ? "unknown" : "none";
}

/** Finds how much one copy of the app handles. Saves the result on the app and in the diary. */
export async function capacityTest(appName: string, opts: CapacityOptions = {}): Promise<CapacityResult> {
  const slug = sanitizeSlug(appName);
  const app = loadState().apps[slug];
  if (!app || app.trashedAt) throw new Error(`App '${slug}' not found.`);
  const testPath = validateTestPath(opts.path || app.healthcheckPath || "/");
  const stepSeconds = Math.round(Number(opts.stepSeconds ?? 5));
  if (!Number.isInteger(stepSeconds) || stepSeconds < 2 || stepSeconds > 30) throw new Error("Step seconds must be a whole number from 2 to 30.");
  const maxC = Math.round(Number(opts.maxConcurrency ?? 32));
  if (!Number.isInteger(maxC) || maxC < 1 || maxC > MAX_CONCURRENCY) throw new Error(`Parallel requests must be from 1 to ${MAX_CONCURRENCY}.`);
  const url = `http://127.0.0.1:${app.localPort}${testPath}`;
  const ref = cpuReference(app);
  const agent = new http.Agent({ keepAlive: true, maxSockets: maxC });

  const steps: CapacityResult["steps"] = [];
  let stoppedBy: "errors" | "latency" | undefined;
  let plateau = 0;
  try {
    await runStep(url, 1, 1000, agent); // warm-up, not counted
    for (let c = 1; c <= maxC; c *= 2) {
      const cpuBefore = process.cpuUsage();
      const wallBefore = performance.now();
      // Container CPU is read in the middle of the step, while the load is steady.
      const statsLater = new Promise<Awaited<ReturnType<typeof dockerStats>>>((resolve) =>
        setTimeout(() => dockerStats().then(resolve), Math.round(stepSeconds * 400))
      );
      const [r, stats] = await Promise.all([runStep(url, c, stepSeconds * 1000, agent), statsLater]);
      const used = process.cpuUsage(cpuBefore);
      const wall = performance.now() - wallBefore;
      const appCpu = stats[app.containerName]?.cpu ?? null;
      const dbCpu = stats["paasmcp-postgres"]?.cpu ?? null;
      const ok = r.latencies.length;
      const step = {
        concurrency: c,
        seconds: Math.round(r.seconds * 10) / 10,
        requests: ok + r.errors,
        errors: r.errors,
        rps: Math.round(ok / r.seconds),
        p50Ms: Math.round(percentile(r.latencies, 0.5)),
        p95Ms: Math.round(percentile(r.latencies, 0.95)),
        appCpu: appCpu === null ? null : Math.round(appCpu),
        dbCpu: dbCpu === null ? null : Math.round(dbCpu),
        clientCpu: Math.round(((used.user + used.system) / 1000 / wall) * 100),
      };
      steps.push(step);
      opts.onStep?.(step);
      const errRate = step.requests ? step.errors / step.requests : 1;
      if (errRate > 0.05) {
        stoppedBy = "errors";
        break;
      }
      if (step.p95Ms > 2000) {
        stoppedBy = "latency";
        break;
      }
      const bestSoFar = Math.max(...steps.slice(0, -1).map((s) => s.rps), 0);
      plateau = steps.length > 1 && step.rps < bestSoFar * 1.1 ? plateau + 1 : 0;
      if (plateau >= 2) break;
    }
  } finally {
    agent.destroy();
  }

  const clean = steps.filter((s) => !s.requests || s.errors / s.requests <= 0.01);
  const best = (clean.length ? clean : steps).reduce((a, b) => (b.rps > a.rps ? b : a), steps[0]);
  const last = steps[steps.length - 1];
  const saturated = Boolean(stoppedBy) || plateau >= 2;
  const bottleneck = classifyBottleneck({
    appCpuOfLimit: last.appCpu === null ? null : last.appCpu / ref,
    dbCpu: last.dbCpu,
    clientCpu: last.clientCpu,
    stoppedBy,
    saturated,
  });
  const result: CapacityResult = {
    at: new Date().toISOString(),
    path: testPath,
    rps: best.rps,
    concurrency: best.concurrency,
    p95Ms: best.p95Ms,
    cpu: best.appCpu === null ? null : Math.round(best.appCpu / ref),
    bottleneck,
    suggestedTargetRps: Math.floor(best.rps * 0.7),
    steps,
  };
  return result;
}

/** Stores a capacity result on the app (under the caller's state lock) and in the diary. */
export function saveCapacity(appName: string, result: CapacityResult, by = "cli"): void {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) return;
  app.scale = { ...(app.scale || {}), capacity: result };
  saveState(state);
  audit({ event: "scale.test", app: slug, rps: result.rps, bottleneck: result.bottleneck, by });
  appendDiary({
    t: result.at,
    app: slug,
    kind: "capacity",
    p: { rps: result.rps, path: result.path, p95: result.p95Ms, bottleneck: result.bottleneck },
  });
}
