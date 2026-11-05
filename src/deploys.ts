import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AppRecord, PAAS_DATA_DIR, sanitizeSlug, writeFileAtomic } from "./config.js";
import { DASHBOARD_APP_NAME } from "./guard.js";
import { readFollow } from "./selfupdate.js";

// Deploy progress, readable while a deploy runs. Deploys start in several processes (dashboard,
// CLI, MCP, the poll timer, webhooks), so each one writes its progress to deploys/<app>.json and the
// dashboard reads those files. Each file keeps the last MAX_RUNS deploys of one app, newest first.

export const DEPLOYS_DIR = path.join(PAAS_DATA_DIR, "deploys");
const MAX_RUNS = 10;
const LOG_TAIL_LINES = 30;
const LOG_TAIL_CHARS = 4000;
/** A running deploy rewrites its file at least this often (unless a long synchronous step blocks it). */
const HEARTBEAT_MS = 20_000;
/** Seen from another host or PID namespace (the dashboard container), a run silent this long is interrupted. */
const STALE_MS = 10 * 60_000;

/**
 * detected: a new commit was seen (poll timer, webhook) and the deploy is starting;
 * fetching: getting the code; building: building the image; checking: the new version runs beside the
 * old one and must answer the health check; switching: the new version takes over;
 * live: done; failed: stopped, the previous version (if any) keeps running.
 */
export type DeployPhase = "detected" | "fetching" | "building" | "checking" | "switching" | "live" | "failed";
export type DeployTrigger = "dashboard" | "cli" | "mcp" | "webhook" | "poll" | "active" | "mirror";
const ACTIVE_PHASES: DeployPhase[] = ["detected", "fetching", "building", "checking", "switching"];

export interface DeployCommit {
  sha: string;
  short: string;
  /** First line of the commit message (repository content: escape before showing). */
  message?: string;
  author?: string;
  date?: string;
}

export interface DeployRun {
  id: string;
  app: string;
  phase: DeployPhase;
  trigger: DeployTrigger;
  branch: string;
  /** What is being deployed: the announced commit until the code is fetched, then the real one. */
  commit?: DeployCommit;
  startedAt: string;
  updatedAt: string;
  finishedAt?: string;
  /** Process running the deploy, and where: a run whose process is gone shows as interrupted. */
  pid: number;
  host?: string;
  /** Failed runs: first line of the error, and the last lines of the output (credentials removed). */
  error?: string;
  log?: string;
  warning?: string;
}

interface DeployFile {
  runs: DeployRun[];
}

function fileFor(app: string): string {
  return path.join(DEPLOYS_DIR, `${sanitizeSlug(app)}.json`);
}

function readFile(app: string): DeployFile {
  try {
    const parsed = JSON.parse(fs.readFileSync(fileFor(app), "utf-8")) as DeployFile;
    return Array.isArray(parsed.runs) ? parsed : { runs: [] };
  } catch {
    return { runs: [] };
  }
}

function writeRun(run: DeployRun): void {
  try {
    fs.mkdirSync(DEPLOYS_DIR, { recursive: true, mode: 0o700 });
    const file = readFile(run.app);
    const runs = [run, ...file.runs.filter((r) => r.id !== run.id)]
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .slice(0, MAX_RUNS);
    writeFileAtomic(fileFor(run.app), JSON.stringify({ runs }, null, 2));
  } catch {
    // Progress is informative only: a write problem must never break a deploy.
  }
}

/** Removes credentials from URLs (https://user:token@host) and GitHub tokens from text. */
export function redactCredentials(text: string): string {
  return text
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, "$1***@")
    .replace(/\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, "***");
}

/** Strips control characters and caps the length of text coming from a repository. */
export function cleanText(text: string | undefined, max: number): string | undefined {
  if (!text) return undefined;
  // eslint-disable-next-line no-control-regex
  const clean = text.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  if (!clean) return undefined;
  return clean.length > max ? clean.slice(0, max - 1) + "…" : clean;
}

export function logTail(text: string): string | undefined {
  const lines = redactCredentials(text).trim().split("\n");
  const tail = lines.slice(-LOG_TAIL_LINES).join("\n");
  const cut = tail.length > LOG_TAIL_CHARS ? tail.slice(-LOG_TAIL_CHARS) : tail;
  return cut || undefined;
}

export function shortCommit(sha: string): DeployCommit | undefined {
  return /^[0-9a-f]{40}$/.test(sha) ? { sha, short: sha.slice(0, 7) } : undefined;
}

export interface DeployTracker {
  readonly run: DeployRun;
  phase(phase: DeployPhase): void;
  commit(commit: DeployCommit): void;
  succeed(warning?: string): void;
  fail(err: unknown): void;
}

export function startDeployRun(opts: {
  app: string;
  trigger: DeployTrigger;
  branch: string;
  commit?: DeployCommit;
  phase?: DeployPhase;
}): DeployTracker {
  const now = new Date().toISOString();
  const run: DeployRun = {
    id: `${now.replace(/[-:.TZ]/g, "")}-${crypto.randomBytes(3).toString("hex")}`,
    app: sanitizeSlug(opts.app),
    phase: opts.phase || "fetching",
    trigger: opts.trigger,
    branch: opts.branch,
    commit: opts.commit,
    startedAt: now,
    updatedAt: now,
    pid: process.pid,
    host: os.hostname(),
  };
  writeRun(run);
  return trackerFor(run);
}

/**
 * Picks up a run started by another process (the dashboard hands its own update to a helper
 * container, which finishes the same run). Undefined when the run is unknown or already finished.
 */
export function continueDeployRun(app: string, id: string): DeployTracker | undefined {
  const found = readFile(app).runs.find((r) => r.id === id);
  if (!found || found.finishedAt) return undefined;
  const run: DeployRun = { ...found, pid: process.pid, host: os.hostname() };
  writeRun(run);
  return trackerFor(run);
}

function trackerFor(run: DeployRun): DeployTracker {
  const touch = () => {
    run.updatedAt = new Date().toISOString();
    writeRun(run);
  };
  const heartbeat = setInterval(touch, HEARTBEAT_MS);
  heartbeat.unref();
  return {
    run,
    phase(phase) {
      if (run.finishedAt) return;
      run.phase = phase;
      touch();
    },
    commit(commit) {
      run.commit = commit;
      touch();
    },
    succeed(warning) {
      clearInterval(heartbeat);
      run.phase = "live";
      run.finishedAt = new Date().toISOString();
      if (warning) run.warning = cleanText(redactCredentials(warning), 500);
      touch();
    },
    fail(err) {
      clearInterval(heartbeat);
      const message = err instanceof Error ? err.message : String(err);
      run.phase = "failed";
      run.finishedAt = new Date().toISOString();
      run.error = cleanText(redactCredentials(message.split("\n")[0]), 300);
      run.log = logTail(message.split("\n").slice(1).join("\n"));
      touch();
    },
  };
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function interrupted(r: DeployRun, alive: (pid: number) => boolean, now: number): boolean {
  if (!ACTIVE_PHASES.includes(r.phase)) return false;
  // The PID means something only in the same host and PID namespace (hostname differs inside a container).
  if (!r.host || r.host === os.hostname()) return !alive(r.pid);
  return now - Date.parse(r.updatedAt) > STALE_MS;
}

/** Last deploys of one app, newest first. A run whose process died mid-way shows as failed. */
export function deployRuns(app: string, alive: (pid: number) => boolean = processAlive, now = Date.now()): DeployRun[] {
  return readFile(app).runs.map((r) =>
    interrupted(r, alive, now)
      ? { ...r, phase: "failed" as const, finishedAt: r.updatedAt, error: "Interrupted: the process running this deploy stopped." }
      : r
  );
}

export function forgetDeploys(app: string): void {
  try {
    fs.rmSync(fileFor(app), { force: true });
  } catch {
    // ignore
  }
}

export interface GithubSource {
  /** owner/repo */
  name: string;
  url: string;
  branchUrl: string;
}

const GH_PART = /^[A-Za-z0-9_.-]{1,100}$/;

/**
 * GitHub page of an app's repository, or undefined when the source is not on github.com. Only the
 * owner and repository name are kept, so credentials in the stored URL never reach a page.
 */
export function githubSource(repoUrl: string | undefined, branch: string): GithubSource | undefined {
  if (!repoUrl) return undefined;
  const raw = repoUrl.trim();
  let rest: string | undefined;
  const https = raw.match(/^(?:https?|ssh|git):\/\/(?:[^/@\s]+@)?(?:www\.)?github\.com(?::\d+)?\/(.+)$/i);
  const scp = raw.match(/^[^/@\s]+@github\.com:(.+)$/i);
  if (https) rest = https[1];
  else if (scp) rest = scp[1];
  else if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(raw)) rest = raw;
  if (!rest) return undefined;
  const [owner, repoPart, ...extra] = rest.replace(/\/+$/, "").split("/");
  const repo = (repoPart || "").replace(/\.git$/i, "");
  if (extra.length || !GH_PART.test(owner || "") || !GH_PART.test(repo) || repo === "." || repo === "..") return undefined;
  const url = `https://github.com/${owner}/${repo}`;
  return { name: `${owner}/${repo}`, url, branchUrl: `${url}/tree/${encodeURIComponent(branch)}` };
}

export function commitUrl(source: GithubSource | undefined, sha: string | undefined): string | undefined {
  return source && sha && /^[0-9a-f]{40}$/.test(sha) ? `${source.url}/commit/${sha}` : undefined;
}

export interface AppDeploySummary {
  /** Deploy in progress, if any. */
  active?: DeployRun & { commitUrl?: string };
  /** Last finished deploy (live or failed). */
  last?: DeployRun & { commitUrl?: string };
  /** Version running now (the app record), with the commit message when a deploy recorded it. */
  running?: DeployCommit & { commitUrl?: string };
  source?: GithubSource;
}

/**
 * One line per app for the dashboard: what runs, where it comes from, and the deploy in progress.
 * Apps on their first deploy have no record yet and show up from their deploy file alone.
 */
export function deploySummary(apps: Record<string, AppRecord>, alive?: (pid: number) => boolean): Record<string, AppDeploySummary> {
  const names = new Set(Object.keys(apps));
  try {
    for (const f of fs.readdirSync(DEPLOYS_DIR)) if (f.endsWith(".json")) names.add(f.slice(0, -5));
  } catch {
    // no deploys recorded yet
  }
  const out: Record<string, AppDeploySummary> = {};
  for (const name of names) {
    const app = apps[name];
    const runs = deployRuns(name, alive);
    if (!app && !runs.length) continue;
    const branch = app?.branch || runs[0]?.branch || "main";
    // The dashboard has no repoUrl (webhooks and mirrors must not redeploy it as an app): it shows the
    // branch it follows instead.
    const followed = name === DASHBOARD_APP_NAME ? readFollow() : null;
    const source = githubSource(app?.repoUrl || followed?.repoUrl, followed?.branch || branch);
    const withUrl = (r: DeployRun | undefined) =>
      r ? { ...r, commitUrl: commitUrl(source, r.commit?.sha) } : undefined;
    const active = runs.find((r) => ACTIVE_PHASES.includes(r.phase));
    // A brand-new app has no record until its first deploy ends: drop its old failed runs once it is gone.
    if (!app && !active) continue;
    const last = runs.find((r) => r.finishedAt);
    let running: AppDeploySummary["running"];
    const sha = app?.lastCommitSha;
    if (sha) {
      const known = runs.find((r) => r.phase === "live" && r.commit?.sha === sha)?.commit;
      running = { ...(known || { sha, short: sha.slice(0, 7) }), commitUrl: commitUrl(source, sha) };
    } else if (app?.lastCommit && app.lastCommit !== "unknown") {
      running = { sha: "", short: app.lastCommit };
    }
    out[name] = {
      ...(active ? { active: withUrl(active) } : {}),
      ...(last ? { last: withUrl(last) } : {}),
      ...(running ? { running } : {}),
      ...(source ? { source } : {}),
    };
  }
  return out;
}
