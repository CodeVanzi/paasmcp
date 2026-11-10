import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DOCKER_NETWORK, ensureDataDir, HOMELAB_ROOT, PAAS_DATA_DIR, tailscaleSocketDir, validateBranchName, writeFileAtomic } from "./config.js";
import { audit, DASHBOARD_APP_NAME } from "./guard.js";
import { cleanText, continueDeployRun, DeployCommit, DeployTracker, DeployTrigger, shortCommit, startDeployRun } from "./deploys.js";

// The dashboard follows a branch (opt-in). It never runs from the folder someone is editing: each new
// commit is cloned into releases/<sha>, built and tested inside the dashboard image, and only then
// swapped in. If the new dashboard does not answer within 60 s, the previous code comes back.
//
// Who checks: the dashboard itself every 2 min (`poll run` child process), or a systemd timer when
// there is no dashboard. Inside the dashboard container the swap is done by a short-lived helper
// container, since a container cannot replace itself and then check the result.

export const CONTROL_PLANE_DIR = path.join(PAAS_DATA_DIR, "control-plane");
export const RELEASES_DIR = path.join(CONTROL_PLANE_DIR, "releases");
const FOLLOW_FILE = path.join(CONTROL_PLANE_DIR, "follow.json");
const LOCK_FILE = path.join(CONTROL_PLANE_DIR, "update.lock");
const SWAP_CONTAINER = "paasmcp-dashboard-swap";
const DASHBOARD_CONTAINER = "paasmcp-dashboard";

export interface FollowState {
  enabled: boolean;
  repoUrl: string;
  branch: string;
  /** Commit the dashboard runs now (a folder under releases/). */
  current?: string;
  previous?: string;
  /** A commit whose build, tests or start failed: not retried until a newer commit (or --force). */
  failedCommit?: string;
  lastError?: { commit: string; step: string; message: string; at: string };
  lastCheckAt?: string;
  updatedAt?: string;
}

export function readFollow(): FollowState | null {
  try {
    return JSON.parse(fs.readFileSync(FOLLOW_FILE, "utf-8")) as FollowState;
  } catch {
    return null;
  }
}

/** Files written as root inside the dashboard container keep the data folder's owner. */
function keepOwner(p: string, recursive = false): void {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return;
  const st = fs.statSync(PAAS_DATA_DIR);
  if (st.uid === 0) return;
  if (recursive) execFileSync("chown", ["-R", `${st.uid}:${st.gid}`, p], { stdio: "ignore" });
  else fs.chownSync(p, st.uid, st.gid);
}

function writeFollow(st: FollowState): void {
  ensureDataDir(CONTROL_PLANE_DIR);
  writeFileAtomic(FOLLOW_FILE, JSON.stringify(st, null, 2));
  keepOwner(FOLLOW_FILE);
}

export const releaseDir = (sha: string) => path.join(RELEASES_DIR, validateCommit(sha));

function validateCommit(sha: string): string {
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`Invalid commit '${sha}'.`);
  return sha;
}

/** Only remote git URLs: a local folder would bring back "runs whatever is being edited". */
export function validateFollowRepo(url: string): string {
  const u = url.trim();
  if (!/^(https:\/\/[A-Za-z0-9.-]+(:\d+)?\/[A-Za-z0-9._~\/-]+|git@[A-Za-z0-9.-]+:[A-Za-z0-9._~\/-]+)$/.test(u)) {
    throw new Error(`Repository '${url}' is not a remote git URL (https://... or git@host:owner/repo).`);
  }
  return u;
}

/** Code the dashboard should run: the followed release, when there is one on disk. */
export function followedCode(): { dir: string; commit: string; branch: string } | null {
  const st = readFollow();
  if (!st?.current) return null;
  const dir = releaseDir(st.current);
  if (!fs.existsSync(path.join(dir, "dist", "cli.js"))) return null;
  return { dir, commit: st.current, branch: st.branch };
}

/** The repository the running code came from (its `origin`), as the default to follow. */
export function originOf(codeDir: string): string | undefined {
  try {
    return execFileSync("git", ["-c", `safe.directory=${codeDir}`, "-C", codeDir, "remote", "get-url", "origin"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim() || undefined;
  } catch {
    return undefined;
  }
}

export function setFollow(on: boolean, opts: { repoUrl?: string; branch?: string } = {}): FollowState {
  const prev = readFollow();
  if (!on) {
    if (!prev) return { enabled: false, repoUrl: "", branch: "main" };
    const st = { ...prev, enabled: false };
    writeFollow(st);
    audit({ event: "dashboard.follow", enabled: false });
    return st;
  }
  const repoUrl = validateFollowRepo(opts.repoUrl || prev?.repoUrl || "");
  const branch = validateBranchName(opts.branch || prev?.branch || "main");
  const changed = !prev || prev.repoUrl !== repoUrl || prev.branch !== branch;
  const st: FollowState = { ...(prev || {}), enabled: true, repoUrl, branch, ...(changed ? { failedCommit: undefined, lastError: undefined } : {}) };
  writeFollow(st);
  audit({ event: "dashboard.follow", enabled: true, repoUrl, branch });
  return st;
}

export function followStatus(): {
  enabled: boolean;
  repoUrl?: string;
  branch?: string;
  current?: string;
  lastError?: FollowState["lastError"];
  lastCheckAt?: string;
  updatedAt?: string;
} {
  const st = readFollow();
  if (!st) return { enabled: false };
  return {
    enabled: st.enabled,
    repoUrl: st.repoUrl,
    branch: st.branch,
    current: st.current,
    lastError: st.lastError,
    lastCheckAt: st.lastCheckAt,
    updatedAt: st.updatedAt,
  };
}

// ---------------------------------------------------------------------------------------------------
// One round

export interface ControlPlaneDeps {
  /** Commit at the tip of the branch. */
  head(repoUrl: string, branch: string): string;
  /**
   * Clones exactly `sha` into `dir`, then installs, builds and tests it. Throws StepError on failure.
   * Reports each step (clone, install, build, test); may return the commit's message and author.
   */
  build(repoUrl: string, branch: string, sha: string, dir: string, onStep?: (step: string) => void): Partial<DeployCommit> | void;
  /** Points the dashboard at `dir` (compose up). */
  restart(dir: string, commit: string | undefined): void | Promise<void>;
  /** Folder the dashboard runs from right now (to come back to). */
  runningDir(): string | undefined;
  healthy(): Promise<boolean>;
  /** Inside the dashboard container: start the helper that swaps (this process cannot). */
  swapViaHelper?(sha: string, runId: string): void;
}

export class StepError extends Error {
  constructor(public step: string, message: string) {
    super(message);
  }
}

function takeLock(): (() => void) | null {
  ensureDataDir(CONTROL_PLANE_DIR);
  for (let i = 0; i < 2; i++) {
    try {
      fs.writeFileSync(LOCK_FILE, JSON.stringify({ pid: process.pid, at: Date.now() }), { flag: "wx", mode: 0o600 });
      keepOwner(LOCK_FILE);
      return () => fs.rmSync(LOCK_FILE, { force: true });
    } catch {
      // A lock older than 30 min belongs to a round that died.
      try {
        const held = JSON.parse(fs.readFileSync(LOCK_FILE, "utf-8")) as { at: number };
        if (Date.now() - held.at < 30 * 60 * 1000) return null;
      } catch {
        /* unreadable: treat as stale */
      }
      fs.rmSync(LOCK_FILE, { force: true });
    }
  }
  return null;
}

function prune(keep: (string | undefined)[]): void {
  if (!fs.existsSync(RELEASES_DIR)) return;
  for (const name of fs.readdirSync(RELEASES_DIR)) {
    if (keep.includes(name)) continue;
    fs.rmSync(path.join(RELEASES_DIR, name), { recursive: true, force: true });
  }
}

function fail(st: FollowState, sha: string, err: unknown): FollowState {
  const step = err instanceof StepError ? err.step : "update";
  const message = (err instanceof Error ? err.message : String(err)).split("\n").slice(-6).join("\n").slice(0, 1500);
  const next = { ...st, failedCommit: sha, lastError: { commit: sha, step, message, at: new Date().toISOString() } };
  writeFollow(next);
  audit({ event: "dashboard.update.failed", commit: sha, step });
  return next;
}

export type ControlPlaneResult =
  | { status: "off" | "busy" | "up-to-date" }
  | { status: "skipped"; commit: string; reason: string }
  | { status: "swapping"; commit: string }
  | { status: "updated"; commit: string; previous?: string }
  | { status: "failed"; commit: string; step: string; error: string; rolledBack: boolean };

export async function controlPlaneTick(
  deps: ControlPlaneDeps,
  opts: { force?: boolean; trigger?: DeployTrigger } = {}
): Promise<ControlPlaneResult> {
  let st = readFollow();
  if (!st?.enabled) return { status: "off" };
  const release = takeLock();
  if (!release) return { status: "busy" };
  try {
    const sha = validateCommit(deps.head(st.repoUrl, st.branch));
    st = { ...st, lastCheckAt: new Date().toISOString() };
    writeFollow(st);
    if (sha === st.current && !opts.force) return { status: "up-to-date" };
    if (sha === st.failedCommit && !opts.force) return { status: "skipped", commit: sha, reason: `${st.lastError?.step || "update"} failed for this commit` };

    // Same progress record as app deploys: the apps table shows each phase live.
    const run = startDeployRun({ app: DASHBOARD_APP_NAME, trigger: opts.trigger || "poll", branch: st.branch, commit: shortCommit(sha), phase: "detected" });
    const dir = releaseDir(sha);
    if (!fs.existsSync(path.join(dir, "dist", "cli.js"))) {
      ensureDataDir(RELEASES_DIR);
      const tmp = path.join(RELEASES_DIR, `.tmp-${sha.slice(0, 12)}-${process.pid}`);
      fs.rmSync(tmp, { recursive: true, force: true });
      try {
        const info = deps.build(st.repoUrl, st.branch, sha, tmp, (step) => run.phase(step === "clone" ? "fetching" : "building"));
        if (info) run.commit({ sha, short: sha.slice(0, 7), ...info });
        keepOwner(tmp, true);
        fs.rmSync(dir, { recursive: true, force: true });
        fs.renameSync(tmp, dir);
      } catch (err) {
        fs.rmSync(tmp, { recursive: true, force: true });
        const f = fail(st, sha, err);
        run.fail(`${f.lastError!.step} failed; the dashboard keeps its current version.\n${f.lastError!.message}`);
        return { status: "failed", commit: sha, step: f.lastError!.step, error: f.lastError!.message, rolledBack: false };
      }
    }

    if (deps.swapViaHelper) {
      run.phase("checking");
      try {
        deps.swapViaHelper(sha, run.run.id);
      } catch (err) {
        run.fail(err);
        throw err;
      }
      return { status: "swapping", commit: sha };
    }
    return await swapTo(sha, deps, run);
  } finally {
    release();
  }
}

/** Points the dashboard at releases/<sha>, waits for it, and goes back if it does not answer. */
export async function swapTo(
  sha: string,
  deps: Pick<ControlPlaneDeps, "restart" | "runningDir" | "healthy">,
  /** The progress record to finish (or the id of one started by the dashboard). */
  tracking?: DeployTracker | string
): Promise<ControlPlaneResult> {
  const st = readFollow();
  const run = typeof tracking === "string" ? continueDeployRun(DASHBOARD_APP_NAME, tracking) : tracking;
  if (!st) throw new Error("The dashboard does not follow a branch (paasmcp dashboard follow).");
  const dir = releaseDir(sha);
  if (!fs.existsSync(path.join(dir, "dist", "cli.js"))) throw new Error(`Release ${sha.slice(0, 7)} is not built.`);
  const before = deps.runningDir();
  const beforeCommit = st.current && before === releaseDir(st.current) ? st.current : undefined;
  try {
    run?.phase("switching");
    await deps.restart(dir, sha);
    run?.phase("checking");
    if (!(await deps.healthy())) throw new StepError("start", "The new dashboard did not answer within 60 s.");
  } catch (err) {
    let rolledBack = false;
    if (before && before !== dir && fs.existsSync(before)) {
      try {
        await deps.restart(before, beforeCommit);
        rolledBack = await deps.healthy();
      } catch {
        rolledBack = false;
      }
    }
    const f = fail(st, sha, err instanceof StepError ? err : new StepError("start", err instanceof Error ? err.message : String(err)));
    run?.fail(`${f.lastError!.message}${rolledBack ? " The previous version is back." : ""}`);
    return { status: "failed", commit: sha, step: f.lastError!.step, error: f.lastError!.message, rolledBack };
  }
  const previous = beforeCommit;
  writeFollow({ ...st, current: sha, previous, failedCommit: undefined, lastError: undefined, updatedAt: new Date().toISOString() });
  prune([sha, previous]);
  audit({ event: "dashboard.update", commit: sha, previous });
  run?.succeed();
  return { status: "updated", commit: sha, previous };
}

// ---------------------------------------------------------------------------------------------------
// Real helpers (Docker)

/** Same Node and tools as the running dashboard: what passes here runs there. */
export function buildInImage(image: string): ControlPlaneDeps["build"] {
  return (repoUrl, branch, sha, dir, onStep) => {
    const st = fs.statSync(PAAS_DATA_DIR);
    const parent = path.dirname(dir);
    const run = (step: string, workdir: string, cmd: string[], timeout: number) => {
      try {
        execFileSync(
          "docker",
          [
            "run", "--rm",
            "--user", `${st.uid}:${st.gid}`,
            "-e", "HOME=/tmp",
            "-e", "GIT_TERMINAL_PROMPT=0",
            "-e", "npm_config_update_notifier=false",
            "-v", `${parent}:${parent}`,
            "-w", workdir,
            image,
            ...cmd,
          ],
          { stdio: ["ignore", "pipe", "pipe"], timeout, maxBuffer: 32 * 1024 * 1024 }
        );
      } catch (err) {
        const e = err as { stderr?: Buffer; stdout?: Buffer; message?: string };
        const out = `${e.stdout?.toString() || ""}\n${e.stderr?.toString() || ""}`.trim() || e.message || String(err);
        throw new StepError(step, out);
      }
    };
    const step = (name: string) => onStep?.(name);
    step("clone");
    run("clone", parent, ["git", "clone", "--quiet", "--branch", validateBranchName(branch), "--", validateFollowRepo(repoUrl), dir], 5 * 60_000);
    run("clone", dir, ["git", "-c", "advice.detachedHead=false", "checkout", "--quiet", validateCommit(sha)], 60_000);
    const info = commitInfo(dir);
    step("install");
    run("install", dir, ["npm", "ci", "--no-audit", "--no-fund"], 10 * 60_000);
    step("build");
    run("build", dir, ["npm", "run", "build"], 10 * 60_000);
    step("test");
    run("test", dir, ["npm", "test"], 10 * 60_000);
    fs.rmSync(path.join(dir, ".git"), { recursive: true, force: true });
    return info;
  };
}

/** Message, author and date of the checked-out commit (shown in the apps table; text from the repository). */
function commitInfo(dir: string): Partial<DeployCommit> {
  try {
    const [message, author, date] = execFileSync("git", ["-c", `safe.directory=${dir}`, "-C", dir, "log", "-1", "--format=%s%x00%an%x00%cI"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim().split("\0");
    return { message: cleanText(message, 200), author: cleanText(author, 100), date: /^\d{4}-\d\d-\d\dT/.test(date || "") ? date : undefined };
  } catch {
    return {};
  }
}

/** Folder mounted at /app in the dashboard's compose file. */
export function composeCodeDir(composePath: string): string | undefined {
  try {
    const m = fs.readFileSync(composePath, "utf-8").match(/^\s*-\s*(\/[^\s:]+):\/app:ro\s*$/m);
    return m?.[1];
  } catch {
    return undefined;
  }
}

export function waitForDashboard(url: string, seconds = 60): Promise<boolean> {
  const deadline = Date.now() + seconds * 1000;
  const once = () =>
    new Promise<boolean>((resolve) => {
      const req = http.get(url, { timeout: 3000 }, (res) => {
        res.resume();
        resolve((res.statusCode || 500) < 500);
      });
      req.on("error", () => resolve(false));
      req.on("timeout", () => {
        req.destroy();
        resolve(false);
      });
    });
  return (async () => {
    // Give compose a moment to replace the old container before the first check.
    await new Promise((r) => setTimeout(r, 2000));
    while (Date.now() < deadline) {
      if (await once()) return true;
      await new Promise((r) => setTimeout(r, 2000));
    }
    return false;
  })();
}

/** Inside the dashboard container: a sibling container (the known-good code) does the swap. */
export function startSwapHelper(image: string, sha: string, runId: string): void {
  validateCommit(sha);
  if (!/^[0-9]{8,20}-[0-9a-f]{6}$/.test(runId)) throw new Error("Invalid deploy run id.");
  const code = followedCode()?.dir || releaseDir(sha);
  // The helper recreates the dashboard container: it needs the Tailscale socket to keep mounting it.
  const tsDir = tailscaleSocketDir();
  try {
    execFileSync("docker", ["rm", "-f", SWAP_CONTAINER], { stdio: "ignore" });
  } catch {
    /* none */
  }
  execFileSync(
    "docker",
    [
      "run", "-d", "--rm",
      "--name", SWAP_CONTAINER,
      "--network", DOCKER_NETWORK,
      "-e", `PAASMCP_ROOT=${HOMELAB_ROOT}`,
      "-e", "PAASMCP_SWAP_HELPER=1",
      ...(process.env.PAASMCP_ENV_LABEL ? ["-e", `PAASMCP_ENV_LABEL=${process.env.PAASMCP_ENV_LABEL}`] : []),
      "-v", `${HOMELAB_ROOT}:${HOMELAB_ROOT}`,
      "-v", "/var/run/docker.sock:/var/run/docker.sock",
      ...(tsDir ? ["-v", `${tsDir}:${tsDir}`] : []),
      "-v", `${code}:/app:ro`,
      "-w", "/app",
      image,
      "node", "dist/cli.js", "dashboard", "swap", sha, "--run", runId,
    ],
    { stdio: "pipe" }
  );
}

/** Where to check the dashboard: from the helper container, by name on the Docker network. */
export function dashboardHealthUrl(port: number): string {
  return process.env.PAASMCP_SWAP_HELPER === "1" ? `http://${DASHBOARD_CONTAINER}:${port}/` : `http://127.0.0.1:${port}/`;
}

export const insideDashboard = () => process.env.PAASMCP_IN_DASHBOARD === "1";
