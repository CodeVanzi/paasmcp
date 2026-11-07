import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DOCKER_NETWORK,
  ensureDataDir,
  JobRecord,
  loadState,
  PAAS_DATA_DIR,
  sanitizeSlug,
  saveState,
  validateBranchName,
} from "./config.js";
import { cloneOrUpdateRepo } from "./github.js";
import { detectOrGenerateDockerfile } from "./github.js";
import { writeRuntimeEnvFile } from "./vault.js";

/** Jobs are disposable containers: no worker or scheduler stays resident between runs. */
export interface JobScheduleInput {
  name: string;
  repoSource: string;
  branch?: string;
  schedule: string;
  secretScope?: string;
  /** null explicitly clears a previously saved command when editing. */
  command?: string[] | null;
  timeoutSeconds?: number;
}

export interface JobSummary {
  name: string;
  repoUrl: string;
  branch: string;
  image: string;
  secretScope: string;
  schedule: string;
  command?: string[];
  timeoutSeconds: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  builtAt?: string;
  lastCommit?: string;
  lastCommitSha?: string;
  lastRun?: JobRecord["lastRun"];
  timer?: JobRecord["timer"];
}

export interface TimerInstallResult {
  service: string;
  timer: string;
  by: "systemd" | "systemd-user" | "manual";
  enabled: boolean;
  note?: string;
}

const JOBS_DIR = path.join(PAAS_DATA_DIR, "jobs");
const MAX_JOB_TIMEOUT_SECONDS = 24 * 60 * 60;
const MAX_SCHEDULE_LENGTH = 120;

function jobDir(name: string): string {
  return path.join(JOBS_DIR, sanitizeSlug(name));
}

function envPath(name: string): string {
  return path.join(jobDir(name), ".env.runtime");
}

function containerName(name: string): string {
  return `paasmcp-job-${sanitizeSlug(name)}`;
}

function imageName(name: string): string {
  return `paasmcp/job-${sanitizeSlug(name)}:latest`;
}

/** Validates a systemd OnCalendar value before it is written to a unit file. */
export function validateJobSchedule(value: string): string {
  const schedule = String(value || "").trim();
  if (!schedule || schedule.length > MAX_SCHEDULE_LENGTH || /[\r\n]/.test(schedule)) {
    throw new Error(`Invalid job schedule. Use a systemd OnCalendar expression such as 'daily' or '*-*-* 03:00:00'.`);
  }
  // Systemd calendar expressions use these characters. Reject shell/unit syntax and URLs.
  if (!/^[A-Za-z0-9*?.,:/_+\- ]+$/.test(schedule) || schedule.startsWith("-")) {
    throw new Error(`Invalid job schedule '${schedule}'.`);
  }
  return schedule;
}

export function validateJobCommand(command?: string[]): string[] | undefined {
  if (command === undefined) return undefined;
  if (!Array.isArray(command) || command.length === 0 || command.length > 64) {
    throw new Error("A job command must be a non-empty array with at most 64 arguments.");
  }
  const clean = command.map((arg) => String(arg));
  if (clean.some((arg) => arg.length > 4096 || arg.includes("\0"))) {
    throw new Error("Job command arguments must be at most 4096 characters and cannot contain NUL bytes.");
  }
  return clean;
}

function validateTimeout(value?: number): number {
  const timeout = value === undefined ? 3600 : Number(value);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAX_JOB_TIMEOUT_SECONDS) {
    throw new Error(`Job timeout must be an integer from 1 to ${MAX_JOB_TIMEOUT_SECONDS} seconds.`);
  }
  return timeout;
}

function cleanRepoSource(value: string): string {
  const source = String(value || "").trim();
  if (!source || source.includes("\0") || /[\r\n]/.test(source) || source.startsWith("-")) {
    throw new Error("Invalid job repository source.");
  }
  return source;
}

function summary(job: JobRecord): JobSummary {
  return {
    name: job.name,
    repoUrl: job.repoUrl,
    branch: job.branch,
    image: job.image,
    secretScope: job.secretScope,
    schedule: job.schedule,
    ...(job.command ? { command: [...job.command] } : {}),
    timeoutSeconds: job.timeoutSeconds,
    enabled: job.enabled,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    builtAt: job.builtAt,
    lastCommit: job.lastCommit,
    lastCommitSha: job.lastCommitSha,
    lastRun: job.lastRun,
    timer: job.timer,
  };
}

export function listJobs(): JobSummary[] {
  return Object.values(loadState().jobs || {}).sort((a, b) => a.name.localeCompare(b.name)).map(summary);
}

function commandError(prefix: string, err: unknown): Error {
  const code = err && typeof err === "object" && "status" in err ? String((err as { status?: unknown }).status) : "unknown";
  return new Error(`${prefix} (exit ${code}).`);
}

function runProcess(command: string, args: string[], cwd?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ["ignore", "ignore", "ignore"] });
    child.once("error", (err) => reject(commandError(`Could not start ${command}`, err)));
    child.once("close", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} failed (${signal || `exit ${code}`}).`));
    });
  });
}

async function buildImage(name: string, repoSource: string, branch: string): Promise<{ repoDir: string; commitHash: string; commitSha?: string }> {
  ensureDataDir(JOBS_DIR);
  const dir = jobDir(name);
  const repoDir = path.join(dir, "repo");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const checked = cloneOrUpdateRepo(repoSource, repoDir, branch);
  const plan = detectOrGenerateDockerfile(repoDir);
  if (plan.composeFile) {
    throw new Error("Scheduled jobs need a Dockerfile or an auto-detected single application stack; docker-compose repositories are not used as job images.");
  }
  const dockerfile = path.resolve(repoDir, plan.dockerfilePath);
  const relative = path.relative(repoDir, dockerfile);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("The job Dockerfile must stay inside its repository.");
  }
  const dockerignore = path.join(repoDir, ".dockerignore");
  const protectedBuildFiles = [".git", ".env", ".env.*", "*.enc.json", ".master.key"];
  const currentIgnore = fs.existsSync(dockerignore) ? fs.readFileSync(dockerignore, "utf-8") : "";
  const missingIgnore = protectedBuildFiles.filter((entry) => !currentIgnore.split(/\r?\n/).includes(entry));
  if (missingIgnore.length) {
    fs.appendFileSync(dockerignore, `${currentIgnore && !currentIgnore.endsWith("\n") ? "\n" : ""}# PaaSMCP job build safety\n${missingIgnore.join("\n")}\n`, { mode: 0o600 });
  }
  try {
    await runProcess("docker", ["build", "--tag", imageName(name), "--file", relative, "."], repoDir);
  } catch (err) {
    throw commandError(`Could not build image for job '${sanitizeSlug(name)}'`, err);
  }
  return { repoDir, commitHash: checked.commitHash, commitSha: checked.commitSha };
}

/** Builds or rebuilds an existing job image from its saved branch and repository. */
export async function buildJob(name: string): Promise<JobSummary> {
  const slug = sanitizeSlug(name);
  const state = loadState();
  const job = state.jobs?.[slug];
  if (!job) throw new Error(`Job '${slug}' not found.`);
  const built = await buildImage(slug, job.repoUrl, job.branch);
  const now = new Date().toISOString();
  const latest = loadState();
  const current = latest.jobs?.[slug];
  if (!current) throw new Error(`Job '${slug}' was removed while its image was building.`);
  const updated: JobRecord = {
    ...current,
    repoDir: built.repoDir,
    builtAt: now,
    updatedAt: now,
    lastCommit: built.commitHash,
    lastCommitSha: built.commitSha,
  };
  latest.jobs![slug] = updated;
  saveState(latest);
  return summary(updated);
}

function systemdQuote(value: string): string {
  if (!value || /[\r\n]/.test(value)) throw new Error("Invalid systemd command path.");
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function timerPaths(name: string): { service: string; timer: string; user: boolean; dir: string } {
  const slug = sanitizeSlug(name);
  const user = typeof process.getuid !== "function" || process.getuid() !== 0;
  const dir = user
    ? path.join(process.env.HOME || "", ".config", "systemd", "user")
    : "/etc/systemd/system";
  if (user && !process.env.HOME) throw new Error("HOME is not set; cannot install a user job timer.");
  return {
    dir,
    user,
    service: path.join(dir, `paasmcp-job-${slug}.service`),
    timer: path.join(dir, `paasmcp-job-${slug}.timer`),
  };
}

/** Installs one short-lived service and timer. The timer itself consumes no resident process. */
export function installJobTimer(job: JobRecord): TimerInstallResult {
  const paths = timerPaths(job.name);
  if (process.env.PAASMCP_IN_DASHBOARD === "1") {
    return {
      service: paths.service,
      timer: paths.timer,
      by: "manual",
      enabled: false,
      note: "The dashboard container cannot install a host systemd timer. Run 'paasmcp jobs enable <name>' on the server CLI.",
    };
  }
  fs.mkdirSync(paths.dir, { recursive: true, mode: 0o755 });
  // The job may be scheduled from MCP, where argv[1] is mcp-server.js. The CLI is installed
  // beside this module in dist/ and is the stable entry point for the systemd service.
  const cliPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "cli.js");
  const root = process.env.PAASMCP_ROOT || "/opt/homelab";
  fs.writeFileSync(
    paths.service,
    `[Unit]\nDescription=PaaSMCP scheduled job ${job.name}\n\n[Service]\nType=oneshot\nEnvironment=PAASMCP_ROOT=${systemdQuote(root)}\nExecStart=${systemdQuote(process.execPath)} ${systemdQuote(cliPath)} jobs run ${job.name} --scheduled\n`,
    { mode: 0o644 }
  );
  fs.writeFileSync(
    paths.timer,
    `[Unit]\nDescription=Run PaaSMCP job ${job.name}\n\n[Timer]\nOnBootSec=2min\nOnCalendar=${job.schedule}\nPersistent=true\n\n[Install]\nWantedBy=${paths.user ? "default.target" : "timers.target"}\n`,
    { mode: 0o644 }
  );
  const by = paths.user ? "systemd-user" : "systemd";
  try {
    const prefix = paths.user ? ["--user"] : [];
    execFileSync("systemctl", [...prefix, "daemon-reload"], { stdio: "pipe" });
    execFileSync("systemctl", [...prefix, "enable", "--now", path.basename(paths.timer)], { stdio: "pipe" });
    return { service: paths.service, timer: paths.timer, by, enabled: true };
  } catch {
    return {
      service: paths.service,
      timer: paths.timer,
      by: "manual",
      enabled: false,
      note: `Unit files were written, but systemd could not enable the timer. Run systemctl ${paths.user ? "--user " : ""}daemon-reload and enable ${path.basename(paths.timer)}.`,
    };
  }
}

export function uninstallJobTimer(name: string): { service: string; timer: string } {
  const paths = timerPaths(name);
  const timerName = path.basename(paths.timer);
  try {
    execFileSync("systemctl", [...(paths.user ? ["--user"] : []), "disable", "--now", timerName], { stdio: "ignore" });
  } catch {
    // It may not have been enabled, or this is a container without systemd.
  }
  for (const file of [paths.service, paths.timer]) fs.rmSync(file, { force: true });
  return { service: paths.service, timer: paths.timer };
}

/** Creates/replaces a job, builds its image, and installs its timer. */
export async function scheduleJob(input: JobScheduleInput): Promise<JobSummary & { timerInstall: TimerInstallResult }> {
  const name = sanitizeSlug(input.name);
  const repoSource = cleanRepoSource(input.repoSource);
  const branch = validateBranchName(input.branch || "main");
  const schedule = validateJobSchedule(input.schedule);
  const secretScope = sanitizeSlug(input.secretScope || name);
  const commandProvided = input.command !== undefined;
  const command = input.command === null ? undefined : validateJobCommand(input.command);
  const timeoutSeconds = validateTimeout(input.timeoutSeconds);
  const built = await buildImage(name, repoSource, branch);
  const now = new Date().toISOString();
  const previous = loadState().jobs?.[name];
  const job: JobRecord = {
    ...previous,
    name,
    repoUrl: repoSource,
    branch,
    repoDir: built.repoDir,
    image: imageName(name),
    secretScope,
    schedule,
    ...(commandProvided ? (command ? { command } : {}) : {}),
    timeoutSeconds,
    enabled: previous?.enabled ?? true,
    createdAt: previous?.createdAt || now,
    updatedAt: now,
    builtAt: now,
    lastCommit: built.commitHash,
    lastCommitSha: built.commitSha,
  };
  const timerInstall = installJobTimer(job);
  if (!job.enabled) {
    uninstallJobTimer(name);
    timerInstall.enabled = false;
  }
  job.timer = {
    service: timerInstall.service,
    timer: timerInstall.timer,
    by: timerInstall.by,
  };
  const state = loadState();
  state.jobs![name] = job;
  saveState(state);
  return { ...summary(job), timerInstall };
}

export function setJobEnabled(name: string, enabled: boolean): JobSummary {
  const slug = sanitizeSlug(name);
  const state = loadState();
  const job = state.jobs?.[slug];
  if (!job) throw new Error(`Job '${slug}' not found.`);
  if (enabled) {
    const timer = installJobTimer(job);
    job.timer = { service: timer.service, timer: timer.timer, by: timer.by };
  } else {
    uninstallJobTimer(slug);
  }
  job.enabled = enabled;
  job.updatedAt = new Date().toISOString();
  saveState(state);
  return summary(job);
}

export function removeJob(name: string): { removed: string; timer: { service: string; timer: string } } {
  const slug = sanitizeSlug(name);
  const state = loadState();
  const job = state.jobs?.[slug];
  if (!job) throw new Error(`Job '${slug}' not found.`);
  const timer = uninstallJobTimer(slug);
  delete state.jobs![slug];
  saveState(state);
  fs.rmSync(jobDir(slug), { recursive: true, force: true });
  try {
    execFileSync("docker", ["image", "rm", job.image], { stdio: "ignore" });
  } catch {
    // The image may be in use or Docker may be unavailable; state and timer are already removed.
  }
  return { removed: slug, timer };
}

function dockerContainerRunning(name: string): boolean {
  try {
    return Boolean(execFileSync("docker", ["ps", "-q", "--filter", `name=^${containerName(name)}$`], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim());
  } catch {
    return false;
  }
}

function runContainer(job: JobRecord, runtimeEnv: string): Promise<void> {
  const args = [
    "run", "--rm", "--init", "--name", containerName(job.name),
    "--label", "com.paasmcp.managed=true", "--label", `com.paasmcp.job=${job.name}`,
    "--network", DOCKER_NETWORK, "--env-file", runtimeEnv, job.image,
    ...(job.command || []),
  ];
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, { stdio: ["ignore", "ignore", "ignore"] });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { execFileSync("docker", ["rm", "-f", containerName(job.name)], { stdio: "ignore" }); } catch { /* best effort */ }
      child.kill("SIGTERM");
    }, job.timeoutSeconds * 1000);
    child.once("error", (err) => {
      clearTimeout(timer);
      reject(commandError("Could not start Docker for scheduled job", err));
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) reject(new Error(`Job '${job.name}' exceeded its ${job.timeoutSeconds}-second timeout.`));
      else if (code === 0) resolve();
      else reject(new Error(`Job '${job.name}' failed (${signal || `exit ${code}`}).`));
    });
  });
}

/** Runs one job and records only timing/success metadata; container output is never returned or saved. */
export async function runJob(name: string, opts: { allowDisabled?: boolean } = {}): Promise<{ name: string; skipped?: boolean; ok: boolean; startedAt?: string; finishedAt?: string; durationMs?: number; error?: string }> {
  const slug = sanitizeSlug(name);
  const state = loadState();
  const job = state.jobs?.[slug];
  if (!job) throw new Error(`Job '${slug}' not found.`);
  if (!job.enabled && !opts.allowDisabled) return { name: slug, skipped: true, ok: true };
  if (dockerContainerRunning(slug)) throw new Error(`Job '${slug}' is already running; overlapping executions are refused.`);
  fs.mkdirSync(jobDir(slug), { recursive: true, mode: 0o700 });
  const runtimeEnv = envPath(slug);
  const startedAt = new Date().toISOString();
  let ok = false;
  let error: string | undefined;
  try {
    writeRuntimeEnvFile(job.secretScope, runtimeEnv, { PAASMCP_JOB_NAME: job.name });
    fs.chmodSync(runtimeEnv, 0o600);
    await runContainer(job, runtimeEnv);
    ok = true;
  } catch (err) {
    error = err instanceof Error ? err.message : "Scheduled job failed.";
  } finally {
    fs.rmSync(runtimeEnv, { force: true });
  }
  const finishedAt = new Date().toISOString();
  const latest = loadState();
  const current = latest.jobs?.[slug];
  if (current) {
    current.lastRun = { startedAt, finishedAt, ok, ...(error ? { error } : {}) };
    current.updatedAt = finishedAt;
    saveState(latest);
  }
  const result = { name: slug, ok, startedAt, finishedAt, durationMs: Date.parse(finishedAt) - Date.parse(startedAt), ...(error ? { error } : {}) };
  if (!ok) throw Object.assign(new Error(error || `Job '${slug}' failed.`), { jobResult: result });
  return result;
}
