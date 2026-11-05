import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import YAML from "yaml";
import {
  allocateAppPort,
  AppMetrics,
  AppRecord,
  DOCKER_NETWORK,
  HOMEPAGE_SERVICES_YAML,
  loadState,
  PAAS_APPS_DIR,
  PAAS_TRASH_DIR,
  sanitizeSlug,
  saveState,
  validateBranchName,
  validateResourceLimit,
  WATCHTOWER_OFF_COMPOSE,
  withWatchtowerOff,
} from "./config.js";
import { checkHost } from "./hostcheck.js";
import { ensureDockerNetwork, provisionDatabase } from "./database.js";
import { cloneOrUpdateRepo, DetectedBuildPlan, detectOrGenerateDockerfile, headCommitInfo } from "./github.js";
import { cleanText, DeployTracker, DeployTrigger, forgetDeploys, shortCommit, startDeployRun } from "./deploys.js";
import { getSecrets, setSecretEntries, writeRuntimeEnvFile } from "./vault.js";
import { activeComposeExtras, publishActiveState } from "./active.js";
import { forgetScaleData } from "./scale.js";

export interface DeployOptions {
  appName: string;
  /** true = keep host-escape compose fields (caller must have a strong confirmation, guard.ts "app.trust"); false = revoke. */
  trusted?: boolean;
  repoSource: string;
  branch?: string;
  internalPort?: number;
  withPostgres?: boolean;
  withRedis?: boolean;
  env?: Record<string, string>;
  memoryLimit?: string;
  cpuLimit?: string;
  /** Path probed on the candidate before the cutover (default "/", kept for later deploys). */
  healthcheckPath?: string;
  /** Seconds to wait for a healthy answer (default 20, max 300, kept for later deploys). */
  healthcheckTimeoutSeconds?: number;
  /** true = old behaviour (no candidate, no probe) for apps that do not speak HTTP; kept for later deploys. */
  skipHealthcheck?: boolean;
  /** Exact full commit SHA to build instead of the branch head (active-active peers). */
  commit?: string;
  /** Who started the deploy, shown on the dashboard (default "cli"). */
  trigger?: DeployTrigger;
  /** Commit that made the deploy start (poll timer, webhook), shown until the code is fetched. */
  announcedCommit?: string;
}

const RUN_OUTPUT_LIMIT = 64 * 1024;

/** Runs a command without blocking the event loop; the error carries the end of its output. */
export function runAsync(cmd: string, args: string[], cwd: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const keep = (chunk: Buffer) => {
      output += chunk.toString("utf-8");
      if (output.length > RUN_OUTPUT_LIMIT) output = output.slice(-RUN_OUTPUT_LIMIT);
    };
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code === 0) return resolve();
      const tail = output.trim().split("\n").slice(-60).join("\n");
      reject(new Error(`Command failed: ${cmd} ${args.join(" ")} (${signal || `exit ${code}`})\n${tail}`));
    });
  });
}

export function syncHomepageDashboard(): void {
  try {
    if (!fs.existsSync(HOMEPAGE_SERVICES_YAML)) return;
    const state = loadState();
    const raw = fs.readFileSync(HOMEPAGE_SERVICES_YAML, "utf-8");
    const doc = YAML.parse(raw) as Array<Record<string, Array<Record<string, unknown>>>>;
    if (!Array.isArray(doc)) return;

    const sectionTitle = "Aplicações (PaaSMCP)";
    const appEntries = Object.values(state.apps).map((app) => {
      const primaryUrl =
        app.domains[0]?.url || `http://127.0.0.1:${app.localPort}`;
      return {
        [app.name]: {
          icon: "docker.png",
          href: primaryUrl,
          description: `${app.runtimeType} | Porta local :${app.localPort}${
            app.databases.length ? ` | DB: ${app.databases.join(", ")}` : ""
          }`,
        },
      };
    });

    const existingIdx = doc.findIndex((group) => sectionTitle in group);
    if (appEntries.length === 0) {
      if (existingIdx !== -1) {
        doc.splice(existingIdx, 1);
      }
    } else if (existingIdx !== -1) {
      doc[existingIdx][sectionTitle] = appEntries;
    } else {
      doc.push({ [sectionTitle]: appEntries });
    }

    fs.writeFileSync(HOMEPAGE_SERVICES_YAML, YAML.stringify(doc), "utf-8");
  } catch {
    // Non-fatal if homepage config is read-only or absent
  }
}

// Fields that let a container escape to the host. Removed unless the app is trusted (guard.ts "app.trust").
const HOST_ESCAPE_FIELDS = [
  "privileged",
  "network_mode",
  "pid",
  "ipc",
  "uts",
  "userns_mode",
  "cap_add",
  "devices",
  "device_cgroup_rules",
  "security_opt",
  "cgroup",
  "cgroup_parent",
  "volumes_from",
];

/** A volume source that reaches the host filesystem (absolute, home, parent, or env-interpolated path). */
function isHostPath(source: string): boolean {
  return /^(\/|~|\$)/.test(source) || source.split(/[\\/]/).includes("..");
}

function hostVolumeSource(v: unknown): string | undefined {
  if (typeof v === "string") {
    const source = v.split(":")[0] || "";
    return isHostPath(source) ? source : undefined;
  }
  if (v && typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const source = String(obj.source ?? "");
    if (obj.type === "bind" || isHostPath(source)) return source || "(bind)";
  }
  return undefined;
}

export function generateSanitizedComposeFromRepo(opts: {
  repoComposePath: string;
  slug: string;
  containerName: string;
  localPort: number;
  internalPort: number;
  primaryServiceName: string;
  memoryLimit?: string;
  cpuLimit?: string;
  trusted?: boolean;
  /** Active-active (active.ts): host:ip entries for every service and extra published ports for the primary one. */
  extraHosts?: string[];
  extraPorts?: string[];
}): { yaml: string; findings: string[]; primaryImage?: string } {
  const raw = fs.readFileSync(opts.repoComposePath, "utf-8");
  const parsed = YAML.parse(raw) as {
    services?: Record<string, Record<string, unknown>>;
    volumes?: Record<string, unknown>;
  };

  if (!parsed || !parsed.services || typeof parsed.services !== "object") {
    throw new Error("Invalid docker-compose file: missing 'services' root object.");
  }

  // Host-escape findings: removed for untrusted apps, kept (and reported) for trusted ones.
  const findings: string[] = [];
  const safeServices: Record<string, Record<string, unknown>> = {};
  for (const [svcName, svcDef] of Object.entries(parsed.services)) {
    const cleanSvc: Record<string, unknown> = { ...svcDef };

    for (const field of HOST_ESCAPE_FIELDS) {
      if (cleanSvc[field] === undefined) continue;
      findings.push(`${svcName}.${field}`);
      if (!opts.trusted) delete cleanSvc[field];
    }
    // `extends` can pull service definitions from arbitrary files; never trusted.
    if (cleanSvc.extends !== undefined) {
      findings.push(`${svcName}.extends (always removed)`);
      delete cleanSvc.extends;
    }

    // Rewrite build context to point inside ./repo (always enforced)
    if (typeof cleanSvc.build === "string") {
      const rel = cleanSvc.build.replace(/^\.\//, "");
      if (rel.includes("..") || path.isAbsolute(rel)) {
        throw new Error(`Unsafe build path in service '${svcName}': ${cleanSvc.build}`);
      }
      cleanSvc.build = rel ? `./repo/${rel}` : "./repo";
    } else if (cleanSvc.build && typeof cleanSvc.build === "object") {
      const bObj = { ...(cleanSvc.build as Record<string, unknown>) };
      const ctx = String(bObj.context || ".").replace(/^\.\//, "");
      if (ctx.includes("..") || path.isAbsolute(ctx)) {
        throw new Error(`Unsafe build context in service '${svcName}': ${ctx}`);
      }
      bObj.context = ctx && ctx !== "." ? `./repo/${ctx}` : "./repo";
      if (bObj.additional_contexts !== undefined) {
        findings.push(`${svcName}.build.additional_contexts (always removed)`);
        delete bObj.additional_contexts;
      }
      cleanSvc.build = bObj;
    }

    // Host bind mounts (short or long syntax, absolute, ~, $VAR or ..)
    if (Array.isArray(cleanSvc.volumes)) {
      cleanSvc.volumes = cleanSvc.volumes.filter((v) => {
        const hostSource = hostVolumeSource(v);
        if (!hostSource) return true;
        findings.push(`${svcName}.volumes: ${hostSource}`);
        return Boolean(opts.trusted);
      });
    }

    // Inject encrypted Vault runtime environment and homelab-network into every service
    cleanSvc.env_file = [".env.runtime"];
    cleanSvc.restart = "unless-stopped";
    cleanSvc.labels = withWatchtowerOff(cleanSvc.labels);
    if (cleanSvc.network_mode === undefined) cleanSvc.networks = [DOCKER_NETWORK];

    if (opts.extraHosts?.length) {
      const own = Array.isArray(cleanSvc.extra_hosts) ? (cleanSvc.extra_hosts as string[]) : [];
      cleanSvc.extra_hosts = [...own, ...opts.extraHosts];
    }
    if (opts.memoryLimit) cleanSvc.mem_limit = opts.memoryLimit;
    if (opts.cpuLimit) cleanSvc.cpus = Number(opts.cpuLimit);

    // Loopback-only port enforcement: only primary service gets 127.0.0.1:<localPort>:<internalPort>
    if (svcName === opts.primaryServiceName) {
      cleanSvc.container_name = opts.containerName;
      // A fixed tag lets the blue/green cutover restore the old image and keeps rollback working.
      if (cleanSvc.build !== undefined && cleanSvc.image === undefined) cleanSvc.image = `paasmcp/${opts.slug}:latest`;
      cleanSvc.ports = [`127.0.0.1:${opts.localPort}:${opts.internalPort}`, ...(opts.extraPorts || [])];
    } else {
      cleanSvc.container_name = `${opts.containerName}-${ sanitizeSlug(svcName) }`;
      delete cleanSvc.ports;
    }

    safeServices[svcName] = cleanSvc;
  }

  const outputCompose: Record<string, unknown> = {
    services: safeServices,
    networks: {
      [DOCKER_NETWORK]: {
        external: true,
      },
    },
  };

  if (parsed.volumes && typeof parsed.volumes === "object") {
    // A named volume with driver_opts (type: none, o: bind, device: /etc) is a host bind mount in disguise.
    const volumes: Record<string, unknown> = {};
    for (const [volName, volDef] of Object.entries(parsed.volumes)) {
      const driverOpts = (volDef as Record<string, unknown> | null)?.driver_opts;
      if (driverOpts && !opts.trusted) {
        findings.push(`volumes.${volName}.driver_opts`);
        volumes[volName] = {};
      } else {
        if (driverOpts) findings.push(`volumes.${volName}.driver_opts`);
        volumes[volName] = volDef;
      }
    }
    outputCompose.volumes = volumes;
  }

  const primaryImage = safeServices[opts.primaryServiceName]?.image;
  return {
    yaml: YAML.stringify(outputCompose),
    findings,
    ...(typeof primaryImage === "string" ? { primaryImage } : {}),
  };
}

export const DEFAULT_HEALTHCHECK_TIMEOUT_SECONDS = 20;
const MAX_HEALTHCHECK_TIMEOUT_SECONDS = 300;
const CANDIDATE_LOG_LINES = 80;

/** Only a plain absolute URL path: it is appended to http://127.0.0.1:<port>. */
export function validateHealthcheckPath(value?: string): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (value.length > 512 || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/.test(value)) {
    throw new Error(`Invalid healthcheckPath '${value}': use a URL path such as '/' or '/healthz'.`);
  }
  return value;
}

export function validateHealthcheckTimeout(value?: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value) || value < 1 || value > MAX_HEALTHCHECK_TIMEOUT_SECONDS) {
    throw new Error(`healthcheckTimeoutSeconds must be between 1 and ${MAX_HEALTHCHECK_TIMEOUT_SECONDS}.`);
  }
  return Math.round(value);
}

export interface HealthcheckResult {
  healthy: boolean;
  status?: number;
  elapsedMs: number;
  reason?: string;
}

/**
 * Polls `url` until it answers with a status below 500 (redirects and 4xx count as "the app is up").
 * Stops early when `isAlive` says the container already exited.
 */
export async function waitForHealthy(opts: {
  url: string;
  timeoutMs: number;
  intervalMs?: number;
  isAlive?: () => boolean;
}): Promise<HealthcheckResult> {
  const started = Date.now();
  const interval = opts.intervalMs ?? 500;
  let lastStatus: number | undefined;
  let lastProblem = "no answer";
  for (;;) {
    const elapsed = Date.now() - started;
    const remaining = opts.timeoutMs - elapsed;
    if (remaining <= 0) break;
    if (opts.isAlive && !opts.isAlive()) {
      return { healthy: false, status: lastStatus, elapsedMs: elapsed, reason: "the container exited before answering" };
    }
    try {
      const res = await fetch(opts.url, {
        redirect: "manual",
        signal: AbortSignal.timeout(Math.max(250, Math.min(3000, remaining))),
      });
      lastStatus = res.status;
      await res.body?.cancel().catch(() => undefined);
      if (res.status < 500) return { healthy: true, status: res.status, elapsedMs: Date.now() - started };
      lastProblem = `HTTP ${res.status}`;
    } catch (err) {
      const cause = (err as { cause?: { code?: string } }).cause?.code;
      lastProblem = cause || (err instanceof Error ? err.name : String(err));
    }
    await new Promise((r) => setTimeout(r, Math.max(0, Math.min(interval, opts.timeoutMs - (Date.now() - started)))));
  }
  return {
    healthy: false,
    status: lastStatus,
    elapsedMs: Date.now() - started,
    reason: `no healthy answer within ${Math.round(opts.timeoutMs / 1000)}s (last: ${lastProblem})`,
  };
}

/** Thrown when the new version fails its healthcheck; the running version was left untouched. */
export class HealthcheckFailedError extends Error {
  constructor(
    readonly app: string,
    readonly healthcheck: HealthcheckResult & { path: string },
    readonly candidateLogs: string
  ) {
    super(
      `Deploy of '${app}' aborted: the new version failed its healthcheck (GET ${healthcheck.path}: ${healthcheck.reason}). ` +
        `The version that was running is untouched and still serving traffic. Fix the error below and deploy again.\n` +
        `--- candidate logs (last ${CANDIDATE_LOG_LINES} lines) ---\n${candidateLogs || "(no output)"}`
    );
    this.name = "HealthcheckFailedError";
  }
}

/** A free loopback port picked by the kernel (closed again right away; docker binds it next). */
export function findFreeLoopbackPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

/** `docker tag`, false when the source image does not exist. */
function tagImage(source: string, target: string): boolean {
  return spawnSync("docker", ["tag", source, target], { stdio: "ignore" }).status === 0;
}

function containerRunning(name: string): boolean {
  try {
    return (
      execFileSync("docker", ["inspect", "--format", "{{.State.Running}}", name], {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim() === "true"
    );
  } catch {
    return false;
  }
}

function removeContainer(name: string): void {
  spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" });
}

function containerLogs(name: string, lines = CANDIDATE_LOG_LINES): string {
  const res = spawnSync("docker", ["logs", "--tail", String(lines), name], { encoding: "utf-8" });
  const out = `${res.stdout || ""}${res.stderr || ""}`.trim();
  return out.length > 6000 ? out.slice(-6000) : out;
}

export interface DeployResult {
  app: AppRecord;
  commitHash: string;
  provisionedDatabases: string[];
  previousImageSaved: boolean;
  cutover: "blue-green" | "direct";
  healthcheck?: HealthcheckResult & { path: string; candidatePort: number };
  warning?: string;
  removedForSafety?: string[];
  hostAccessKept?: string[];
  hint?: string;
}

/**
 * Builds and starts an app. Progress (fetching, building, checking, switching, live/failed) is written
 * to deploys/<app>.json as it goes, so the dashboard can show it live whichever process deploys.
 */
export async function deployApp(opts: DeployOptions): Promise<DeployResult> {
  const slug = sanitizeSlug(opts.appName);
  const announced = opts.announcedCommit || opts.commit;
  const tracker = startDeployRun({
    app: slug,
    trigger: opts.trigger || "cli",
    branch: opts.branch || "main",
    commit: announced ? shortCommit(announced) : undefined,
    phase: opts.trigger === "poll" || opts.trigger === "webhook" ? "detected" : "fetching",
  });
  try {
    const result = await runDeploy(opts, tracker);
    tracker.succeed(result.warning);
    return result;
  } catch (err) {
    tracker.fail(err);
    throw err;
  }
}

async function runDeploy(opts: DeployOptions, tracker: DeployTracker): Promise<DeployResult> {
  const slug = sanitizeSlug(opts.appName);
  const branch = validateBranchName(opts.branch || "main");
  const memoryLimit = validateResourceLimit(opts.memoryLimit, "memory");
  const cpuLimit = validateResourceLimit(opts.cpuLimit, "cpu");
  const state = loadState();
  const prior = state.apps[slug];
  const healthcheckPath = validateHealthcheckPath(opts.healthcheckPath) ?? prior?.healthcheckPath;
  const healthcheckTimeoutSeconds =
    validateHealthcheckTimeout(opts.healthcheckTimeoutSeconds) ?? prior?.healthcheckTimeoutSeconds;
  const healthcheckDisabled = opts.skipHealthcheck ?? prior?.healthcheckDisabled ?? false;
  if (state.mirror?.fenced && !state.apps[slug]?.originNodeId) {
    throw new Error(`This server is fenced: since epoch ${state.mirror.fenced.epoch} another server serves its data. Follow the failback steps ('paasmcp mirror status').`);
  }
  // Several servers: this server served another server's data after a takeover, and a later takeover
  // moved that data elsewhere. Its apps must not start here again.
  const origin = state.apps[slug]?.originNodeId;
  const lost = origin ? Object.values(state.mirror?.replicas || {}).find((r) => r.peerNodeId === origin && r.promotedAt && r.supersededBy && !r.handedBackAt) : undefined;
  if (lost) {
    throw new Error(`Another server (${lost.supersededBy!.nodeId}) took over the data of '${lost.peerName}' at ${lost.supersededBy!.at}: its apps no longer run here ('paasmcp mirror status').`);
  }
  if (state.apps[slug]?.trashedAt) {
    throw new Error(`App '${slug}' is in the trash. Restore it (action 'restore') or purge it before deploying again.`);
  }
  // Docker comes after the checks above, so a refused deploy touches nothing.
  ensureDockerNetwork();
  const trusted = opts.trusted ?? state.apps[slug]?.trusted ?? false;
  const localPort = allocateAppPort(state, slug);
  const appDir = path.join(PAAS_APPS_DIR, slug);
  const repoDir = path.join(appDir, "repo");
  const containerName = `paasmcp-${slug}`;

  fs.mkdirSync(appDir, { recursive: true, mode: 0o700 });

  if (opts.env && Object.keys(opts.env).length > 0) {
    setSecretEntries(slug, opts.env);
  }

  const provisionedDatabases: string[] = [];
  if (opts.withPostgres) {
    const res = provisionDatabase(slug, "postgres");
    provisionedDatabases.push(res.record.name);
  }
  if (opts.withRedis) {
    const res = provisionDatabase(slug, "redis");
    provisionedDatabases.push(res.record.name);
  }

  tracker.phase("fetching");
  const { commitHash, commitSha } = cloneOrUpdateRepo(opts.repoSource, repoDir, branch, opts.commit);
  if (commitSha) {
    const info = headCommitInfo(repoDir);
    tracker.commit({
      sha: commitSha,
      short: commitHash,
      message: cleanText(info.subject, 200),
      author: cleanText(info.author, 80),
      date: info.date,
    });
  }
  tracker.phase("building");
  const buildPlan: DetectedBuildPlan = detectOrGenerateDockerfile(repoDir, opts.internalPort);
  const internalPort = opts.internalPort || buildPlan.detectedPort;

  // Active-active: shared services on the origin, Tailscale port, replica URL (empty for other apps).
  const active = activeComposeExtras(
    loadState(),
    { activeActive: prior?.activeActive, originNodeId: prior?.originNodeId, localPort },
    internalPort,
    getSecrets(slug)
  );

  const runtimeEnvPath = path.join(appDir, ".env.runtime");
  writeRuntimeEnvFile(slug, runtimeEnvPath, {
    PORT: String(internalPort),
    NODE_ENV: "production",
    ...active.extraEnv,
  });

  const currentImg = `paasmcp/${slug}:latest`;
  const prevImg = `paasmcp/${slug}:previous`;

  const composePath = path.join(appDir, "compose.yaml");
  const isComposePassThrough = Boolean(buildPlan.composeFile);
  let composeFindings: string[] = [];
  let primaryService = "app";
  let primaryImage: string | undefined = currentImg;

  if (isComposePassThrough && buildPlan.composeFile && buildPlan.primaryServiceName) {
    const repoComposePath = path.join(repoDir, buildPlan.composeFile);
    const sanitized = generateSanitizedComposeFromRepo({
      repoComposePath,
      slug,
      containerName,
      localPort,
      internalPort,
      primaryServiceName: buildPlan.primaryServiceName,
      memoryLimit,
      cpuLimit,
      trusted,
      extraHosts: active.extraHosts,
      extraPorts: active.extraPorts,
    });
    composeFindings = sanitized.findings;
    primaryService = buildPlan.primaryServiceName;
    primaryImage = sanitized.primaryImage;
    fs.writeFileSync(composePath, sanitized.yaml, { mode: 0o600 });
  } else {
    const memLine = memoryLimit ? `    mem_limit: ${memoryLimit}\n` : "";
    const cpuLine = cpuLimit ? `    cpus: ${cpuLimit}\n` : "";
    const extraPortLines = active.extraPorts.map((p) => `\n      - "${p}"`).join("");
    const hostsBlock = active.extraHosts.length
      ? `    extra_hosts:\n${active.extraHosts.map((h) => `      - "${h}"\n`).join("")}`
      : "";
    const composeContent = `services:
  app:
    build:
      context: ./repo
      dockerfile: ${buildPlan.dockerfilePath}
    image: ${currentImg}
    container_name: ${containerName}
    restart: unless-stopped
${WATCHTOWER_OFF_COMPOSE}${memLine}${cpuLine}    env_file:
      - .env.runtime
    ports:
      - "127.0.0.1:${localPort}:${internalPort}"${extraPortLines}
${hostsBlock}    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`;
    fs.writeFileSync(composePath, composeContent, { mode: 0o600 });
  }

  const compose = (...args: string[]) =>
    execFileSync("docker", ["compose", "-f", composePath, ...args], { cwd: appDir, stdio: "pipe" });

  // Hold the running version's image under its own tag (an untagged image can vanish with the
  // containerd image store), then build the new image while the running version keeps serving.
  const holdImg = `paasmcp/${slug}:pre-deploy`;
  const hadOldImage = primaryImage ? tagImage(primaryImage, holdImg) : false;
  const releaseHold = () => {
    if (hadOldImage) spawnSync("docker", ["image", "rm", holdImg], { stdio: "ignore" });
  };
  // Until the swap starts, any failure puts the tag back on the running version's image.
  const abort = () => {
    if (primaryImage && hadOldImage) tagImage(holdImg, primaryImage);
    releaseHold();
  };

  let healthcheck: (HealthcheckResult & { path: string; candidatePort: number }) | undefined;
  let warning: string | undefined;
  const probePath = healthcheckPath || "/";
  const timeoutMs = (healthcheckTimeoutSeconds || DEFAULT_HEALTHCHECK_TIMEOUT_SECONDS) * 1000;
  const candidateName = `${containerName}-candidate`;
  try {
    // Asynchronous: a long build must not freeze the dashboard (it answers progress requests meanwhile).
    await runAsync("docker", ["compose", "-f", composePath, "build"], appDir);
    if (!healthcheckDisabled) {
      tracker.phase("checking");
      // Blue/green: run the new image as a one-off candidate on a free loopback port and probe it.
      const candidatePort = await findFreeLoopbackPort();
      removeContainer(candidateName); // leftover from an interrupted deploy
      compose(
        "run", "-d",
        "--name", candidateName,
        "--label", `paasmcp.candidate=${slug}`,
        "--publish", `127.0.0.1:${candidatePort}:${internalPort}`,
        primaryService
      );
      const result = await waitForHealthy({
        url: `http://127.0.0.1:${candidatePort}${probePath}`,
        timeoutMs,
        isAlive: () => containerRunning(candidateName),
      });
      healthcheck = { ...result, path: probePath, candidatePort };
      if (!result.healthy) {
        throw new HealthcheckFailedError(slug, healthcheck, containerLogs(candidateName));
      }

      // Healthy: let the candidate answer for the container name (Cloudflare Tunnel routes by it on
      // the Docker network) while the production container is recreated, so tunnel traffic sees no gap.
      try {
        execFileSync("docker", ["network", "disconnect", DOCKER_NETWORK, candidateName], { stdio: "ignore" });
        execFileSync("docker", ["network", "connect", "--alias", containerName, DOCKER_NETWORK, candidateName], {
          stdio: "ignore",
        });
      } catch {
        // Best effort: without the alias the cutover still works, with the usual 1-2 s recreate gap.
      }
    }
  } catch (err) {
    removeContainer(candidateName);
    abort();
    throw err;
  }

  // Swap: recreate the production container(s) from the new image.
  tracker.phase("switching");
  try {
    compose("up", "-d", "--no-build", "--remove-orphans");
    if (healthcheck) {
      const settled = await waitForHealthy({
        url: `http://127.0.0.1:${localPort}${probePath}`,
        timeoutMs,
        isAlive: () => containerRunning(containerName),
      });
      if (!settled.healthy) {
        warning = `The candidate passed, but ${containerName} did not answer GET ${probePath} on 127.0.0.1:${localPort} after the swap (${settled.reason}). Check paas_app_lifecycle(action='logs') or roll back.`;
      }
    }
  } finally {
    removeContainer(candidateName);
  }

  // Keep the replaced image as :previous for the 1-second rollback.
  const previousImageSaved = hadOldImage && primaryImage === currentImg && tagImage(holdImg, prevImg);
  releaseHold();

  const latestState = loadState();
  const existing = latestState.apps[slug];
  const now = new Date().toISOString();

  const dbList = Array.from(
    new Set([...(existing?.databases || []), ...provisionedDatabases])
  );

  const record: AppRecord = {
    // Keep fields other features own (originNodeId for the mirror, autoDeploy for polling, ...).
    ...existing,
    name: slug,
    repoUrl: opts.repoSource,
    branch,
    localPort,
    internalPort,
    containerName,
    appDir,
    runtimeType: buildPlan.runtimeType,
    databases: dbList,
    domains: existing?.domains || [],
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    status: "running",
    lastCommit: commitHash,
    lastCommitSha: commitSha || (opts.repoSource === existing?.repoUrl ? existing?.lastCommitSha : undefined),
    previousImageTag: previousImageSaved ? prevImg : existing?.previousImageTag,
    composePassThrough: isComposePassThrough,
    memoryLimit: memoryLimit || existing?.memoryLimit,
    cpuLimit: cpuLimit || existing?.cpuLimit,
    trusted,
    healthcheckPath,
    healthcheckTimeoutSeconds,
    healthcheckDisabled: healthcheckDisabled || undefined,
  };

  latestState.apps[slug] = record;
  saveState(latestState);
  syncHomepageDashboard();

  // Origin of an active-active app: tell the other server which version and settings to run.
  if (record.activeActive && !record.originNodeId) {
    try {
      const pub = publishActiveState();
      if (!pub.published && pub.reason !== "unchanged") active.warnings.push(`The other server was not told about this version: ${pub.reason}.`);
    } catch (err) {
      active.warnings.push(`The other server was not told about this version: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
    }
  }
  // Copies on helper PCs (pool.ts) follow this version: new image, variables or limits, one at a time.
  if (record.pool?.enabled) {
    try {
      const { reconcilePool } = await import("./pool.js");
      const r = await reconcilePool(slug);
      const problems = [...r.errors.map((e) => (e.helper ? `${e.helper}: ` : "") + e.error.split("\n")[0]), ...r.warnings];
      if (problems.length) active.warnings.push(`Copies on helpers: ${problems.join("; ")}`);
    } catch (err) {
      active.warnings.push(`Copies on helpers were not updated: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
    }
  }
  if (active.warnings.length) warning = [warning, ...active.warnings].filter(Boolean).join(" ");

  return {
    app: record,
    commitHash,
    provisionedDatabases,
    previousImageSaved,
    cutover: healthcheckDisabled ? "direct" : "blue-green",
    ...(healthcheck ? { healthcheck } : {}),
    ...(warning ? { warning } : {}),
    ...(composeFindings.length
      ? trusted
        ? { hostAccessKept: composeFindings }
        : {
            removedForSafety: composeFindings,
            hint: "These compose fields reach the host and were removed. To keep them, redeploy with trusted=true (needs a strong confirmation).",
          }
      : {}),
  };
}

export const TRASH_RETENTION_DAYS = 30;

export type AppLifecycleAction =
  | "logs"
  | "restart"
  | "stop"
  | "start"
  | "rollback"
  | "destroy"
  | "restore"
  | "purge";

/** Deletes apps that stayed in the trash longer than TRASH_RETENTION_DAYS (run daily from cron/timer). */
export function purgeExpiredTrash(now = Date.now()): string[] {
  const cutoff = now - TRASH_RETENTION_DAYS * 24 * 3600 * 1000;
  const expired = Object.values(loadState().apps).filter(
    (a) => a.trashedAt && Date.parse(a.trashedAt) < cutoff
  );
  return expired.map((a) => manageAppLifecycle(a.name, "purge"));
}

export function manageAppLifecycle(
  appName: string,
  action: AppLifecycleAction,
  tailLines = 80
): string {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) {
    throw new Error(`App '${slug}' is not registered in PaaSMCP.`);
  }

  if (app.trashedAt && app.trashDir) {
    const trashCompose = path.join(app.trashDir, "compose.yaml");
    if (action === "restore") {
      if (fs.existsSync(app.appDir)) {
        throw new Error(`Cannot restore '${slug}': ${app.appDir} already exists.`);
      }
      fs.renameSync(app.trashDir, app.appDir);
      delete app.trashedAt;
      delete app.trashDir;
      app.status = "running";
      saveState(state);
      execFileSync("docker", ["compose", "-f", path.join(app.appDir, "compose.yaml"), "up", "-d"], {
        cwd: app.appDir,
        stdio: "pipe",
      });
      syncHomepageDashboard();
      return `App '${slug}' restored from the trash and started.`;
    }
    if (action === "purge") {
      try {
        execFileSync("docker", ["compose", "-f", trashCompose, "down", "-v", "--rmi", "local"], {
          cwd: app.trashDir,
          stdio: "pipe",
        });
      } catch {
        // containers may already be gone
      }
      const resolvedTrash = path.resolve(app.trashDir);
      if (resolvedTrash.startsWith(path.resolve(PAAS_TRASH_DIR) + path.sep)) {
        fs.rmSync(resolvedTrash, { recursive: true, force: true });
      }
      delete state.apps[slug];
      saveState(state);
      forgetScaleData(slug);
      forgetDeploys(slug);
      syncHomepageDashboard();
      return `App '${slug}' was permanently deleted (containers, volumes, images and files).`;
    }
    throw new Error(`App '${slug}' is in the trash since ${app.trashedAt}. Use 'restore' or 'purge'.`);
  }
  if (action === "restore" || action === "purge") {
    throw new Error(`App '${slug}' is not in the trash. Use 'destroy' first.`);
  }
  const composePath = path.join(app.appDir, "compose.yaml");

  if (action === "logs") {
    const safeLines = Math.max(1, Math.min(2000, Number(tailLines) || 80));
    return execFileSync(
      "docker",
      ["logs", "--tail", String(safeLines), app.containerName],
      { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }
    );
  }

  if (action === "rollback") {
    const prevImg = `paasmcp/${slug}:previous`;
    const latestImg = `paasmcp/${slug}:latest`;
    try {
      execFileSync("docker", ["image", "inspect", prevImg], { stdio: "ignore" });
    } catch {
      throw new Error(
        `No previous image snapshot ('${prevImg}') found for app '${slug}' to roll back to.`
      );
    }
    execFileSync("docker", ["tag", prevImg, latestImg], { stdio: "pipe" });
    execFileSync("docker", ["compose", "-f", composePath, "up", "-d", "--no-build"], {
      cwd: app.appDir,
      stdio: "pipe",
    });
    app.updatedAt = new Date().toISOString();
    app.status = "running (rolled back)";
    saveState(state);
    return `App '${slug}' rolled back to previous image (${prevImg}) and restarted.`;
  }

  if (action === "restart") {
    execFileSync("docker", ["compose", "-f", composePath, "restart"], {
      cwd: app.appDir,
      stdio: "pipe",
    });
    return `Container ${app.containerName} restarted.`;
  }

  if (action === "stop") {
    execFileSync("docker", ["compose", "-f", composePath, "stop"], {
      cwd: app.appDir,
      stdio: "pipe",
    });
    app.status = "stopped";
    saveState(state);
    return `Container ${app.containerName} stopped.`;
  }

  if (action === "start") {
    execFileSync("docker", ["compose", "-f", composePath, "start"], {
      cwd: app.appDir,
      stdio: "pipe",
    });
    app.status = "running";
    saveState(state);
    return `Container ${app.containerName} started.`;
  }

  if (action === "destroy") {
    // Reversible: stop containers, keep volumes/images/files in the trash for TRASH_RETENTION_DAYS.
    try {
      execFileSync("docker", ["compose", "-f", composePath, "down"], { cwd: app.appDir, stdio: "pipe" });
    } catch {
      // ignore if already stopped
    }
    const resolvedDir = path.resolve(app.appDir);
    if (!resolvedDir.startsWith(path.resolve(PAAS_APPS_DIR) + path.sep)) {
      throw new Error(`Refusing to move ${app.appDir}: outside ${PAAS_APPS_DIR}.`);
    }
    const now = new Date();
    const trashDir = path.join(PAAS_TRASH_DIR, `${slug}-${now.toISOString().replace(/[:.]/g, "-")}`);
    if (fs.existsSync(resolvedDir)) fs.renameSync(resolvedDir, trashDir);
    else fs.mkdirSync(trashDir, { recursive: true, mode: 0o700 });
    app.trashedAt = now.toISOString();
    app.trashDir = trashDir;
    app.status = "trashed";
    saveState(state);
    syncHomepageDashboard();
    return `App '${slug}' stopped and moved to the trash (kept for ${TRASH_RETENTION_DAYS} days; use 'restore' to bring it back or 'purge' to delete it now).`;
  }

  throw new Error(`Unsupported action: ${action}`);
}

export function getContainerMetrics(): Record<string, AppMetrics> {
  const metrics: Record<string, AppMetrics> = {};
  if (process.env.PAASMCP_OFFLINE_TEST === "1") {
    return metrics;
  }
  try {
    const out = execFileSync(
      "docker",
      ["stats", "--no-stream", "--format", "{{json .}}"],
      { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 4000 }
    );
    for (const line of out.trim().split("\n")) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as {
          Name?: string;
          CPUPerc?: string;
          MemUsage?: string;
          MemPerc?: string;
          NetIO?: string;
          PIDs?: string;
        };
        if (row.Name && row.Name.startsWith("paasmcp-")) {
          metrics[row.Name] = {
            cpuPercent: row.CPUPerc || "0.00%",
            memUsage: row.MemUsage || "0B / 0B",
            memPercent: row.MemPerc || "0.00%",
            netIO: row.NetIO || "0B / 0B",
            pids: row.PIDs || "0",
          };
        }
      } catch {
        // ignore malformed row
      }
    }
  } catch {
    // Docker daemon unavailable or no running containers
  }
  return metrics;
}

export interface DoctorDiagnosticItem {
  target: string;
  severity: "healthy" | "warning" | "critical";
  summary: string;
  recommendation?: string;
  details?: Record<string, unknown>;
}

export function runPaaSDoctor(appName?: string): {
  checkedAt: string;
  overallHealth: "healthy" | "warning" | "critical";
  diagnostics: DoctorDiagnosticItem[];
} {
  const state = loadState();
  const diagnostics: DoctorDiagnosticItem[] = [];
  const metrics = getContainerMetrics();

  const appsToInspect = appName
    ? [state.apps[sanitizeSlug(appName)]].filter(Boolean)
    : Object.values(state.apps);

  for (const app of appsToInspect) {
    if (!app) continue;
    if (process.env.PAASMCP_OFFLINE_TEST === "1") {
      diagnostics.push({
        target: app.name,
        severity: "healthy",
        summary: `Container ${app.containerName} registered on 127.0.0.1:${app.localPort}.`,
      });
      continue;
    }

    try {
      const inspectRaw = execFileSync(
        "docker",
        ["inspect", app.containerName],
        { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }
      );
      const parsed = JSON.parse(inspectRaw) as Array<{
        State?: {
          Status?: string;
          Running?: boolean;
          OOMKilled?: boolean;
          ExitCode?: number;
          Error?: string;
        };
        RestartCount?: number;
      }>;
      const info = parsed[0];
      const cState = info?.State || {};
      const restartCount = info?.RestartCount || 0;
      const containerMetric = metrics[app.containerName];

      if (cState.OOMKilled) {
        diagnostics.push({
          target: app.name,
          severity: "critical",
          summary: `Container ${app.containerName} was terminated by Linux OOMKiller (Out of Memory).`,
          recommendation: `Increase memoryLimit in paas_app_deploy or optimize memory usage in ${app.name}.`,
          details: { status: cState.Status, exitCode: cState.ExitCode, restartCount },
        });
      } else if (!cState.Running && app.status !== "stopped") {
        let lastLogs = "";
        try {
          lastLogs = execFileSync(
            "docker",
            ["logs", "--tail", "25", app.containerName],
            { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }
          );
        } catch {
          // ignore
        }
        diagnostics.push({
          target: app.name,
          severity: "critical",
          summary: `Container ${app.containerName} is not running (status=${cState.Status}, exitCode=${cState.ExitCode}).`,
          recommendation:
            "Inspect recent container logs below, check missing Vault environment variables, or trigger paas_app_lifecycle(action='rollback').",
          details: {
            status: cState.Status,
            exitCode: cState.ExitCode,
            restartCount,
            lastLogs: lastLogs.slice(-1500),
          },
        });
      } else if (restartCount > 3) {
        diagnostics.push({
          target: app.name,
          severity: "warning",
          summary: `Container ${app.containerName} is running but has restarted ${restartCount} times.`,
          recommendation: "Check paas_app_lifecycle(action='logs') for intermittent crashes.",
          details: { restartCount, metrics: containerMetric },
        });
      } else {
        diagnostics.push({
          target: app.name,
          severity: "healthy",
          summary: `Container ${app.containerName} is healthy and bound to 127.0.0.1:${app.localPort}.`,
          details: { restartCount, metrics: containerMetric },
        });
      }
    } catch {
      diagnostics.push({
        target: app.name,
        severity: app.status === "stopped" ? "healthy" : "warning",
        summary: `Container ${app.containerName} not found in Docker engine.`,
        recommendation: `Re-run paas_app_deploy for '${app.name}' to recreate the container stack.`,
      });
    }
  }

  // Without an app, also look at the server around PaaSMCP (DNS, Watchtower, Docker networks, tunnel).
  if (!appName) diagnostics.push(...checkHost());

  let overallHealth: "healthy" | "warning" | "critical" = "healthy";
  if (diagnostics.some((d) => d.severity === "critical")) {
    overallHealth = "critical";
  } else if (diagnostics.some((d) => d.severity === "warning")) {
    overallHealth = "warning";
  }

  return {
    checkedAt: new Date().toISOString(),
    overallHealth,
    diagnostics,
  };
}
