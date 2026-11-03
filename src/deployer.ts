import { execFileSync } from "node:child_process";
import fs from "node:fs";
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
} from "./config.js";
import { ensureDockerNetwork, provisionDatabase } from "./database.js";
import { cloneOrUpdateRepo, DetectedBuildPlan, detectOrGenerateDockerfile } from "./github.js";
import { setSecretEntries, writeRuntimeEnvFile } from "./vault.js";

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
}): { yaml: string; findings: string[] } {
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
    if (cleanSvc.network_mode === undefined) cleanSvc.networks = [DOCKER_NETWORK];

    if (opts.memoryLimit) cleanSvc.mem_limit = opts.memoryLimit;
    if (opts.cpuLimit) cleanSvc.cpus = Number(opts.cpuLimit);

    // Loopback-only port enforcement: only primary service gets 127.0.0.1:<localPort>:<internalPort>
    if (svcName === opts.primaryServiceName) {
      cleanSvc.container_name = opts.containerName;
      cleanSvc.ports = [`127.0.0.1:${opts.localPort}:${opts.internalPort}`];
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

  return { yaml: YAML.stringify(outputCompose), findings };
}

export function deployApp(opts: DeployOptions): {
  app: AppRecord;
  commitHash: string;
  provisionedDatabases: string[];
  previousImageSaved: boolean;
  removedForSafety?: string[];
  hostAccessKept?: string[];
  hint?: string;
} {
  ensureDockerNetwork();
  const slug = sanitizeSlug(opts.appName);
  const branch = validateBranchName(opts.branch || "main");
  const memoryLimit = validateResourceLimit(opts.memoryLimit, "memory");
  const cpuLimit = validateResourceLimit(opts.cpuLimit, "cpu");
  const state = loadState();
  if (state.apps[slug]?.trashedAt) {
    throw new Error(`App '${slug}' is in the trash. Restore it (action 'restore') or purge it before deploying again.`);
  }
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

  const { commitHash } = cloneOrUpdateRepo(opts.repoSource, repoDir, branch);
  const buildPlan: DetectedBuildPlan = detectOrGenerateDockerfile(repoDir, opts.internalPort);
  const internalPort = opts.internalPort || buildPlan.detectedPort;

  const runtimeEnvPath = path.join(appDir, ".env.runtime");
  writeRuntimeEnvFile(slug, runtimeEnvPath, {
    PORT: String(internalPort),
    NODE_ENV: "production",
  });

  // Preserve current image as :previous for 1-second rollback if it exists
  let previousImageSaved = false;
  const currentImg = `paasmcp/${slug}:latest`;
  const prevImg = `paasmcp/${slug}:previous`;
  try {
    execFileSync("docker", ["image", "inspect", currentImg], { stdio: "ignore" });
    execFileSync("docker", ["tag", currentImg, prevImg], { stdio: "ignore" });
    previousImageSaved = true;
  } catch {
    // First deploy or image not present yet
  }

  const composePath = path.join(appDir, "compose.yaml");
  const isComposePassThrough = Boolean(buildPlan.composeFile);
  let composeFindings: string[] = [];

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
    });
    composeFindings = sanitized.findings;
    fs.writeFileSync(composePath, sanitized.yaml, { mode: 0o600 });
  } else {
    const memLine = memoryLimit ? `    mem_limit: ${memoryLimit}\n` : "";
    const cpuLine = cpuLimit ? `    cpus: ${cpuLimit}\n` : "";
    const composeContent = `services:
  app:
    build:
      context: ./repo
      dockerfile: ${buildPlan.dockerfilePath}
    image: ${currentImg}
    container_name: ${containerName}
    restart: unless-stopped
${memLine}${cpuLine}    env_file:
      - .env.runtime
    ports:
      - "127.0.0.1:${localPort}:${internalPort}"
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`;
    fs.writeFileSync(composePath, composeContent, { mode: 0o600 });
  }

  execFileSync(
    "docker",
    ["compose", "-f", composePath, "up", "-d", "--build", "--remove-orphans"],
    {
      cwd: appDir,
      stdio: "pipe",
    }
  );

  const latestState = loadState();
  const existing = latestState.apps[slug];
  const now = new Date().toISOString();

  const dbList = Array.from(
    new Set([...(existing?.databases || []), ...provisionedDatabases])
  );

  const record: AppRecord = {
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
    previousImageTag: previousImageSaved ? prevImg : existing?.previousImageTag,
    composePassThrough: isComposePassThrough,
    memoryLimit: memoryLimit || existing?.memoryLimit,
    cpuLimit: cpuLimit || existing?.cpuLimit,
    trusted,
  };

  latestState.apps[slug] = record;
  saveState(latestState);
  syncHomepageDashboard();

  return {
    app: record,
    commitHash,
    provisionedDatabases,
    previousImageSaved,
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
