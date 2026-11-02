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

export function generateSanitizedComposeFromRepo(opts: {
  repoComposePath: string;
  slug: string;
  containerName: string;
  localPort: number;
  internalPort: number;
  primaryServiceName: string;
  memoryLimit?: string;
  cpuLimit?: string;
}): string {
  const raw = fs.readFileSync(opts.repoComposePath, "utf-8");
  const parsed = YAML.parse(raw) as {
    services?: Record<string, Record<string, unknown>>;
    volumes?: Record<string, unknown>;
  };

  if (!parsed || !parsed.services || typeof parsed.services !== "object") {
    throw new Error("Invalid docker-compose file: missing 'services' root object.");
  }

  const safeServices: Record<string, Record<string, unknown>> = {};
  for (const [svcName, svcDef] of Object.entries(parsed.services)) {
    const cleanSvc: Record<string, unknown> = { ...svcDef };

    // Security hardening: strip privileged/host-escape directives from untrusted compose files
    delete cleanSvc.privileged;
    delete cleanSvc.network_mode;
    delete cleanSvc.pid;
    delete cleanSvc.ipc;
    delete cleanSvc.userns_mode;
    delete cleanSvc.cap_add;
    delete cleanSvc.devices;
    delete cleanSvc.security_opt;

    // Rewrite build context to point inside ./repo
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
      cleanSvc.build = bObj;
    }

    // Sanitize volumes: block host bind mounts (starting with / or ..)
    if (Array.isArray(cleanSvc.volumes)) {
      cleanSvc.volumes = cleanSvc.volumes.filter((v) => {
        const volStr = typeof v === "string" ? v : "";
        const source = volStr.split(":")[0] || "";
        if (source.startsWith("/") || source.includes("..")) {
          return false;
        }
        return true;
      });
    }

    // Inject encrypted Vault runtime environment and homelab-network into every service
    cleanSvc.env_file = [".env.runtime"];
    cleanSvc.restart = "unless-stopped";
    cleanSvc.networks = [DOCKER_NETWORK];

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
    outputCompose.volumes = parsed.volumes;
  }

  return YAML.stringify(outputCompose);
}

export function deployApp(opts: DeployOptions): {
  app: AppRecord;
  commitHash: string;
  provisionedDatabases: string[];
  previousImageSaved: boolean;
} {
  ensureDockerNetwork();
  const slug = sanitizeSlug(opts.appName);
  const branch = validateBranchName(opts.branch || "main");
  const memoryLimit = validateResourceLimit(opts.memoryLimit, "memory");
  const cpuLimit = validateResourceLimit(opts.cpuLimit, "cpu");
  const state = loadState();
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

  if (isComposePassThrough && buildPlan.composeFile && buildPlan.primaryServiceName) {
    const repoComposePath = path.join(repoDir, buildPlan.composeFile);
    const composeContent = generateSanitizedComposeFromRepo({
      repoComposePath,
      slug,
      containerName,
      localPort,
      internalPort,
      primaryServiceName: buildPlan.primaryServiceName,
      memoryLimit,
      cpuLimit,
    });
    fs.writeFileSync(composePath, composeContent, { mode: 0o600 });
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
  };

  latestState.apps[slug] = record;
  saveState(latestState);
  syncHomepageDashboard();

  return { app: record, commitHash, provisionedDatabases, previousImageSaved };
}

export function manageAppLifecycle(
  appName: string,
  action: "logs" | "restart" | "stop" | "start" | "destroy" | "rollback",
  tailLines = 80
): string {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) {
    throw new Error(`App '${slug}' is not registered in PaaSMCP.`);
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
    try {
      execFileSync("docker", ["compose", "-f", composePath, "down", "-v", "--rmi", "local"], {
        cwd: app.appDir,
        stdio: "pipe",
      });
    } catch {
      // ignore if already stopped
    }
    const resolvedDir = path.resolve(app.appDir);
    const allowedAppsRoot = path.resolve(PAAS_APPS_DIR);
    if (resolvedDir.startsWith(allowedAppsRoot + path.sep)) {
      fs.rmSync(resolvedDir, { recursive: true, force: true });
    }
    delete state.apps[slug];
    saveState(state);
    syncHomepageDashboard();
    return `App '${slug}' and its containers/files in ${app.appDir} were destroyed.`;
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
