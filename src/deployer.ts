import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import {
  allocateAppPort,
  AppRecord,
  DOCKER_NETWORK,
  HOMEPAGE_SERVICES_YAML,
  loadState,
  PAAS_APPS_DIR,
  sanitizeSlug,
  saveState,
} from "./config.js";
import { ensureDockerNetwork, provisionDatabase } from "./database.js";
import { cloneOrUpdateRepo, detectOrGenerateDockerfile } from "./github.js";
import { setSecretEntries, writeRuntimeEnvFile } from "./vault.js";

export interface DeployOptions {
  appName: string;
  repoSource: string;
  branch?: string;
  internalPort?: number;
  withPostgres?: boolean;
  withRedis?: boolean;
  env?: Record<string, string>;
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

export function deployApp(opts: DeployOptions): {
  app: AppRecord;
  commitHash: string;
  provisionedDatabases: string[];
} {
  ensureDockerNetwork();
  const slug = sanitizeSlug(opts.appName);
  const branch = opts.branch || "main";
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
  const buildPlan = detectOrGenerateDockerfile(repoDir, opts.internalPort);
  const internalPort = opts.internalPort || buildPlan.detectedPort;

  const runtimeEnvPath = path.join(appDir, ".env.runtime");
  writeRuntimeEnvFile(slug, runtimeEnvPath, {
    PORT: String(internalPort),
    NODE_ENV: "production",
  });

  const composePath = path.join(appDir, "compose.yaml");
  const composeContent = `services:
  app:
    build:
      context: ./repo
      dockerfile: ${buildPlan.dockerfilePath}
    image: paasmcp/${slug}:latest
    container_name: ${containerName}
    restart: unless-stopped
    env_file:
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

  execFileSync(
    "docker",
    ["compose", "-f", composePath, "up", "-d", "--build", "--remove-orphans"],
    {
      cwd: appDir,
      stdio: "pipe",
    }
  );

  // Reload state in case provisionDatabase updated it
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
  };

  latestState.apps[slug] = record;
  saveState(latestState);
  syncHomepageDashboard();

  return { app: record, commitHash, provisionedDatabases };
}

export function manageAppLifecycle(
  appName: string,
  action: "logs" | "restart" | "stop" | "start" | "destroy",
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
    return execFileSync(
      "docker",
      ["logs", "--tail", String(tailLines), app.containerName],
      { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }
    );
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
    fs.rmSync(app.appDir, { recursive: true, force: true });
    delete state.apps[slug];
    saveState(state);
    syncHomepageDashboard();
    return `App '${slug}' and its containers/files in ${app.appDir} were destroyed.`;
  }

  throw new Error(`Unsupported action: ${action}`);
}
