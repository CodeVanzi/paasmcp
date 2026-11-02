#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import os from "node:os";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  ensureDirectories,
  loadState,
  PAAS_APPS_DIR,
  PAAS_DATA_DIR,
  updatePlatformConfig,
} from "./config.js";
import {
  ensureDockerNetwork,
  ensureSharedPostgresCluster,
  ensureSharedRedisCluster,
  provisionDatabase,
} from "./database.js";
import { ensureDashboardBackgroundService, getOrCreateDashboardToken } from "./dashboard.js";
import { deployApp, manageAppLifecycle } from "./deployer.js";
import { exposeApplication } from "./exposure.js";
import { getOrCreateSshDeployKey, registerGitHubDeployKey } from "./github.js";
import {
  deleteSecretKey,
  importDotEnvFile,
  listMaskedSecrets,
  setSecretEntries,
  setSecretFromFile,
} from "./vault.js";

export function getSystemStatusSummary() {
  ensureDirectories();
  const state = loadState();
  const keyInfo = getOrCreateSshDeployKey();
  const sysSecrets = listMaskedSecrets("system");

  let diskFree = "unknown";
  try {
    diskFree =
      execFileSync("df", ["-h", "/"], { encoding: "utf-8" })
        .trim()
        .split("\n")
        .pop() || "unknown";
  } catch {
    // ignore
  }

  return {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()} (${os.arch()})`,
    cpus: os.cpus().length,
    totalMemGb: +(os.totalmem() / 1024 ** 3).toFixed(2),
    freeMemGb: +(os.freemem() / 1024 ** 3).toFixed(2),
    rootDisk: diskFree,
    paasDataDir: PAAS_DATA_DIR,
    paasAppsDir: PAAS_APPS_DIR,
    sshPublicKey: keyInfo.publicKey,
    systemSecretsConfigured: sysSecrets,
    tailscaleDomain: state.tailscaleDomain,
    cloudflare: state.cloudflare,
    appsCount: Object.keys(state.apps).length,
    databasesCount: Object.keys(state.databases).length,
    apps: state.apps,
    databases: state.databases,
  };
}

const server = new Server(
  {
    name: "paasmcp-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "paas_system_status",
        description:
          "Returns full status of PaaSMCP on the server: CPU/RAM/Disk, configured system tokens (masked), SSH deploy public key, provisioned databases, and deployed applications.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "paas_bootstrap",
        description:
          "Initializes PaaSMCP directories (/opt/homelab/paasmcp), AES-256-GCM master key, SSH deploy key, Docker network (homelab-network), and optionally starts the shared PostgreSQL 16 and Redis 7 clusters.",
        inputSchema: {
          type: "object",
          properties: {
            startPostgres: {
              type: "boolean",
              description: "Start the shared PostgreSQL 16 container cluster immediately.",
            },
            startRedis: {
              type: "boolean",
              description: "Start the shared Redis 7 container cluster immediately.",
            },
          },
        },
      },
      {
        name: "paas_configure",
        description:
          "Updates platform-level settings such as Cloudflare Account ID, Tunnel ID, Base Domain, Zero Trust allowed emails, and Tailscale hostname.",
        inputSchema: {
          type: "object",
          properties: {
            accountId: { type: "string", description: "Cloudflare Account ID" },
            tunnelId: { type: "string", description: "Cloudflare Tunnel UUID" },
            baseDomain: { type: "string", description: "Base domain (e.g. example.com)" },
            zeroTrustEmails: {
              type: "array",
              items: { type: "string" },
              description: "Allowed email addresses for Cloudflare Zero Trust OTP policies",
            },
            tailscaleDomain: {
              type: "string",
              description: "Optional Tailscale MagicDNS hostname override",
            },
          },
        },
      },
      {
        name: "paas_dashboard",
        description:
          "Starts the built-in PaaSMCP Web Control Plane Dashboard container (on 127.0.0.1:4099) and optionally exposes it on a subdomain via Cloudflare Tunnel (recommended with mode=\"zero-trust\") or Tailscale Serve.",
        inputSchema: {
          type: "object",
          properties: {
            port: {
              type: "number",
              description: "Local port for the dashboard (default: 4099).",
            },
            exposeMode: {
              type: "string",
              enum: ["public", "zero-trust", "tailscale"],
              description: "Optional exposure mode to publish the dashboard.",
            },
            subdomain: {
              type: "string",
              description: "Subdomain for the dashboard (default: \"paas\").",
            },
          },
        },
      },
      {
        name: "paas_github_key",
        description:
          "Returns the PaaSMCP SSH Ed25519 public deploy key for GitHub, and optionally registers it automatically on a target GitHub repository if GITHUB_TOKEN is configured in the 'system' vault.",
        inputSchema: {
          type: "object",
          properties: {
            repoFullName: {
              type: "string",
              description:
                "Optional GitHub repo in 'owner/repo' format to auto-register the deploy key.",
            },
          },
        },
      },
      {
        name: "paas_secret_set",
        description:
          "Encrypts and stores environment variables / secrets in the AES-256-GCM Vault for a given app (or 'system' scope for CF_API_TOKEN / GITHUB_TOKEN). Supports direct key-value pairs, reading a single secret from a file path (compatible with T3 request_secret file delivery), or importing a .env file.",
        inputSchema: {
          type: "object",
          properties: {
            scope: {
              type: "string",
              description: "Application slug or 'system' for platform tokens.",
            },
            secrets: {
              type: "object",
              additionalProperties: { type: "string" },
              description: "Key-value map of environment variables to encrypt and store.",
            },
            secretFromFile: {
              type: "object",
              properties: {
                keyName: { type: "string" },
                filePath: { type: "string" },
                deleteAfterRead: { type: "boolean" },
              },
              required: ["keyName", "filePath"],
              description:
                "Read a single secret value from a file on disk without exposing it in chat.",
            },
            dotEnvFilePath: {
              type: "string",
              description: "Optional path to a .env file to import into the encrypted vault.",
            },
          },
          required: ["scope"],
        },
      },
      {
        name: "paas_secret_list",
        description:
          "Lists all environment variable keys stored in the encrypted Vault for an app or 'system' with masked values.",
        inputSchema: {
          type: "object",
          properties: {
            scope: {
              type: "string",
              description: "Application slug or 'system'.",
            },
          },
          required: ["scope"],
        },
      },
      {
        name: "paas_secret_delete",
        description: "Removes a secret key from an app's encrypted Vault.",
        inputSchema: {
          type: "object",
          properties: {
            scope: { type: "string" },
            keyName: { type: "string" },
          },
          required: ["scope", "keyName"],
        },
      },
      {
        name: "paas_db_provision",
        description:
          "Provisions an isolated PostgreSQL database or Redis instance for an application and automatically injects DATABASE_URL / REDIS_URL into the application's encrypted Vault.",
        inputSchema: {
          type: "object",
          properties: {
            appName: {
              type: "string",
              description: "Application name/slug that will own this database.",
            },
            engine: {
              type: "string",
              enum: ["postgres", "redis"],
              description: "Database engine to provision (default: postgres).",
            },
          },
          required: ["appName"],
        },
      },
      {
        name: "paas_app_deploy",
        description:
          "Deploys an application from a GitHub repository ('owner/repo' or git URL) or local directory path. Automatically detects the stack (or uses Dockerfile), injects encrypted secrets and database URLs, binds to an isolated 127.0.0.1 port + homelab-network, and updates the Homelab Homepage dashboard.",
        inputSchema: {
          type: "object",
          properties: {
            appName: {
              type: "string",
              description: "Application slug (e.g., 'meu-saas').",
            },
            repoSource: {
              type: "string",
              description:
                "GitHub 'owner/repo', SSH/HTTPS git URL, or absolute local directory path.",
            },
            branch: {
              type: "string",
              description: "Git branch to deploy (default: 'main').",
            },
            internalPort: {
              type: "number",
              description:
                "Optional container listening port override (auto-detected if omitted).",
            },
            withPostgres: {
              type: "boolean",
              description:
                "Automatically provision and link a PostgreSQL database before deploying.",
            },
            withRedis: {
              type: "boolean",
              description:
                "Automatically provision and link a Redis database before deploying.",
            },
            env: {
              type: "object",
              additionalProperties: { type: "string" },
              description:
                "Optional environment variables to save in the app's Vault before starting.",
            },
          },
          required: ["appName", "repoSource"],
        },
      },
      {
        name: "paas_app_expose",
        description:
          "Exposes a deployed application to the internet via Cloudflare Tunnel ('public' or 'zero-trust' protection) or privately via Tailscale Serve.",
        inputSchema: {
          type: "object",
          properties: {
            appName: {
              type: "string",
              description: "Application slug.",
            },
            subdomain: {
              type: "string",
              description: "Subdomain under configured baseDomain (defaults to appName).",
            },
            mode: {
              type: "string",
              enum: ["public", "zero-trust", "tailscale"],
              description:
                "'public' = open on the internet via Cloudflare Tunnel; 'zero-trust' = protected by Cloudflare Access OTP login; 'tailscale' = private HTTPS on Tailnet.",
            },
          },
          required: ["appName", "mode"],
        },
      },
      {
        name: "paas_app_lifecycle",
        description:
          "View container logs, restart, stop, start, or destroy a deployed application.",
        inputSchema: {
          type: "object",
          properties: {
            appName: {
              type: "string",
              description: "Application slug.",
            },
            action: {
              type: "string",
              enum: ["logs", "restart", "stop", "start", "destroy"],
            },
            tailLines: {
              type: "number",
              description:
                "Number of log lines to fetch when action='logs' (default: 80).",
            },
          },
          required: ["appName", "action"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    switch (name) {
      case "paas_system_status": {
        const status = getSystemStatusSummary();
        return {
          content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
        };
      }

      case "paas_bootstrap": {
        ensureDirectories();
        ensureDockerNetwork();
        const keyInfo = getOrCreateSshDeployKey();
        const servicesStarted: string[] = [];
        if (args.startPostgres) {
          ensureSharedPostgresCluster();
          servicesStarted.push("paasmcp-postgres (127.0.0.1:5432)");
        }
        if (args.startRedis) {
          ensureSharedRedisCluster();
          servicesStarted.push("paasmcp-redis (127.0.0.1:6379)");
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  bootstrapped: true,
                  paasDataDir: PAAS_DATA_DIR,
                  dockerNetwork: "homelab-network",
                  sshPublicKey: keyInfo.publicKey,
                  servicesStarted,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "paas_configure": {
        const updated = updatePlatformConfig({
          accountId: args.accountId ? String(args.accountId) : undefined,
          tunnelId: args.tunnelId ? String(args.tunnelId) : undefined,
          baseDomain: args.baseDomain ? String(args.baseDomain) : undefined,
          zeroTrustEmails: Array.isArray(args.zeroTrustEmails)
            ? args.zeroTrustEmails.map(String)
            : undefined,
          tailscaleDomain: args.tailscaleDomain
            ? String(args.tailscaleDomain)
            : undefined,
        });
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  tailscaleDomain: updated.tailscaleDomain,
                  cloudflare: updated.cloudflare,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "paas_dashboard": {
        const port = args.port ? Number(args.port) : 4099;
        const info = ensureDashboardBackgroundService(port);
        let exposure: unknown = undefined;
        if (args.exposeMode) {
          exposure = await exposeApplication({
            appName: "paasmcp-dashboard",
            mode: args.exposeMode as "public" | "zero-trust" | "tailscale",
            subdomain: args.subdomain ? String(args.subdomain) : "paas",
          });
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...info,
                  tokenConfiguredInSystemVault: Boolean(getOrCreateDashboardToken()),
                  exposure,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "paas_github_key": {
        const repoFullName = args.repoFullName as string | undefined;
        if (repoFullName) {
          const result = await registerGitHubDeployKey(repoFullName);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }
        const keyInfo = getOrCreateSshDeployKey();
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  publicKey: keyInfo.publicKey,
                  publicKeyPath: keyInfo.publicKeyPath,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "paas_secret_set": {
        const scope = String(args.scope);
        const updatedKeys: string[] = [];
        if (args.secrets && typeof args.secrets === "object") {
          updatedKeys.push(
            ...setSecretEntries(scope, args.secrets as Record<string, string>)
          );
        }
        if (args.secretFromFile && typeof args.secretFromFile === "object") {
          const sff = args.secretFromFile as {
            keyName: string;
            filePath: string;
            deleteAfterRead?: boolean;
          };
          setSecretFromFile(
            scope,
            sff.keyName,
            sff.filePath,
            Boolean(sff.deleteAfterRead)
          );
          updatedKeys.push(sff.keyName);
        }
        if (typeof args.dotEnvFilePath === "string") {
          updatedKeys.push(...importDotEnvFile(scope, args.dotEnvFilePath));
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  scope,
                  updatedKeys,
                  maskedSecrets: listMaskedSecrets(scope),
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "paas_secret_list": {
        const scope = String(args.scope);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  scope,
                  secrets: listMaskedSecrets(scope),
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "paas_secret_delete": {
        const scope = String(args.scope);
        const keyName = String(args.keyName);
        const deleted = deleteSecretKey(scope, keyName);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ scope, keyName, deleted }, null, 2),
            },
          ],
        };
      }

      case "paas_db_provision": {
        const appName = String(args.appName);
        const engine = (args.engine as "postgres" | "redis") || "postgres";
        const result = provisionDatabase(appName, engine);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "paas_app_deploy": {
        const result = deployApp({
          appName: String(args.appName),
          repoSource: String(args.repoSource),
          branch: args.branch ? String(args.branch) : "main",
          internalPort: args.internalPort ? Number(args.internalPort) : undefined,
          withPostgres: Boolean(args.withPostgres),
          withRedis: Boolean(args.withRedis),
          env: (args.env as Record<string, string>) || undefined,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "paas_app_expose": {
        const result = await exposeApplication({
          appName: String(args.appName),
          subdomain: args.subdomain ? String(args.subdomain) : undefined,
          mode: args.mode as "public" | "zero-trust" | "tailscale",
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "paas_app_lifecycle": {
        const output = manageAppLifecycle(
          String(args.appName),
          args.action as "logs" | "restart" | "stop" | "start" | "destroy",
          args.tailLines ? Number(args.tailLines) : 80
        );
        return {
          content: [{ type: "text", text: output }],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      isError: true,
      content: [{ type: "text", text: `Error executing ${name}: ${message}` }],
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("Fatal error in paasmcp-mcp:", err);
    process.exit(1);
  });
}
