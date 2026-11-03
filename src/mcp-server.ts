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
  PAAS_BACKUPS_DIR,
  PAAS_DATA_DIR,
  sanitizeSlug,
  saveState,
  updatePlatformConfig,
  withStateLock,
} from "./config.js";
import {
  assessRisk,
  authorizeAgent,
  ConfirmationRequiredError,
  ForbiddenActionError,
  listApprovals,
} from "./guard.js";
import {
  backupDatabase,
  ensureDockerNetwork,
  ensureSharedPostgresCluster,
  ensureSharedRedisCluster,
  listDatabaseBackups,
  provisionDatabase,
  restoreDatabase,
} from "./database.js";
import { provisionEmail } from "./email.js";
import { setPolling } from "./poller.js";
import { applyUpdate, checkUpdates, Component, PINNED } from "./updater.js";
import { mirrorStatus, promoteMirror } from "./mirror.js";
import { provisionStorage } from "./storage.js";
import { backupAppVolumes, fetchOffsite, syncOffsite, testRestore } from "./backup.js";
import { ensureDashboardBackgroundService, getOrCreateDashboardToken } from "./dashboard.js";
import {
  AppLifecycleAction,
  deployApp,
  getContainerMetrics,
  manageAppLifecycle,
  runPaaSDoctor,
} from "./deployer.js";
import { exposeApplication } from "./exposure.js";
import {
  applyEncryptedFederationSyncBundle,
  buildEncryptedFederationSyncBundle,
  generateFederationJoinToken,
  getOrCreateWebhookSecret,
  parseAndVerifyFederationJoinToken,
  registerFederationPeer,
} from "./federation.js";
import { getOrCreateSshDeployKey, registerGitHubDeployKey } from "./github.js";
import { levelAllows, TokenLevel } from "./tokens.js";
import {
  deleteSecretKey,
  importDotEnvFile,
  listMaskedSecrets,
   maskSecretValue,
  setSecretEntries,
  setSecretFromFile,
} from "./vault.js";

export function getSystemStatusSummary(includeMetrics = true) {
  ensureDirectories();
  const state = loadState();
  const keyInfo = getOrCreateSshDeployKey();
  const sysSecrets = listMaskedSecrets("system");
  const containerMetrics = includeMetrics ? getContainerMetrics() : {};

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
    paasBackupsDir: PAAS_BACKUPS_DIR,
    sshPublicKey: keyInfo.publicKey,
    sshKeyFingerprint: keyInfo.fingerprint,
    systemSecretsConfigured: sysSecrets,
    webhookEndpointPath: "/api/webhooks/github",
    webhookSecretMasked: maskSecretValue(getOrCreateWebhookSecret()),
    tailscaleDomain: state.tailscaleDomain,
    cloudflare: state.cloudflare,
    federation: state.federation,
    appsCount: Object.keys(state.apps).length,
    databasesCount: Object.keys(state.databases).length,
    backupsCount: Object.keys(state.backups || {}).length,
    apps: state.apps,
    containerMetrics,
    databases: state.databases,
    backups: listDatabaseBackups(),
    storage: Object.values(state.storage || {}),
    mirror: state.mirror,
  };
}


// Tools that can trigger a confirmation accept the id of a request a person approved.
const APPROVAL_ID_PROPERTY = {
  type: "string",
  description:
    "Id of a confirmation request a person already approved (dashboard Approvals or `paasmcp approve <id>`). Only needed after a call answered 'Confirmation required'.",
};
const TOOLS_WITH_APPROVAL = new Set([
  "paas_dashboard",
  "paas_secret_delete",
  "paas_db_backup",
  "paas_mirror",
  "paas_update",
  "paas_app_deploy",
  "paas_app_expose",
  "paas_app_lifecycle",
  "paas_node_federation",
]);
// Read-only tools skip the state lock so they answer while a long deploy runs; they are all a "read" token sees.
const READ_ONLY_TOOLS = new Set(["paas_system_status", "paas_secret_list", "paas_doctor", "paas_approvals"]);

/**
 * One MCP server per connection. `level` comes from the caller: stdio runs on the server itself
 * ("destroy"), HTTP callers get the level of their personal token (tokens.ts).
 */
export function createMcpServer(level: TokenLevel = "destroy"): Server {
  const server = new Server(
    { name: "paasmcp-mcp", version: "1.2.0" },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => listToolsFor(level));
  server.setRequestHandler(CallToolRequestSchema, async (request) =>
    handleToolCall(request.params.name, request.params.arguments ?? {}, level)
  );
  return server;
}

async function listToolsFor(level: TokenLevel) {
  const listed = await listTools();
  return {
    tools: listed.tools
      .filter((tool) => level !== "read" || READ_ONLY_TOOLS.has(tool.name))
      .map((tool) =>
      TOOLS_WITH_APPROVAL.has(tool.name)
        ? {
            ...tool,
            inputSchema: {
              ...tool.inputSchema,
              properties: { ...tool.inputSchema.properties, approvalId: APPROVAL_ID_PROPERTY },
            },
          }
        : tool
      ),
  };
}

async function listTools() {
  return {
    tools: [
      {
        name: "paas_approvals",
        description:
          "Lists confirmation requests (pending, approved, used, rejected). Risky actions (destroy, purge, public exposure, restore, deleting secrets, trusted apps, federation) need a person to approve them in the dashboard or with `paasmcp approve <id>` on the server; agents cannot approve.",
        inputSchema: {
          type: "object",
          properties: {
            onlyPending: { type: "boolean", description: "Only pending requests (default: true)." },
          },
        },
      },
      {
        name: "paas_system_status",
        description:
          "Returns full status of PaaSMCP on the server: CPU/RAM/Disk, live container metrics (docker stats snapshot), configured system tokens (masked), SSH deploy public key, databases, encrypted backups, multi-node federation status, and deployed applications.",
        inputSchema: {
          type: "object",
          properties: {
            includeMetrics: {
              type: "boolean",
              description: "Include live docker stats CPU/RAM snapshot per container (default: true).",
            },
          },
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
          "Encrypts and stores environment variables / secrets in the AES-256-GCM Vault for a given app (or 'system' scope for CF_API_TOKEN / GITHUB_TOKEN). Supports direct key-value pairs, reading a single secret from a file path (out-of-band file delivery), or importing a .env file.",
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
        name: "paas_mirror",
        description:
          "Two-server mirror. 'status' shows, per peer, whether its Postgres copy is streaming, caught up and how many seconds behind, plus WAL kept for a peer that is away and the current epoch. 'promote' makes this server take over a peer's apps with its copy (manual failover): needs a person's strong confirmation, raises the epoch, redeploys the peer's apps here and points their DNS here. Pairing (offer/accept) is CLI-only because the token carries passwords.",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string", enum: ["status", "promote"] },
            peer: { type: "string", description: "Peer server name (required for promote)." },
          },
          required: ["action"],
        },
      },
      {
        name: "paas_email_provision",
        description:
          "Lets an app send email through the server's relay (Brevo, SES... set once by a person with 'paasmcp email set'). Injects SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SECURE, EMAIL_FROM, DEFAULT_FROM_EMAIL, EMAIL_URL (and BREVO_API_KEY when an HTTP API key is set) into the app's vault; sender is <app>@<domain>. Redeploy the app to load them.",
        inputSchema: {
          type: "object",
          properties: {
            appName: { type: "string", description: "Application slug." },
            fromName: { type: "string", description: "Optional display name for the sender, e.g. 'Guarapps'." },
          },
          required: ["appName"],
        },
      },
      {
        name: "paas_update",
        description:
          "Keeps the shared services (postgres, redis, garage) on pinned images. 'check' lists newer releases within the same major; 'apply' (needs a person's confirmation) backs up the databases, switches the image (mirror copies first), health-checks for 60 s and rolls back on failure. Major upgrades are refused.",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string", enum: ["check", "apply"] },
            component: { type: "string", enum: ["postgres", "redis", "garage"] },
            image: { type: "string", description: "Target image for apply (default: the newest found by check)." },
          },
          required: ["action"],
        },
      },
      {
        name: "paas_storage_provision",
        description:
          "Gives an app its own S3-compatible bucket on this server (Garage, started on first use) with a dedicated access key. Injects S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_REGION and the AWS_* equivalents into the app's vault (redeploy the app to load them). Idempotent: calling again returns the existing bucket.",
        inputSchema: {
          type: "object",
          properties: {
            appName: { type: "string", description: "Application slug that will own the bucket." },
          },
          required: ["appName"],
        },
      },
      {
        name: "paas_db_backup",
        description:
          "Encrypted (AES-256-GCM) backups of databases (pg_dump / Redis RDB) and app Docker volumes. 'create' a snapshot, 'list' them, 'restore' one (needs human confirmation; a safety backup is taken first), 'test' that a backup really restores (into a temporary database, live data untouched), 'sync' new backups off-site (S3/R2/B2, BACKUP_S3_* in the system vault) or 'fetch' one back from off-site.",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["create", "list", "restore", "test", "sync", "fetch"],
              description: "create | list | restore | test | sync | fetch (see tool description).",
            },
            appName: {
              type: "string",
              description: "Application slug (required when action='create', optional filter when action='list').",
            },
            engine: {
              type: "string",
              enum: ["postgres", "redis", "volume"],
              description: "What to back up on 'create' (default: postgres; 'volume' backs up every Docker volume of the app).",
            },
            backupId: {
              type: "string",
              description: "Backup ID (required for restore, test and fetch).",
            },
          },
          required: ["action"],
        },
      },
      {
        name: "paas_app_deploy",
        description:
          "Deploys an application from a GitHub repository ('owner/repo' or git URL) or local directory path. Supports single-container buildpacks (Node, Next.js, Python, Go, Static) and multi-service docker-compose.yml pass-through with automatic Vault injection, loopback security hardening, resource limits, and rollback image tagging. Zero-downtime blue/green: the new image first runs as a candidate container and must answer an HTTP healthcheck (status < 500) before it replaces the running one; if it fails, the running version is untouched and the error contains the candidate's logs.",
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
            memoryLimit: {
              type: "string",
              description: "Optional container memory limit (e.g., '512m', '1g').",
            },
            autoDeploy: {
              type: "string",
              enum: ["poll"],
              description: "'poll': redeploy automatically when the branch gets new commits (checked every 2 min by 'paasmcp poll install-timer'; no public webhook needed).",
            },
            cpuLimit: {
              type: "string",
              description: "Optional container CPU limit (e.g., '0.5', '1.0', '2').",
            },
            healthcheckPath: {
              type: "string",
              description:
                "Blue/green cutover: path probed on the new version before it replaces the running one (default '/'; any status below 500 passes). Remembered for later deploys.",
            },
            healthcheckTimeoutSeconds: {
              type: "number",
              description: "Seconds the new version has to answer the healthcheck (default 20, max 300). Remembered for later deploys.",
            },
            skipHealthcheck: {
              type: "boolean",
              description:
                "true = replace the container directly without a candidate/healthcheck (for apps that do not serve HTTP). Remembered; pass false to turn the healthcheck back on.",
            },
            env: {
              type: "object",
              additionalProperties: { type: "string" },
              description:
                "Optional environment variables to save in the app's Vault before starting.",
            },
            trusted: {
              type: "boolean",
              description:
                "true keeps host-access compose fields (privileged, host network, host folders, docker.sock): needs a strong confirmation by a person. false revokes it. Omit to keep the current setting.",
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
          "View container logs, restart, stop, start, rollback to the previous working image, or destroy a deployed application.",
        inputSchema: {
          type: "object",
          properties: {
            appName: {
              type: "string",
              description: "Application slug.",
            },
            action: {
              type: "string",
              enum: ["logs", "restart", "stop", "start", "rollback", "destroy", "restore", "purge"],
              description:
                "'destroy' stops the app and moves it to the trash for 30 days (needs confirmation); 'restore' brings it back; 'purge' deletes it for good (strong confirmation).",
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
      {
        name: "paas_doctor",
        description:
          "Runs automated diagnostics across deployed applications: detects OOMKilled containers, crash-loops, non-zero exit codes, resource pressure, and returns actionable remediation advice.",
        inputSchema: {
          type: "object",
          properties: {
            appName: {
              type: "string",
              description: "Optional application slug to inspect (inspects all apps if omitted).",
            },
          },
        },
      },
      {
        name: "paas_node_federation",
        description:
          "Manages Multi-Server High Availability (HA) Handshake and Redundancy: generates signed pairing Join Tokens ('paasmcp-join://...'), verifies peer handshakes, and exports/imports AES-256-GCM encrypted Vault & State sync bundles for active-active Cloudflare Tunnel or warm-standby server clusters.",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: [
                "status",
                "create-join-token",
                "join-cluster",
                "export-sync-bundle",
                "import-sync-bundle",
              ],
            },
            endpointUrl: {
              type: "string",
              description: "Primary node URL or Tailscale address when creating a join token or joining.",
            },
            mode: {
              type: "string",
              enum: ["active-active-tunnel", "warm-standby"],
              description: "Redundancy mode: 'active-active-tunnel' (Cloudflare Tunnel multi-connector) or 'warm-standby'.",
            },
            joinToken: {
              type: "string",
              description: "Signed 'paasmcp-join://...' token when action='join-cluster'.",
            },
            encryptedBase64: {
              type: "string",
              description: "Encrypted sync bundle payload when action='import-sync-bundle'.",
            },
            hmacSignature: {
              type: "string",
              description: "HMAC-SHA256 signature when action='import-sync-bundle'.",
            },
          },
          required: ["action"],
        },
      },
    ],
  };
}

export async function handleToolCall(name: string, args: Record<string, unknown>, level: TokenLevel) {
  try {
    if (!READ_ONLY_TOOLS.has(name) && !levelAllows(level, "deploy")) {
      throw new ForbiddenActionError(`This token has level '${level}' and can only use read-only tools.`);
    }
    return READ_ONLY_TOOLS.has(name)
      ? await callTool(name, args, level)
      : await withStateLock(() => callTool(name, args, level));
  } catch (err) {
    if (err instanceof ConfirmationRequiredError) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                confirmationRequired: true,
                approvalId: err.approvalId,
                level: err.risk.level,
                warning: err.risk.warning,
                nextStep: err.message,
              },
              null,
              2
            ),
          },
        ],
      };
    }
    const message = err instanceof Error ? err.message : String(err);
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `${err instanceof ForbiddenActionError ? "Forbidden" : "Error executing"} ${name}: ${message}`,
        },
      ],
    };
  }
}

async function callTool(name: string, args: Record<string, unknown>, level: TokenLevel) {
  const approvalId = args.approvalId ? String(args.approvalId) : undefined;
  // Risky actions need a "destroy" token, and then still a person's approval.
  const authorize = (action: string, params: Record<string, unknown>) => {
    if (assessRisk(action, params) && !levelAllows(level, "destroy")) {
      throw new ForbiddenActionError(
        `'${action}' needs a token with level 'destroy' (this one is '${level}'), and then a person's approval.`
      );
    }
    authorizeAgent(action, params, approvalId);
  };
  {
    switch (name) {
      case "paas_approvals": {
        const approvals = listApprovals(args.onlyPending !== false);
        return {
          content: [{ type: "text", text: JSON.stringify({ approvals }, null, 2) }],
        };
      }

      case "paas_system_status": {
        const includeMetrics = args.includeMetrics !== false;
        const status = getSystemStatusSummary(includeMetrics);
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
                  sshKeyFingerprint: keyInfo.fingerprint,
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
        if (args.exposeMode) {
          authorize("app.expose", { appName: "paasmcp-dashboard", mode: String(args.exposeMode) });
        }
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
                  fingerprint: keyInfo.fingerprint,
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
        authorize("secret.delete", { scope, keyName });
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

      case "paas_mirror": {
        if (args.action === "promote") {
          if (!args.peer) throw new Error("'peer' is required for promote.");
          authorize("mirror.promote", { peer: String(args.peer) });
          return { content: [{ type: "text", text: JSON.stringify(await promoteMirror(String(args.peer)), null, 2) }] };
        }
        return { content: [{ type: "text", text: JSON.stringify(mirrorStatus(), null, 2) }] };
      }

      case "paas_email_provision": {
        const result = provisionEmail(String(args.appName), args.fromName ? String(args.fromName) : undefined);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "paas_update": {
        if (args.action === "apply") {
          const component = String(args.component) as Component;
          if (!PINNED[component]) throw new Error("'component' must be postgres, redis or garage.");
          const image = args.image ? String(args.image) : (await checkUpdates()).find((u) => u.component === component)?.available;
          if (!image) throw new Error(`${component} is already on the newest release of its major version.`);
          authorize("update.apply", { component, image });
          return { content: [{ type: "text", text: JSON.stringify(applyUpdate(component, image), null, 2) }] };
        }
        return { content: [{ type: "text", text: JSON.stringify(await checkUpdates(), null, 2) }] };
      }

      case "paas_storage_provision": {
        const result = await provisionStorage(String(args.appName));
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "paas_db_backup": {
        const action = String(args.action || "list");
        if (action === "list") {
          const backups = listDatabaseBackups(
            args.appName ? String(args.appName) : undefined
          );
          return {
            content: [{ type: "text", text: JSON.stringify({ backups }, null, 2) }],
          };
        }
        if (action === "create") {
          if (!args.appName) {
            throw new Error("'appName' is required when action='create'.");
          }
          const engine = (args.engine as "postgres" | "redis" | "volume") || "postgres";
          const record =
            engine === "volume" ? backupAppVolumes(String(args.appName)) : backupDatabase(String(args.appName), engine);
          return {
            content: [{ type: "text", text: JSON.stringify(record, null, 2) }],
          };
        }
        if (action === "restore") {
          if (!args.backupId) {
            throw new Error("'backupId' is required when action='restore'.");
          }
          authorize("db.restore", { backupId: String(args.backupId) });
          const result = restoreDatabase(String(args.backupId));
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }
        if (action === "sync") {
          return { content: [{ type: "text", text: JSON.stringify(await syncOffsite(), null, 2) }] };
        }
        if (action === "test" || action === "fetch") {
          if (!args.backupId) throw new Error(`'backupId' is required when action='${action}'.`);
          const result = action === "test" ? testRestore(String(args.backupId)) : await fetchOffsite(String(args.backupId));
          return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }
        throw new Error(`Unsupported paas_db_backup action: ${action}`);
      }

      case "paas_app_deploy": {
        const trusted = typeof args.trusted === "boolean" ? args.trusted : undefined;
        if (trusted && !loadState().apps[sanitizeSlug(String(args.appName))]?.trusted) {
          authorize("app.trust", { appName: sanitizeSlug(String(args.appName)) });
        }
        const result = await deployApp({
          trusted,
          healthcheckPath: args.healthcheckPath ? String(args.healthcheckPath) : undefined,
          healthcheckTimeoutSeconds: args.healthcheckTimeoutSeconds ? Number(args.healthcheckTimeoutSeconds) : undefined,
          skipHealthcheck: typeof args.skipHealthcheck === "boolean" ? args.skipHealthcheck : undefined,
          appName: String(args.appName),
          repoSource: String(args.repoSource),
          branch: args.branch ? String(args.branch) : "main",
          internalPort: args.internalPort ? Number(args.internalPort) : undefined,
          withPostgres: Boolean(args.withPostgres),
          withRedis: Boolean(args.withRedis),
          memoryLimit: args.memoryLimit ? String(args.memoryLimit) : undefined,
          cpuLimit: args.cpuLimit ? String(args.cpuLimit) : undefined,
          env: (args.env as Record<string, string>) || undefined,
        });
        if (args.autoDeploy === "poll") setPolling(String(args.appName), true);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      case "paas_app_expose": {
        authorize("app.expose", { appName: String(args.appName), mode: String(args.mode) });
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
        const action = args.action as AppLifecycleAction;
        if (action === "destroy" || action === "purge") {
          authorize(`app.${action}`, { appName: String(args.appName) });
        }
        const output = manageAppLifecycle(
          String(args.appName),
          action,
          args.tailLines ? Number(args.tailLines) : 80
        );
        return {
          content: [{ type: "text", text: output }],
        };
      }

      case "paas_doctor": {
        const report = runPaaSDoctor(
          args.appName ? String(args.appName) : undefined
        );
        return {
          content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
        };
      }

      case "paas_node_federation": {
        const action = String(args.action);
        const state = loadState();
        if (action === "status") {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(state.federation || {}, null, 2),
              },
            ],
          };
        }
        if (action === "create-join-token") {
          authorize("federation.invite", { peer: "join-token" });
          const endpointUrl = String(args.endpointUrl || "https://paas.example.com");
          const mode =
            (args.mode as "active-active-tunnel" | "warm-standby") ||
            "active-active-tunnel";
          const tokenInfo = generateFederationJoinToken({
            endpointUrl,
            mode,
          });
          return {
            content: [{ type: "text", text: JSON.stringify(tokenInfo, null, 2) }],
          };
        }
        if (action === "join-cluster") {
          if (!args.joinToken) {
            throw new Error("'joinToken' is required when action='join-cluster'.");
          }
          const verified = parseAndVerifyFederationJoinToken(String(args.joinToken));
          authorize("federation.join", { peer: verified.primaryName, joinToken: String(args.joinToken) });
          setSecretEntries("system", {
            FEDERATION_CLUSTER_KEY: verified.clusterKeyHex,
          });
          const peer = registerFederationPeer({
            nodeId: verified.primaryNodeId,
            name: verified.primaryName,
            endpointUrl: verified.endpointUrl,
            mode: verified.mode,
            publicKeyFingerprint: verified.fingerprint,
          });
          const latest = loadState();
          if (latest.federation) {
            latest.federation.role = "replica";
            latest.federation.redundancyMode = verified.mode;
            saveState(latest);
          }
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    joined: true,
                    role: "replica",
                    redundancyMode: verified.mode,
                    primaryPeer: peer,
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }
        if (action === "export-sync-bundle") {
          const bundle = buildEncryptedFederationSyncBundle();
          return {
            content: [{ type: "text", text: JSON.stringify(bundle, null, 2) }],
          };
        }
        if (action === "import-sync-bundle") {
          if (!args.encryptedBase64 || !args.hmacSignature) {
            throw new Error(
              "'encryptedBase64' and 'hmacSignature' are required when action='import-sync-bundle'."
            );
          }
          authorize("federation.import", { peer: "sync-bundle", hmacSignature: String(args.hmacSignature) });
          const imported = applyEncryptedFederationSyncBundle(
            String(args.encryptedBase64),
            String(args.hmacSignature)
          );
          return {
            content: [{ type: "text", text: JSON.stringify(imported, null, 2) }],
          };
        }
        throw new Error(`Unsupported paas_node_federation action: ${action}`);
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
}

async function main() {
  const transport = new StdioServerTransport();
  await createMcpServer("destroy").connect(transport);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("Fatal error in paasmcp-mcp:", err);
    process.exit(1);
  });
}
