#!/usr/bin/env node
import readline from "node:readline/promises";
import {
  ensureDirectories,
  loadState,
  sanitizeSlug,
  saveState,
  updatePlatformConfig,
  withStateLock,
} from "./config.js";
import { assessRisk, authorizeHuman, decideApproval, listApprovals } from "./guard.js";
import {
  ensureDashboardBackgroundService,
  getOrCreateDashboardToken,
  startDashboardServer,
} from "./dashboard.js";
import {
  backupDatabase,
  ensureDockerNetwork,
  ensureSharedPostgresCluster,
  ensureSharedRedisCluster,
  listDatabaseBackups,
  provisionDatabase,
  restoreDatabase,
} from "./database.js";
import {
  AppLifecycleAction,
  deployApp,
  manageAppLifecycle,
  purgeExpiredTrash,
  runPaaSDoctor,
} from "./deployer.js";
import { exposeApplication } from "./exposure.js";
import {
  applyEncryptedFederationSyncBundle,
  buildEncryptedFederationSyncBundle,
  generateFederationJoinToken,
  parseAndVerifyFederationJoinToken,
  registerFederationPeer,
} from "./federation.js";
import { getOrCreateSshDeployKey, registerGitHubDeployKey } from "./github.js";
import { startMcpHttpServer } from "./mcp-http.js";
import { getSystemStatusSummary } from "./mcp-server.js";
import { createToken, listTokens, revokeToken, TokenLevel } from "./tokens.js";
import {
  enableDashboardTwoFactor,
  isDashboardTwoFactorEnabled,
  newTotpSecret,
  otpauthUri,
} from "./totp.js";
import {
  deleteSecretKey,
  importDotEnvFile,
  listMaskedSecrets,
  setSecretEntries,
  setSecretFromFile,
} from "./vault.js";

function getFlagValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

async function ask(question: string): Promise<string | undefined> {
  if (!process.stdin.isTTY) return undefined;
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/**
 * Asks the person at the terminal before risky actions (guard.ts). `--yes` skips normal
 * confirmations; strong ones need the name typed or `--confirm-name <name>`.
 */
async function confirmInCli(action: string, params: Record<string, unknown>, args: string[]): Promise<void> {
  const r = assessRisk(action, params);
  if (!r) return;
  console.error(`⚠️  ${r.warning.en}`);
  let confirmName = getFlagValue(args, "--confirm-name");
  let confirmed = args.includes("--yes") || Boolean(confirmName);
  if (r.level === "strong" && confirmName === undefined) {
    confirmName = await ask(`Type "${r.subject}" to confirm: `);
    confirmed = Boolean(confirmName);
  } else if (!confirmed) {
    confirmed = (await ask("Continue? [y/N] "))?.toLowerCase() === "y";
  }
  authorizeHuman(action, params, { confirmed, confirmName, by: `cli:${process.env.USER || "unknown"}` });
}

async function runCli() {
  const [, , cmd, ...rest] = process.argv;

  switch (cmd) {
    case "status": {
      console.log(JSON.stringify(getSystemStatusSummary(), null, 2));
      break;
    }

    case "doctor": {
      const [appName] = rest;
      console.log(JSON.stringify(runPaaSDoctor(appName), null, 2));
      break;
    }

    case "init":
    case "bootstrap": {
      ensureDirectories();
      ensureDockerNetwork();
      const key = getOrCreateSshDeployKey();
      const withPg = rest.includes("--postgres");
      const withRedis = rest.includes("--redis");
      const withDashboard = rest.includes("--dashboard");
      if (withPg) ensureSharedPostgresCluster();
      if (withRedis) ensureSharedRedisCluster();
      let dashboardInfo: unknown = undefined;
      if (withDashboard) {
        dashboardInfo = ensureDashboardBackgroundService(4099);
      }
      console.log(
        JSON.stringify(
          {
            status: "initialized",
            sshDeployPublicKey: key.publicKey,
            sshKeyFingerprint: key.fingerprint,
            postgresStarted: withPg,
            redisStarted: withRedis,
            dashboard: dashboardInfo,
          },
          null,
          2
        )
      );
      break;
    }

    case "dashboard": {
      const sub = rest[0] || "start";
      const port = Number(getFlagValue(rest, "--port") || 4099);
      const host = getFlagValue(rest, "--host") || "127.0.0.1";
      if (sub === "token") {
        console.log(
          JSON.stringify({ dashboardToken: getOrCreateDashboardToken() }, null, 2)
        );
      } else if (sub === "2fa") {
        const action = rest[1];
        if (action === "enable") {
          const secret = newTotpSecret();
          console.error("Add this key to an authenticator app (Aegis, Google Authenticator, 1Password...):");
          console.error(`  ${otpauthUri(secret)}`);
          console.error(`  manual key: ${secret}`);
          const code = getFlagValue(rest, "--code") ?? (await ask("Type the 6-digit code shown by the app: "));
          enableDashboardTwoFactor(secret, code || "");
          console.log(JSON.stringify({ twoFactor: "enabled", note: "Everyone was logged out; sign in again with token + code." }, null, 2));
        } else if (action === "disable") {
          await confirmInCli("dashboard.2fa-off", {}, rest);
          deleteSecretKey("system", "DASHBOARD_TOTP_SECRET");
          console.log(JSON.stringify({ twoFactor: "disabled" }, null, 2));
        } else {
          console.log(JSON.stringify({ twoFactor: isDashboardTwoFactorEnabled() ? "enabled" : "disabled" }, null, 2));
        }
      } else if (sub === "serve") {
        startDashboardServer(port, host);
        console.log(`PaaSMCP Dashboard listening on http://${host}:${port}`);
      } else {
        const mode = getFlagValue(rest, "--expose") as
          | "public"
          | "zero-trust"
          | "tailscale"
          | undefined;
        if (mode) await confirmInCli("app.expose", { appName: "paasmcp-dashboard", mode }, rest);
        const info = ensureDashboardBackgroundService(port);
        const subdomain = getFlagValue(rest, "--subdomain") || "paas";
        let exposure: unknown = undefined;
        if (mode) {
          exposure = await exposeApplication({
            appName: "paasmcp-dashboard",
            mode,
            subdomain,
          });
        }
        console.log(JSON.stringify({ ...info, exposure }, null, 2));
      }
      break;
    }

    case "config": {
      const accountId = getFlagValue(rest, "--account-id");
      const tunnelId = getFlagValue(rest, "--tunnel-id");
      const baseDomain = getFlagValue(rest, "--domain");
      const emailsRaw = getFlagValue(rest, "--zero-trust-emails");
      const tailscaleDomain = getFlagValue(rest, "--tailscale-domain");
      const state = updatePlatformConfig({
        accountId,
        tunnelId,
        baseDomain,
        zeroTrustEmails: emailsRaw
          ? emailsRaw.split(",").map((e) => e.trim()).filter(Boolean)
          : undefined,
        tailscaleDomain,
      });
      console.log(
        JSON.stringify(
          {
            tailscaleDomain: state.tailscaleDomain,
            cloudflare: state.cloudflare,
          },
          null,
          2
        )
      );
      break;
    }

    case "github-key": {
      const repo = rest[0];
      if (repo) {
        console.log(JSON.stringify(await registerGitHubDeployKey(repo), null, 2));
      } else {
        console.log(JSON.stringify(getOrCreateSshDeployKey(), null, 2));
      }
      break;
    }

    case "secret": {
      const [sub, scope, ...kvArgs] = rest;
      if (!scope) {
        throw new Error(
          "Usage: paasmcp secret <set|set-file|import-env|list|delete> <scope> ..."
        );
      }
      if (sub === "list") {
        console.log(JSON.stringify(listMaskedSecrets(scope), null, 2));
      } else if (sub === "set") {
        const entries: Record<string, string> = {};
        for (const item of kvArgs) {
          const eq = item.indexOf("=");
          if (eq === -1) continue;
          entries[item.slice(0, eq)] = item.slice(eq + 1);
        }
        setSecretEntries(scope, entries);
        console.log(JSON.stringify(listMaskedSecrets(scope), null, 2));
      } else if (sub === "set-file") {
        const [keyName, filePath] = kvArgs;
        setSecretFromFile(scope, keyName, filePath, false);
        console.log(JSON.stringify(listMaskedSecrets(scope), null, 2));
      } else if (sub === "import-env") {
        const [envFile] = kvArgs;
        importDotEnvFile(scope, envFile);
        console.log(JSON.stringify(listMaskedSecrets(scope), null, 2));
      } else if (sub === "delete") {
        const [keyName] = kvArgs;
        await confirmInCli("secret.delete", { scope, keyName }, kvArgs);
        deleteSecretKey(scope, keyName);
        console.log(JSON.stringify(listMaskedSecrets(scope), null, 2));
      } else {
        throw new Error(`Unknown secret subcommand: ${sub}`);
      }
      break;
    }

    case "db": {
      const [appName, engineArg] = rest;
      if (!appName) throw new Error("Usage: paasmcp db <appName> [postgres|redis]");
      const engine = (engineArg as "postgres" | "redis") || "postgres";
      console.log(JSON.stringify(provisionDatabase(appName, engine), null, 2));
      break;
    }

    case "db-backup": {
      const [sub, arg1, arg2] = rest;
      if (!sub || sub === "list") {
        console.log(JSON.stringify(listDatabaseBackups(arg1), null, 2));
      } else if (sub === "create") {
        if (!arg1) throw new Error("Usage: paasmcp db-backup create <appName> [postgres|redis]");
        const engine = (arg2 as "postgres" | "redis") || "postgres";
        console.log(JSON.stringify(backupDatabase(arg1, engine), null, 2));
      } else if (sub === "restore") {
        if (!arg1) throw new Error("Usage: paasmcp db-backup restore <backupId> [--yes]");
        await confirmInCli("db.restore", { backupId: arg1 }, rest);
        console.log(JSON.stringify(restoreDatabase(arg1), null, 2));
      } else {
        // Shorthand: paasmcp db-backup <appName>
        const engine = (arg1 as "postgres" | "redis") || "postgres";
        console.log(JSON.stringify(backupDatabase(sub, engine), null, 2));
      }
      break;
    }

    case "node": {
      const [sub, arg1] = rest;
      const state = loadState();
      if (!sub || sub === "status") {
        console.log(JSON.stringify(state.federation || {}, null, 2));
      } else if (sub === "invite") {
        const endpointUrl = arg1 || getFlagValue(rest, "--url") || "https://paas.example.com";
        const mode =
          (getFlagValue(rest, "--mode") as "active-active-tunnel" | "warm-standby") ||
          "active-active-tunnel";
        console.log(
          JSON.stringify(generateFederationJoinToken({ endpointUrl, mode }), null, 2)
        );
      } else if (sub === "join") {
        if (!arg1) throw new Error("Usage: paasmcp node join <paasmcp-join://...>");
        const verified = parseAndVerifyFederationJoinToken(arg1);
        await confirmInCli("federation.join", { peer: verified.primaryName, joinToken: arg1 }, rest);
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
        console.log(JSON.stringify({ joined: true, primaryPeer: peer }, null, 2));
      } else if (sub === "export-sync") {
        console.log(JSON.stringify(buildEncryptedFederationSyncBundle(), null, 2));
      } else if (sub === "import-sync") {
        const sig = getFlagValue(rest, "--sig") || "";
        if (!arg1 || !sig) {
          throw new Error("Usage: paasmcp node import-sync <encryptedBase64> --sig <hmac>");
        }
        await confirmInCli("federation.import", { peer: "sync-bundle", hmacSignature: sig }, rest);
        console.log(
          JSON.stringify(applyEncryptedFederationSyncBundle(arg1, sig), null, 2)
        );
      } else {
        throw new Error("Usage: paasmcp node <status|invite|join|export-sync|import-sync>");
      }
      break;
    }

    case "deploy": {
      const [appName, repoSource] = rest;
      if (!appName || !repoSource) {
        throw new Error(
          "Usage: paasmcp deploy <appName> <repoSource> [--branch main] [--port 3000] [--postgres] [--redis] [--memory 512m] [--cpus 1.0]"
        );
      }
      const branch = getFlagValue(rest, "--branch") || "main";
      const portStr = getFlagValue(rest, "--port");
      const internalPort = portStr ? Number(portStr) : undefined;
      const memoryLimit = getFlagValue(rest, "--memory");
      const cpuLimit = getFlagValue(rest, "--cpus");
      const withPostgres = rest.includes("--postgres");
      const withRedis = rest.includes("--redis");
      const trusted = rest.includes("--trusted") ? true : rest.includes("--untrusted") ? false : undefined;
      if (trusted && !loadState().apps[sanitizeSlug(appName)]?.trusted) {
        await confirmInCli("app.trust", { appName: sanitizeSlug(appName) }, rest);
      }

      const res = deployApp({
        trusted,
        appName,
        repoSource,
        branch,
        internalPort,
        withPostgres,
        withRedis,
        memoryLimit,
        cpuLimit,
      });
      console.log(JSON.stringify(res, null, 2));
      break;
    }

    case "expose": {
      const [appName, modeArg, subdomain] = rest;
      if (!appName || !modeArg) {
        throw new Error(
          "Usage: paasmcp expose <appName> <public|zero-trust|tailscale> [subdomain]"
        );
      }
      await confirmInCli("app.expose", { appName, mode: modeArg }, rest);
      const res = await exposeApplication({
        appName,
        mode: modeArg as "public" | "zero-trust" | "tailscale",
        subdomain: subdomain?.startsWith("--") ? undefined : subdomain,
      });
      console.log(JSON.stringify(res, null, 2));
      break;
    }

    case "logs":
    case "restart":
    case "stop":
    case "start":
    case "rollback":
    case "destroy":
    case "restore":
    case "purge": {
      const [appName] = rest;
      if (!appName) throw new Error(`Usage: paasmcp ${cmd} <appName>`);
      if (cmd === "destroy" || cmd === "purge") await confirmInCli(`app.${cmd}`, { appName }, rest);
      console.log(manageAppLifecycle(appName, cmd as AppLifecycleAction));
      break;
    }

    case "mcp": {
      if (rest[0] !== "serve") throw new Error("Usage: paasmcp mcp serve [--port 4098] [--host 127.0.0.1|tailscale]");
      const port = Number(getFlagValue(rest, "--port") || 4098);
      const host = getFlagValue(rest, "--host") || "127.0.0.1";
      startMcpHttpServer(port, host);
      console.error(`PaaSMCP MCP over HTTP listening on http://${host}:${port}/mcp (Bearer token required)`);
      break;
    }

    case "token": {
      const [sub, arg] = rest;
      if (sub === "create") {
        if (!arg) throw new Error("Usage: paasmcp token create <name> [--level read|deploy|destroy]");
        const level = (getFlagValue(rest, "--level") || "deploy") as TokenLevel;
        if (level === "destroy") {
          console.error("⚠️  A 'destroy' token can request risky actions (they still need a person's approval).");
        }
        const { token, record } = createToken(arg, level);
        console.error("Copy the token now: it is not stored and will not be shown again.");
        console.log(JSON.stringify({ token, id: record.id, name: record.name, level: record.level }, null, 2));
      } else if (sub === "revoke") {
        if (!arg) throw new Error("Usage: paasmcp token revoke <id>");
        console.log(JSON.stringify({ revoked: revokeToken(arg) }, null, 2));
      } else {
        console.log(JSON.stringify(listTokens(), null, 2));
      }
      break;
    }

    case "trash": {
      // For a daily cron/systemd timer: deletes apps trashed more than 30 days ago.
      if (rest[0] !== "purge-expired") throw new Error("Usage: paasmcp trash purge-expired");
      console.log(JSON.stringify({ purged: purgeExpiredTrash() }, null, 2));
      break;
    }

    case "approvals": {
      console.log(JSON.stringify(listApprovals(!rest.includes("--all")), null, 2));
      break;
    }

    case "approve":
    case "reject": {
      const [id] = rest;
      if (!id) throw new Error(`Usage: paasmcp ${cmd} <requestId> [--confirm-name <name>]`);
      const pending = listApprovals(false).find((a) => a.id === id);
      if (!pending) throw new Error(`Approval request '${id}' not found.`);
      console.error(`⚠️  ${pending.warning.en}`);
      let confirmName = getFlagValue(rest, "--confirm-name");
      if (cmd === "approve" && pending.level === "strong" && confirmName === undefined) {
        confirmName = await ask(`Type "${pending.subject}" to confirm: `);
      }
      const rec = decideApproval(id, cmd === "approve", `cli:${process.env.USER || "unknown"}`, confirmName);
      console.log(JSON.stringify(rec, null, 2));
      break;
    }

    default: {
      console.log(`PaaSMCP — Agent-First Micro-PaaS & MCP Server
Commands:
  paasmcp init [--postgres] [--redis] [--dashboard]  Initialize PaaS storage, SSH key & services
  paasmcp dashboard [start|token] [--expose zero-trust --subdomain paas]  Start & expose Web Control Plane
  paasmcp config [options]                           Configure Cloudflare Tunnel, Base Domain & Zero Trust
  paasmcp status                                     Show full system, metrics, apps, DBs & federation status
  paasmcp doctor [appName]                           Diagnose OOMKills, crashes, and container health
  paasmcp github-key [owner/repo]                    Show or register GitHub SSH Deploy Key
  paasmcp secret set <scope> KEY=VAL ...             Encrypt & store secrets in AES-256-GCM Vault
  paasmcp secret set-file <scope> <KEY> <path>       Store secret from file without printing it
  paasmcp secret import-env <scope> <.env>           Import .env file into encrypted Vault
  paasmcp secret list <scope>                        List masked secrets in scope
  paasmcp db <appName> [postgres|redis]              Provision isolated DB & bind DATABASE_URL
  paasmcp db-backup <create|list|restore> ...        Encrypted AES-256-GCM database snapshots & restore
  paasmcp deploy <app> <repo> [--postgres]           Build & deploy repo (or multi-service compose.yaml)
  paasmcp expose <app> <public|zero-trust|tailscale> [subdomain]
  paasmcp <logs|restart|stop|start|rollback> <app>
  paasmcp destroy <app> [--yes]                      Stop app and move it to the trash (30 days)
  paasmcp restore <app>                              Bring an app back from the trash
  paasmcp purge <app> [--confirm-name <app>]         Delete a trashed app for good (strong confirmation)
  paasmcp trash purge-expired                        Delete apps trashed more than 30 days ago (cron)
  paasmcp dashboard 2fa <enable|disable|status>      Two-factor login for the dashboard (needed to publish it openly)
  paasmcp mcp serve [--port 4098] [--host tailscale] MCP over HTTP for remote AI clients (token required)
  paasmcp token <create|list|revoke> ...             Personal MCP tokens (levels: read, deploy, destroy)
  paasmcp approvals [--all]                          List confirmation requests made by AI agents
  paasmcp approve|reject <id> [--confirm-name <x>]   Decide a confirmation request (people only)
  paasmcp node <status|invite|join|export-sync>      Multi-Server HA Handshake & Federation`);
      break;
    }
  }
}

// Read-only commands and the long-running dashboard server skip the state lock.
const LOCK_FREE_COMMANDS = new Set(["status", "doctor", "logs", "approvals", "approve", "reject", "dashboard", "mcp", "token", undefined]);
const command = process.argv[2];
(LOCK_FREE_COMMANDS.has(command) ? runCli() : withStateLock(runCli)).catch((err) => {
  console.error("Error:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
