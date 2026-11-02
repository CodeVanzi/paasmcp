#!/usr/bin/env node
import { ensureDirectories, updatePlatformConfig } from "./config.js";
import {
  ensureDashboardBackgroundService,
  getOrCreateDashboardToken,
  startDashboardServer,
} from "./dashboard.js";
import {
  ensureDockerNetwork,
  ensureSharedPostgresCluster,
  ensureSharedRedisCluster,
  provisionDatabase,
} from "./database.js";
import { deployApp, manageAppLifecycle } from "./deployer.js";
import { exposeApplication } from "./exposure.js";
import { getOrCreateSshDeployKey, registerGitHubDeployKey } from "./github.js";
import { getSystemStatusSummary } from "./mcp-server.js";
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

async function runCli() {
  const [, , cmd, ...rest] = process.argv;

  switch (cmd) {
    case "status": {
      console.log(JSON.stringify(getSystemStatusSummary(), null, 2));
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
      } else if (sub === "serve") {
        startDashboardServer(port, host);
        console.log(`PaaSMCP Dashboard listening on http://${host}:${port}`);
      } else {
        const info = ensureDashboardBackgroundService(port);
        const mode = getFlagValue(rest, "--expose") as
          | "public"
          | "zero-trust"
          | "tailscale"
          | undefined;
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

    case "deploy": {
      const [appName, repoSource] = rest;
      if (!appName || !repoSource) {
        throw new Error(
          "Usage: paasmcp deploy <appName> <repoSource> [--branch main] [--port 3000] [--postgres] [--redis]"
        );
      }
      const branch = getFlagValue(rest, "--branch") || "main";
      const portStr = getFlagValue(rest, "--port");
      const internalPort = portStr ? Number(portStr) : undefined;
      const withPostgres = rest.includes("--postgres");
      const withRedis = rest.includes("--redis");

      const res = deployApp({
        appName,
        repoSource,
        branch,
        internalPort,
        withPostgres,
        withRedis,
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
      const res = await exposeApplication({
        appName,
        mode: modeArg as "public" | "zero-trust" | "tailscale",
        subdomain,
      });
      console.log(JSON.stringify(res, null, 2));
      break;
    }

    case "logs":
    case "restart":
    case "stop":
    case "start":
    case "destroy": {
      const [appName] = rest;
      if (!appName) throw new Error(`Usage: paasmcp ${cmd} <appName>`);
      console.log(
        manageAppLifecycle(
          appName,
          cmd as "logs" | "restart" | "stop" | "start" | "destroy"
        )
      );
      break;
    }

    default: {
      console.log(`PaaSMCP — Agent-First Micro-PaaS & MCP Server
Commands:
  paasmcp init [--postgres] [--redis] [--dashboard]  Initialize PaaS storage, SSH key & services
  paasmcp dashboard [start|token] [--expose zero-trust --subdomain paas]  Start & expose Web Control Plane
  paasmcp config [options]                           Configure Cloudflare Tunnel, Base Domain & Zero Trust
  paasmcp status                                     Show full system, apps, and databases status
  paasmcp github-key [owner/repo]                    Show or register GitHub SSH Deploy Key
  paasmcp secret set <scope> KEY=VAL ...             Encrypt & store secrets in AES-256-GCM Vault
  paasmcp secret set-file <scope> <KEY> <path>       Store secret from file without printing it
  paasmcp secret import-env <scope> <.env>           Import .env file into encrypted Vault
  paasmcp secret list <scope>                        List masked secrets in scope
  paasmcp db <appName> [postgres|redis]              Provision isolated DB & bind DATABASE_URL
  paasmcp deploy <app> <repo> [--postgres]           Build & deploy repo to /opt/homelab/apps/<app>
  paasmcp expose <app> <public|zero-trust|tailscale> [subdomain]
  paasmcp <logs|restart|stop|start|destroy> <app>`);
      break;
    }
  }
}

runCli().catch((err) => {
  console.error("Error:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
