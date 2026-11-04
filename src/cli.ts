#!/usr/bin/env node
import fs from "node:fs";
import readline from "node:readline/promises";
import {
  ensureDirectories,
  loadState,
  sanitizeSlug,
  saveState,
  updatePlatformConfig,
  withStateLock,
} from "./config.js";
import {
  addArbiterKey, arbiterClusterId, deriveArbiterKey, installArbiterService, listArbiterClusters, parseArbiterKeys, removeArbiterKey,
  resolveArbiterHost, startArbiterServer,
} from "./arbiter.js";
import { installPollTimer, pollRepos, setPolling } from "./poller.js";
import { activeReadiness, activeStatus, publishActiveState, switchActiveActive, syncActiveFiles, syncActivePeers } from "./active.js";
import { activeTunnelStatus, disableActiveTunnel, enableActiveTunnel, routeActiveTunnel, tunnelWatchTick } from "./activetunnel.js";
import { addEdgeSite, edgeStatus, installEdge, refreshEdge, removeEdgeSite, uninstallEdge } from "./edge.js";
import { applyUpdate, checkUpdates, Component, PINNED } from "./updater.js";
import { getEmailRelay, provisionEmail, sendTestEmail, setEmailRelay } from "./email.js";
import {
  acceptMirror,
  handbackMirror,
  installMirrorWatch,
  mirrorStatus,
  offerMirror,
  promoteMirror,
  checkArbiter,
  setAutoFailover,
  watchTick,
} from "./mirror.js";
import { listStorage, provisionStorage } from "./storage.js";
import {
  backupAppVolumes,
  fetchOffsite,
  installBackupTimer,
  pruneLocalBackups,
  runNightlyBackup,
  syncOffsite,
  testRestore,
} from "./backup.js";
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
import { installMcpService, startMcpHttpServer } from "./mcp-http.js";
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
  getOrCreateMasterKey,
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
        if (!arg1) throw new Error("Usage: paasmcp db-backup create <appName> [postgres|redis|volume]");
        const engine = (arg2 as "postgres" | "redis" | "volume") || "postgres";
        console.log(JSON.stringify(engine === "volume" ? backupAppVolumes(arg1) : backupDatabase(arg1, engine), null, 2));
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

    case "mirror": {
      const [sub, arg1] = rest;
      if (sub === "offer" && arg1) {
        const peerCidr = getFlagValue(rest, "--peer-ip");
        if (!peerCidr) throw new Error("Usage: paasmcp mirror offer <peerName> --peer-ip <peer Tailscale IP> [--advertise <this server's IP>] [--no-backups]");
        const r = await offerMirror({
          peerName: arg1,
          peerCidr,
          advertiseHost: getFlagValue(rest, "--advertise"),
          withBackups: !rest.includes("--no-backups"),
          fromCopyOf: getFlagValue(rest, "--from-copy-of"),
        });
        console.error(`Run on '${arg1}' within one hour (the token carries passwords; do not paste it into chats):`);
        console.log(`paasmcp mirror accept ${r.token}`);
        console.error(JSON.stringify({ ...r, token: undefined }, null, 2));
      } else if (sub === "accept" && arg1) {
        const rejoin = rest.includes("--rejoin");
        if (rejoin && !loadState().mirror?.fenced) await confirmInCli("mirror.rejoin", {}, rest);
        console.log(JSON.stringify(acceptMirror(arg1, { rejoin }), null, 2));
      } else if (sub === "handback" && arg1) {
        await confirmInCli("mirror.handback", { peer: arg1 }, rest);
        console.log(JSON.stringify(await handbackMirror(arg1), null, 2));
      } else if (sub === "auto" && (arg1 === "on" || arg1 === "off") && rest[2]) {
        const arbiterUrl = getFlagValue(rest, "--arbiter");
        if (arg1 === "on") await confirmInCli("mirror.auto", { peer: rest[2], arbiterUrl }, rest);
        console.log(JSON.stringify(setAutoFailover(rest[2], arg1 === "on", arbiterUrl), null, 2));
      } else if (sub === "watch") {
        // Bucket copies run in the background, one at a time, outside the state lock: a slow or
        // unreachable origin never delays the next failover check or a deploy.
        let filesRun: Promise<void> | undefined;
        for (;;) {
          try {
            const r = await withStateLock(() => watchTick());
            if (Object.keys(r).some((k) => k !== "epoch")) console.log(new Date().toISOString(), JSON.stringify(r));
          } catch (err) {
            console.error(new Date().toISOString(), err instanceof Error ? err.message : String(err));
          }
          // Active-active apps of the other server follow its version within one round (~15 s).
          try {
            const sync = await withStateLock(() => runActiveSync());
            if (sync.some((p) => p.status !== "unchanged" && p.status !== "no manifest")) console.log(new Date().toISOString(), JSON.stringify({ activeSync: sync }));
          } catch (err) {
            console.error(new Date().toISOString(), "active sync:", err instanceof Error ? err.message : String(err));
          }
          filesRun ??= syncActiveFiles({ lock: (fn) => withStateLock(fn) })
            .then((files) => {
              if (files.length) console.log(new Date().toISOString(), JSON.stringify({ activeFiles: files }));
            })
            .catch((err) => console.error(new Date().toISOString(), "active files:", err instanceof Error ? err.message : String(err)))
            .finally(() => (filesRun = undefined));
          // Tunnel for apps on both servers: take a sick copy out / back in, and (origin) move the
          // addresses whose copy now answers. Outside the lock; only short state writes take it.
          try {
            const w = await tunnelWatchTick();
            if (w && w.action !== "none") console.log(new Date().toISOString(), JSON.stringify({ activeTunnel: w }));
            if (loadState().activeTunnel) {
              const r = await routeActiveTunnel({ lock: (fn) => withStateLock(fn) });
              if (r.dnsChanged) console.log(new Date().toISOString(), JSON.stringify({ activeTunnelRoutes: r }));
            }
          } catch (err) {
            console.error(new Date().toISOString(), "active tunnel:", err instanceof Error ? err.message : String(err));
          }
          if (rest.includes("--once")) {
            await filesRun;
            break;
          }
          await new Promise((r) => setTimeout(r, 15_000));
        }
      } else if (sub === "install-watch") {
        console.log(installMirrorWatch());
      } else if (sub === "promote" && arg1) {
        await confirmInCli("mirror.promote", { peer: arg1 }, rest);
        console.log(JSON.stringify(await promoteMirror(arg1), null, 2));
      } else if (!sub || sub === "status") {
        console.log(JSON.stringify(mirrorStatus(), null, 2));
      } else {
        throw new Error(
          "Usage: paasmcp mirror <offer <peer> --peer-ip <ip> [--from-copy-of <peer>]|accept <token> [--rejoin]|status|promote <peer>|handback <peer>|auto on|off <peer> [--arbiter <url>]|watch [--once]|install-watch>"
        );
      }
      break;
    }

    case "active": {
      const [sub, arg1] = rest;
      if ((sub === "on" || sub === "off") && arg1) {
        const slug = sanitizeSlug(arg1);
        if (sub === "on") {
          const ready = activeReadiness(slug);
          if (!ready.ok) throw new Error(`App '${slug}' cannot run on both servers yet:\n- ${ready.problems.join("\n- ")}`);
          for (const w of ready.warnings) console.error(`⚠️  ${w}`);
          await confirmInCli("app.active", { appName: slug }, rest);
        }
        console.log(JSON.stringify(await switchActiveActive(slug, sub === "on"), null, 2));
        if (sub === "on") {
          console.error("On the other server, the app starts within ~15 s if 'paasmcp mirror watch' runs there, or at the next 'paasmcp poll' (timer). To do it now: paasmcp active sync");
          console.error("Entry: with Cloudflare Tunnel, 'paasmcp active tunnel on' (a tunnel just for apps on both servers, run on both). Without Cloudflare: paasmcp edge install (on a server with a public IP).");
        }
      } else if (sub === "tunnel") {
        if (arg1 === "on") {
          await confirmInCli("active.tunnel", {}, rest);
          console.log(JSON.stringify(await enableActiveTunnel(), null, 2));
          console.error("Run 'sudo paasmcp mirror install-watch' on both servers: it moves each address once the other server's copy answers, and takes a sick copy out of the tunnel.");
        } else if (arg1 === "off") {
          console.log(JSON.stringify(await disableActiveTunnel(), null, 2));
        } else if (!arg1 || arg1 === "status") {
          console.log(JSON.stringify(activeTunnelStatus(), null, 2));
        } else {
          throw new Error("Usage: paasmcp active tunnel <status|on|off>");
        }
      } else if (sub === "check" && arg1) {
        console.log(JSON.stringify(activeReadiness(arg1), null, 2));
      } else if (sub === "sync") {
        console.log(JSON.stringify(await runActiveSyncWithFiles(), null, 2));
      } else if (sub === "publish") {
        console.log(JSON.stringify(publishActiveState(), null, 2));
      } else if (!sub || sub === "status") {
        console.log(JSON.stringify(activeStatus(), null, 2));
      } else {
        throw new Error("Usage: paasmcp active <status|check <app>|on <app>|off <app>|sync|publish|tunnel <status|on|off>>");
      }
      break;
    }

    case "edge": {
      const [sub, arg1, arg2] = rest;
      if (sub === "install") {
        await confirmInCli("edge.install", {}, rest);
        console.log(JSON.stringify(await installEdge({ email: getFlagValue(rest, "--email") }), null, 2));
      } else if (sub === "add" && arg1 && arg2) {
        await confirmInCli("app.expose", { appName: sanitizeSlug(arg1), mode: "public" }, rest);
        console.log(JSON.stringify(addEdgeSite(arg1, arg2), null, 2));
      } else if (sub === "remove" && arg1) {
        console.log(JSON.stringify(removeEdgeSite(arg1), null, 2));
      } else if (sub === "reload") {
        console.log(JSON.stringify({ changed: refreshEdge() }, null, 2));
      } else if (sub === "uninstall") {
        console.log(JSON.stringify(uninstallEdge(), null, 2));
      } else if (!sub || sub === "status") {
        console.log(JSON.stringify(await edgeStatus(), null, 2));
      } else {
        throw new Error("Usage: paasmcp edge <status|install [--email you@example.com]|add <app> <hostname>|remove <hostname>|reload|uninstall>");
      }
      break;
    }

    case "arbiter": {
      const [sub] = rest;
      if (sub === "key") {
        const key = deriveArbiterKey();
        console.error("Give this key to the arbiter device only (it cannot decrypt tokens or the vault):");
        console.log(key);
        console.error(`This cluster's id on the arbiter: ${arbiterClusterId(key)}. An arbiter that already serves another cluster takes it with 'paasmcp arbiter add-key <key>'.`);
      } else if (sub === "serve") {
        const keys = parseArbiterKeys(getFlagValue(rest, "--key") || process.env.PAASMCP_ARBITER_KEY);
        const hostFlag = getFlagValue(rest, "--host");
        if (!keys.length || !hostFlag) throw new Error("Usage: paasmcp arbiter serve --host <Tailscale IP|tailscale> [--port 4097] --key <key>[,<key of another cluster>...] (or PAASMCP_ARBITER_KEY)");
        const host = resolveArbiterHost(hostFlag);
        const port = Number(getFlagValue(rest, "--port") || 4097);
        startArbiterServer({ port, host, keys });
        console.error(`Arbiter listening on http://${host}:${port}/arbiter for ${keys.length} cluster(s): ${keys.map(arbiterClusterId).join(", ")}`);
        console.error(`On the servers, use the arbiter address http://${host}:${port}`);
        await new Promise(() => {});
      } else if (sub === "install-service") {
        const key = getFlagValue(rest, "--key") || process.env.PAASMCP_ARBITER_KEY;
        if (!key) throw new Error("Usage: sudo paasmcp arbiter install-service --key <from 'paasmcp arbiter key'> [--host tailscale] [--port 4097]");
        const port = Number(getFlagValue(rest, "--port") || 4097);
        const hostFlag = getFlagValue(rest, "--host") || "tailscale";
        const out = installArbiterService({ host: hostFlag, port, key });
        console.log(JSON.stringify(out, null, 2));
        const shown = hostFlag === "tailscale" ? (() => { try { return resolveArbiterHost("tailscale"); } catch { return "<Tailscale IP of this device>"; } })() : hostFlag;
        console.error(`Arbiter running. On the servers, use the arbiter address http://${shown}:${port}`);
      } else if (sub === "add-key" && rest[1]) {
        console.log(JSON.stringify(addArbiterKey(rest[1]), null, 2));
      } else if (sub === "remove-key" && rest[1]) {
        console.log(JSON.stringify(removeArbiterKey(rest[1]), null, 2));
      } else if (sub === "clusters") {
        console.log(JSON.stringify({ clusters: listArbiterClusters() }, null, 2));
      } else if (sub === "check") {
        console.log(JSON.stringify(await checkArbiter(rest[1]), null, 2));
      } else {
        throw new Error("Usage: paasmcp arbiter <key|serve|install-service|add-key <key>|remove-key <cluster id>|clusters|check [url]>");
      }
      break;
    }

    case "poll": {
      const [sub, arg1] = rest;
      if (!sub || sub === "run") {
        const polled = await pollRepos();
        let activeSync: unknown;
        try {
          activeSync = await runActiveSyncWithFiles();
        } catch (err) {
          activeSync = { error: err instanceof Error ? err.message : String(err) };
        }
        console.log(JSON.stringify({ ...polled, activeSync }, null, 2));
      } else if ((sub === "enable" || sub === "disable") && arg1) {
        console.log(JSON.stringify(setPolling(arg1, sub === "enable"), null, 2));
      } else if (sub === "install-timer") {
        console.log(JSON.stringify(installPollTimer(Number(getFlagValue(rest, "--minutes") || 2)), null, 2));
      } else {
        throw new Error("Usage: paasmcp poll [run]|enable <app>|disable <app>|install-timer [--minutes 2]");
      }
      break;
    }

    case "update": {
      const [sub, comp, image] = rest;
      if (!sub || sub === "check") {
        console.log(JSON.stringify(await checkUpdates(), null, 2));
      } else if (sub === "apply" && comp && PINNED[comp as Component]) {
        const target = image && !image.startsWith("--") ? image : (await checkUpdates()).find((u) => u.component === comp)?.available;
        if (!target) throw new Error(`${comp} is already on the newest release of its major version.`);
        await confirmInCli("update.apply", { component: comp, image: target }, rest);
        console.log(JSON.stringify(applyUpdate(comp as Component, target), null, 2));
      } else {
        throw new Error("Usage: paasmcp update <check|apply <postgres|redis|garage> [image]>");
      }
      break;
    }

    case "email": {
      const [sub, arg1] = rest;
      if (sub === "set") {
        const host = getFlagValue(rest, "--host");
        const fromDomain = getFlagValue(rest, "--from-domain");
        if (!host || !fromDomain) {
          throw new Error("Usage: paasmcp email set --host <smtp host> [--port 587] --user <login> --from-domain <domain> [--password-file f] [--api-key-file f]");
        }
        const pwFile = getFlagValue(rest, "--password-file");
        const password = pwFile ? fs.readFileSync(pwFile, "utf-8").trim() : await ask("SMTP password (or key): ");
        if (!password) throw new Error("No password given (use --password-file when not in a terminal).");
        const apiFile = getFlagValue(rest, "--api-key-file");
        setEmailRelay({
          host,
          port: Number(getFlagValue(rest, "--port") || 587),
          user: getFlagValue(rest, "--user") || "",
          password,
          fromDomain,
          apiKey: apiFile ? fs.readFileSync(apiFile, "utf-8").trim() : undefined,
        });
        console.log(JSON.stringify({ configured: true, host, fromDomain }, null, 2));
      } else if (sub === "provision" && arg1) {
        console.log(JSON.stringify(provisionEmail(arg1, getFlagValue(rest, "--from-name")), null, 2));
      } else if (sub === "test" && arg1) {
        console.log(JSON.stringify(await sendTestEmail(arg1), null, 2));
      } else if (!sub || sub === "status") {
        const r = getEmailRelay();
        console.log(JSON.stringify(r ? { host: r.host, port: r.port, user: r.user, fromDomain: r.fromDomain, httpApi: !!r.apiKey } : { configured: false }, null, 2));
      } else {
        throw new Error("Usage: paasmcp email <set|status|provision <app> [--from-name N]|test <to>>");
      }
      break;
    }

    case "storage": {
      const [sub, arg1] = rest;
      if (sub === "provision" && arg1) {
        console.log(JSON.stringify(await provisionStorage(arg1), null, 2));
      } else if (!sub || sub === "list") {
        console.log(JSON.stringify(listStorage(), null, 2));
      } else {
        throw new Error("Usage: paasmcp storage <provision <appName>|list>");
      }
      break;
    }

    case "backup": {
      const [sub, arg1] = rest;
      const days = Number(getFlagValue(rest, "--days") || 7);
      if (sub === "test") {
        if (!arg1) throw new Error("Usage: paasmcp backup test <backupId>");
        console.log(JSON.stringify(testRestore(arg1), null, 2));
      } else if (sub === "sync") {
        console.log(JSON.stringify(await syncOffsite(), null, 2));
      } else if (sub === "fetch") {
        if (!arg1) throw new Error("Usage: paasmcp backup fetch <backupId>");
        console.log(JSON.stringify(await fetchOffsite(arg1), null, 2));
      } else if (sub === "prune") {
        console.log(JSON.stringify(pruneLocalBackups(days), null, 2));
      } else if (sub === "nightly") {
        console.log(JSON.stringify(await runNightlyBackup(days), null, 2));
      } else if (sub === "install-timer") {
        console.log(JSON.stringify(installBackupTimer(Number(getFlagValue(rest, "--hour") || 3)), null, 2));
      } else if (sub === "export-key") {
        console.error(
          "This is the master key that decrypts the vault and every backup. Off-site backups are useless without it.\n" +
            "Keep it outside this server (password manager or paper). Anyone with it and the backups can read your data."
        );
        console.log(getOrCreateMasterKey().toString("hex"));
      } else {
        throw new Error("Usage: paasmcp backup <test|sync|fetch|prune|nightly|install-timer|export-key> [--days N] [--hour H]");
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
          "Usage: paasmcp deploy <appName> <repoSource> [--branch main] [--port 3000] [--postgres] [--redis] [--memory 512m] [--cpus 1.0] [--healthcheck-path /healthz] [--healthcheck-timeout 20] [--no-healthcheck]"
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

      const hcTimeout = getFlagValue(rest, "--healthcheck-timeout");
      const res = await deployApp({
        trusted,
        healthcheckPath: getFlagValue(rest, "--healthcheck-path"),
        healthcheckTimeoutSeconds: hcTimeout ? Number(hcTimeout) : undefined,
        skipHealthcheck: rest.includes("--no-healthcheck") ? true : rest.includes("--healthcheck") ? false : undefined,
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
      if (rest[0] === "install-service") {
        console.log(JSON.stringify(installMcpService(getFlagValue(rest, "--host") || "tailscale", Number(getFlagValue(rest, "--port") || 4098)), null, 2));
        break;
      }
      if (rest[0] !== "serve") throw new Error("Usage: paasmcp mcp <serve [--port 4098] [--host 127.0.0.1|tailscale]|install-service [--host tailscale] [--port 4098]>");
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
  paasmcp db-backup <create|list|restore> ...        Encrypted AES-256-GCM database/volume snapshots & restore
  paasmcp mirror <offer|accept|status|promote|handback|auto|watch|install-watch>
                                                    Live Postgres copy between two servers, failover, failback
  paasmcp arbiter <key|serve|install-service|add-key|remove-key|clusters|check>
                                                    Third vote for automatic failover (one device can serve several clusters)
  paasmcp active <status|check|on|off|sync> [app]   Run an app on both servers at once (needs the mirror)
  paasmcp active tunnel <status|on|off>             Cloudflare Tunnel just for those apps, on both servers
  paasmcp edge <status|install|add|remove|reload|uninstall>  Self-hosted entry (Caddy) splitting requests between both servers
  paasmcp poll <run|enable <app>|disable <app>|install-timer>  Auto-deploy by polling git (no public webhook, 0 MB idle)
  paasmcp update <check|apply <component> [image]>  Pinned Postgres/Redis/Garage; backup, health check, rollback
  paasmcp email <set|status|provision <app>|test <to>>  One relay (Brevo, SES...) for every app's email
  paasmcp storage <provision <app>|list>            S3 bucket + key per app on this server (Garage)
  paasmcp backup <test|sync|fetch|prune|nightly|install-timer|export-key>
                                                    Restore test, off-site sync (S3/R2/B2), daily timer, master key export
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

/** Peer side of active-active, then the edge picks up new or removed backends. */
async function runActiveSync() {
  const r = await syncActivePeers();
  if (r.some((p) => p.deployed.length || p.stopped.length)) refreshEdge();
  return r;
}

/** One-shot commands already hold the state lock: copy buckets right after, within a time budget. */
async function runActiveSyncWithFiles() {
  const peers = await runActiveSync();
  let tunnel: unknown;
  if (loadState().activeTunnel) {
    try {
      tunnel = await routeActiveTunnel();
    } catch (err) {
      tunnel = { error: err instanceof Error ? err.message : String(err) };
    }
  }
  let files: unknown;
  try {
    files = await syncActiveFiles({ budgetMs: 5 * 60 * 1000 });
  } catch (err) {
    files = { error: err instanceof Error ? err.message : String(err) };
  }
  return { peers, files, ...(tunnel ? { tunnel } : {}) };
}

// Read-only commands and the long-running dashboard server skip the state lock.
const LOCK_FREE_COMMANDS = new Set(["status", "doctor", "logs", "approvals", "approve", "reject", "dashboard", "mcp", "token", undefined]);
const command = process.argv[2];
// Long-running loops take the lock per round instead of holding it.
const lockFree = LOCK_FREE_COMMANDS.has(command) || command === "arbiter" || (command === "mirror" && process.argv[3] === "watch");
(lockFree ? runCli() : withStateLock(runCli)).catch((err) => {
  console.error("Error:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
