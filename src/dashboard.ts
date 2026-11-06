import { backupAppVolumes, syncOffsite, testRestore } from "./backup.js";
import { deploySummary } from "./deploys.js";
import { getEmailRelay, provisionEmail, sendTestEmail, setEmailRelay } from "./email.js";
import { arbiterInstallCommand } from "./arbiter.js";
import { acceptMirror, checkArbiter, handbackMirror, mirrorStatus, offerMirror, promoteMirror, retireCopy, setArbiterUrl, setAutoFailover } from "./mirror.js";
import { setPolling } from "./poller.js";
import { DiaryLang, ruleFor, ruleRiskParams, scaleDiary, scaleHistory, scaleStatus, setDiaryLanguage, setScaleRule } from "./scale.js";
import { autoRiskParams, setAutoScale } from "./autoscale.js";
import { addHelper, createInvite, disablePool, pauseHelper, poolAcl, poolAfterLifecycle, poolReadiness, poolStatus, removeHelper, setCopies, setCourtesy, validateCourtesy } from "./pool.js";
import { setWake } from "./wake.js";
import { validateHelperName } from "./poolproto.js";
import { activeReadiness, activeStatus, switchActiveActive } from "./active.js";
import { activeTunnelStatus, disableActiveTunnel, enableActiveTunnel } from "./activetunnel.js";
import { addEdgeSite, edgeStatus, removeEdgeSite } from "./edge.js";
import { createToken, listTokens, revokeToken, TokenLevel } from "./tokens.js";
import { listStorage, provisionStorage } from "./storage.js";
import { checkGitHub, ConnectionError, connectionsSummary, discoverCloudflare, ensureRepoHook, githubRepoOf, listGitHubRepos, listRepoHooks, saveCloudflare } from "./connections.js";
import { explainDeployError } from "./deployhelp.js";
import { prepareTemplate, TEMPLATES } from "./templates.js";
import { clearNotify, NotifyError, notifySummary, saveNotify } from "./notify.js";
import { clearOffsiteTarget, createBackupGrant, listBackupGrants, OffsiteError, offsiteSummary, retestOffsiteTarget, revokeBackupGrant, saveOffsiteTarget } from "./offsite.js";
import { applyUpdate, checkUpdates, Component, PINNED } from "./updater.js";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DOCKER_NETWORK, HOMELAB_ROOT, PAAS_DATA_DIR, loadState, sanitizeSlug, saveState, tailscaleSocketDir, withStateLock, WATCHTOWER_OFF_COMPOSE } from "./config.js";
import { getDashboardTotpSecret, isDashboardTwoFactorEnabled, verifyTotp } from "./totp.js";
import {
  authorizeHuman,
  ConfirmationRequiredError,
  decideApproval,
  DASHBOARD_APP_NAME,
  ForbiddenActionError,
  listApprovals,
  audit,
} from "./guard.js";
import {
  backupDatabase,
  ensureDockerNetwork,
  listDatabaseBackups,
  provisionDatabase,
  restoreDatabase,
} from "./database.js";
import {
  AppLifecycleAction,
  deployApp,
  manageAppLifecycle,
  runPaaSDoctor,
  syncHomepageDashboard,
} from "./deployer.js";
import { exposeApplication, ExposeError, releaseAddresses, removeAppAddress } from "./exposure.js";
import { trashDeleteDate } from "./trashclean.js";
import {
  applyEncryptedFederationSyncBundle,
  buildEncryptedFederationSyncBundle,
  generateFederationJoinToken,
  getOrCreateWebhookSecret,
  handleGitHubPushWebhook,
  parseAndVerifyFederationJoinToken,
  registerFederationPeer,
  verifyGitHubWebhookSignature,
} from "./federation.js";
import { getSystemStatusSummary, resourceSnapshot } from "./mcp-server.js";
import { followedCode, followStatus, originOf, setFollow } from "./selfupdate.js";
import { startPollLoop } from "./pollloop.js";
import { startAppWatch } from "./appwatch.js";
import { startNightlyLoop } from "./nightly.js";
import {
  deleteSecretKey,
  getSecrets,
  listMaskedSecrets,
  setSecretEntries,
  timingSafeCompare,
  parseDotenv,
} from "./vault.js";

const LOGIN_ATTEMPTS = new Map<string, { count: number; resetAt: number }>();

function checkLoginRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = LOGIN_ATTEMPTS.get(ip);
  if (!entry || now > entry.resetAt) {
    LOGIN_ATTEMPTS.set(ip, { count: 1, resetAt: now + 5 * 60 * 1000 });
    return true;
  }
  entry.count += 1;
  return entry.count <= 12;
}


// Helper pool tasks can take minutes (sending an image, 30 s drains), longer than a proxy waits for an
// answer: they run in the background, one at a time, under the state lock, and the screen follows them.
interface PoolJob {
  id: string;
  kind: string;
  subject: string;
  startedAt: string;
  log: string[];
  done: boolean;
  finishedAt?: string;
  result?: unknown;
  error?: string;
}
let poolJob: PoolJob | undefined;

function startPoolJob(kind: string, subject: string, fn: (log: (l: string) => void) => Promise<unknown>): PoolJob {
  if (poolJob && !poolJob.done) throw new Error(`Wait for the current helper task to finish (${poolJob.kind} ${poolJob.subject}).`);
  const job: PoolJob = { id: crypto.randomBytes(4).toString("hex"), kind, subject, startedAt: new Date().toISOString(), log: [], done: false };
  poolJob = job;
  const log = (l: string) => {
    job.log.push(`${new Date().toISOString().slice(11, 19)} ${l}`);
    if (job.log.length > 200) job.log.splice(0, job.log.length - 200);
  };
  withStateLock(() => fn(log))
    .then((r) => {
      job.result = r;
    })
    .catch((err) => {
      job.error = err instanceof Error ? err.message : String(err);
    })
    .finally(() => {
      job.done = true;
      job.finishedAt = new Date().toISOString();
    });
  return job;
}

export function getOrCreateDashboardToken(): string {
  const sys = getSecrets("system");
  if (sys.DASHBOARD_TOKEN) {
    return sys.DASHBOARD_TOKEN;
  }
  const token = crypto.randomBytes(24).toString("hex");
  setSecretEntries("system", { DASHBOARD_TOKEN: token });
  return token;
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function readRawBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 2_000_000) {
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

async function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readRawBody(req);
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

// Signed session cookie: "<expiry>.<hmac>". The key mixes the token and the 2FA secret, so a session
// cannot be forged from the token alone, and changing either one logs everybody out.
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;

function sessionKey(expectedToken: string): Buffer {
  return crypto.createHash("sha256").update(`${expectedToken}|${getDashboardTotpSecret() || ""}`).digest();
}

function createSession(expectedToken: string): string {
  const exp = String(Date.now() + SESSION_TTL_MS);
  return `${exp}.${crypto.createHmac("sha256", sessionKey(expectedToken)).update(exp).digest("hex")}`;
}

function isValidSession(value: string | undefined, expectedToken: string): boolean {
  const [exp, sig] = String(value || "").split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return timingSafeCompare(sig, crypto.createHmac("sha256", sessionKey(expectedToken)).update(exp).digest("hex"));
}

function isAuthenticated(req: http.IncomingMessage, expectedToken: string): boolean {
  const cookies = parseCookies(req.headers.cookie);
  if (isValidSession(cookies.paasmcp_session, expectedToken)) return true;
  // With two-factor on, the token alone (header or old cookie) is never enough.
  if (isDashboardTwoFactorEnabled()) return false;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const provided = authHeader.slice("Bearer ".length).trim();
    if (timingSafeCompare(provided, expectedToken)) return true;
  }
  if (cookies.paasmcp_token && timingSafeCompare(cookies.paasmcp_token, expectedToken)) {
    return true;
  }
  return false;
}

function setSecurityHeaders(res: http.ServerResponse): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
  );
}

export function startDashboardServer(port = 4099, host = "127.0.0.1"): http.Server {
  const expectedToken = getOrCreateDashboardToken();

  const server = http.createServer(async (req, res) => {
    setSecurityHeaders(res);
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;

    // 1. Public HMAC-Authenticated GitHub Webhook Receiver
    if (pathname === "/api/webhooks/github" && req.method === "POST") {
      try {
        const rawBody = await readRawBody(req);
        const sig = req.headers["x-hub-signature-256"] as string | undefined;
        if (!verifyGitHubWebhookSignature(rawBody, sig)) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid X-Hub-Signature-256" }));
          return;
        }
        const eventName = req.headers["x-github-event"] || "push";
        if (eventName === "ping") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true, pong: true }));
          return;
        }
        const payload = JSON.parse(rawBody || "{}") as Record<string, unknown>;
        const result = await withStateLock(() => handleGitHubPushWebhook(payload));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, ...result }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(err) }));
      }
      return;
    }

    // 2. Public HMAC-Authenticated Multi-Node Federation Sync Endpoint
    if (pathname === "/api/federation/sync" && req.method === "POST") {
      try {
        const body = await readJsonBody(req);
        const encryptedBase64 = String(body.encryptedBase64 || "");
        const hmacSignature = String(body.hmacSignature || "");
        const result = await withStateLock(() =>
          applyEncryptedFederationSyncBundle(encryptedBase64, hmacSignature)
        );
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, ...result }));
      } catch (err) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(err) }));
      }
      return;
    }

    // 3. Login endpoint with rate limiting & constant-time token compare
    if (pathname === "/api/login" && req.method === "POST") {
      const clientIp =
        (req.headers["cf-connecting-ip"] as string) ||
        req.socket.remoteAddress ||
        "unknown";
      if (!checkLoginRateLimit(clientIp)) {
        res.writeHead(429, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Too many login attempts. Try again in 5 minutes." }));
        return;
      }
      try {
        const body = await readJsonBody(req);
        const totpSecret = getDashboardTotpSecret();
        const tokenOk = typeof body.token === "string" && timingSafeCompare(body.token.trim(), expectedToken);
        const codeOk = !totpSecret || verifyTotp(totpSecret, String(body.code || ""));
        if (tokenOk && codeOk) {
          const secureFlag = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Set-Cookie": `paasmcp_session=${createSession(expectedToken)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secureFlag}`,
          });
          res.end(JSON.stringify({ ok: true }));
        } else {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid access token" }));
        }
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: String(err) }));
      }
      return;
    }

    if (pathname === "/api/logout" && req.method === "POST") {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": ["paasmcp_session=; HttpOnly; Path=/; Max-Age=0", "paasmcp_token=; HttpOnly; Path=/; Max-Age=0"],
      });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // Serve UI HTML
    if (pathname === "/" && (req.method === "GET" || req.method === "HEAD")) {
      const authed = isAuthenticated(req, expectedToken);
      const cfEmail = req.headers["cf-access-authenticated-user-email"] as
        | string
        | undefined;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      if (req.method === "HEAD") {
        res.end();
      } else {
        res.end(renderDashboardHtml(authed, cfEmail, isDashboardTwoFactorEnabled()));
      }
      return;
    }

    if (pathname === "/vendor/htmx.min.js" && req.method === "GET") {
      const vendorPath = path.resolve(__dirname, "../vendor/htmx.min.js");
      if (fs.existsSync(vendorPath)) {
        res.writeHead(200, {
          "Content-Type": "application/javascript; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
        });
        res.end(fs.readFileSync(vendorPath));
        return;
      }
    }

    // Protect all authenticated /api/* routes
    if (pathname.startsWith("/api/")) {
      if (!isAuthenticated(req, expectedToken)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }

      const actor = (req.headers["cf-access-authenticated-user-email"] as string | undefined) || "dashboard";
      // Risky actions answer 409 with the warning until the person confirms (body.confirmed / body.confirmName).
      const confirmFromBody = (action: string, params: Record<string, unknown>, body: Record<string, unknown>) =>
        authorizeHuman(action, params, {
          confirmed: body.confirmed === true,
          confirmName: typeof body.confirmName === "string" ? body.confirmName : undefined,
          by: actor,
        });
      const handleApi = async (): Promise<boolean> => {
        if (pathname === "/api/approvals" && req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ approvals: listApprovals(url.searchParams.get("all") !== "1") }));
          return true;
        }

        if (pathname === "/api/approvals/decide" && req.method === "POST") {
          const body = await readJsonBody(req);
          const rec = decideApproval(
            String(body.id || ""),
            body.approve === true,
            actor,
            typeof body.confirmName === "string" ? body.confirmName : undefined
          );
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(rec));
          return true;
        }

        if (pathname === "/api/status" && req.method === "GET") {
          const status = { ...getSystemStatusSummary(true), controlPlane: followStatus() };
          // Trashed apps: the day the trash deletes them for good (trashclean.ts).
          const statusApps = (status as { apps?: Record<string, { trashedAt?: string }> }).apps;
          if (statusApps && process.env.PAASMCP_TRASH_AUTO !== "0") {
            for (const [k, a] of Object.entries(statusApps)) {
              if (a?.trashedAt) statusApps[k] = { ...a, trashDeleteOn: trashDeleteDate(a as { name: string; trashedAt?: string }) } as typeof a;
            }
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(status));
          return true;
        }

        // Live numbers for the Resource usage card (polled while the page is open), lighter than /api/status.
        if (pathname === "/api/resources" && req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
          res.end(JSON.stringify(resourceSnapshot(true)));
          return true;
        }

        if (pathname === "/api/deploys" && req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
          res.end(JSON.stringify({ deploys: deploySummary(loadState().apps) }));
          return true;
        }

        if (pathname === "/api/doctor" && req.method === "GET") {
          const appName = url.searchParams.get("app") || undefined;
          const report = runPaaSDoctor(appName);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(report));
          return true;
        }

        if (pathname === "/api/webhook-secret" && req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ webhookSecret: getOrCreateWebhookSecret() }));
          return true;
        }

        if (pathname === "/api/secrets" && req.method === "GET") {
          const scope = url.searchParams.get("scope") || "system";
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              scope,
              secrets: listMaskedSecrets(scope),
            })
          );
          return true;
        }

        if (pathname === "/api/secrets" && req.method === "POST") {
          const body = await readJsonBody(req);
          const scope = String(body.scope || "system");
          // A pasted .env file: every variable at once (Railway, Render and Vercel take the same format).
          if (typeof body.dotenv === "string") {
            if (body.dotenv.length > 256 * 1024) throw new Error("The pasted text is too long (256 KB at most).");
            const { entries, skipped } = parseDotenv(body.dotenv);
            const keys = Object.keys(entries);
            if (!keys.length) throw new Error("No KEY=value line found in the pasted text.");
            if (keys.length > 300) throw new Error("Too many variables at once (300 at most).");
            const saved = setSecretEntries(scope, entries);
            audit({ event: "secret.import", scope: sanitizeSlug(scope), keys: saved.length, by: actor });
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ scope, saved, skipped, secrets: listMaskedSecrets(scope) }));
            return true;
          }
          const key = String(body.key || "").trim();
          const value = String(body.value || "");
          if (!key) throw new Error("Key is required");
          setSecretEntries(scope, { [key]: value });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              scope,
              secrets: listMaskedSecrets(scope),
            })
          );
          return true;
        }

        if (pathname === "/api/secrets" && req.method === "DELETE") {
          const body = await readJsonBody(req);
          const scope = String(body.scope || "system");
          const key = String(body.key || "");
          confirmFromBody("secret.delete", { scope, keyName: key }, body);
          deleteSecretKey(scope, key);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              scope,
              secrets: listMaskedSecrets(scope),
            })
          );
          return true;
        }

        if (pathname === "/api/db" && req.method === "POST") {
          const body = await readJsonBody(req);
          const appName = String(body.appName || "");
          const engine = (body.engine as "postgres" | "redis") || "postgres";
          const result = provisionDatabase(appName, engine);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        if (pathname === "/api/backups" && req.method === "GET") {
          const appName = url.searchParams.get("app") || undefined;
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ backups: listDatabaseBackups(appName) }));
          return true;
        }

        if (pathname === "/api/backups" && req.method === "POST") {
          const body = await readJsonBody(req);
          const appName = String(body.appName || "");
          const engine = (body.engine as "postgres" | "redis" | "volume") || "postgres";
          const backup = engine === "volume" ? backupAppVolumes(appName) : backupDatabase(appName, engine);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(backup));
          return true;
        }

        if (pathname === "/api/backups/test" && req.method === "POST") {
          const body = await readJsonBody(req);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(testRestore(String(body.backupId || ""))));
          return true;
        }

        if (pathname === "/api/backups/restore" && req.method === "POST") {
          const body = await readJsonBody(req);
          const backupId = String(body.backupId || "");
          confirmFromBody("db.restore", { backupId }, body);
          const result = restoreDatabase(backupId);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        if (pathname === "/api/federation/invite" && req.method === "POST") {
          const body = await readJsonBody(req);
          const endpointUrl = String(body.endpointUrl || `https://${req.headers.host || "localhost"}`);
          const mode =
            (body.mode as "active-active-tunnel" | "warm-standby") ||
            "active-active-tunnel";
          confirmFromBody("federation.invite", { peer: "join-token" }, body);
          const invite = generateFederationJoinToken({ endpointUrl, mode });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(invite));
          return true;
        }

        if (pathname === "/api/federation/join" && req.method === "POST") {
          const body = await readJsonBody(req);
          const joinToken = String(body.joinToken || "");
          const verified = parseAndVerifyFederationJoinToken(joinToken);
          confirmFromBody("federation.join", { peer: verified.primaryName, joinToken }, body);
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
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ joined: true, primaryPeer: peer }));
          return true;
        }

        if (pathname === "/api/federation/export" && req.method === "POST") {
          const bundle = buildEncryptedFederationSyncBundle();
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(bundle));
          return true;
        }

        // A failed deploy answers with the raw error plus what probably happened, for a plain-words card.
        const deployFailed = (err: unknown) => {
          res.writeHead(422, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err), failure: explainDeployError(err) }));
          return true;
        };
        if (pathname === "/api/deploy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const trusted = typeof body.trusted === "boolean" ? body.trusted : undefined;
          if (trusted && !loadState().apps[sanitizeSlug(String(body.appName))]?.trusted) {
            confirmFromBody("app.trust", { appName: sanitizeSlug(String(body.appName)) }, body);
          }
          let result;
          try {
            result = await deployApp({
            trigger: "dashboard",
            trusted,
            healthcheckPath: body.healthcheckPath ? String(body.healthcheckPath) : undefined,
            healthcheckTimeoutSeconds: body.healthcheckTimeoutSeconds ? Number(body.healthcheckTimeoutSeconds) : undefined,
            skipHealthcheck: typeof body.skipHealthcheck === "boolean" ? body.skipHealthcheck : undefined,
            appName: String(body.appName),
            repoSource: String(body.repoSource),
            branch: body.branch ? String(body.branch) : "main",
            internalPort: body.internalPort ? Number(body.internalPort) : undefined,
            withPostgres: Boolean(body.withPostgres),
            withRedis: Boolean(body.withRedis),
            memoryLimit: body.memoryLimit ? String(body.memoryLimit) : undefined,
            cpuLimit: body.cpuLimit ? String(body.cpuLimit) : undefined,
            });
          } catch (err) {
            return deployFailed(err);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        // Ready-made apps: a pinned compose file written by PaaSMCP, published like a local folder.
        if (pathname === "/api/templates" && req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ templates: TEMPLATES }));
          return true;
        }
        if (pathname === "/api/templates/deploy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const { dir, template } = prepareTemplate(String(body.id || ""));
          const appName = sanitizeSlug(String(body.appName || template.id));
          // Never replace an app that came from somewhere else (a repository, the dashboard itself).
          const existing = loadState().apps[appName];
          if (existing && existing.repoUrl !== dir) {
            return deployFailed(new Error(`An app named '${appName}' already exists with other code. Pick another name.`));
          }
          let result;
          try {
            result = await deployApp({ appName, repoSource: dir, branch: "main", trigger: "dashboard" });
          } catch (err) {
            return deployFailed(err);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        // Publish again with what the app already has (same repository and branch): new passwords take effect.
        if (pathname === "/api/apps/redeploy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const slug = sanitizeSlug(String(body.appName || ""));
          const app = loadState().apps[slug];
          if (!app) throw new Error(`App '${slug}' not found.`);
          if (!app.repoUrl || app.runtimeType === "paasmcp-control-plane") throw new Error(`App '${slug}' has no code source to publish again.`);
          let result;
          try {
            result = await deployApp({ appName: slug, repoSource: app.repoUrl, branch: app.branch, trusted: app.trusted, trigger: "dashboard" });
          } catch (err) {
            return deployFailed(err);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        if (pathname === "/api/expose" && req.method === "POST") {
          const body = await readJsonBody(req);
          confirmFromBody("app.expose", { appName: String(body.appName), mode: String(body.mode) }, body);
          const result = await exposeApplication({
            appName: String(body.appName),
            mode: body.mode as "public" | "zero-trust" | "tailscale",
            subdomain: body.subdomain ? String(body.subdomain) : undefined,
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        if (pathname === "/api/unexpose" && req.method === "POST") {
          const body = await readJsonBody(req);
          const appName = sanitizeSlug(String(body.appName || ""));
          const hostname = String(body.hostname || "");
          confirmFromBody("app.unexpose", { appName, hostname }, body);
          const result = await removeAppAddress(appName, hostname);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return true;
        }

        if (pathname === "/api/lifecycle" && req.method === "POST") {
          const body = await readJsonBody(req);
          const action = body.action as AppLifecycleAction;
          if (action === "destroy" || action === "purge") {
            confirmFromBody(`app.${action}`, { appName: String(body.appName) }, body);
          }
          const addressNote = action === "purge" && loadState().apps[sanitizeSlug(String(body.appName))]?.trashedAt ? await releaseAddresses(String(body.appName)) : "";
          const output = manageAppLifecycle(
            String(body.appName),
            action,
            body.tailLines ? Number(body.tailLines) : 120
          ) + (addressNote ? `\n${addressNote}` : "");
          // Copies on helper PCs follow this server's copy, in the background.
          let poolNote = "";
          let pool: "updating" | "failed" | undefined;
          const lifeSlug = sanitizeSlug(String(body.appName));
          if (loadState().apps[lifeSlug]?.pool && ["restart", "stop", "start", "rollback", "destroy"].includes(action)) {
            try {
              startPoolJob(action, lifeSlug, (log) => poolAfterLifecycle(lifeSlug, action, log));
              poolNote = "\nCopies on helper PCs are being updated (Helpers screen).";
              pool = "updating";
            } catch (err) {
              poolNote = `\nCopies on helper PCs were not updated: ${err instanceof Error ? err.message : String(err)}`;
              pool = "failed";
            }
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ output: output + poolNote, ...(pool ? { pool } : {}) }));
          return true;
        }

        const reply = (data: unknown) => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(data));
          return true;
        };

        if (pathname === "/api/tokens" && req.method === "GET") return reply({ tokens: listTokens() });
        if (pathname === "/api/tokens" && req.method === "POST") {
          const body = await readJsonBody(req);
          const { token, record } = createToken(String(body.name || "ai"), String(body.level || "deploy") as TokenLevel);
          return reply({ token, id: record.id, name: record.name, level: record.level });
        }
        if (pathname === "/api/tokens" && req.method === "DELETE") {
          const body = await readJsonBody(req);
          return reply({ revoked: revokeToken(String(body.id || "")) });
        }

        if (pathname === "/api/scale" && req.method === "GET") {
          const lang: DiaryLang = url.searchParams.get("lang") === "en" ? "en" : "pt";
          const status = scaleStatus({ lang });
          const wanted = url.searchParams.get("app");
          const app = status.apps.find((a) => a.app === wanted)?.app ?? status.apps[0]?.app;
          const st = loadState();
          return reply({
            ...status,
            app: app || null,
            history: app ? scaleHistory(app, { bucketMinutes: 5 }) : null,
            diary: app ? scaleDiary({ app, lang, limit: 30 }) : [],
            pool: app
              ? {
                  readiness: poolReadiness(app, st),
                  helpers: Object.keys(st.pool?.helpers || {}).length,
                  copies: (st.apps[app]?.pool?.placed || []).map((c) => ({ helper: c.helper, since: c.startedAt })),
                  job: poolJob || null,
                }
              : null,
          });
        }
        if (pathname === "/api/scale/rule" && req.method === "POST") {
          const body = await readJsonBody(req);
          const input: Record<string, unknown> = {};
          for (const k of ["min", "max", "targetCpu", "targetRps", "upRounds", "downAfterSeconds", "cooldownSeconds"]) if (body[k] !== undefined) input[k] = body[k];
          confirmFromBody("scale.rule", ruleRiskParams(String(body.appName || ""), input), body);
          return reply(setScaleRule(String(body.appName || ""), input, actor));
        }
        if (pathname === "/api/scale/auto" && req.method === "POST") {
          const body = await readJsonBody(req);
          const slug = sanitizeSlug(String(body.appName || ""));
          if (body.enabled !== true) return reply(await setAutoScale(slug, false, { by: actor }));
          const input = { min: body.min, max: body.max };
          confirmFromBody("scale.auto", autoRiskParams(slug, input), body);
          return reply({ job: startPoolJob("auto", slug, (log) => setAutoScale(slug, true, { ...input, by: actor, log })) });
        }
        if (pathname === "/api/scale/language" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(setDiaryLanguage(String(body.language || "")));
        }
        if (pathname === "/api/scale/copies" && req.method === "POST") {
          const body = await readJsonBody(req);
          const slug = sanitizeSlug(String(body.appName || ""));
          const app = loadState().apps[slug];
          if (!app) throw new Error(`App '${slug}' not found.`);
          if (app.scale?.auto) throw new Error(`Automatic scaling is on for '${slug}': it sets the copies within the rule. Change the minimum or maximum, turn it off, or stop everything.`);
          const copies = Number(body.copies);
          if (!Number.isInteger(copies) || copies < 1 || copies > 20) throw new Error("Copies must be a whole number from 1 to 20.");
          if (copies > 1) {
            const ready = poolReadiness(slug);
            if (!ready.ok) throw new Error(`App '${slug}' cannot have copies on helpers yet:\n- ${ready.problems.join("\n- ")}`);
          }
          confirmFromBody("app.pool", { appName: slug, copies, enabling: !app.pool?.enabled, max: ruleFor(app).max }, body);
          return reply({ job: startPoolJob("copies", slug, (log) => setCopies(slug, copies, { by: actor, log })) });
        }
        if (pathname === "/api/scale/off" && req.method === "POST") {
          const body = await readJsonBody(req);
          const slug = sanitizeSlug(String(body.appName || ""));
          return reply({ job: startPoolJob("off", slug, (log) => disablePool(slug, { by: actor, log })) });
        }

        if (pathname === "/api/pool" && req.method === "GET") {
          return reply({ ...(await poolStatus({ probe: url.searchParams.get("probe") === "1" })), job: poolJob || null, acl: poolAcl() });
        }
        if (pathname === "/api/pool/job" && req.method === "GET") return reply({ job: poolJob || null });
        if (pathname === "/api/pool/invite" && req.method === "POST") {
          const body = await readJsonBody(req);
          const name = validateHelperName(String(body.name || ""));
          confirmFromBody("pool.invite", { helper: name }, body);
          return reply(await createInvite(name, { by: actor }));
        }
        if (pathname === "/api/pool/add" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await addHelper(String(body.name || ""), String(body.ip || ""), { by: actor }));
        }
        if (pathname === "/api/pool/pause" && req.method === "POST") {
          const body = await readJsonBody(req);
          const name = validateHelperName(String(body.name || ""));
          const paused = body.paused === true;
          return reply({ job: startPoolJob(paused ? "pause" : "resume", name, (log) => pauseHelper(name, paused, { by: actor, log })) });
        }
        if (pathname === "/api/pool/courtesy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const name = validateHelperName(String(body.name || ""));
          // Checked before the job starts, so a bad value answers at once.
          validateCourtesy(body.mode, body.cpuPct);
          return reply({ job: startPoolJob("courtesy", name, (log) => setCourtesy(name, body.mode, body.cpuPct, { by: actor, log })) });
        }
        if (pathname === "/api/pool/wake" && req.method === "POST") {
          // Quick (no copies move): answered at once, with the warnings to show on the PC's card.
          const body = await readJsonBody(req);
          return reply(await setWake(String(body.name || ""), body.action, { by: actor }));
        }
        if (pathname === "/api/pool/remove" && req.method === "POST") {
          const body = await readJsonBody(req);
          const name = validateHelperName(String(body.name || ""));
          confirmFromBody("pool.remove", { helper: name }, body);
          return reply({ job: startPoolJob("remove", name, (log) => removeHelper(name, { by: actor, log })) });
        }

        if (pathname === "/api/poll" && req.method === "POST") {
          const body = await readJsonBody(req);
          if (String(body.appName || "") === DASHBOARD_APP_NAME) {
            // The dashboard itself: follow a branch (built + tested in its own folder, rollback on failure).
            if (body.on !== true) {
              setFollow(false);
              return reply({ controlPlane: followStatus() });
            }
            const known = followStatus();
            const repoUrl = known.repoUrl || originOf(path.resolve(path.dirname(new URL(import.meta.url).pathname), ".."));
            if (!repoUrl) throw new Error("Unknown repository: run `paasmcp dashboard follow --repo <git URL>` once on the server.");
            const branch = known.branch || "main";
            confirmFromBody("dashboard.follow", { repoUrl, branch }, body);
            setFollow(true, { repoUrl, branch });
            return reply({ controlPlane: followStatus() });
          }
          return reply(setPolling(String(body.appName || ""), body.on === true));
        }

        if (pathname === "/api/backups/sync" && req.method === "POST") return reply(await syncOffsite());

        // Off-site destination (receiving side) and keys for other computers (providing side).
        if (pathname === "/api/offsite" && req.method === "GET") {
          return reply({ target: offsiteSummary(), grants: await listBackupGrants() });
        }
        if (pathname === "/api/offsite/target" && req.method === "POST") {
          const body = await readJsonBody(req);
          const r = await saveOffsiteTarget(
            {
              provider: String(body.provider || ""),
              accountId: body.accountId ? String(body.accountId) : undefined,
              region: body.region ? String(body.region) : undefined,
              endpoint: body.endpoint ? String(body.endpoint) : undefined,
              bucket: body.bucket ? String(body.bucket) : undefined,
              accessKeyId: body.accessKeyId ? String(body.accessKeyId) : undefined,
              secretAccessKey: body.secretAccessKey ? String(body.secretAccessKey) : undefined,
              prefix: body.prefix ? String(body.prefix) : undefined,
              code: body.code ? String(body.code) : undefined,
            },
            (params) => confirmFromBody("backup.target", params, body)
          );
          return reply(r);
        }
        if (pathname === "/api/offsite/test" && req.method === "POST") return reply(await retestOffsiteTarget());
        if (pathname === "/api/offsite/clear" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await clearOffsiteTarget((params) => confirmFromBody("backup.target.clear", params, body)));
        }
        if (pathname === "/api/offsite/grants" && req.method === "POST") {
          const body = await readJsonBody(req);
          const r = await createBackupGrant(
            String(body.name || ""),
            { maxGb: body.maxGb === undefined || body.maxGb === "" || body.maxGb === null ? undefined : Number(body.maxGb) },
            (params) => confirmFromBody("backup.grant", params, body)
          );
          // The secret is in this answer only: never cached, never logged.
          res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
          res.end(JSON.stringify(r));
          return true;
        }
        if (pathname === "/api/offsite/grants/revoke" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await revokeBackupGrant(String(body.name || "")));
        }

        // Connections (Cloudflare, GitHub): tokens come in to be tested or saved, never go back out.
        if (pathname === "/api/connections" && req.method === "GET") return reply(connectionsSummary());
        if (pathname === "/api/connections/cloudflare/discover" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await discoverCloudflare(body.token));
        }
        if (pathname === "/api/connections/cloudflare" && req.method === "POST") {
          const body = await readJsonBody(req);
          const r = await saveCloudflare(
            {
              token: typeof body.token === "string" ? body.token : undefined,
              accountId: String(body.accountId || ""),
              baseDomain: String(body.baseDomain || ""),
              tunnelId: String(body.tunnelId || ""),
              runHere: body.runHere === true,
              zeroTrustEmails: typeof body.zeroTrustEmails === "string" || Array.isArray(body.zeroTrustEmails) ? (body.zeroTrustEmails as string | string[]) : undefined,
            },
            (params) => confirmFromBody("connect.cloudflare", params, body)
          );
          return reply({ ...r, summary: connectionsSummary() });
        }
        if (pathname === "/api/connections/github/repos" && req.method === "GET") return reply({ repos: await listGitHubRepos() });
        // Push notices: the saved token creates or fixes the webhook on the apps' repositories.
        if (pathname === "/api/connections/github/webhooks" && req.method === "GET") {
          const apps = Object.values(loadState().apps).map((a) => ({ name: a.name, repoUrl: a.repoUrl }));
          return reply({ repos: await listRepoHooks(apps, url.searchParams.get("address")) });
        }
        if (pathname === "/api/connections/github/webhooks" && req.method === "POST") {
          const body = await readJsonBody(req);
          // Only repositories that an app here is published from: the token may reach many more.
          const repo = githubRepoOf(body.repo).toLowerCase();
          if (!repo || !Object.values(loadState().apps).some((a) => githubRepoOf(a.repoUrl).toLowerCase() === repo)) {
            throw new ConnectionError("No app here is published from this repository.", "Nenhum app daqui é publicado deste repositório.");
          }
          return reply(await ensureRepoHook(body.repo, body.address, getOrCreateWebhookSecret()));
        }
        if (pathname === "/api/connections/github" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await checkGitHub(body.token));
        }
        // Notices (Discord, Slack, ntfy): a test notice must arrive before the address is saved.
        if (pathname === "/api/connections/notify" && req.method === "GET") return reply(notifySummary());
        if (pathname === "/api/connections/notify" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await saveNotify({ url: String(body.url || ""), onSuccess: Boolean(body.onSuccess), lang: String(body.lang || "pt") }));
        }
        if (pathname === "/api/connections/notify" && req.method === "DELETE") {
          clearNotify();
          return reply(notifySummary());
        }

        if (pathname === "/api/storage" && req.method === "GET") return reply({ storage: listStorage() });
        if (pathname === "/api/storage" && req.method === "POST") {
          const body = await readJsonBody(req);
          const { record, reused } = await provisionStorage(String(body.appName || ""));
          return reply({ record, reused });
        }

        if (pathname === "/api/email" && req.method === "GET") {
          const r = getEmailRelay();
          return reply({ relay: r && { host: r.host, port: r.port, user: r.user, fromDomain: r.fromDomain, apiKey: Boolean(r.apiKey) } });
        }
        if (pathname === "/api/email" && req.method === "POST") {
          const body = await readJsonBody(req);
          const current = getEmailRelay();
          // An empty password keeps the saved one, so the form never has to show it back.
          const password = String(body.password || "") || current?.password || "";
          if (!password) throw new Error("Password or API key is required.");
          setEmailRelay({ host: String(body.host || ""), port: Number(body.port || 587), user: String(body.user || ""), password, fromDomain: String(body.fromDomain || "") });
          return reply({ ok: true });
        }
        if (pathname === "/api/email/test" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(await sendTestEmail(String(body.to || "")));
        }
        if (pathname === "/api/email/provision" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(provisionEmail(String(body.appName || ""), body.fromName ? String(body.fromName) : undefined));
        }

        if (pathname === "/api/updates" && req.method === "GET") return reply({ updates: await checkUpdates() });
        if (pathname === "/api/updates/apply" && req.method === "POST") {
          const body = await readJsonBody(req);
          const component = String(body.component) as Component;
          if (!PINNED[component]) throw new Error("'component' must be postgres, redis or garage.");
          const image = body.image ? String(body.image) : (await checkUpdates()).find((u) => u.component === component)?.available;
          if (!image) throw new Error(`${component} is already on the newest release of its major version.`);
          confirmFromBody("update.apply", { component, image }, body);
          return reply(applyUpdate(component, image));
        }

        if (pathname === "/api/mirror" && req.method === "GET") return reply(mirrorStatus());
        if (pathname === "/api/mirror/offer" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(
            await offerMirror({
              peerName: String(body.peer || ""),
              peerCidr: String(body.peerIp || ""),
              fromCopyOf: body.fromCopyOf ? String(body.fromCopyOf) : undefined,
            })
          );
        }
        if (pathname === "/api/mirror/accept" && req.method === "POST") {
          const body = await readJsonBody(req);
          const rejoin = body.rejoin === true;
          if (rejoin && !loadState().mirror?.fenced) confirmFromBody("mirror.rejoin", {}, body);
          return reply(acceptMirror(String(body.token || ""), { rejoin }));
        }
        if (pathname === "/api/mirror/promote" && req.method === "POST") {
          const body = await readJsonBody(req);
          const peer = String(body.peer || "");
          confirmFromBody("mirror.promote", { peer }, body);
          return reply(await promoteMirror(peer));
        }
        if (pathname === "/api/mirror/retire" && req.method === "POST") {
          const body = await readJsonBody(req);
          const peer = String(body.peer || "");
          confirmFromBody("mirror.retire", { peer }, body);
          return reply(retireCopy(peer));
        }
        if (pathname === "/api/mirror/handback" && req.method === "POST") {
          const body = await readJsonBody(req);
          const peer = String(body.peer || "");
          confirmFromBody("mirror.handback", { peer }, body);
          return reply(await handbackMirror(peer));
        }
        // Test the arbiter (the saved one, or ?url= typed in the form before saving). A plain heartbeat.
        if (pathname === "/api/mirror/arbiter" && req.method === "GET") return reply(await checkArbiter(url.searchParams.get("url") || undefined));
        // The arbiter's install command with this cluster's key already in it (same as `paasmcp arbiter key`).
        // POST and no-store: the key only works on the arbiter, but it should not sit in caches or history.
        if (pathname === "/api/mirror/arbiter/install" && req.method === "POST") {
          const repo = followStatus().repoUrl || originOf(path.resolve(path.dirname(new URL(import.meta.url).pathname), ".."));
          const out = arbiterInstallCommand(repo);
          audit({ event: "mirror.arbiter-key-shown", by: actor, cluster: out.cluster });
          res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
          res.end(JSON.stringify(out));
          return true;
        }
        if (pathname === "/api/mirror/arbiter" && req.method === "POST") {
          const body = await readJsonBody(req);
          return reply(setArbiterUrl(String(body.url || "")));
        }
        // App on both servers (active.ts) and the self-hosted entry (edge.ts).
        if (pathname === "/api/active" && req.method === "GET") {
          const state = loadState();
          const candidates = Object.values(state.apps)
            .filter((a) => !a.originNodeId && !a.trashedAt && a.name !== "paasmcp-dashboard")
            .map((a) => ({ ...activeReadiness(a.name, state), on: Boolean(a.activeActive) }));
          return reply({ ...activeStatus(state), candidates, edge: await edgeStatus(), tunnel: activeTunnelStatus(state) });
        }
        if (pathname === "/api/active" && req.method === "POST") {
          const body = await readJsonBody(req);
          const appName = sanitizeSlug(String(body.appName || ""));
          const on = body.on === true;
          if (on) {
            const ready = activeReadiness(appName);
            if (!ready.ok) throw new Error(ready.problems.join(" "));
            confirmFromBody("app.active", { appName }, body);
          }
          return reply(await switchActiveActive(appName, on));
        }
        if (pathname === "/api/active/tunnel" && req.method === "POST") {
          const body = await readJsonBody(req);
          if (body.on === true) {
            confirmFromBody("active.tunnel", {}, body);
            return reply(await enableActiveTunnel());
          }
          return reply(await disableActiveTunnel());
        }
        if (pathname === "/api/edge/site" && req.method === "POST") {
          const body = await readJsonBody(req);
          const appName = sanitizeSlug(String(body.appName || ""));
          if (body.remove === true) return reply(removeEdgeSite(String(body.hostname || "")));
          confirmFromBody("app.expose", { appName, mode: "public" }, body);
          return reply(addEdgeSite(appName, String(body.hostname || "")));
        }
        if (pathname === "/api/mirror/auto" && req.method === "POST") {
          const body = await readJsonBody(req);
          const peer = String(body.peer || "");
          const on = body.on === true;
          const arbiterUrl = body.arbiterUrl ? String(body.arbiterUrl) : undefined;
          if (on) confirmFromBody("mirror.auto", { peer, arbiterUrl }, body);
          return reply(setAutoFailover(peer, on, arbiterUrl));
        }
        return false;
      };

      try {
        const handled = req.method === "GET" ? await handleApi() : await withStateLock(handleApi);
        if (handled) return;
      } catch (err) {
        if (err instanceof ConfirmationRequiredError) {
          res.writeHead(409, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              confirmationRequired: true,
              level: err.risk.level,
              subject: err.risk.subject,
              warning: err.risk.warning,
            })
          );
          return;
        }
        // Input mistakes answer 400; OffsiteError also carries the Portuguese text for the screen.
        const userError = err instanceof OffsiteError || err instanceof ConnectionError || err instanceof NotifyError || err instanceof ExposeError;
        const status = err instanceof ForbiddenActionError ? 403 : userError ? 400 : 500;
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: err instanceof Error ? err.message : String(err),
            ...(userError ? { errorPt: (err as OffsiteError | ConnectionError | NotifyError | ExposeError).pt } : {}),
          })
        );
        return;
      }
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  server.listen(port, host);
  // In the dashboard container the dashboard also does the auto-deploy checks, so no timer is needed.
  const stopPolling = startPollLoop();
  server.on("close", stopPolling);
  // ...and it notices apps that stop on their own (a notice only when Connections → Notices is set up).
  const stopWatch = startAppWatch();
  server.on("close", stopWatch);
  // ...and it makes the nightly backup, so no systemd timer has to be installed by hand.
  const stopNightly = startNightlyLoop();
  server.on("close", stopNightly);
  return server;
}

function escapeHtmlServer(s?: string): string {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderDashboardHtml(authed: boolean, cfEmail?: string, twoFactor = false): string {
  const safeCfEmail = cfEmail ? escapeHtmlServer(cfEmail) : "";
  const sharedCss = `
    :root, [data-theme="dark"] {
      --bg: #121720;
      --bg-elevated: #181e29;
      --bg-subtle: #1e2532;
      --card: #181e29;
      --card-hover: #1e2533;
      --border: #29324a;
      --border-strong: #3a465f;
      --text: #f1f5f9;
      --muted: #8896aa;
      --input-bg: #10141c;
      --accent: #00f0ff;
      --accent-hover: #38bdf8;
      --accent-soft: rgba(0, 240, 255, 0.12);
      --accent-text: #00f0ff;
      --success: #00f59b;
      --success-soft: rgba(0, 245, 155, 0.12);
      --warning: #f59e0b;
      --warning-soft: rgba(245, 158, 11, 0.12);
      --danger: #ff4757;
      --danger-soft: rgba(255, 71, 87, 0.12);
      --code-bg: #0f131a;
      --code-text: #00f0ff;
      --shadow: 0 4px 20px -4px rgba(0, 0, 0, 0.4);
    }
    /* Light theme: soft blue-grey tones, never plain white (easier on the eyes), with readable contrast */
    [data-theme="light"] {
      --bg: #e3e8ee;
      --bg-elevated: #ecf0f4;
      --bg-subtle: #dbe1e8;
      --card: #ecf0f4;
      --card-hover: #e6ebf0;
      --border: #c7d0db;
      --border-strong: #a9b5c3;
      --text: #141d28;
      --muted: #4b5a6b;
      --input-bg: #f2f4f7;
      --accent: #0369a1;
      --accent-hover: #075985;
      --accent-soft: rgba(3, 105, 161, 0.11);
      --accent-text: #035a8a;
      --success: #047857;
      --success-soft: rgba(4, 120, 87, 0.11);
      --warning: #a16207;
      --warning-soft: rgba(161, 98, 7, 0.11);
      --danger: #b91c1c;
      --danger-soft: rgba(185, 28, 28, 0.10);
      --code-bg: #dce3ea;
      --code-text: #075985;
      --shadow: 0 1px 3px rgba(20, 29, 40, 0.08);
    }
    * { box-sizing: border-box; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
    }
    a { color: var(--accent-text); text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    code, pre {
      background: var(--code-bg);
      color: var(--code-text);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 6px;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
    }
    pre {
      padding: 14px;
      overflow-x: auto;
      max-height: 360px;
      line-height: 1.55;
      margin: 8px 0 0;
    }
    input, select, textarea {
      padding: 9px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--input-bg);
      color: var(--text);
      font-size: 13px;
      width: 100%;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    input:focus, select:focus, textarea:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }
    button {
      padding: 8px 14px;
      border-radius: 8px;
      border: 1px solid transparent;
      background: var(--accent);
      color: #07090e;
      font-weight: 600;
      font-size: 12.5px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
      white-space: nowrap;
    }
    [data-theme="light"] button {
      color: #ffffff;
    }
    button:hover:not(:disabled) {
      filter: brightness(1.1);
      transform: translateY(-1px);
    }
    button:active:not(:disabled) {
      transform: translateY(0);
    }
    button:disabled { opacity: 0.55; cursor: not-allowed; }
    button.secondary {
      background: var(--bg-subtle);
      border-color: var(--border);
      color: var(--text);
    }
    [data-theme="light"] button.secondary {
      color: var(--text);
    }
    button.secondary:hover:not(:disabled) {
      background: var(--card-hover);
      border-color: var(--border-strong);
      color: var(--text);
    }
    button.danger {
      background: var(--danger-soft);
      border-color: rgba(239, 68, 68, 0.3);
      color: var(--danger);
    }
    button.chip {
      padding: 4px 10px;
      font-size: 11px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent-text);
      border: 1px solid rgba(99, 102, 241, 0.25);
      font-weight: 500;
    }
    button.chip:hover, button.chip.selected { background: var(--accent); color: #07090e; }
    [data-theme="light"] button.chip:hover, [data-theme="light"] button.chip.selected { color: #ffffff; }
    .ofs-h { font-size: 14px; margin: 14px 0 6px; }
    .ofs-note { font-size: 12.5px; color: var(--muted); margin: 0 0 8px; line-height: 1.5; }
    .ofs-chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
    .ofs-chips button.chip { font-size: 12px; padding: 6px 12px; }
    .ofs-msg { font-size: 12.5px; margin-top: 8px; line-height: 1.5; }
    .ofs-msg.err { color: var(--danger); }
    .ofs-msg.ok { color: var(--success, #22c55e); }
    .ofs-secret { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; padding: 8px 10px; border-radius: 8px; background: var(--bg-subtle); border: 1px solid var(--border); margin: 4px 0 8px; }
    .ofs-kv { display: grid; grid-template-columns: max-content 1fr auto; gap: 4px 10px; align-items: center; font-size: 12.5px; }
    .ofs-kv code { word-break: break-all; }
    @media (max-width: 560px) { .ofs-kv { grid-template-columns: 1fr auto; } .ofs-kv .k { grid-column: 1 / -1; color: var(--muted); } }
    .tut-row { display: flex; gap: 12px; align-items: center; padding: 11px 14px; margin-bottom: 8px; border-radius: 10px; background: var(--bg-subtle); border: 1px solid var(--border); font-size: 13px; }
    .tut-check { flex: 0 0 22px; height: 22px; border-radius: 50%; border: 2px solid var(--border); display: inline-flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; color: #fff; }
    .tut-done .tut-check { background: var(--success, #22c55e); border-color: var(--success, #22c55e); }
    .tut-done .tut-text strong { color: var(--muted); }
    .tut-text { flex: 1; min-width: 0; }
    .tut-desc { color: var(--muted); margin-top: 3px; line-height: 1.5; }
    .tut-guide { margin-left: 4px; white-space: nowrap; }
    .tut-act { flex: 0 0 auto; }
    .tut-bar { height: 8px; border-radius: 99px; background: var(--bg-subtle); border: 1px solid var(--border); overflow: hidden; }
    .tut-bar span { display: block; height: 100%; background: var(--success, #22c55e); transition: width .4s ease; }
    .tut-count { font-size: 12.5px; color: var(--muted); margin: 6px 0 4px; }
    .guide-steps { margin: 0; padding-left: 22px; display: grid; gap: 16px; }
    .guide-step { font-size: 13.5px; line-height: 1.5; padding-left: 4px; }
    .guide-step::marker { font-weight: 700; color: var(--accent, var(--text)); }
    @media (max-width: 560px) { .tut-row { flex-wrap: wrap; } .tut-act { margin-left: 34px; } }
    .sec-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 8px 10px; margin-bottom: 6px; border-radius: 8px; background: var(--bg-subtle); border: 1px solid var(--border); font-size: 12.5px; flex-wrap: wrap; }
    .sec-k { min-width: 0; word-break: break-all; }
    .sec-act { display: flex; gap: 6px; }
    .sec-act button { padding: 3px 9px; font-size: 11px; }
    .sec-apply.changed { color: var(--text); border-left: 3px solid var(--warning, #d97706); padding-left: 8px; }
    .sec-paste summary { cursor: pointer; font-size: 13px; font-weight: 600; }
    .sec-paste textarea { width: 100%; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .dep-more { margin: 4px 0 14px; }
    .dep-more summary { cursor: pointer; font-size: 13px; font-weight: 600; margin-bottom: 4px; }
    .dep-pick { margin: -4px 0 14px; max-width: 520px; }
    .nt-list { margin: 0 0 12px; padding-left: 18px; }
    .bak-nightly { font-size: 12.5px; margin: 0 0 14px; padding: 10px 12px; border-radius: 8px; background: var(--bg-subtle); border: 1px solid var(--border); line-height: 1.5; }
    .bak-nightly.err { border-color: var(--danger); }
    .tpl-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; }
    .tpl-item { border: 1px solid var(--border); border-radius: 10px; padding: 12px; display: flex; flex-direction: column; gap: 6px; font-size: 12.5px; }
    .tpl-item strong { font-size: 13.5px; }
    .tpl-item p { margin: 0; color: var(--muted); flex: 1; }
    .tpl-item .tpl-row { display: flex; gap: 6px; align-items: center; justify-content: space-between; }
    .nt-list li { margin-bottom: 4px; }
    .dep-result { margin-top: 14px; padding: 12px 14px; border-radius: 10px; font-size: 13px; line-height: 1.5; max-width: 720px; }
    .dep-result.ok { background: var(--success-soft); }
    .dep-result.err { background: var(--danger-soft); }
    .dep-result p { margin: 4px 0 8px; }
    .dep-result-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .dep-result details { margin-top: 8px; }
    .dep-result summary { cursor: pointer; font-size: 12.5px; }
    .dep-result pre { white-space: pre-wrap; word-break: break-word; max-height: 320px; overflow: auto; font-size: 11.5px; margin: 6px 0 0; }
    .preset-hint { display: none; margin: -4px 0 12px; font-size: 12px; color: var(--muted); line-height: 1.5; }
    .preset-hint.show { display: block; }
    .badge {
      background: var(--accent-soft);
      color: var(--accent-text);
      border: 1px solid rgba(99, 102, 241, 0.25);
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 11.5px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .badge.success {
      background: var(--success-soft);
      color: var(--success);
      border-color: rgba(16, 185, 129, 0.3);
    }
    .badge.warning {
      background: var(--warning-soft);
      color: var(--warning);
      border-color: rgba(245, 158, 11, 0.3);
    }
    .badge.danger {
      background: var(--danger-soft);
      color: var(--danger);
      border-color: rgba(239, 68, 68, 0.3);
    }
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--card);
      color: var(--text);
      border: 1px solid var(--accent);
      box-shadow: var(--shadow);
      padding: 12px 18px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 500;
      z-index: 9999;
      display: none;
    }
  `;

  if (!authed) {
    return `<!DOCTYPE html>
<html lang="pt-BR" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PaaSMCP — Control Plane Login</title>
  <style>
    ${sharedCss}
    body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 20px; background: radial-gradient(circle at 50% 0%, rgba(99,102,241,0.14), transparent 55%), var(--bg); }
    .login-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: var(--shadow);
    }
    .login-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
    h1 { margin: 0 0 8px; font-size: 22px; display: flex; align-items: center; gap: 10px; letter-spacing: -0.02em; }
    p { margin: 0 0 20px; color: var(--muted); font-size: 13.5px; line-height: 1.55; }
    .err { color: var(--danger); font-size: 13px; margin-top: 12px; display: none; }
    .help-box {
      margin-top: 20px;
      padding: 12px;
      border-radius: 10px;
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      font-size: 12px;
      color: var(--muted);
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="login-top">
      <span class="badge">Agent-First Micro-PaaS</span>
      <div style="display:flex;gap:6px;">
        <button class="secondary" onclick="toggleLang()" id="langBtn" style="padding:5px 10px;font-size:11.5px;">🇧🇷 PT-BR</button>
        <button class="secondary" onclick="toggleTheme()" id="themeBtn" style="padding:5px 10px;font-size:11.5px;">☀️ Light</button>
      </div>
    </div>
    <h1 style="display:flex;align-items:center;gap:10px;">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2" style="stroke: var(--accent); fill: var(--accent-soft); fill-opacity: 0.3;"></rect>
        <circle cx="7" cy="10" r="1.5" fill="var(--accent)"></circle>
        <path d="M12 7l3 3-3 3"></path>
        <path d="M7 17v4"></path>
        <path d="M17 17v4"></path>
      </svg>
      <span>PaaSMCP</span>
    </h1>
    <p id="loginDesc"></p>
    ${safeCfEmail ? `<div style="margin-bottom:16px;"><span class="badge success">✓ Cloudflare Zero Trust: ${safeCfEmail}</span></div>` : ""}
    <input type="password" id="token" placeholder="Token..." autofocus style="margin-bottom: 14px;" />
    ${twoFactor ? `<input type="text" id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" aria-label="2FA" style="margin-bottom: 14px;" />` : ""}
    <button onclick="doLogin()" style="width:100%; padding: 11px;" id="loginBtn"></button>
    <div class="err" id="err"></div>
    <div class="help-box">
      <strong id="helpTitle"></strong><br/>
      <code>paasmcp dashboard token</code>
    </div>
  </div>
  <script>
    const I18N_LOGIN = {
      pt: {
        desc: "Workspace de infraestrutura para Agentes de IA e Humanos. Gerencie deploys GitHub, bancos PostgreSQL/Redis, Cofre AES-256-GCM, Webhooks e Cluster Multi-Servidor.",
        placeholder: "Cole seu DASHBOARD_TOKEN...",
        btn: "Entrar no Control Plane",
        err: "Token inválido ou limite de tentativas excedido.",
        help: "💡 Consulte o token no terminal do servidor:"
      },
      en: {
        desc: "Infrastructure workspace for AI Agents and Humans. Manage GitHub deploys, PostgreSQL/Redis, AES-256-GCM Vault, Webhooks, and Multi-Server HA Clusters.",
        placeholder: "Paste your DASHBOARD_TOKEN...",
        btn: "Sign In to Control Plane",
        err: "Invalid access token or rate limit exceeded.",
        help: "💡 Retrieve your token in the server terminal:"
      }
    };
    let currentLang = localStorage.getItem('paasmcp_lang') || ((navigator.language || '').toLowerCase().startsWith('pt') ? 'pt' : 'en');
    let currentTheme = localStorage.getItem('paasmcp_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    function applyPrefs() {
      const isPt = currentLang === 'pt';
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.getElementById('themeBtn').textContent = currentTheme === 'dark' ? (isPt ? '☀️ Claro' : '☀️ Light') : (isPt ? '🌙 Escuro' : '🌙 Dark');
      document.getElementById('langBtn').textContent = isPt ? '🇧🇷 PT-BR' : '🇺🇸 EN';
      const t = I18N_LOGIN[currentLang];
      document.getElementById('loginDesc').textContent = t.desc;
      document.getElementById('token').placeholder = t.placeholder;
      document.getElementById('loginBtn').textContent = t.btn;
      document.getElementById('err').textContent = t.err;
      document.getElementById('helpTitle').textContent = t.help;
    }
    function toggleTheme() { currentTheme = currentTheme === 'dark' ? 'light' : 'dark'; localStorage.setItem('paasmcp_theme', currentTheme); applyPrefs(); }
    function toggleLang() { currentLang = currentLang === 'pt' ? 'en' : 'pt'; localStorage.setItem('paasmcp_lang', currentLang); applyPrefs(); }
    async function doLogin() {
      const token = document.getElementById('token').value.trim();
      const codeEl = document.getElementById('code');
      const code = codeEl ? codeEl.value.trim() : undefined;
      const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, code }) });
      if (res.ok) location.reload();
      else document.getElementById('err').style.display = 'block';
    }
    document.getElementById('token').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    if (document.getElementById('code')) document.getElementById('code').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    applyPrefs();
  </script>
</body>
</html>`;
  }

  return `<!DOCTYPE html>
<html lang="pt-BR" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PaaSMCP — Workspace & Control Plane</title>
  <style>
    ${sharedCss}
    /* Top Console Header */
    .console-header {
      background: var(--card);
      border-bottom: 1px solid var(--border);
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }
    .console-header-left {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }
    .console-logo-link {
      display: inline-flex;
      align-items: center;
      gap: 9px;
      color: var(--text);
      text-decoration: none;
      font-weight: 700;
      font-size: 15px;
      letter-spacing: -0.01em;
    }
    .console-logo-link:hover {
      text-decoration: none;
    }
    .brand-icon-svg {
      width: 22px;
      height: 22px;
      flex-shrink: 0;
    }
    .host-badge-capsule {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace;
    }
    .engine-status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      background: var(--success-soft);
      border: 1px solid rgba(0, 245, 155, 0.35);
      color: var(--success);
    }
    @keyframes radar-ping {
      0% {
        transform: scale(0.95);
        box-shadow: 0 0 0 0 rgba(0, 245, 155, 0.7);
      }
      70% {
        transform: scale(1);
        box-shadow: 0 0 0 6px rgba(0, 245, 155, 0);
      }
      100% {
        transform: scale(0.95);
        box-shadow: 0 0 0 0 rgba(0, 245, 155, 0);
      }
    }
    .engine-status-dot, .telemetry-title .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 8px rgba(0, 245, 155, 0.6);
      animation: radar-ping 2.2s cubic-bezier(0, 0, 0.2, 1) infinite;
      display: inline-block;
      flex-shrink: 0;
    }

    /* Left side navigation (collapsible), like GitHub: sections, items, nested pages */
    .console-header { position: sticky; top: 0; z-index: 30; }
    button.nav-toggle-mobile { display: none; padding: 6px; background: transparent; border: 1px solid var(--border); color: var(--text); }
    .console-sidenav {
      position: sticky;
      top: 64px;
      align-self: start;
      max-height: calc(100vh - 80px);
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 1px;
      padding: 4px 2px 12px;
    }
    .sidenav-head { display: flex; justify-content: flex-end; padding: 0 4px 4px; }
    button.sidenav-collapse {
      padding: 5px; background: transparent; border: 1px solid transparent; color: var(--muted); border-radius: 6px; display: inline-flex;
    }
    button.sidenav-collapse:hover { color: var(--text); background: var(--accent-soft); transform: none; filter: none; }
    button.nav-section {
      display: flex;
      align-items: center;
      justify-content: flex-start;
      gap: 6px;
      width: 100%;
      font-size: 11px;
      font-weight: 650;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      padding: 14px 10px 4px 13px;
      background: transparent;
      border: 0;
      border-radius: 6px;
      box-shadow: none;
      cursor: pointer;
    }
    button.nav-section:hover { color: var(--text); background: transparent; transform: none; filter: none; }
    .nav-chevron { flex-shrink: 0; transition: transform 0.28s cubic-bezier(0.32, 0.72, 0, 1), opacity 0.2s ease; }
    button.nav-section[aria-expanded="false"] .nav-chevron { transform: rotate(-90deg); }
    /* Section groups open and close with a smooth height animation (grid rows 1fr <-> 0fr). */
    .nav-group { display: grid; grid-template-rows: 1fr; transition: grid-template-rows 0.32s cubic-bezier(0.32, 0.72, 0, 1), opacity 0.24s ease; }
    .nav-group.closed { grid-template-rows: 0fr; opacity: 0; }
    .nav-group-inner { min-height: 0; overflow: hidden; display: flex; flex-direction: column; gap: 1px; padding-left: 2px; }
    /* Icon-only menu: groups always open, so every icon stays reachable. */
    .nav-collapsed .nav-group.closed { grid-template-rows: 1fr; opacity: 1; }
    .nav-collapsed .nav-chevron { opacity: 0; }
    .console-sidenav { scrollbar-width: thin; scrollbar-color: transparent transparent; }
    .console-sidenav:hover { scrollbar-color: var(--border-strong) transparent; }
    .console-sidenav::-webkit-scrollbar { width: 6px; }
    .console-sidenav::-webkit-scrollbar-thumb { background: transparent; border-radius: 3px; }
    .console-sidenav:hover::-webkit-scrollbar-thumb { background: var(--border-strong); }
    button.nav-item {
      position: relative;
      display: flex;
      align-items: center;
      gap: 10px;
      width: 100%;
      padding: 7px 10px;
      font-size: 13.5px;
      font-weight: 500;
      color: var(--text);
      background: transparent;
      border: 0;
      border-radius: 7px;
      text-align: left;
      justify-content: flex-start;
      cursor: pointer;
      white-space: nowrap;
      box-shadow: none;
    }
    button.nav-item:hover { background: var(--accent-soft); color: var(--text); transform: none; filter: none; }
    button.nav-item.active { background: var(--accent-soft); font-weight: 650; color: var(--text); }
    button.nav-item.active::before {
      content: ""; position: absolute; left: -2px; top: 6px; bottom: 6px; width: 3px; border-radius: 0 3px 3px 0; background: var(--accent);
    }
    .nav-label { flex: 1; overflow: hidden; text-overflow: ellipsis; }
    .nav-icon { width: 16px; height: 16px; flex-shrink: 0; stroke-width: 2; color: var(--muted); }
    button.nav-item:hover .nav-icon, button.nav-item.active .nav-icon { color: var(--accent); }
    .nav-counter {
      padding: 0 7px;
      font-size: 11px;
      font-weight: 600;
      line-height: 18px;
      border-radius: 10px;
      border: 1px solid var(--border-strong);
      color: var(--muted);
      font-variant-numeric: tabular-nums;
      cursor: help;
    }
    .nav-counter:empty, .nav-counter[hidden] { display: none; }
    button.nav-item.active .nav-counter { color: var(--accent-text); border-color: var(--accent); }
    .nav-subs { display: none; flex-direction: column; margin: 2px 0 6px 25px; border-left: 1px solid var(--border); }
    button.nav-item.active + .nav-subs { display: flex; }
    button.nav-sub {
      background: transparent; border: 0; border-radius: 0 6px 6px 0; box-shadow: none;
      text-align: left; justify-content: flex-start; display: flex; padding: 5px 10px; font-size: 13px; font-weight: 500; color: var(--muted); cursor: pointer;
    }
    button.nav-sub:hover { color: var(--text); background: var(--accent-soft); transform: none; filter: none; }
    button.nav-sub.active { color: var(--accent-text); font-weight: 650; }

    .page-head { display: flex; flex-direction: column; gap: 2px; margin: 0 0 12px; }
    .page-crumb { font-size: 12.5px; color: var(--muted); display: flex; gap: 6px; align-items: center; }
    .page-head h1 { margin: 0; font-size: 21px; font-weight: 700; letter-spacing: -0.015em; display: flex; align-items: center; gap: 10px; text-wrap: balance; }
    .page-head h1 .nav-counter { font-size: 12px; }
    .page-lead { margin: 2px 0 0; color: var(--muted); font-size: 13.5px; max-width: 80ch; }
    .page-head .nav-icon { width: 20px; height: 20px; color: var(--accent); }
    /* Folder tabs at the top of a page that has more than one part */
    .page-tabs {
      display: flex;
      gap: 2px;
      border-bottom: 1px solid var(--border);
      margin: 0 0 18px;
      overflow-x: auto;
      overflow-y: hidden;
      scrollbar-width: none;
    }
    .page-tabs::-webkit-scrollbar { display: none; }
    button.page-tab {
      background: transparent; border: 0; border-bottom: 2px solid transparent; border-radius: 0; box-shadow: none;
      padding: 9px 14px; margin-bottom: -1px; font-size: 13.5px; font-weight: 500; color: var(--muted); white-space: nowrap; cursor: pointer;
    }
    button.page-tab:hover { color: var(--text); background: transparent; transform: none; filter: none; }
    button.page-tab.active { color: var(--text); font-weight: 650; border-bottom-color: var(--accent); }
    .tab-pane [data-sub].sub-hidden { display: none !important; }

    /* Three-column workspace: navigation | page | telemetry */
    /* Fills the screen up to 2400 px; the side columns grow on big screens. */
    .console-container {
      --nav-w: 232px;
      --aside-w: 300px;
      max-width: 2400px;
      margin: 18px auto;
      padding: 0 24px;
      display: grid;
      grid-template-columns: var(--nav-w) minmax(0, 1fr) var(--aside-w);
      gap: 24px;
      align-items: start;
      transition: grid-template-columns 0.34s cubic-bezier(0.32, 0.72, 0, 1);
    }
    @media (min-width: 1700px) { .console-container { --nav-w: 252px; --aside-w: 330px; gap: 32px; padding: 0 32px; } }
    @media (min-width: 2200px) { .console-container { --nav-w: 272px; --aside-w: 360px; } }
    .console-container.nav-collapsed { --nav-w: 54px; }
    /* Collapse animation: names fade and shrink while the column narrows; icons stay put. */
    .console-sidenav { overflow-x: hidden; }
    .console-sidenav button.nav-item { padding-left: 15px; overflow: hidden; }
    .console-sidenav .nav-label, .console-sidenav .nav-counter {
      max-width: 200px; opacity: 1;
      transition: opacity 0.2s ease 0.08s, max-width 0.34s cubic-bezier(0.32, 0.72, 0, 1);
    }
    .console-sidenav .nav-section { white-space: nowrap; transition: color 0.2s ease; }
    .console-sidenav .nav-section::after { content: ""; display: block; border-top: 1px solid var(--border); opacity: 0; transition: opacity 0.2s ease; margin-top: -1px; }
    .console-sidenav .nav-subs { overflow: hidden; max-height: 320px; transition: max-height 0.34s cubic-bezier(0.32, 0.72, 0, 1), opacity 0.2s ease; }
    .sidenav-head { justify-content: flex-start; padding-left: 9px; }
    .nav-collapsed .console-sidenav .nav-label, .nav-collapsed .console-sidenav .nav-counter { max-width: 0; opacity: 0; transition: opacity 0.12s ease, max-width 0.3s cubic-bezier(0.32, 0.72, 0, 1); }
    .nav-collapsed .console-sidenav .nav-counter { padding: 0; border-width: 0; }
    .nav-collapsed .console-sidenav .nav-section { color: transparent; }
    .nav-collapsed .console-sidenav .nav-section::after { opacity: 1; }
    .nav-collapsed .console-sidenav .nav-subs { max-height: 0; opacity: 0; margin-top: 0; margin-bottom: 0; }
    @media (prefers-reduced-motion: reduce) {
      .nav-group, .nav-chevron, .console-container, .console-sidenav .nav-label, .console-sidenav .nav-counter, .console-sidenav .nav-subs, .console-sidenav .nav-section, .console-sidenav .nav-section::after { transition: none !important; }
    }
    .console-main {
      min-width: 0;
      display: flex;
      flex-direction: column;
    }
    .console-sidebar {
      display: flex;
      flex-direction: column;
      gap: 16px;
      min-width: 0;
    }
    .nav-scrim { display: none; }
    .header-actions button.icon-only { padding: 7px 9px; }
    .ui-tip {
      position: fixed; z-index: 100; pointer-events: none; max-width: 280px;
      background: var(--text); color: var(--bg); font-size: 12px; font-weight: 500; line-height: 1.35;
      padding: 5px 9px; border-radius: 6px; box-shadow: var(--shadow);
      opacity: 0; transform: translateY(-2px); transition: opacity 0.12s ease, transform 0.12s ease;
    }
    .ui-tip.show { opacity: 1; transform: none; }
    @media (max-width: 1240px) {
      .console-container, .console-container.nav-collapsed { grid-template-columns: 52px minmax(0, 1fr); }
      .console-container .nav-label, .console-container .nav-counter, .console-container .nav-subs { display: none !important; }
      .console-container .nav-section { font-size: 0; padding: 10px 8px 4px; }
      .console-container .nav-section::after { content: ""; display: block; border-top: 1px solid var(--border); opacity: 1; }
      .console-container button.nav-item { justify-content: center; padding: 9px 0; }
      .console-container .sidenav-head { display: none; }
      .console-container .nav-group.closed { grid-template-rows: 1fr; opacity: 1; }
      .console-container .nav-chevron { display: none; }
      .console-sidebar { grid-column: 2; display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; align-items: start; }
      .console-sidebar .telemetry-card { margin-bottom: 0; }
      #statsGrid { display: contents; }
    }
    @media (max-width: 720px) {
      .console-header { padding: 10px 16px; gap: 8px; }
      .console-header .hide-sm, .console-header .btn-text { display: none !important; }
      .header-actions { gap: 6px !important; flex-wrap: nowrap !important; }
      .header-actions button { padding: 6px 9px; }
      button.nav-toggle-mobile { display: inline-flex; }
      .console-container, .console-container.nav-collapsed { grid-template-columns: minmax(0, 1fr); padding: 0 16px; margin-top: 14px; }
      .console-sidebar { grid-column: 1; }
      .console-sidenav {
        position: fixed; z-index: 40; top: 0; left: 0; bottom: 0; width: 272px; max-height: none; height: 100%;
        background: var(--bg-elevated); border-right: 1px solid var(--border); padding: 16px 10px;
        transform: translateX(-100%); visibility: hidden;
        transition: transform 0.36s cubic-bezier(0.32, 0.72, 0, 1), visibility 0s linear 0.36s, box-shadow 0.36s ease;
      }
      .console-container.nav-open .console-sidenav { transform: none; visibility: visible; box-shadow: 8px 0 32px rgba(0, 0, 0, 0.35); transition: transform 0.36s cubic-bezier(0.32, 0.72, 0, 1), visibility 0s, box-shadow 0.36s ease; }
      .nav-scrim { display: block; position: fixed; inset: 0; z-index: 39; background: rgba(0, 0, 0, 0.45); opacity: 0; pointer-events: none; transition: opacity 0.3s ease; }
      .console-container.nav-open .nav-scrim { opacity: 1; pointer-events: auto; }
      .console-container.nav-collapsed .console-sidenav .nav-label, .console-container.nav-collapsed .console-sidenav .nav-counter { max-width: 200px; opacity: 1; }
      .console-container.nav-collapsed .console-sidenav .nav-section { color: var(--muted); }
      .console-container.nav-collapsed .console-sidenav .nav-section::after { opacity: 0; }
      .console-container.nav-collapsed .console-sidenav .nav-subs { max-height: 320px; opacity: 1; }
      .console-container .nav-label, .console-container .nav-counter { display: initial !important; }
      .console-container .nav-counter:empty, .console-container .nav-counter[hidden] { display: none !important; }
      .console-container button.nav-item.active + .nav-subs { display: flex !important; }
      .console-container .nav-section { font-size: 11px; padding: 14px 10px 4px 13px; }
      .console-container .nav-section::after { display: none; }
      .console-container .nav-chevron { display: block; opacity: 1; }
      .console-container .nav-group.closed { grid-template-rows: 0fr; opacity: 0; }
      .console-container button.nav-item { justify-content: flex-start; padding: 8px 10px; }
    }
    @media (prefers-reduced-motion: reduce) { .console-sidenav { transition: none; } }

    /* Right Column Telemetry & Resource Cards */
    .telemetry-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px 20px;
      margin-bottom: 16px;
      box-shadow: var(--shadow);
    }
    .telemetry-title {
      font-size: 13.5px;
      font-weight: 650;
      letter-spacing: -0.01em;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .telemetry-item {
      font-size: 12.5px;
      color: var(--muted);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 5px 0;
      border-bottom: 1px solid var(--border);
    }
    .telemetry-item:last-child {
      border-bottom: none;
    }
    .telemetry-val {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace;
      color: var(--text);
      font-weight: 500;
      font-size: 12px;
    }
    .progress-track {
      height: 7px;
      border-radius: 4px;
      background: var(--bg-subtle);
      overflow: hidden;
      margin: 6px 0 10px;
      border: 1px solid var(--border);
    }
    .progress-fill {
      height: 100%;
      background: var(--success);
      border-radius: 3px;
      transition: width 0.3s ease;
    }
    .progress-fill.warning {
      background: var(--warning);
    }
    .progress-fill.danger {
      background: var(--danger);
    }
    .progress-track.stacked { display: flex; }
    .progress-track .seg { height: 100%; transition: width 0.3s ease; }
    .progress-track .seg.paas { background: var(--accent); }
    .progress-track .seg.other { background: var(--muted); opacity: 0.55; }
    .res-legend { font-size: 11px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 4px 12px; margin: -4px 0 10px; }
    .res-legend .res-dot { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 4px; vertical-align: -0.5px; }
    .res-legend .res-dot.paas { background: var(--accent); }
    .res-legend .res-dot.other { background: var(--muted); opacity: 0.55; }
    .res-hint { font-size: 11px; color: var(--muted); line-height: 1.45; margin: 2px 0 8px; }

    .telemetry-card button.health-row {
      width: 100%; background: transparent; border: 0; border-bottom: 1px solid var(--border); border-radius: 0; box-shadow: none;
      padding: 6px 0; margin: 0; cursor: pointer; text-align: left; font-weight: 400; gap: 10px; color: var(--muted);
    }
    .telemetry-card button.health-row:last-child { border-bottom: none; }
    .telemetry-card button.health-row:hover { background: transparent; transform: none; filter: none; color: var(--text); }
    .telemetry-card button.health-row .telemetry-val { text-align: right; }
    /* Search & Filter Bar */
    .console-search-bar {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-bottom: 16px;
    }
    .console-search-input {
      flex: 1;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 13.5px;
      padding: 7px 12px;
      border-radius: 6px;
      outline: none;
    }
    .console-search-input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 22px 24px;
      margin-bottom: 22px;
      box-shadow: var(--shadow);
    }
    .card-header { margin-bottom: 16px; }
    .card-header h2 {
      margin: 0 0 6px;
      font-size: 17px;
      font-weight: 650;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }
    .card-desc { margin: 0; font-size: 13px; color: var(--muted); line-height: 1.55; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 980px) { .row { grid-template-columns: 1fr; } }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .field-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .examples-bar {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
      margin-bottom: 14px;
      padding: 10px 12px;
      border-radius: 8px;
      background: var(--bg-subtle);
      border: 1px dashed var(--border);
      font-size: 12px;
      color: var(--muted);
    }
    table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }
    th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; background: var(--bg-subtle); }
    th:first-child { border-top-left-radius: 8px; }
    th:last-child { border-top-right-radius: 8px; }
    tr:last-child td { border-bottom: none; }
    tbody tr { transition: background 0.12s ease; }
    tbody tr:hover { background: var(--card-hover); }
    .actions { display: flex; gap: 5px; flex-wrap: wrap; align-items: center; }
    .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--success); margin-right: 7px; }
    .status-dot.stopped { background: var(--danger); }
    .status-dot.deploying { background: var(--warning); animation: dep-pulse 1.2s ease-in-out infinite; }
    .status-dot.failed { background: var(--warning); }
    @keyframes dep-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    @media (prefers-reduced-motion: reduce) { .status-dot.deploying { animation: none; } }
    .dep-line { font-size: 11px; color: var(--muted); margin-top: 3px; line-height: 1.45; }
    .dep-line.active { color: var(--warning); font-weight: 600; }
    .dep-line.failed { color: var(--danger); font-weight: 600; }
    .dep-msg { display: inline-block; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
    .dep-err summary { cursor: pointer; font-size: 11px; color: var(--muted); }
    .dep-err pre { max-width: 420px; max-height: 220px; overflow: auto; white-space: pre-wrap; word-break: break-word; font-size: 10.5px; margin: 4px 0 0; }
    .apps-card-list {
      display: flex;
      flex-direction: column;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      background: var(--card);
    }
    .app-entry-row {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 10px;
      transition: background 0.12s ease;
    }
    .app-entry-row:last-child {
      border-bottom: none;
    }
    .app-entry-row:hover {
      background: var(--card-hover);
    }
    .app-row-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      flex-wrap: wrap;
    }
    .app-row-main-identity {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .app-row-name-link {
      font-size: 16px;
      font-weight: 650;
      letter-spacing: -0.01em;
      color: var(--accent-text);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 7px;
    }
    .app-row-name-link:hover {
      text-decoration: underline;
    }
    .app-badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11.5px;
      font-weight: 500;
      line-height: 16px;
      border: 1px solid var(--border);
      color: var(--muted);
      background: var(--bg-subtle);
    }
    .app-badge-pill.status-live {
      background: var(--success-soft);
      color: var(--success);
      border-color: rgba(63, 185, 80, 0.35);
      font-weight: 600;
    }
    .app-badge-pill.status-deploying {
      background: var(--warning-soft);
      color: var(--warning);
      border-color: rgba(210, 153, 34, 0.35);
      font-weight: 600;
    }
    .app-badge-pill.status-stopped {
      background: var(--danger-soft);
      color: var(--danger);
      border-color: rgba(248, 81, 73, 0.35);
      font-weight: 600;
    }
    .app-actions-group {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }
    .app-actions-group button {
      padding: 4px 10px;
      font-size: 12px;
      border-radius: 6px;
      font-weight: 500;
    }
    .app-row-commit-bar {
      font-size: 13px;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      line-height: 1.45;
    }
    .app-row-meta-bar {
      display: flex;
      align-items: center;
      gap: 16px;
      font-size: 12px;
      color: var(--muted);
      flex-wrap: wrap;
    }
    .runtime-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 500;
      color: var(--text);
    }
    .lang-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      display: inline-block;
    }
    .arch-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }
    .arch-box {
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
    }
    .arch-box h3 { margin: 0 0 6px; font-size: 13.5px; }
    .arch-box p { margin: 0; font-size: 12px; color: var(--muted); line-height: 1.45; }
    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
      margin-top: 10px;
    }
    .guide-box {
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
      margin-top: 14px;
    }
    .guide-box-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 6px;
      margin: 0 0 10px 0;
    }
    .guide-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
    }
    .guide-item {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 12px;
      line-height: 1.45;
    }
    .guide-item strong {
      display: block;
      color: var(--accent-text);
      margin-bottom: 3px;
      font-size: 12px;
    }
    .guide-item span {
      color: var(--muted);
    }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
  </style>
</head>
<body>
  <!-- Top Console Header -->
  <header class="console-header">
    <div class="console-header-left">
      <button class="nav-toggle-mobile" id="navToggleMobile" onclick="toggleNavDrawer(true)" aria-label="Menu" aria-controls="sideNav" aria-expanded="false">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M3 12h18M3 18h18"></path></svg>
      </button>
      <a href="#" class="console-logo-link" onclick="location.reload(); return false;">
        <svg class="brand-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2" style="stroke: var(--accent); fill: var(--accent-soft); fill-opacity: 0.3;"></rect>
          <circle cx="7" cy="10" r="1.5" fill="var(--accent)"></circle>
          <path d="M12 7l3 3-3 3"></path>
          <path d="M7 17v4"></path>
          <path d="M17 17v4"></path>
        </svg>
        <span style="font-weight:700;font-size:15px;letter-spacing:-0.01em;">PaaSMCP</span>
      </a>
      <span class="host-badge-capsule hide-sm" id="topHostCapsule">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
        <span>Host: <strong id="topHostname" style="font-weight:600;">-</strong></span>
      </span>
      <span class="engine-status-pill hide-sm">
        <span class="engine-status-dot"></span>
        <span id="topHealthBadge">Sistema Online</span>
      </span>
      <span class="host-badge-capsule hide-sm" id="topDomainBadge">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
        <span>Domínio: -</span>
      </span>
      ${safeCfEmail ? `<span class="engine-status-pill hide-sm" style="color:var(--accent-text);border-color:rgba(0,240,255,0.35);background:var(--accent-soft);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:2px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> Zero Trust: ${safeCfEmail}</span>` : ""}
    </div>
    <div class="header-actions" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <span id="sidebarSubtitle" style="display:none;">Agent-First Micro-PaaS</span>
      <button class="secondary" onclick="toggleLang()" id="langBtn">🇧🇷 PT-BR</button>
      <button class="secondary icon-only" onclick="toggleTheme()" id="themeBtn">🌙 Escuro</button>
      <button class="secondary icon-only" onclick="loadAll()" id="btnRefresh">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:2px;"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
        <span>Atualizar</span>
      </button>
      <button class="danger" onclick="logout()" id="btnLogout">Sair</button>
    </div>
  </header>

  <!-- Three-column workspace: side navigation | page | telemetry -->
  <div class="console-container" id="consoleContainer">
    <nav class="console-sidenav" id="sideNav" aria-label="Menu">
      <div class="sidenav-head">
        <button class="sidenav-collapse" id="navCollapseBtn" onclick="toggleNavCollapsed()" aria-label="Menu">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"></rect><path d="M9 3v18"></path></svg>
        </button>
      </div>
      <button class="nav-item nav-btn" onclick="goTo('home')" id="navHome">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
        <span class="nav-label"></span>
      </button>
      <div class="nav-subs" data-subs-for="home"></div>
      <button class="nav-section" data-section="apps" aria-expanded="true" aria-controls="navGroup-apps" onclick="toggleNavSection('apps')"><svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg><span data-i18n="navSecApps"></span></button>
      <div class="nav-group" id="navGroup-apps"><div class="nav-group-inner">
        <button class="nav-item nav-btn" onclick="goTo('overview')" id="navOverview">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountApps" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="overview"></div>
        <button class="nav-item nav-btn" onclick="goTo('databases')" id="navDatabases">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountDbs" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="databases"></div>
        <button class="nav-item nav-btn" onclick="goTo('vault')" id="navVault">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountVault" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="vault"></div>
      </div></div>
      <button class="nav-section" data-section="servers" aria-expanded="true" aria-controls="navGroup-servers" onclick="toggleNavSection('servers')"><svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg><span data-i18n="navSecServers"></span></button>
      <div class="nav-group" id="navGroup-servers"><div class="nav-group-inner">
        <button class="nav-item nav-btn" onclick="goTo('mirror')" id="navMirror">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"></polyline><path d="M3 11V9a4 4 0 0 1 4-4h14"></path><polyline points="7 23 3 19 7 15"></polyline><path d="M21 13v2a4 4 0 0 1-4 4H3"></path></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountMirror" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="mirror"></div>
        <button class="nav-item nav-btn" onclick="goTo('pool')" id="navPool">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountPool" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="pool"></div>
      </div></div>
      <button class="nav-section" data-section="integrations" aria-expanded="true" aria-controls="navGroup-integrations" onclick="toggleNavSection('integrations')"><svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg><span data-i18n="navSecIntegrations"></span></button>
      <div class="nav-group" id="navGroup-integrations"><div class="nav-group-inner">
        <button class="nav-item nav-btn" onclick="goTo('connect')" id="navConnect">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountConnect" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="connect"></div>
        <button class="nav-item nav-btn" onclick="goTo('agents')" id="navAgents">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
          <span class="nav-label"></span>
          <span class="nav-counter" id="tabCountAgents" hidden></span>
        </button>
        <div class="nav-subs" data-subs-for="agents"></div>
        <button class="nav-item nav-btn" onclick="goTo('email')" id="navEmail">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
          <span class="nav-label"></span>
        </button>
        <div class="nav-subs" data-subs-for="email"></div>
      </div></div>
      <button class="nav-section" data-section="system" aria-expanded="true" aria-controls="navGroup-system" onclick="toggleNavSection('system')"><svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"></path></svg><span data-i18n="navSecSystem"></span></button>
      <div class="nav-group" id="navGroup-system"><div class="nav-group-inner">
        <button class="nav-item nav-btn" onclick="goTo('doctor')" id="navDoctor">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
          <span class="nav-label"></span>
        </button>
        <div class="nav-subs" data-subs-for="doctor"></div>
        <button class="nav-item nav-btn" onclick="goTo('updates')" id="navUpdates">
          <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
          <span class="nav-label"></span>
        </button>
        <div class="nav-subs" data-subs-for="updates"></div>
      </div></div>
    </nav>
    <div class="nav-scrim" onclick="toggleNavDrawer(false)"></div>
    <div class="console-main">
      <!-- TAB: HOME / SETUP -->
      <div class="tab-pane" id="tab-home">
        <div class="card" data-sub="start">
          <div class="card-header">
            <h2 id="homeTitle">Resumo do servidor</h2>
            <p class="card-desc" data-i18n="homeDesc"></p>
          </div>
          <div class="grid-2" id="homeTiles"></div>
        </div>
        <div class="card" data-sub="start">
          <div class="card-header">
            <h2 data-i18n="stepsTitle"></h2>
            <p class="card-desc" data-i18n="stepsDesc"></p>
          </div>
          <div id="homeSteps"></div>
        </div>
        <div class="card" data-sub="tutorial">
          <div class="card-header">
            <h2 data-i18n="tutTitle"></h2>
            <p class="card-desc" data-i18n="tutDesc"></p>
          </div>
          <div id="tutProgress"></div>
          <div id="tutList"></div>
        </div>
      </div>
      <div class="tab-pane" id="tab-guide"></div>

      <!-- TAB 2: OVERVIEW, APPS, DEPLOY & EXPOSE -->
      <div class="tab-pane active" id="tab-overview">
        <div class="card" data-sub="list" style="margin-bottom:20px;">
          <div class="card-header" style="margin-bottom:14px;">
            <h2>
              <span id="appsTitle">📦 Aplicações Hospedadas &amp; Métricas</span>
              <span class="badge" id="appsBadgeCount">0 apps</span>
            </h2>
            <p class="card-desc" id="appsDesc">Containers isolados em <code>127.0.0.1:4000-4998</code> com suporte a Rollback em 1s, limites de CPU/RAM e Docker Compose multi-serviço.</p>
          </div>
          <div class="console-search-bar">
            <input class="console-search-input" id="appSearchInput" placeholder="Buscar aplicações por nome, stack ou porta..." oninput="filterApps(this.value)" />
            <button class="secondary" id="btnNewApp" onclick="goTo('overview', 'deploy'); const depEl = document.getElementById('depApp'); if (depEl) depEl.focus();" style="padding:6px 12px;font-size:12.5px;">+ Publicar um app</button>
          </div>
          <div class="apps-card-list" id="appsTable">
            <div style="padding: 24px; text-align: center; color: var(--muted);">...</div>
          </div>
        </div>

          
            <div class="card" data-sub="deploy">
              <div class="card-header">
                <h2 id="deployTitle">➕ Novo Deploy (GitHub, Multi-Service Compose ou Local)</h2>
                <p class="card-desc" id="deployDesc">Detecta automaticamente Node, Next.js, Python, Go, SPA, Dockerfile ou <code>docker-compose.yml</code> (injetando segredos do Vault com segurança).</p>
              </div>
              <div class="examples-bar">
                <span id="lblQuickFillDeploy">⚡ Presets:</span>
                <button class="chip" id="presetSaas" onclick="fillDeployPreset('saas', this)">SaaS Next.js + PG (512MB)</button>
                <button class="chip" id="presetDjango" onclick="fillDeployPreset('django', this)">Django + PG</button>
                <button class="chip" id="presetFastapi" onclick="fillDeployPreset('fastapi', this)">FastAPI + PG</button>
                <button class="chip" id="presetNode" onclick="fillDeployPreset('node', this)">API Node / Express</button>
                <button class="chip" id="presetGo" onclick="fillDeployPreset('go', this)">API Go</button>
                <button class="chip" id="presetDotnet" onclick="fillDeployPreset('dotnet', this)">C# / ASP.NET + PG</button>
                <button class="chip" id="presetCompose" onclick="fillDeployPreset('compose', this)">Multi-Service Compose + PG + Redis</button>
                <button class="chip" id="presetSpa" onclick="fillDeployPreset('spa', this)">SPA / Site Estático</button>
                <button class="chip" id="presetDockerfile" onclick="fillDeployPreset('dockerfile', this)">Dockerfile próprio (Rails, Laravel…)</button>
              </div>
              <p class="preset-hint" id="deployPresetHint"></p>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblDepApp">Nome do app</label>
                  <input id="depApp" placeholder="ex: meu-saas" />
                </div>
                <div>
                  <label class="field-label" id="lblDepRepo">Repositório (dono/nome) ou pasta do servidor</label>
                  <input id="depRepo" placeholder="ex: seu-usuario/meu-repo" />
                </div>
                <div>
                  <label class="field-label" id="lblDepBranch">Branch</label>
                  <input id="depBranch" placeholder="main" value="main" />
                </div>
              </div>
              <div id="depRepoPick" class="dep-pick"></div>
              <div style="display:flex; gap:18px; align-items:center; margin-bottom:14px; font-size:12.5px; flex-wrap:wrap;">
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depPg" style="width:auto;" />
                  <span id="lblDepPg">Banco PostgreSQL (o app recebe <code>DATABASE_URL</code>)</span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depRedis" style="width:auto;" />
                  <span id="lblDepRedis">Cache Redis (o app recebe <code>REDIS_URL</code>)</span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depPoll" style="width:auto;" />
                  <span data-i18n="lblDepPoll"></span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depStorage" style="width:auto;" />
                  <span data-i18n="lblDepStorage"></span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depEmail" style="width:auto;" />
                  <span data-i18n="lblDepEmail"></span>
                </label>
              </div>
              <details class="dep-more">
                <summary data-i18n="depMore"></summary>
                <p class="ofs-note" data-i18n="depMoreDesc" style="margin-top:8px;"></p>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblDepMem">Memória máxima</label>
                  <input id="depMem" placeholder="ex: 512m ou 1g" />
                </div>
                <div>
                  <label class="field-label" id="lblDepCpu">Processadores (CPUs) no máximo</label>
                  <input id="depCpu" placeholder="ex: 0.5 ou 1.0" />
                </div>
                <div>
                  <label class="field-label" data-i18n="lblDepHealth"></label>
                  <input id="depHealth" placeholder="/" />
                </div>
              </div>
                <label style="margin-bottom:12px;font-size:12.5px;display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depNoHealth" style="width:auto;" />
                  <span data-i18n="lblDepNoHealth"></span>
                </label>
              </details>
              <button onclick="deployNewApp()" id="btnDeploy">🚀 Publicar</button>
              <div id="depResult"></div>
            </div>

            <div class="card" data-sub="deploy">
              <div class="card-header">
                <h2 data-i18n="tplTitle"></h2>
                <p class="card-desc" data-i18n="tplDesc"></p>
              </div>
              <div id="tplList" class="tpl-grid"></div>
              <div id="tplResult"></div>
            </div>

            <div class="card" data-sub="expose">
              <div class="card-header">
                <h2 id="exposeTitle">🌐 Expor Aplicação (Cloudflare Tunnel / Zero Trust / Tailscale)</h2>
                <p class="card-desc" id="exposeDesc">Configura rota no Cloudflare Tunnel + DNS CNAME proxied + política Zero Trust sem abrir nenhuma porta no roteador.</p>
              </div>
              <div id="exposeCfHint"></div>
              <p class="preset-hint show" id="expModeHint" style="margin:0 0 10px;"></p>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblExpApp">Aplicação</label>
                  <input id="expApp" list="hostedAppsList" placeholder="ex: meu-saas" oninput="expAppChanged()" />
                  <datalist id="hostedAppsList"></datalist>
                </div>
                <div>
                  <label class="field-label" id="lblExpMode">Quem pode abrir</label>
                  <select id="expMode" onchange="renderExposeHint()">
                    <option value="public" id="optPublic">Cloudflare Público (HTTPS aberto)</option>
                    <option value="zero-trust" id="optZT">Cloudflare Zero Trust (Login PIN por E-mail)</option>
                    <option value="tailscale" id="optTS">Tailscale Serve (Privado na Tailnet)</option>
                  </select>
                </div>
                <div id="expSubBox">
                  <label class="field-label" id="lblExpSub">Subdomínio</label>
                  <input id="expSub" placeholder="ex: loja" oninput="renderExposeHint()" />
                </div>
              </div>
              <p class="ofs-note" id="expPreviewLine" style="margin:-4px 0 10px;"></p>
              <button onclick="exposeApp()" id="btnExpose">🔗 Publicar Endereço</button>
              <div id="expList" style="margin-top:18px;"></div>
            </div>
          

          <div class="card" data-sub="scale" id="scaleCard">
            <div class="card-header">
              <h2 data-i18n="scaleTitle"></h2>
              <p class="card-desc" data-i18n="scaleDesc"></p>
            </div>
            <div id="scaleTimerNote"></div>
            <div class="form-grid" style="grid-template-columns:minmax(0,280px);">
              <div><label class="field-label" for="scaleApp" data-i18n="lblScaleApp"></label><select id="scaleApp" onchange="loadScale()"></select></div>
            </div>
            <div id="scaleNow"></div>
            <div id="scaleCharts" style="margin-top:10px;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:10px;"></div>
            <div id="scaleBody">
              <h3 data-i18n="scaleAutoTitle" style="margin-top:18px;"></h3>
              <p class="card-desc" data-i18n="scaleAutoDesc"></p>
              <div id="autoBox"></div>
              <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
                <button onclick="setAuto(true)" id="btnScaleAutoOn" data-i18n="btnScaleAutoOn"></button>
                <button class="secondary" onclick="setAuto(false)" id="btnScaleAutoOff" data-i18n="btnScaleAutoOff"></button>
              </div>
              <h3 data-i18n="copiesTitle" style="margin-top:18px;"></h3>
              <p class="card-desc" data-i18n="copiesDesc"></p>
              <div id="copiesBox"></div>
              <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
                <div id="copiesManual" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
                  <div style="width:160px;"><label class="field-label" for="copiesN" data-i18n="lblCopiesN"></label><input id="copiesN" type="number" min="1" max="20" /></div>
                  <button onclick="applyCopies()" data-i18n="btnCopiesApply"></button>
                </div>
                <button class="secondary" onclick="copiesOff()" id="btnCopiesOff" data-i18n="btnCopiesOff"></button>
              </div>
              <div id="copiesJobBox" style="margin-top:8px;"></div>
              <h3 data-i18n="scaleRuleTitle" style="margin-top:18px;"></h3>
              <p class="card-desc" data-i18n="scaleRuleDesc"></p>
              <div class="form-grid">
                <div><label class="field-label" for="scaleMin" data-i18n="lblScaleMin"></label><input id="scaleMin" type="number" min="1" max="20" /></div>
                <div><label class="field-label" for="scaleMax" data-i18n="lblScaleMax"></label><input id="scaleMax" type="number" min="1" max="20" /></div>
                <div><label class="field-label" for="scaleTarget" data-i18n="lblScaleTarget"></label><input id="scaleTarget" type="number" min="10" max="95" /></div>
                <div><label class="field-label" for="scaleTargetRps" data-i18n="lblScaleTargetRps"></label><input id="scaleTargetRps" type="number" min="0" max="100000" /></div>
                <div><label class="field-label" for="scaleUp" data-i18n="lblScaleUp"></label><input id="scaleUp" type="number" min="1" max="20" /></div>
                <div><label class="field-label" for="scaleDown" data-i18n="lblScaleDown"></label><input id="scaleDown" type="number" min="1" max="1440" /></div>
                <div><label class="field-label" for="scaleCooldown" data-i18n="lblScaleCooldown"></label><input id="scaleCooldown" type="number" min="0" max="3600" /></div>
              </div>
              <button onclick="saveScaleRule()" data-i18n="btnSave"></button>
              <h3 data-i18n="scaleCapTitle" style="margin-top:18px;"></h3>
              <p class="card-desc" data-i18n="scaleCapDesc"></p>
              <div id="scaleCapacity"></div>
            </div>
          </div>

          <div class="card" data-sub="diary" id="diaryCard">
            <div class="card-header">
              <h2 data-i18n="scaleDiaryTitle"></h2>
              <p class="card-desc" data-i18n="scaleDiaryDesc"></p>
            </div>
            <div class="form-grid" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),320px));">
              <div><label class="field-label" for="diaryApp" data-i18n="lblScaleApp"></label><select id="diaryApp" onchange="document.getElementById('scaleApp').value = this.value; loadScale();"></select></div>
              <div><label class="field-label" for="scaleLang" data-i18n="lblScaleLang"></label>
                <select id="scaleLang" onchange="saveScaleLang()"><option value="pt">Português</option><option value="en">English</option></select></div>
            </div>
            <div id="scaleDiary" style="margin-top:6px;"></div>
          </div>

          <div class="card" data-sub="webhook">
            <div class="card-header">
              <h2 id="whTitle">⚡ Auto-Deploy via GitHub Webhook & Deploy Key SSH</h2>
              <p class="card-desc" id="whDesc">Receba <code>git push</code> do GitHub com validação de assinatura <code>X-Hub-Signature-256</code> em tempo constante para reconstruir seus apps automaticamente.</p>
            </div>
            <div id="whAuto">
              <h3 class="ofs-h" data-i18n="whAutoTitle"></h3>
              <p class="ofs-note" id="whAutoNote"></p>
              <div class="wh-form" style="display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;">
                <div style="flex:1 1 240px;min-width:0;"><label class="field-label" for="whAddress" data-i18n="whLblAddress"></label><input id="whAddress" type="url" autocomplete="off" spellcheck="false" placeholder="https://painel.seudominio.com" /></div>
                <div><button class="secondary" onclick="loadHooks()" data-i18n="whBtnCheck"></button></div>
              </div>
              <div class="ofs-msg" id="whMsg" role="status" aria-live="polite"></div>
              <div id="whRepos" style="margin-top:8px;"></div>
            </div>
            <details id="whManual" style="margin-top:16px;">
              <summary style="cursor:pointer;font-weight:600;font-size:14px;" data-i18n="whManualTitle"></summary>
              <div style="margin:12px 0 14px;">
                <span class="field-label" data-i18n="whLblUrl"></span>
                <code id="webhookUrlBox" style="display:block;padding:8px 10px;user-select:all;">/api/webhooks/github</code>
              </div>
              <div style="margin-bottom:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">
                  <span class="field-label" data-i18n="whLblSecret" style="margin:0;">Webhook Secret (HMAC-SHA256):</span>
                  <button class="chip" onclick="revealWebhookSecret()" id="btnRevealWhSecret">👁️ Revelar / Copiar Secret</button>
                </div>
                <code id="webhookSecretBox" style="display:block;padding:8px 10px;">••••••••••••</code>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <span class="field-label" id="lblSshKey" style="margin:0;">Chave SSH Pública de Deploy (Ed25519):</span>
                <button class="chip" onclick="copySshKey()" id="btnCopySsh">📋 Copiar Chave SSH</button>
              </div>
              <pre id="sshKeyBox" style="margin-top:6px;user-select:all;"></pre>
            </details>
          </div>
        </div>

        <!-- TAB 2: ENCRYPTED VAULT -->
        <div class="tab-pane" id="tab-vault">
          <div class="card">
            <div class="card-header">
              <h2 id="vaultTitle"></h2>
              <p class="card-desc" id="vaultDesc"></p>
            </div>
            <div class="form-grid" style="grid-template-columns:minmax(0,320px);">
              <div>
                <label class="field-label" for="secScope" id="lblSecScope"></label>
                <select id="secScope" onchange="loadSecrets()"><option value="system"></option></select>
              </div>
            </div>
            <div id="secApply"></div>
            <h3 class="ofs-h" data-i18n="secListTitle"></h3>
            <div id="secretsList"></div>
            <h3 class="ofs-h" style="margin-top:18px;" data-i18n="secAddTitle"></h3>
            <div class="form-grid">
              <div>
                <label class="field-label" for="secKey" id="lblSecKey"></label>
                <input id="secKey" placeholder="STRIPE_SECRET_KEY" autocomplete="off" spellcheck="false" />
              </div>
              <div>
                <label class="field-label" for="secVal" id="lblSecVal"></label>
                <input id="secVal" type="password" autocomplete="new-password" />
              </div>
            </div>
            <div class="actions" style="margin-bottom:6px;">
              <button onclick="saveSecret()" id="btnSaveSecret"></button>
            </div>
            <details class="sec-paste" style="margin-top:14px;">
              <summary data-i18n="secPasteTitle"></summary>
              <p class="ofs-note" data-i18n="secPasteDesc" style="margin-top:8px;"></p>
              <textarea id="secDotenv" rows="7" spellcheck="false" autocomplete="off" placeholder="DATABASE_URL=postgres://...&#10;STRIPE_SECRET_KEY=sk_live_...&#10;# comentários são ignorados"></textarea>
              <div class="ofs-msg" id="secPasteMsg" role="status" aria-live="polite"></div>
              <div style="margin-top:8px;"><button class="secondary" onclick="saveDotenv()" data-i18n="secPasteBtn"></button></div>
            </details>
          </div>
        </div>

        <!-- TAB 3: DATABASES & ENCRYPTED BACKUPS -->
        <div class="tab-pane" id="tab-databases">
          <div class="card" data-sub="offsite">
            <div class="card-header">
              <h2 data-i18n="offsiteTitle"></h2>
              <p class="card-desc" data-i18n="offsiteDesc"></p>
            </div>
            <h3 class="ofs-h" data-i18n="ofsSendTitle"></h3>
            <div id="ofsCurrent"></div>
            <div id="ofsForm" style="display:none;">
              <p class="ofs-note" data-i18n="ofsPickProvider"></p>
              <div id="ofsProviders" class="ofs-chips"></div>
              <div id="ofsFields"></div>
              <div class="ofs-msg" id="ofsMsg" role="status" aria-live="polite"></div>
              <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
                <button onclick="saveOffsiteUi()" id="btnOfsSave" data-i18n="ofsBtnSave"></button>
                <button class="secondary" onclick="closeOffsiteForm()" id="btnOfsCancel" data-i18n="ofsBtnCancel" style="display:none;"></button>
              </div>
            </div>
            <h3 class="ofs-h" style="margin-top:22px;" data-i18n="ofsGiveTitle"></h3>
            <p class="ofs-note" data-i18n="ofsGiveDesc"></p>
            <div id="ofsGrants"></div>
            <div class="form-grid" style="margin-top:8px;">
              <div>
                <label class="field-label" for="ofsGrantName" data-i18n="ofsGrantName"></label>
                <input id="ofsGrantName" placeholder="ex: notebook" autocomplete="off" />
              </div>
              <div>
                <label class="field-label" for="ofsGrantGb" data-i18n="ofsGrantGb"></label>
                <input id="ofsGrantGb" type="number" min="1" step="1" placeholder="50" />
              </div>
            </div>
            <div class="ofs-msg" id="ofsGrantMsg" role="status" aria-live="polite"></div>
            <div style="margin-top:10px;"><button class="secondary" onclick="createGrantUi()" id="btnOfsGrant" data-i18n="ofsBtnGrant"></button></div>
            <div id="ofsGrantResult"></div>
            <details style="margin-top:14px;font-size:12.5px;color:var(--muted);"><summary data-i18n="detailsTech"></summary><p data-i18n="offsiteTech"></p></details>
          </div>
          <div class="card" data-sub="files">
            <div class="card-header">
              <h2 data-i18n="storageTitle"></h2>
              <p class="card-desc" data-i18n="storageDesc"></p>
            </div>
            <div id="storageList" style="margin-bottom:10px;"></div>
            <label class="field-label" for="stoApp" data-i18n="lblAppName"></label>
            <input id="stoApp" placeholder="ex: meu-saas" />
            <div style="margin-top:10px;"><button onclick="provisionStorageUi()" data-i18n="btnStorage"></button></div>
          </div>
          
            <div class="card" data-sub="dbs">
              <div class="card-header">
                <h2 id="dbTitle">🗄️ Provisionar Banco Multi-Tenant Isolado</h2>
                <p class="card-desc" id="dbDesc">Cria banco, role exclusiva e injeta <code>DATABASE_URL</code> / <code>REDIS_URL</code> diretamente no Cofre do app.</p>
              </div>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblDbApp">Aplicação</label>
                  <input id="dbApp" list="hostedAppsList" placeholder="ex: meu-saas" />
                </div>
                <div>
                  <label class="field-label" id="lblDbEngine">Tipo</label>
                  <select id="dbEngine">
                    <option value="postgres" id="optDbPg">PostgreSQL 16 (Isolado por DB + Role)</option>
                    <option value="redis" id="optDbRedis">Redis 7 (DB Lógico Isolado)</option>
                  </select>
                </div>
              </div>
              <button onclick="createDb()" id="btnCreateDb" style="margin-bottom:16px;">+ Provisionar Banco</button>
              <div id="dbResult"></div>
              <div id="dbList"></div>
            </div>

            <div class="card" data-sub="backups">
              <div class="card-header">
                <h2 id="backupsTitle">🛡️ Snapshots & Restore Criptografados (AES-256-GCM)</h2>
                <p class="card-desc" id="backupsDesc">Gera <code>pg_dump</code> ou snapshot Redis, criptografa com a chave mestra do Vault e verifica integridade SHA-256 antes do restore.</p>
              </div>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblBakApp">App para Backup</label>
                  <input id="bakApp" list="hostedAppsList" placeholder="ex: meu-saas" />
                </div>
                <div>
                  <label class="field-label" id="lblBakEngine">O que copiar</label>
                  <select id="bakEngine">
                    <option value="postgres" id="optBakPg">PostgreSQL 16 (pg_dump)</option>
                    <option value="redis" id="optBakRedis">Redis 7 (RDB)</option>
                    <option value="volume" id="optBakVol">Docker volumes</option>
                  </select>
                </div>
              </div>
              <div id="bakNightly" class="bak-nightly"></div>
              <button onclick="createBackup()" id="btnCreateBackup" style="margin-bottom:16px;">📸 Fazer uma cópia agora</button>
              <div id="backupsList"></div>
            </div>
          
        </div>


        <div class="tab-pane" id="tab-connect">
          <div class="card" data-sub="cloudflare">
            <div class="card-header">
              <h2 data-i18n="cnCfTitle"></h2>
              <p class="card-desc" data-i18n="cnCfDesc"></p>
            </div>
            <div id="cfStatus"></div>
            <div id="cfForm">
              <h3 class="ofs-h" data-i18n="cnCfStep1"></h3>
              <p class="ofs-note" data-i18n="cnCfStep1Desc"></p>
              <p style="margin:0 0 6px;"><a id="cfTokenLink" target="_blank" rel="noreferrer" data-i18n="cnCfTokenLink"></a></p>
              <h3 class="ofs-h" data-i18n="cnCfStep2"></h3>
              <div class="form-grid" style="grid-template-columns:minmax(0,1fr) auto;align-items:end;">
                <div><label class="field-label" for="cfToken" data-i18n="cnCfToken"></label><input id="cfToken" type="password" autocomplete="off" spellcheck="false" /></div>
                <div><button class="secondary" onclick="cfDiscover()" id="btnCfDiscover" data-i18n="cnBtnCheck"></button></div>
              </div>
              <div class="ofs-msg" id="cfMsg" role="status" aria-live="polite"></div>
              <div id="cfChoose" style="display:none;">
                <h3 class="ofs-h" data-i18n="cnCfStep3"></h3>
                <div class="form-grid">
                  <div><label class="field-label" for="cfAccount" data-i18n="cnCfAccount"></label><select id="cfAccount" onchange="cfFillChoices()"></select></div>
                  <div><label class="field-label" for="cfDomain" data-i18n="cnCfDomain"></label><select id="cfDomain"></select></div>
                  <div><label class="field-label" for="cfTunnel" data-i18n="cnCfTunnel"></label><select id="cfTunnel" onchange="cfTunnelHint()"></select></div>
                </div>
                <p class="ofs-note" id="cfTunnelNote"></p>
                <label id="cfRunHereRow" style="display:none;align-items:center;gap:6px;cursor:pointer;font-size:12.5px;margin-bottom:10px;">
                  <input type="checkbox" id="cfRunHere" style="width:auto;" /> <span data-i18n="cnCfRunHere"></span>
                </label>
                <label class="field-label" for="cfEmails" data-i18n="cnCfEmails"></label>
                <input id="cfEmails" placeholder="voce@exemplo.com, socio@exemplo.com" autocomplete="off" />
                <p class="ofs-note" data-i18n="cnCfEmailsHint" style="margin-top:4px;"></p>
                <div class="ofs-msg" id="cfSaveMsg" role="status" aria-live="polite"></div>
                <div style="margin-top:10px;"><button onclick="cfSave()" id="btnCfSave" data-i18n="cnBtnCfSave"></button></div>
              </div>
            </div>
          </div>
          <div class="card" data-sub="github">
            <div class="card-header">
              <h2 data-i18n="cnGhTitle"></h2>
              <p class="card-desc" data-i18n="cnGhDesc"></p>
            </div>
            <div id="ghStatus"></div>
            <h3 class="ofs-h" data-i18n="cnGhKeyTitle"></h3>
            <p class="ofs-note" data-i18n="cnGhKeyDesc"></p>
            <div class="ofs-secret" id="ghSshKey">...</div>
            <button class="secondary" onclick="copyText(document.getElementById('ghSshKey').textContent)" data-i18n="cnBtnCopyKey"></button>
            <h3 class="ofs-h" style="margin-top:20px;" data-i18n="cnGhTokenTitle"></h3>
            <p class="ofs-note" data-i18n="cnGhTokenDesc"></p>
            <p style="margin:0 0 8px;"><a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noreferrer" data-i18n="cnGhTokenLink"></a></p>
            <div class="form-grid" style="grid-template-columns:minmax(0,1fr) auto;align-items:end;">
              <div><label class="field-label" for="ghToken" data-i18n="cnGhToken"></label><input id="ghToken" type="password" autocomplete="off" spellcheck="false" placeholder="github_pat_..." /></div>
              <div><button onclick="ghSave()" id="btnGhSave" data-i18n="cnBtnGhSave"></button></div>
            </div>
            <div class="ofs-msg" id="ghMsg" role="status" aria-live="polite"></div>
          </div>
          <div class="card" data-sub="alerts">
            <div class="card-header">
              <h2 data-i18n="ntTitle"></h2>
              <p class="card-desc" data-i18n="ntDesc"></p>
            </div>
            <div id="ntStatus"></div>
            <div id="ntForm">
              <p class="ofs-note" data-i18n="ntHow"></p>
              <ul class="ofs-note nt-list">
                <li data-i18n="ntHowNtfy"></li>
                <li data-i18n="ntHowDiscord"></li>
                <li data-i18n="ntHowSlack"></li>
              </ul>
              <label class="field-label" for="ntUrl" data-i18n="ntUrl"></label>
              <input id="ntUrl" type="password" autocomplete="off" spellcheck="false" placeholder="https://ntfy.sh/..." />
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12.5px;margin:10px 0 12px;">
                <input type="checkbox" id="ntSuccess" style="width:auto;" />
                <span data-i18n="ntOnSuccess"></span>
              </label>
              <button onclick="ntSave()" id="btnNtSave" data-i18n="ntSave"></button>
            </div>
            <div class="ofs-msg" id="ntMsg" role="status" aria-live="polite"></div>
          </div>
        </div>

        <div class="tab-pane" id="tab-email">
          <div class="card">
            <div class="card-header">
              <h2 data-i18n="emailTitle"></h2>
              <p class="card-desc" data-i18n="emailDesc"></p>
            </div>
            <p class="card-desc" id="emailStatus" style="margin-bottom:10px;"></p>
            <div class="grid-2">
              <div><label class="field-label" for="emHost" data-i18n="lblEmHost"></label><input id="emHost" placeholder="smtp-relay.brevo.com" /></div>
              <div><label class="field-label" for="emPort" data-i18n="lblEmPort"></label><input id="emPort" value="587" inputmode="numeric" /></div>
              <div><label class="field-label" for="emUser" data-i18n="lblEmUser"></label><input id="emUser" autocomplete="off" /></div>
              <div><label class="field-label" for="emPass" data-i18n="lblEmPass"></label><input id="emPass" type="password" autocomplete="new-password" /></div>
              <div><label class="field-label" for="emDomain" data-i18n="lblEmDomain"></label><input id="emDomain" placeholder="seudominio.com" /></div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;">
              <button onclick="saveEmail()" data-i18n="btnSave"></button>
            </div>
            <p class="card-desc" data-i18n="emailTip" style="margin-top:10px;"></p>
          </div>
          <div class="grid-2">
            <div class="card">
              <div class="card-header"><h2 data-i18n="emailTestTitle"></h2></div>
              <label class="field-label" for="emTo" data-i18n="lblEmTo"></label>
              <input id="emTo" type="email" />
              <div style="margin-top:10px;"><button class="secondary" onclick="testEmail()" data-i18n="btnEmailTest"></button></div>
            </div>
            <div class="card">
              <div class="card-header"><h2 data-i18n="emailAppTitle"></h2><p class="card-desc" data-i18n="emailAppDesc"></p></div>
              <label class="field-label" for="emApp" data-i18n="lblAppName"></label>
              <input id="emApp" placeholder="ex: meu-saas" />
              <div style="margin-top:10px;"><button onclick="provisionEmailUi()" data-i18n="btnEmailApp"></button></div>
            </div>
          </div>
        </div>

        <div class="tab-pane" id="tab-mirror">
          <div class="card" data-sub="copy">
            <div class="card-header">
              <h2 data-i18n="mirrorTitle"></h2>
              <p class="card-desc" data-i18n="mirrorDesc"></p>
            </div>
            <div id="mirrorStatusBox"></div>
          </div>
          <div class="card" data-sub="connect" id="pairCard">
            <div class="card-header">
              <h2 id="fedTitle">🌐 Handshake Multi-Servidor & Redundância (HA Federation)</h2>
              <p class="card-desc" id="fedDesc">Pareie um segundo servidor (VPS ou outro Homelab) usando token assinado <code>HMAC-SHA256</code> para rodar os mesmos serviços em <strong>Alta Disponibilidade via Cloudflare Tunnel</strong> ou <strong>Warm Standby</strong>.</p>
            </div>
            <div class="form-grid">
              <div>
                <label class="field-label" id="lblFedUrl">URL deste Servidor (Primary)</label>
                <input id="fedUrl" placeholder="https://paas.seudominio.com" />
              </div>
              <div>
                <label class="field-label" id="lblFedMode">Modo de Redundância</label>
                <select id="fedMode">
                  <option value="active-active-tunnel" id="optFedActive">Active-Active (Cloudflare Tunnel Multi-Connector)</option>
                  <option value="warm-standby" id="optFedWarm">Warm Standby (Sync Criptografado de Vault & Apps)</option>
                </select>
              </div>
            </div>
            <div class="actions" style="margin-bottom:12px;">
              <button onclick="generateInvite()" id="btnGenInvite">🔑 Gerar Join Token (15 min)</button>
              <button class="secondary" onclick="exportSyncBundle()" id="btnExportSync">📦 Exportar Bundle Criptografado</button>
            </div>
            <pre id="fedTokenBox" style="display:none;user-select:all;"></pre>
            <hr style="border:none;border-top:1px solid var(--border);margin:16px 0;" />
            <label class="field-label" id="lblJoinPeer">Conectar este servidor como Réplica (Cole um Join Token):</label>
            <div style="display:flex;gap:8px;margin-bottom:14px;">
              <input id="fedJoinInput" placeholder="paasmcp-join://..." />
              <button class="secondary" onclick="joinFederation()" id="btnJoinPeer">🤝 Fazer Handshake</button>
            </div>
            <div id="fedPeersList"></div>
          </div>
          <div class="grid-2" data-sub="copy">
            <div class="card">
              <div class="card-header"><h2 data-i18n="mirrorOfferTitle"></h2><p class="card-desc" data-i18n="mirrorOfferDesc"></p></div>
              <label class="field-label" for="mOfferPeer" data-i18n="lblPeerName"></label>
              <input id="mOfferPeer" placeholder="ex: casa-mae" />
              <label class="field-label" for="mOfferIp" data-i18n="lblPeerIp"></label>
              <input id="mOfferIp" placeholder="100.64.0.2" />
              <label class="field-label" for="mOfferFrom" data-i18n="lblFromCopyOf"></label>
              <input id="mOfferFrom" />
              <div style="margin-top:10px;"><button onclick="mirrorOffer()" data-i18n="btnMirrorOffer"></button></div>
              <pre id="mOfferToken" style="display:none;white-space:pre-wrap;word-break:break-all;font-size:11.5px;margin-top:10px;"></pre>
            </div>
            <div class="card">
              <div class="card-header"><h2 data-i18n="mirrorAcceptTitle"></h2><p class="card-desc" data-i18n="mirrorAcceptDesc"></p></div>
              <label class="field-label" for="mAcceptToken" data-i18n="lblInvite"></label>
              <textarea id="mAcceptToken" rows="4" style="width:100%;box-sizing:border-box;"></textarea>
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;margin-top:10px;font-size:12.5px;">
                <input type="checkbox" id="mRejoin" style="width:auto;" />
                <span data-i18n="lblRejoin"></span>
              </label>
              <div style="margin-top:10px;"><button onclick="mirrorAccept()" data-i18n="btnMirrorAccept"></button></div>
            </div>
          </div>
          <div class="card" data-sub="judge" id="judgeCard">
            <div class="card-header"><h2 data-i18n="judgeTitle"></h2><p class="card-desc" data-i18n="judgeDesc"></p></div>
            <div id="judgeInfoBox"></div>
            <button class="secondary" onclick="loadArbiterStatus()" data-i18n="btnArbRefresh"></button>
          </div>
          <div class="card" data-sub="judge">
            <div class="card-header"><h2 data-i18n="judgeHowTitle"></h2></div>
            <ol style="margin:0 0 12px;padding-left:20px;font-size:13px;line-height:1.7;">
              <li data-i18n="judgeHow1"></li>
              <li data-i18n="judgeHow2"></li>
              <li data-i18n="judgeHow3"></li>
              <li data-i18n="judgeHow4"></li>
            </ol>
            <div id="judgeOwnersBox"></div>
          </div>
          <div class="card" data-sub="judge" id="judgeSetupCard">
            <details id="judgeSetup" open>
              <summary style="cursor:pointer;font-weight:600;font-size:15px;" id="judgeSetupTitle" data-i18n="judgeSetupTitle" onclick="this.parentNode.dataset.touched = '1'"></summary>
              <p class="card-desc" data-i18n="judgeBefore" style="margin-top:10px;"></p>

              <h3 data-i18n="autoStep1" style="margin-top:16px;"></h3>
              <p class="card-desc" data-i18n="autoStep1Desc"></p>

              <h3 data-i18n="autoStep2" style="margin-top:16px;"></h3>
              <p class="card-desc" data-i18n="autoStep2Desc" style="margin-bottom:10px;"></p>
              <button onclick="arbiterInstallCmd()" id="btnArbCmd" data-i18n="btnArbCmd"></button>
              <div id="arbInstallBox" style="display:none;margin-top:10px;">
                <pre id="arbInstallCmd" style="user-select:all;white-space:pre-wrap;word-break:break-all;"></pre>
                <button class="secondary" onclick="copyText(document.getElementById('arbInstallCmd').textContent)" data-i18n="aiCopy"></button>
                <p class="card-desc" data-i18n="autoStep2After" style="margin-top:10px;"></p>
              </div>
              <details style="margin-top:12px;font-size:12.5px;">
                <summary style="cursor:pointer;" data-i18n="autoPrereqTitle"></summary>
                <p class="card-desc" data-i18n="autoPrereqDesc" style="margin-top:8px;"></p>
                <pre style="user-select:all;white-space:pre-wrap;word-break:break-all;">curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs git</pre>
                <p class="card-desc" data-i18n="autoStep3Check" style="margin-top:8px;"></p>
                <pre style="user-select:all;">curl http://$(tailscale ip -4):4097/health</pre>
              </details>

              <h3 data-i18n="autoStep3" style="margin-top:16px;"></h3>
              <p class="card-desc" data-i18n="autoStep3Desc" style="margin-bottom:10px;"></p>
              <label class="field-label" for="mArbiter" data-i18n="lblArbiter"></label>
              <input id="mArbiter" placeholder="http://100.64.0.9:4097" />
              <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
                <button class="secondary" onclick="arbiterTest()" id="btnArbTest" data-i18n="btnArbTest"></button>
                <button onclick="arbiterSave()" data-i18n="btnArbSave"></button>
              </div>
              <div id="arbTestBox" style="margin-top:10px;"></div>
            </details>
          </div>
          <div class="card" data-sub="auto">
            <div class="card-header"><h2 data-i18n="autoTitle"></h2><p class="card-desc" data-i18n="autoDesc"></p></div>
            <div id="arbStatusBox" style="margin-bottom:6px;"></div>
            <p class="card-desc"><span data-i18n="autoBefore"></span> <a href="javascript:void(0)" data-go-tab="mirror" data-go-sub="judge" data-i18n="autoGoJudge"></a></p>

            <h3 data-i18n="autoStep5" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep5Desc" style="margin-bottom:10px;"></p>
            <label class="field-label" for="mAutoPeer" data-i18n="lblAutoPeer"></label>
            <select id="mAutoPeer"></select>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
              <button onclick="mirrorAuto(true)" data-i18n="btnAutoOn"></button>
              <button class="secondary" onclick="mirrorAuto(false)" data-i18n="btnAutoOff"></button>
            </div>

            <h3 data-i18n="autoStep6" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep6Desc"></p>
            <pre style="user-select:all;">sudo paasmcp mirror install-watch</pre>

            <h3 data-i18n="autoStep7" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep7Desc"></p>
            <button class="secondary" onclick="loadArbiterStatus(true)" data-i18n="btnArbRefresh"></button>
          </div>
          <div class="card" data-sub="aa" id="activeCard">
            <div class="card-header"><h2 data-i18n="aaTitle"></h2><p class="card-desc" data-i18n="aaDesc"></p><p class="card-desc" data-i18n="hostReadyNote"></p></div>
            <div id="activeStatusBox" style="margin-bottom:6px;"></div>

            <h3 data-i18n="aaStep1" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="aaStep1Desc"></p>

            <h3 data-i18n="aaStep2" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="aaStep2Desc" style="margin-bottom:10px;"></p>
            <label class="field-label" for="aaApp" data-i18n="lblAppName"></label>
            <select id="aaApp" onchange="renderActiveCheck()"></select>
            <div id="aaCheckBox" style="margin-top:10px;"></div>

            <h3 data-i18n="aaStep3" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="aaStep3Desc" style="margin-bottom:10px;"></p>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button onclick="activeSwitch(true)" data-i18n="btnAaOn"></button>
              <button class="secondary" onclick="activeSwitch(false)" data-i18n="btnAaOff"></button>
            </div>

            <h3 data-i18n="aaStep4" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="aaStep4Desc"></p>
            <p class="card-desc" data-i18n="aaTunnel" style="margin-top:8px;"></p>
            <div id="aaTunnelBox" style="margin-top:8px;"></div>
            <p class="card-desc" data-i18n="aaEdge" style="margin-top:8px;"></p>
            <pre style="user-select:all;">sudo paasmcp edge install --email voce@exemplo.com</pre>
            <label class="field-label" for="aaHost" data-i18n="lblAaHost"></label>
            <input id="aaHost" placeholder="loja.exemplo.com" />
            <div style="margin-top:10px;"><button onclick="edgeAddSite()" data-i18n="btnAaSite"></button></div>
            <div id="edgeStatusBox" style="margin-top:10px;"></div>
          </div>
          <div class="card" data-sub="back">
            <div class="card-header"><h2 data-i18n="failbackTitle"></h2></div>
            <ol style="margin:0;padding-left:20px;font-size:13px;line-height:1.7;">
              <li data-i18n="failback1"></li>
              <li data-i18n="failback2"></li>
              <li data-i18n="failback3"></li>
              <li data-i18n="failback4"></li>
            </ol>
            <details style="margin-top:10px;font-size:12.5px;color:var(--muted);"><summary data-i18n="detailsTech"></summary><p data-i18n="mirrorTech"></p></details>
          </div>
        </div>

        <div class="tab-pane" id="tab-pool">
          <div class="card" data-sub="list">
            <div class="card-header">
              <h2 data-i18n="poolTitle"></h2>
              <p class="card-desc" data-i18n="poolDesc"></p>
              <p class="card-desc" data-i18n="hostReadyNote"></p>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
              <button class="secondary" onclick="loadPool(true)" data-i18n="btnPoolCheck"></button>
            </div>
            <div id="poolJobBox"></div>
            <div id="poolHelpers"></div>
            <h3 data-i18n="poolAppsTitle" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="poolAppsDesc"></p>
            <div id="poolApps"></div>
          </div>
          <div class="card" data-sub="add">
            <div class="card-header"><h2 data-i18n="poolAddTitle"></h2><p class="card-desc" data-i18n="poolAddDesc"></p></div>

            <h3 data-i18n="poolStep1" style="margin-top:12px;"></h3>
            <p class="card-desc" data-i18n="poolStep1Desc"></p>
            <pre style="user-select:all;white-space:pre-wrap;word-break:break-all;">sudo apt install openssh-server
git clone &lt;repository-url&gt; paasmcp &amp;&amp; cd paasmcp &amp;&amp; npm install &amp;&amp; npm run build</pre>

            <h3 data-i18n="poolStep2" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="poolStep2Desc"></p>
            <div class="form-grid" style="grid-template-columns:minmax(0,280px);">
              <div><label class="field-label" for="poolInviteName" data-i18n="lblPoolName"></label><input id="poolInviteName" placeholder="notebook" /></div>
            </div>
            <button onclick="poolInvite()" data-i18n="btnPoolInvite"></button>
            <div id="poolInviteBox" style="display:none;margin-top:10px;">
              <p class="card-desc" id="poolInviteExp"></p>
              <pre id="poolJoinCmd" style="user-select:all;white-space:pre-wrap;word-break:break-all;font-size:11.5px;"></pre>
              <button class="secondary" onclick="copyText(document.getElementById('poolJoinCmd').textContent)" data-i18n="aiCopy"></button>
            </div>

            <h3 data-i18n="poolStep3" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="poolStep3Desc"></p>

            <h3 data-i18n="poolStep4" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="poolStep4Desc"></p>
            <div class="form-grid">
              <div><label class="field-label" for="poolAddName" data-i18n="lblPoolName"></label><input id="poolAddName" placeholder="notebook" /></div>
              <div><label class="field-label" for="poolAddIp" data-i18n="lblPoolIp"></label><input id="poolAddIp" placeholder="100.64.0.7" /></div>
            </div>
            <button onclick="poolAdd()" data-i18n="btnPoolAdd"></button>
            <div id="poolAddBox" style="margin-top:10px;"></div>

            <h3 data-i18n="poolStep5" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="poolStep5Desc"></p>
            <pre style="user-select:all;">sudo tailscale up --advertise-tags=tag:paasmcp-helper</pre>
            <pre id="poolAcl" style="user-select:all;white-space:pre-wrap;word-break:break-all;font-size:11.5px;max-height:320px;overflow:auto;"></pre>
            <button class="secondary" onclick="copyText(document.getElementById('poolAcl').textContent)" data-i18n="aiCopy"></button>
          </div>
          <div class="card" data-sub="how">
            <div class="card-header"><h2 data-i18n="poolHowTitle"></h2></div>
            <p class="card-desc" data-i18n="poolHow1"></p>
            <p class="card-desc" data-i18n="poolHow2"></p>
            <p class="card-desc" data-i18n="poolHow3"></p>
            <p class="card-desc" data-i18n="poolHow4"></p>
          </div>
        </div>

        <div class="tab-pane" id="tab-updates">
          <div class="card">
            <div class="card-header">
              <h2 data-i18n="updatesTitle"></h2>
              <p class="card-desc" data-i18n="updatesDesc"></p>
            </div>
            <div id="updatesList"></div>
            <div style="margin-top:10px;"><button class="secondary" onclick="loadUpdates()" data-i18n="btnCheckUpdates"></button></div>
            <details style="margin-top:10px;font-size:12.5px;color:var(--muted);"><summary data-i18n="updatesMajorQ"></summary><p data-i18n="updatesMajorA"></p></details>
          </div>
        </div>

        <!-- TAB 5: DOCTOR & DIAGNOSTICS -->
        <div class="tab-pane" id="tab-doctor">
          <div class="card">
            <div class="card-header">
              <h2>
                <span id="doctorTitle">🩺 PaaSMCP Doctor — Diagnóstico Automático de Containers</span>
                <button id="btnRunDoctor" onclick="runDoctor(true)">🔍 Executar Diagnóstico Agora</button>
              </h2>
              <p class="card-desc" id="doctorDesc">Verifica <code>OOMKilled</code> (falta de RAM), loops de reinicialização, códigos de saída e saúde de todos os serviços.</p>
            </div>
            <div id="doctorReportBox"></div>
          </div>
        </div>

        <!-- TAB 6: AI AGENT STUDIO & ARCHITECTURE -->
        <div class="tab-pane" id="tab-agents">
          <div class="card" data-sub="connect">
            <div class="card-header">
              <h2 id="agentsTitle">🤖 Como Conectar seu Agente de IA (Clientes MCP Compatíveis)</h2>
              <p class="card-desc" id="agentsDesc">O PaaSMCP expõe <strong>15 ferramentas MCP nativas</strong> via stdio JSON-RPC. Copie a configuração abaixo para que sua IA opere todo o servidor por você:</p>
            </div>
            <p class="card-desc" data-i18n="aiIntro" style="margin:-6px 0 12px;"></p>
            <div class="grid-2" style="margin-bottom:14px;">
              <label class="arch-box" style="cursor:pointer;"><input type="radio" name="aiWhere" value="remote" checked onchange="renderAi()" style="width:auto;" /> <strong data-i18n="aiRemoteTitle"></strong><p data-i18n="aiRemoteDesc"></p></label>
              <label class="arch-box" style="cursor:pointer;"><input type="radio" name="aiWhere" value="local" onchange="renderAi()" style="width:auto;" /> <strong data-i18n="aiLocalTitle"></strong><p data-i18n="aiLocalDesc"></p></label>
            </div>
            <div class="ai-remote">
              <h3 data-i18n="aiStep1"></h3>
              <p class="card-desc" data-i18n="aiStep1Desc"></p>
              <label class="field-label" for="aiTokName" data-i18n="aiTokName"></label>
              <input id="aiTokName" placeholder="ex: notebook" />
              <div style="display:flex;flex-direction:column;gap:6px;margin:10px 0;font-size:12.5px;">
                <label style="display:flex;gap:6px;align-items:flex-start;cursor:pointer;"><input type="radio" name="aiLevel" value="read" style="width:auto;" /> <span data-i18n="aiLvlRead"></span></label>
                <label style="display:flex;gap:6px;align-items:flex-start;cursor:pointer;"><input type="radio" name="aiLevel" value="deploy" checked style="width:auto;" /> <span data-i18n="aiLvlDeploy"></span></label>
                <label style="display:flex;gap:6px;align-items:flex-start;cursor:pointer;"><input type="radio" name="aiLevel" value="destroy" style="width:auto;" /> <span data-i18n="aiLvlDestroy"></span></label>
              </div>
              <button onclick="createAiToken()" data-i18n="aiBtnCreate"></button>
              <div id="aiNewToken" style="display:none;margin-top:10px;"></div>
              <div id="aiTokens" style="margin-top:10px;"></div>
              <h3 data-i18n="aiStep2" style="margin-top:18px;"></h3>
              <p class="card-desc" data-i18n="aiStep2Desc"></p>
              <pre style="user-select:all;">sudo paasmcp mcp install-service</pre>
            </div>
            <h3 data-i18n="aiStep3" style="margin-top:18px;"></h3>
            <div class="grid-2">
              <div><label class="field-label" for="aiClient" data-i18n="aiClient"></label>
                <select id="aiClient" onchange="renderAi()">
                  <option value="claude">Claude Code</option>
                  <option value="codex">Codex CLI</option>
                  <option value="cursor">Cursor</option>
                  <option value="vscode">VS Code (Copilot)</option>
                  <option value="gemini">Gemini CLI</option>
                  <option value="other" data-i18n="aiOther"></option>
                </select></div>
              <div class="ai-remote"><label class="field-label" for="aiHost" data-i18n="aiHost"></label><input id="aiHost" oninput="renderAi()" /></div>
            </div>
            <p class="card-desc" id="aiWhereFile" style="margin-top:10px;"></p>
            <pre id="aiSnippet" style="user-select:all;white-space:pre-wrap;word-break:break-all;"></pre>
            <button class="secondary" onclick="copyText(document.getElementById('aiSnippet').textContent)" data-i18n="aiCopy"></button>
            <h3 data-i18n="aiStep4" style="margin-top:18px;"></h3>
            <p class="card-desc" data-i18n="aiStep4Desc"></p>
            <p class="card-desc" data-i18n="aiWebNote" style="margin-top:10px;"></p>

          </div>

          <div class="card" data-sub="examples">
            <div class="card-header"><h2 data-i18n="aiExamplesTitle"></h2><p class="card-desc" data-i18n="aiExamplesDesc"></p></div>
            <div class="arch-grid" >
              <div class="arch-box">
                <h3 id="promptEx1Title">💬 Deploy & Banco 1-Click</h3>
                <p id="promptEx1Desc">"Faça o deploy do repositório <code>usuario/meu-saas</code> com PostgreSQL, limite de 512m de RAM e publique em <code>saas.{domain}</code>"</p>
              </div>
              <div class="arch-box">
                <h3 id="promptEx2Title">💬 Backup & Rollback</h3>
                <p id="promptEx2Desc">"Crie um backup criptografado do banco do app <code>meu-saas</code> antes de atualizar e faça rollback se der erro"</p>
              </div>
              <div class="arch-box">
                <h3 id="promptEx3Title">💬 Diagnóstico & Multi-Node</h3>
                <p id="promptEx3Desc">"Rode o <code>paas_doctor</code> para ver se algum container sofreu OOMKill e gere um token de pareamento HA"</p>
              </div>
            </div>
          </div>

        </div>

        <!-- Container Logs Drawer -->
        <div class="card" id="logsCard" style="display:none;">
          <div class="card-header">
            <h2>
              <span id="logsTitle">📜 O que o app escreveu (logs)</span>
              <span style="display:flex;gap:6px;">
                <button class="secondary" id="btnRefreshLogs" onclick="if (logsApp) appAction(logsApp, 'logs')" data-i18n="logsRefresh"></button>
                <button class="secondary" id="btnCloseLogs" onclick="document.getElementById('logsCard').style.display='none'">Fechar</button>
              </span>
            </h2>
          </div>
          <p class="ofs-note" id="logsHint" style="margin:0 0 8px;"></p>
          <pre id="logsBox"></pre>
        </div>
      </div>

      <!-- Right Column: Host Telemetry & Resource Usage Sidebar -->
      <aside class="console-sidebar">
        <div id="statsGrid"></div>
        <div class="card" id="approvalsCard" style="display:none;">
          <div class="card-header">
            <h2 id="approvalsTitle" style="font-size:14px;margin:0 0 4px;">✋ Confirmações pendentes</h2>
            <p class="card-desc" id="approvalsDesc" style="font-size:12px;margin:0;">Ações de IA aguardando autorização.</p>
          </div>
          <div id="approvalsList"></div>
        </div>
        <div class="sidebar-footer-note" style="padding:10px 4px;font-size:11.5px;color:var(--muted);display:flex;flex-direction:column;gap:5px;">
          <div>🔒 <strong>Loopback-First</strong> (127.0.0.1)</div>
          <div id="nodeRoleFooter">Node: standalone</div>
        </div>
      </aside>
    </div>

    <div class="toast" id="toast"></div>

  <script>
    let currentLang = localStorage.getItem('paasmcp_lang') || ((navigator.language || '').toLowerCase().startsWith('pt') ? 'pt' : 'en');
    let currentTheme = localStorage.getItem('paasmcp_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    let lastStatus = null;

    const I18N = {
      pt: {
        sidebarSubtitle: "Agent-First Micro-PaaS",
        navHome: "Início",
        navOverview: "Aplicações",
        navVault: "Cofre & Chaves",
        navDatabases: "Bancos de Dados",
        navDoctor: "Diagnóstico",
        navAgents: "MCP & IA",
        navMirror: "Segundo Servidor",
        navPool: "Ajudantes",
        navEmail: "E-mail",
        navUpdates: "Atualizações",
        topHealthBadge: "Sistema Online",
        btnRefresh: "Atualizar",
        btnLogout: "Sair",
        appsTitle: "📦 Aplicações Hospedadas & Métricas em Tempo Real",
        appsDesc: "Containers isolados em <code>127.0.0.1:4000-4998</code> com suporte a Rollback em 1s, limites de CPU/RAM e Docker Compose multi-serviço.",
        thApp: "Aplicação",
        thStack: "Stack / Commit",
        thMetrics: "CPU / RAM (Live)",
        thPort: "Porta / DBs",
        thDomains: "Domínios HTTPS",
        thActions: "Ações Rápidas",
        deployTitle: "➕ Novo Deploy (GitHub, Multi-Service Compose ou Local)",
        deployDesc: "Detecta automaticamente Node, Next.js, Python, Go, SPA, Dockerfile ou <code>docker-compose.yml</code> (injetando segredos do Vault com segurança).",
        exposeTitle: "🌐 Expor Aplicação (Cloudflare Tunnel / Zero Trust / Tailscale)",
        exposeDesc: "Configura rota no Cloudflare Tunnel + DNS CNAME proxied + política Zero Trust sem abrir nenhuma porta no roteador.",
        vaultTitle: "Variáveis de cada app",
        vaultDesc: "O que o código do app lê como variável de ambiente: chaves de serviços (Stripe, OpenAI...), senhas e endereços. Fica cifrado no disco e não aparece inteiro de novo depois de salvo.",
        lblSecScope: "De qual app?",
        lblSecKey: "Nome (letras, números e _)",
        lblSecVal: "Valor",
        btnSaveSecret: "Salvar",
        dbDesc: "Cria banco, role exclusiva e injeta <code>DATABASE_URL</code> / <code>REDIS_URL</code> diretamente no Cofre do app.",
        backupsDesc: "Gera <code>pg_dump</code> ou snapshot Redis, criptografa com a chave mestra do Vault e verifica integridade SHA-256 antes do restore.",
        fedTitle: "🌐 Handshake Multi-Servidor & Redundância (HA Federation)",
        fedDesc: "Pareie um segundo servidor (VPS ou outro Homelab) usando token assinado <code>HMAC-SHA256</code> para rodar os mesmos serviços em <strong>Alta Disponibilidade via Cloudflare Tunnel</strong> ou <strong>Warm Standby</strong>.",
        lblFedUrl: "URL deste Servidor (Primary)",
        lblFedMode: "Modo de Redundância",
        optFedActive: "Active-Active (Cloudflare Tunnel Multi-Connector)",
        optFedWarm: "Warm Standby (Sync Criptografado de Vault & Apps)",
        btnGenInvite: "🔑 Gerar Join Token (15 min)",
        btnExportSync: "📦 Exportar Bundle Criptografado",
        lblJoinPeer: "Conectar este servidor como Réplica (Cole um Join Token):",
        btnJoinPeer: "🤝 Fazer Handshake",
        whTitle: "⚡ Auto-Deploy via GitHub Webhook & Deploy Key SSH",
        whDesc: "Receba <code>git push</code> do GitHub com validação de assinatura <code>X-Hub-Signature-256</code> em tempo constante para reconstruir seus apps automaticamente.",
        doctorTitle: "🩺 PaaSMCP Doctor — Diagnóstico Automático de Containers",
        doctorDesc: "Verifica <code>OOMKilled</code> (falta de RAM), loops de reinicialização, códigos de saída e saúde de todos os serviços.",
        agentsTitle: "🤖 Como Conectar seu Agente de IA (Clientes MCP Compatíveis)",
        agentsDesc: "O PaaSMCP expõe <strong>15 ferramentas MCP nativas</strong> via stdio JSON-RPC. Copie a configuração abaixo para que sua IA opere todo o servidor por você:",
        logsTitle: "📜 O que o app escreveu (logs)",
        btnCloseLogs: "Fechar",
        statHost: "Servidor Host",
        statDisk: "Disco:",
        statMem: "Memória Livre / Total",
        statIdle: "0 MB Idle Daemon",
        statAppsDbs: "Apps & Bancos Isolados",
        statSnapshots: "Snapshots Criptografados",
        statSecurityFed: "Segurança & Federação",
        presetHint_dotnet: "C#: precisa de um <code>.csproj</code> na raiz (ou um projeto web em <code>src/&lt;nome&gt;</code>). O painel roda <code>dotnet publish</code> com a versão do <code>TargetFramework</code> e o app ouve a porta 8080. O banco chega em <code>DATABASE_URL</code>.",
        presetHint_saas: "Next.js: precisa de <code>package.json</code> com os scripts <code>build</code> e <code>start</code>. Roda na porta 3000 e o banco chega em <code>DATABASE_URL</code>.",
        presetHint_django: "Django: precisa de <code>manage.py</code>, <code>requirements.txt</code> e da pasta do projeto com <code>wsgi.py</code>. Roda com gunicorn na porta 8000. Coloque o domínio em <code>ALLOWED_HOSTS</code> e leia o banco de <code>DATABASE_URL</code> (ex.: dj-database-url).",
        presetHint_fastapi: "FastAPI: precisa de <code>requirements.txt</code> com <code>fastapi</code> e <code>uvicorn</code>, e do objeto <code>app</code> em <code>main.py</code> (ou <code>app.py</code>). Roda na porta 8000.",
        presetHint_node: "Node: precisa de <code>package.json</code>. Usa <code>npm start</code> (ou o arquivo de <code>main</code>). O app deve ouvir a porta de <code>process.env.PORT</code> (3000).",
        presetHint_go: "Go: precisa de <code>go.mod</code>; o <code>main</code> pode ficar na raiz ou em <code>cmd/&lt;nome&gt;</code>. O app deve ouvir a porta da variável <code>PORT</code> (8080).",
        presetHint_compose: "Usa o <code>docker-compose.yml</code> do repositório. O serviço <code>web</code>, <code>app</code> ou <code>api</code> (ou o primeiro) recebe o tráfego. Opções inseguras como <code>privileged</code> são removidas.",
        presetHint_spa: "Vite, React ou Astro sem script <code>start</code>: o painel faz o build e serve os arquivos com nginx. Um <code>index.html</code> na raiz também funciona.",
        presetHint_dockerfile: "Para Rails, Laravel, Java ou qualquer outra stack: deixe um <code>Dockerfile</code> na raiz do repositório. A porta vem do <code>EXPOSE</code>.",
        followOn: "Atualiza sozinho",
        followOff: "Atualizar sozinho",
        followOnTitle: "Segue a branch {branch}: cada commit novo é compilado e testado antes de entrar. Clique para parar.",
        followOffTitle: "Passa a seguir a main do repositório: cada commit novo é compilado e testado antes de entrar, e volta sozinho se falhar.",
        followFailed: "Última atualização falhou ({step}) no commit {commit}; o painel segue na versão anterior.",
        promptEx1Title: "💬 Deploy & Banco 1-Click",
        promptEx1Desc: "'Faça o deploy do repositório <code>usuario/meu-saas</code> com PostgreSQL, limite de 512m de RAM e publique em <code>saas.{domain}</code>'",
        promptEx2Title: "💬 Backup & Rollback",
        promptEx2Desc: "'Crie um backup criptografado do banco do app <code>meu-saas</code> antes de atualizar e faça rollback se der erro'",
        promptEx3Title: "💬 Diagnóstico & Multi-Node",
        promptEx3Desc: "'Rode o <code>paas_doctor</code> para ver se algum container sofreu OOMKill e gere um token de pareamento HA'",
        emptyApps: "Nenhuma aplicação hospedada ainda. Use um dos presets abaixo para testar!",
        emptyPeers: "Nenhum servidor secundário pareado ainda.",
        emptySecrets: "Nada salvo aqui ainda.",
        emptyDoctor: "Nenhum container registrado para diagnóstico.",
        actionEnv: "Variáveis",
        actionLogs: "Logs",
        actionRestart: "Reiniciar",
        actionRollback: "Versão anterior",
        actionDelete: "Excluir",
        btnRestartContainer: "🔄 Reiniciar Container",
        lastCheck: "Última checagem:",
        overallStatus: "Status geral:",
        doctorChecking: "⏳ Verificando Containers...",
        doctorDoneToast: "🩺 Diagnóstico concluído",
        approvalsTitle: "✋ Confirmações pendentes",
        approvalsDesc: "Ações arriscadas pedidas por um agente de IA esperam você aqui. O agente não consegue aprovar sozinho.",
        approvalsEmpty: "Nenhuma confirmação pendente.",
        btnApprove: "Aprovar",
        btnReject: "Recusar",
        typeNameToConfirm: "Confirmação forte. Digite o nome para confirmar: ",
        actionRestore: "Restaurar",
        actionPurge: "Apagar de vez",
        trashedStatus: "Na lixeira desde ",
        trashDeleteOn: " · apagado de vez em ",
        toastSecretSaved: "✅ Segredo criptografado no Vault!",
        toastDbCreated: "✅ Banco criado.",
        toastBackupSaved: "📸 Backup criptografado salvo: ",
        toastDbRestored: "✅ Banco restaurado com sucesso",
        toastExposed: "🌐 Publicado em: ",
        toastDeploying: "⏳ Fazendo Build & Deploy...",
        toastDeployDone: "🚀 Deploy concluído: ",
        toastBundleGen: "📦 Bundle criptografado gerado",
        toastHandshakeDone: "🤝 Handshake concluído com o nó primário!",
        copiedToast: "✅ Copiado para a área de transferência!",
        btnRestoreDump: "⏪ Restaurar",
        btnTestRestore: "🧪 Testar",
        offsiteLabel: "fora do servidor",
        btnRemoveSecret: "Remover",
        sizeLabel: "Tamanho:",
        stoppedStatus: "Parado",
        onDemandStatus: "Sem medição de uso agora",
        depPhase_detected: "🔔 Nova versão no repositório",
        depPhase_fetching: "⬇️ Baixando o código",
        depPhase_building: "🔨 Montando a imagem",
        depPhase_checking: "🩺 Testando a nova versão",
        depPhase_switching: "🔁 Trocando de versão",
        depPhase_failed: "❌ Último deploy falhou",
        depOldStillLive: "a versão anterior segue no ar",
        depShowError: "Ver o erro",
        depFirstDeploy: "primeiro deploy",
        depStarted: "começou",
        depDeployed: "deploy",
        depCommitted: "commit",
        depTrig_dashboard: "pelo painel",
        depTrig_cli: "pela linha de comando",
        depTrig_mcp: "pela IA",
        depTrig_webhook: "por push no GitHub",
        depTrig_poll: "pela verificação do repositório",
        depTrig_active: "pelo outro servidor",
        depTrig_mirror: "pelo segundo servidor",
        relNow: "agora",
        relMin: "há {n} min",
        relHour: "há {n} h",
        relDay: "há {n} dias",
      },
      en: {
        sidebarSubtitle: "Agent-First Micro-PaaS",
        navHome: "Home",
        navOverview: "Applications",
        navVault: "Vault & Secrets",
        navDatabases: "Databases",
        navDoctor: "Diagnostics",
        navAgents: "MCP & AI",
        navMirror: "Second Server",
        navPool: "Helpers",
        navEmail: "Email",
        navUpdates: "Updates",
        topHealthBadge: "System Online",
        btnRefresh: "Refresh",
        btnLogout: "Log out",
        appsTitle: "📦 Hosted Applications & Live Metrics",
        appsDesc: "Isolated containers on <code>127.0.0.1:4000-4998</code> with 1s Rollback, CPU/RAM limits, and multi-service Docker Compose.",
        thApp: "Application",
        thStack: "Stack / Commit",
        thMetrics: "CPU / RAM (Live)",
        thPort: "Port / DBs",
        thDomains: "HTTPS Domains",
        thActions: "Quick Actions",
        deployTitle: "➕ New Deploy (GitHub, Multi-Service Compose, or Local)",
        deployDesc: "Auto-detects Node, Next.js, Python, Go, SPA, Dockerfile, or <code>docker-compose.yml</code> (safely injecting Vault secrets).",
        exposeTitle: "🌐 Expose Application (Cloudflare Tunnel / Zero Trust / Tailscale)",
        exposeDesc: "Configures Cloudflare Tunnel routing + proxied DNS CNAME + Zero Trust policy without opening router ports.",
        vaultTitle: "Each app's variables",
        vaultDesc: "What the app's code reads as environment variables: service keys (Stripe, OpenAI...), passwords and addresses. Encrypted on disk and never shown in full again after saving.",
        lblSecScope: "Which app?",
        lblSecKey: "Name (letters, digits and _)",
        lblSecVal: "Value",
        btnSaveSecret: "Save",
        dbDesc: "Creates database, exclusive role, and injects <code>DATABASE_URL</code> / <code>REDIS_URL</code> directly into app Vault.",
        backupsDesc: "Generates <code>pg_dump</code> or Redis snapshot, encrypts with Vault master key, and verifies SHA-256 integrity prior to restore.",
        fedTitle: "🌐 Multi-Server Handshake & Redundancy (HA Federation)",
        fedDesc: "Pair a secondary server (VPS or homelab) via <code>HMAC-SHA256</code> signed token to run identical services in <strong>High Availability via Cloudflare Tunnel</strong> or <strong>Warm Standby</strong>.",
        lblFedUrl: "This Server URL (Primary)",
        lblFedMode: "Redundancy Mode",
        optFedActive: "Active-Active (Cloudflare Tunnel Multi-Connector)",
        optFedWarm: "Warm Standby (Encrypted Vault & App Sync)",
        btnGenInvite: "🔑 Generate Join Token (15 min)",
        btnExportSync: "📦 Export Encrypted Bundle",
        lblJoinPeer: "Connect this server as Replica (Paste Join Token):",
        btnJoinPeer: "🤝 Perform Handshake",
        whTitle: "⚡ Auto-Deploy via GitHub Webhook & SSH Deploy Key",
        whDesc: "Receive GitHub <code>git push</code> with constant-time <code>X-Hub-Signature-256</code> signature validation to auto-rebuild apps.",
        doctorTitle: "🩺 PaaSMCP Doctor — Automated Container Diagnostics",
        doctorDesc: "Checks for <code>OOMKilled</code> (low RAM), restart loops, exit codes, and health of all services.",
        agentsTitle: "🤖 How to Connect your AI Agent (MCP Compatible Clients)",
        agentsDesc: "PaaSMCP exposes <strong>15 native MCP tools</strong> via stdio JSON-RPC. Copy the config below so your AI agent can manage the entire server for you:",
        logsTitle: "📜 What the app wrote (logs)",
        btnCloseLogs: "Close",
        statHost: "Host Server",
        statDisk: "Disk:",
        statMem: "Free / Total Memory",
        statIdle: "0 MB Idle Daemon",
        statAppsDbs: "Isolated Apps & DBs",
        statSnapshots: "Encrypted Snapshots",
        statSecurityFed: "Security & Federation",
        presetHint_dotnet: "C#: needs a <code>.csproj</code> at the root (or one web project in <code>src/&lt;name&gt;</code>). The dashboard runs <code>dotnet publish</code> with the <code>TargetFramework</code> version and the app listens on port 8080. The database arrives in <code>DATABASE_URL</code>.",
        presetHint_saas: "Next.js: needs a <code>package.json</code> with <code>build</code> and <code>start</code> scripts. Runs on port 3000 and the database arrives in <code>DATABASE_URL</code>.",
        presetHint_django: "Django: needs <code>manage.py</code>, <code>requirements.txt</code> and the project folder with <code>wsgi.py</code>. Runs with gunicorn on port 8000. Put the domain in <code>ALLOWED_HOSTS</code> and read the database from <code>DATABASE_URL</code> (e.g. dj-database-url).",
        presetHint_fastapi: "FastAPI: needs a <code>requirements.txt</code> with <code>fastapi</code> and <code>uvicorn</code>, and the <code>app</code> object in <code>main.py</code> (or <code>app.py</code>). Runs on port 8000.",
        presetHint_node: "Node: needs a <code>package.json</code>. Uses <code>npm start</code> (or the <code>main</code> file). The app must listen on <code>process.env.PORT</code> (3000).",
        presetHint_go: "Go: needs <code>go.mod</code>; <code>main</code> can live at the root or in <code>cmd/&lt;name&gt;</code>. The app must listen on the <code>PORT</code> variable (8080).",
        presetHint_compose: "Uses the repository's <code>docker-compose.yml</code>. The <code>web</code>, <code>app</code> or <code>api</code> service (or the first one) gets the traffic. Unsafe options such as <code>privileged</code> are stripped.",
        presetHint_spa: "Vite, React or Astro without a <code>start</code> script: the dashboard builds it and serves the files with nginx. A root <code>index.html</code> works too.",
        presetHint_dockerfile: "For Rails, Laravel, Java or any other stack: put a <code>Dockerfile</code> at the repository root. The port comes from <code>EXPOSE</code>.",
        followOn: "Auto-updates",
        followOff: "Auto-update",
        followOnTitle: "Follows branch {branch}: each new commit is built and tested before it goes live. Click to stop.",
        followOffTitle: "Follow the repository's main branch: each new commit is built and tested before it goes live, and rolls back by itself if it fails.",
        followFailed: "Last update failed ({step}) at commit {commit}; the dashboard stays on the previous version.",
        promptEx1Title: "💬 1-Click Deploy & Database",
        promptEx1Desc: "'Deploy repository <code>user/my-saas</code> with PostgreSQL, 512m RAM limit, and publish on <code>saas.{domain}</code>'",
        promptEx2Title: "💬 Backup & Rollback",
        promptEx2Desc: "'Create an encrypted database backup for app <code>my-saas</code> before upgrading and rollback if it fails'",
        promptEx3Title: "💬 Diagnostics & Multi-Node",
        promptEx3Desc: "'Run <code>paas_doctor</code> to check if any container suffered an OOMKill and generate an HA pairing token'",
        emptyApps: "No hosted applications yet. Use one of the presets below to get started!",
        emptyPeers: "No secondary servers paired yet.",
        emptySecrets: "Nothing saved here yet.",
        emptyDoctor: "No containers registered for diagnostics.",
        actionEnv: "Variables",
        actionLogs: "Logs",
        actionRestart: "Restart",
        actionRollback: "Previous version",
        actionDelete: "Delete",
        btnRestartContainer: "🔄 Restart Container",
        lastCheck: "Last checked:",
        overallStatus: "Overall status:",
        doctorChecking: "⏳ Checking Containers...",
        doctorDoneToast: "🩺 Diagnostics completed",
        approvalsTitle: "✋ Pending confirmations",
        approvalsDesc: "Risky actions requested by an AI agent wait for you here. The agent cannot approve them by itself.",
        approvalsEmpty: "No pending confirmations.",
        btnApprove: "Approve",
        btnReject: "Reject",
        typeNameToConfirm: "Strong confirmation. Type the name to confirm: ",
        actionRestore: "Restore",
        actionPurge: "Delete for good",
        trashedStatus: "In the trash since ",
        trashDeleteOn: " · deleted for good on ",
        toastSecretSaved: "✅ Secret encrypted in Vault!",
        toastDbCreated: "✅ Database created.",
        toastBackupSaved: "📸 Encrypted backup saved: ",
        toastDbRestored: "✅ Database restored successfully",
        toastExposed: "🌐 Published at: ",
        toastDeploying: "⏳ Building & Deploying...",
        toastDeployDone: "🚀 Deploy completed: ",
        toastBundleGen: "📦 Encrypted bundle generated",
        toastHandshakeDone: "🤝 Handshake completed with primary node!",
        copiedToast: "✅ Copied to clipboard!",
        btnRestoreDump: "⏪ Restore",
        btnTestRestore: "🧪 Test",
        offsiteLabel: "off-site",
        btnRemoveSecret: "Remove",
        sizeLabel: "Size:",
        stoppedStatus: "Stopped",
        onDemandStatus: "No usage reading right now",
        depPhase_detected: "🔔 New version in the repository",
        depPhase_fetching: "⬇️ Fetching the code",
        depPhase_building: "🔨 Building the image",
        depPhase_checking: "🩺 Testing the new version",
        depPhase_switching: "🔁 Switching versions",
        depPhase_failed: "❌ Last deploy failed",
        depOldStillLive: "the previous version is still live",
        depShowError: "Show the error",
        depFirstDeploy: "first deploy",
        depStarted: "started",
        depDeployed: "deployed",
        depCommitted: "committed",
        depTrig_dashboard: "from the dashboard",
        depTrig_cli: "from the command line",
        depTrig_mcp: "by the AI",
        depTrig_webhook: "by a GitHub push",
        depTrig_poll: "by the repository check",
        depTrig_active: "by the other server",
        depTrig_mirror: "by the second server",
        relNow: "just now",
        relMin: "{n} min ago",
        relHour: "{n} h ago",
        relDay: "{n} days ago",
      }
    };

    // Plain-language texts (override the older technical ones and add the new screens).
    Object.assign(I18N.pt, {
          "sidebarSubtitle": "Seu servidor de apps",
          "navHome": "Início",
          "navOverview": "Aplicações",
          "navDatabases": "Bancos de dados",
          "navVault": "Senhas e chaves",
          "navEmail": "E-mail",
          "navMirror": "Segundo servidor",
          "navUpdates": "Atualizações",
          "navDoctor": "Diagnóstico",
          "navAgents": "Conectar IA",
          "navPool": "Ajudantes",
          "homeTitle": "Resumo do servidor",
          "appsTitle": "📦 Seus apps",
          "appsDesc": "Cada app roda isolado no servidor. Daqui você vê o uso de memória, abre os logs, volta para a versão anterior ou para o app. Quando chega um commit novo, a linha do app mostra a nova versão sendo montada e testada; a versão atual continua no ar até a nova passar no teste.",
          "deployTitle": "➕ Publicar um app",
          "deployDesc": "Informe o repositório do GitHub (ou uma pasta do servidor). O painel descobre a linguagem e monta tudo sozinho. As senhas do app ficam em Senhas e chaves.",
          "exposeTitle": "🌐 Deixar um app acessível",
          "exposeDesc": "Escolha quem pode abrir: qualquer pessoa na internet, só e-mails autorizados ou só a sua rede privada (Tailscale). Nenhuma porta do roteador é aberta.",
          "dbDesc": "Cada app ganha o seu próprio banco, separado dos outros. O endereço de conexão (<code>DATABASE_URL</code> ou <code>REDIS_URL</code>) entra sozinho nas senhas do app.",
          "backupsDesc": "Cópias cifradas dos bancos e dos arquivos dos apps. Use “Testar” para conferir que a cópia abre antes de precisar dela.",
          "fedTitle": "🔗 Conectar outro servidor",
          "fedDesc": "Primeiro passo para ter um segundo servidor: os dois trocam uma chave de confiança. Depois use a aba “Cópia ao vivo” para copiar os dados.",
          "optFedActive": "Os dois atendem juntos (apps sem dados próprios)",
          "optFedWarm": "Reserva: copia apps e senhas para o outro servidor",
          "btnGenInvite": "🔑 Gerar convite (vale 15 min)",
          "btnExportSync": "📦 Enviar apps e senhas para o outro",
          "lblJoinPeer": "Entrar como segundo servidor (cole o convite):",
          "btnJoinPeer": "🤝 Conectar",
          "whTitle": "⚡ Publicar sozinho a cada git push (webhook)",
          "whDesc": "Opcional, e precisa que o painel seja acessível pela internet. Sem isso, marque “Atualizar sozinho” ao publicar o app: o servidor confere o GitHub a cada 2 minutos.",
          "doctorTitle": "🩺 Diagnóstico",
          "doctorDesc": "Procura apps sem memória, reiniciando sem parar ou parados com erro, e confere o servidor em volta: DNS, Watchtower, redes do Docker e túnel. Diz o que fazer em cada caso.",
          "doctorServer": "🖥️ Este servidor",
          "agentsTitle": "🤖 Conectar sua IA",
          "agentsDesc": "Qualquer IA compatível com MCP (Claude Code, Codex, Gemini CLI, Cursor, VS Code, modelos locais) pode cuidar do servidor por você: publicar apps, fazer cópias, ver o que deu errado. Ações arriscadas sempre esperam a sua aprovação no Início.",
          "homeDesc": "Resumo do servidor, pedidos esperando você e os próximos passos.",
          "optional": "opcional",
          "done": "Feito",
          "openStep": "Fazer agora",
          "never": "Nunca",
          "notConfigured": "Não configurado",
          "off": "Desligada",
          "tileApps": "Apps",
          "tileAppsNote": "rodando neste servidor",
          "tileAppsNone": "Nenhum app ainda",
          "tileBackup": "Última cópia",
          "tileBackupOff": "Guardada também fora do servidor",
          "tileBackupLocal": "Só neste servidor",
          "tileBackupNone": "Nenhuma cópia ainda",
          "tileMirror": "Segundo servidor",
          "tileMirrorOn": "Ligado",
          "tileMirrorOff": "Não usado",
          "tileMirrorNote": "Cópia ao vivo dos dados",
          "tileMirrorWith": "Cópia ao vivo com {who}",
          "tileMirrorStopped": "Parado",
          "tileMirrorStoppedNote": "A cópia com {who} não está passando agora",
          "tileMirrorPairedOnly": "Pareado com {who}, sem cópia dos dados",
          "pairedWith": "Pareado com",
          "pairedNobody": "Ninguém",
          "footerPaired": "Pareado com: {who}",
          "footerUnpaired": "Sem servidor pareado",
          "peerViaCopy": "Pareado pela cópia ao vivo",
          "peerSending": "este servidor manda a cópia",
          "peerReceiving": "este servidor recebe a cópia",
          "tileEmail": "E-mail",
          "tileEmailNote": "Os apps ainda não enviam e-mail",
          "detailsTech": "Detalhes técnicos",
          "offsiteTitle": "☁️ Cópias fora do servidor",
          "offsiteDesc": "Toda noite o servidor faz as cópias e manda para um serviço de armazenamento externo. As cópias locais só são apagadas depois de chegarem lá.",
          "offsiteTech": "As cópias já saem cifradas (AES-256-GCM) deste servidor, então o serviço guarda só dados ilegíveis. O destino fica no cofre, escopo system (BACKUP_S3_*). Pela linha de comando: paasmcp backup target set <serviço>. Horário automático: paasmcp backup install-timer. As chaves geradas aqui são do Garage deste servidor e só funcionam pela Tailscale.",
          "btnSyncOffsite": "☁️ Enviar cópias agora",
          "offsiteDone": "Cópias enviadas:",
          "offsiteFailed": "falharam:",
          "ofsSendTitle": "Para onde mandar as cópias deste servidor",
          "ofsPickProvider": "Escolha onde você tem conta. Só aparecem os campos que esse serviço pede: é copiar e colar.",
          "ofsProvPaasmcp": "Outro PaaSMCP",
          "ofsProvCustom": "Outro (MinIO, S3 compatível)",
          "ofsF_accountId": "ID da conta",
          "ofsF_region": "Região",
          "ofsF_endpoint": "Endereço do servidor",
          "ofsF_bucket": "Nome do bucket",
          "ofsF_accessKeyId": "Access Key ID",
          "ofsF_secretAccessKey": "Secret Access Key",
          "ofsF_code": "Código de acesso",
          "ofsF_prefix": "Pasta dentro do bucket",
          "ofsF_gcs_accessKeyId": "Access key (HMAC)",
          "ofsF_gcs_secretAccessKey": "Secret (HMAC)",
          "ofsF_b2_accessKeyId": "keyID",
          "ofsF_b2_secretAccessKey": "applicationKey",
          "ofsF_custom_region": "Região (se o serviço pedir)",
          "ofsHint_r2": "No painel da Cloudflare, em R2: o ID da conta aparece na página do R2 (pode colar o endereço \\"S3 API\\" inteiro). A chave sai em Gerenciar tokens de API > Criar token, com permissão de leitura e gravação de objetos nesse bucket.",
          "ofsHint_s3": "No console da AWS, em IAM > Usuários > Credenciais de segurança > Criar chave de acesso. Dê ao usuário acesso só a esse bucket.",
          "ofsHint_gcs": "No Google Cloud, em Cloud Storage > Configurações > Interoperabilidade: crie uma chave HMAC para uma conta de serviço com acesso a esse bucket.",
          "ofsHint_b2": "Na Backblaze, em Application Keys > Add a New Application Key, só para esse bucket. A região é o meio do Endpoint do bucket (s3.us-west-004.backblazeb2.com → us-west-004).",
          "ofsHint_wasabi": "No console da Wasabi, em Access Keys > Create New Access Key. A região é a do bucket.",
          "ofsHint_paasmcp": "Cole o código que o outro PaaSMCP gerou em \\"Guardar cópias de outro computador aqui\\". Os dois precisam estar na mesma conta Tailscale.",
          "ofsHint_custom": "Qualquer serviço compatível com S3, como MinIO ou Garage. Use https://, ou http:// só dentro da sua rede ou da Tailscale.",
          "ofsMore": "Mais opções",
          "ofsBtnSave": "Testar e salvar",
          "ofsBtnCancel": "Cancelar",
          "ofsTesting": "Testando: gravando, lendo e apagando um arquivinho no destino…",
          "ofsSaved": "✅ Destino testado e salvo. As cópias vão para lá toda noite.",
          "ofsNoDelete": "(A chave grava mas não apaga; as cópias funcionam assim mesmo.)",
          "ofsTestOk": "✅ O destino respondeu: gravou e leu o arquivo de teste.",
          "ofsActive": "Ativo",
          "ofsFolder": "pasta",
          "ofsKey": "chave",
          "ofsTestedAt": "testado em",
          "ofsBtnTest": "Testar",
          "ofsBtnChange": "Trocar destino",
          "ofsBtnStop": "Parar de enviar",
          "ofsSending": "Enviando…",
          "ofsGiveTitle": "Guardar cópias de outro computador aqui",
          "ofsGiveDesc": "Gera uma chave que outro PaaSMCP, um computador ou um app usa para guardar cópias num bucket só dele neste servidor, pela Tailscale. Ele não enxerga mais nada daqui, e você pode revogar a chave quando quiser.",
          "ofsGrantName": "Nome de quem vai usar",
          "ofsGrantGb": "Limite em GB (vazio = sem limite)",
          "ofsBtnGrant": "Gerar chave",
          "ofsNeedName": "Dê um nome, por exemplo notebook ou servidor-casa.",
          "ofsGrantReady": "Chave criada.",
          "ofsGrantOnce": "Ela aparece só agora: copie antes de fechar. Se perder, revogue e gere outra.",
          "ofsGrantCodeLabel": "Para outro PaaSMCP: cole este código lá, em \\"Outro PaaSMCP\\"",
          "ofsCopyCode": "Copiar código",
          "ofsCopy": "Copiar",
          "ofsDoneHide": "Já copiei, esconder",
          "ofsGrantFields": "Para outro programa (rclone, restic, app): os campos separados",
          "ofsGrantInternal": "Um app que roda neste mesmo servidor usa o endereço interno:",
          "ofsStored": "guardando",
          "ofsLimit": "limite",
          "ofsRevoked": "Revogada",
          "ofsBtnRevoke": "Revogar",
          "ofsRevokedMsg": "A chave de {name} não funciona mais. O que já foi guardado continua aqui.",
          "storageTitle": "🗂️ Arquivos dos apps",
          "storageDesc": "Espaço para fotos, PDFs e uploads. Cada app ganha o seu, com chave própria; as bibliotecas comuns (boto3, AWS SDK) funcionam sem mudar código.",
          "storageNone": "Nenhum app com espaço de arquivos ainda.",
          "btnStorage": "+ Criar espaço de arquivos",
          "storageDone": "Espaço criado. Publique o app de novo para ele usar.",
          "lblAppName": "Nome do app",
          "lblDepPoll": "Atualizar sozinho quando eu mudar o código (confere a cada 2 min)",
          "lblDepStorage": "Criar espaço para arquivos",
          "lblDepEmail": "Deixar o app enviar e-mails",
          "emailTitle": "✉️ Envio de e-mails",
          "emailDesc": "E-mail enviado direto de casa cai no spam ou nem sai. Por isso o painel usa um serviço de envio, configurado uma vez para todos os apps.",
          "emailTip": "Sugestão: o Brevo tem plano gratuito de 300 e-mails por dia. Crie a conta, confirme seu domínio e copie os dados de SMTP. A senha fica cifrada e só é enviada por conexão segura.",
          "lblEmHost": "Servidor SMTP",
          "lblEmPort": "Porta",
          "lblEmUser": "Usuário",
          "lblEmPass": "Senha ou chave",
          "lblEmDomain": "Seu domínio de envio",
          "btnSave": "💾 Salvar",
          "saved": "Salvo.",
          "keepSaved": "(deixe vazio para manter a salva)",
          "emailOn": "Configurado:",
          "emailTestTitle": "Mandar um e-mail de teste",
          "lblEmTo": "Para",
          "btnEmailTest": "📨 Mandar teste",
          "emailSent": "E-mail de teste aceito pelo serviço.",
          "emailAppTitle": "Liberar e-mail para um app",
          "emailAppDesc": "Coloca os dados de envio nas senhas do app. Publique o app de novo para ele usar.",
          "btnEmailApp": "Liberar",
          "emailAppDone": "Pronto. Remetente:",
          "mirrorTitle": "🔁 Segundo servidor",
          "mirrorDesc": "Os dois servidores guardam uma cópia ao vivo um do outro. Se um cair, o outro pode assumir os apps dele com os dados até o último segundo. Antes, conecte os dois na aba “Conectar”.",
          "mirrorNone": "Nenhuma cópia configurada ainda. Use os dois quadros abaixo: um servidor oferece, o outro recebe.",
          "aaTitle": "⚖️ App nos dois servidores",
          "aaDesc": "O app roda aqui e no outro servidor ao mesmo tempo, e os dois recebem visitas. Os dados continuam gravados num banco só, o deste servidor: o outro grava nele pela Tailscale. Se este servidor cair, a troca automática (aba “Troca automática”) faz o outro seguir sozinho.",
          "hostReadyNote": "Antes de testar, abra o Diagnóstico: ele avisa se este servidor está sem DNS de reserva, se o Watchtower pode reiniciar os contêineres do PaaSMCP no meio do teste ou se as redes do Docker estão chegando perto da sua rede de casa.",
          "aaNone": "Nenhum app rodando nos dois servidores ainda.",
          "aaOrigin": "criado aqui, roda nos dois",
          "aaCopy": "vem de {peer}, roda aqui também",
          "aaRunning": "versão aqui",
          "aaWanted": "versão pedida",
          "aaStep1": "1. Antes: cópia e vigia",
          "aaStep1Desc": "Este servidor precisa mandar cópia para o outro (aba “Cópia ao vivo”, quadro “Oferecer cópia”, com o IP do Tailscale), e o vigia precisa rodar no outro servidor (passo 6 da troca automática). É o vigia que mantém o app do outro servidor na mesma versão deste, em até 15 segundos.",
          "aaStep2": "2. Escolha o app e confira",
          "aaStep2Desc": "Só aparecem apps criados neste servidor. O quadro diz o que falta e o que vale ajustar antes de ligar.",
          "aaReady": "Pronto para rodar nos dois",
          "aaIsOn": "Já está rodando nos dois",
          "aaStep3": "3. Ligue",
          "aaStep3Desc": "Ao ligar, o painel pede confirmação, refaz o deploy da mesma versão aqui e avisa o outro servidor, que sobe o app em seguida. Desligar faz o outro servidor parar a cópia do app.",
          "btnAaOn": "Rodar nos dois",
          "btnAaOff": "Rodar só aqui",
          "aaSwitched": "Feito. O outro servidor acompanha em até 15 segundos.",
          "aaStep4": "4. Escolha por onde as visitas entram",
          "aaStep4Desc": "Dá para usar uma das duas entradas, ou as duas.",
          "aaTunnel": "Com Cloudflare Tunnel: ligue o túnel dos dois servidores. O PaaSMCP cria um túnel só para estes apps, roda esse túnel aqui e no outro servidor, e muda o DNS de cada endereço quando a cópia no outro servidor responder. Os outros apps continuam no túnel atual. Se a cópia de um servidor ficar sem saúde, esse servidor sai do túnel sozinho até ela voltar. Para isso, o “paasmcp mirror watch” precisa rodar nos dois servidores.",
          "btnAaTunnelOn": "Ligar o túnel dos dois servidores",
          "btnAaTunnelOff": "Desligar o túnel dos dois servidores",
          "aaTunOn": "Túnel dos dois servidores ligado",
          "aaTunOff": "Túnel dos dois servidores desligado",
          "aaTunCopy": "Este servidor roda o túnel do outro servidor",
          "aaTunNoCf": "A Cloudflare não está configurada neste servidor.",
          "aaTunHere": "conector aqui",
          "aaTunRunning": "no túnel",
          "aaTunStopped": "fora do túnel",
          "aaTunAbsent": "não iniciado",
          "aaTunHosts": "Endereços no túnel",
          "aaTunSick": "sem saúde",
          "aaEdge": "Sem depender de cloud: num servidor com IP público (normalmente o VPS), ligue a entrada própria pelo terminal com o comando abaixo. Ela abre as portas 80 e 443, pega o HTTPS sozinha e confere a cada 5 segundos se o app responde em cada servidor. Depois adicione o site aqui e aponte o DNS (registro A) para o IP público desse servidor.",
          "lblAaHost": "Endereço do site",
          "btnAaSite": "Adicionar site à entrada própria",
          "aaEdgeOff": "A entrada própria não está ligada neste servidor.",
          "aaEdgeOn": "Entrada própria ligada",
          "aaEdgeStopped": "Entrada própria instalada, mas parada",
          "aaHere": "este servidor",
          "aaFiles": "arquivos copiados às {time}",
          "aaFilesErr": "cópia dos arquivos falhou",
          "aaFilesPending": "o resto continua na próxima rodada",
          "aaFilesBig": "{n} arquivo(s) acima de 512 MB não copiados",
          "aaRemove": "Remover",
          "aaDns": "Site adicionado. Agora crie no DNS um registro A de {host} para o IP público deste servidor.",
          "aaP_trashed": "O app está na lixeira.",
          "aaP_fromPeer": "Este app veio do outro servidor: ligue lá, onde ele foi criado.",
          "aaP_localSource": "O app foi publicado de uma pasta local. O outro servidor precisa de um repositório git para montar a mesma versão.",
          "aaP_noCommit": "Faça o deploy do app mais uma vez, para este servidor guardar o commit exato que está no ar.",
          "aaP_noMirror": "Nenhum servidor recebe cópia deste ainda. Configure a cópia primeiro, na aba “Cópia ao vivo”.",
          "aaP_noBindIp": "A cópia foi oferecida sem o IP do Tailscale, então o outro servidor não alcança este banco. Ofereça de novo pelo terminal com --advertise <IP do Tailscale deste servidor>.",
          "aaP_fenced": "Este servidor está bloqueado: outro servidor serve os dados dele agora.",
          "aaP_noHealthcheck": "O app não tem verificação de saúde por HTTP, e a entrada precisa dela para parar de mandar visitas a um servidor que caiu.",
          "aaW_rootHealthPath": "Use um caminho de verificação de saúde que consulte o banco (por exemplo /healthz). Com “/”, um servidor que perdeu o banco continua recebendo visitas.",
          "aaW_zeroTrustBypass": "O app está atrás do login da Cloudflare (Zero Trust). Rodando nos dois, a porta dele também fica no IP do Tailscale, onde qualquer aparelho da sua Tailnet chega sem esse login. Mantenha o login do próprio app, ou limite a Tailnet com ACLs.",
          "aaW_localVolumes": "O app grava arquivos em volumes locais ({v}): esses arquivos ficariam diferentes em cada servidor. Guarde os envios no armazenamento S3 (tela Armazenamento), que é copiado para o outro servidor.",
          "mirrorAuto": "Troca automática",
          "mirrorArbiter": "Juiz",
          "mirrorSendingTo": "Mandando cópia para",
          "connected": "Conectado",
          "waitingPeer": "Esperando o outro servidor",
          "mirrorLost": "O outro servidor ficou fora tempo demais e precisa de uma cópia nova: ofereça de novo.",
          "mirrorCopyOf": "Cópia de",
          "mirrorUpToDate": "Em dia",
          "mirrorNotStreaming": "Parada",
          "mirrorServingHere": "Apps rodando aqui",
          "mirrorPromoteDesc": "Se esse servidor cair, você pode assumir os apps dele aqui.",
          "btnRetire": "Parar de seguir",
          "mirrorRetireDesc": "Se outro servidor já assumiu {peer} à mão, use Parar de seguir aqui: esta cópia ficou para trás e não deve assumir.",
          "mirrorRetired": "Este servidor parou de seguir.",
          "mirrorBehind": "Ficou para trás",
          "mirrorBehindBy": "O servidor {who} assumiu esses dados.",
          "mirrorBehindManual": "Você marcou que outro servidor assumiu esses dados.",
          "mirrorBehindDesc": "Esta cópia não recebe mais nada e nunca assume sozinha. Para refazê-la, peça uma nova oferta a quem guarda os dados agora: {peer}, se voltar, ou o servidor que assumiu, com --from-copy-of {peer} (a cópia antiga fica guardada no disco).",
          "mirrorLostDesc": "Este servidor tinha assumido os dados de {peer}, ficou fora por mais de um minuto e outro assumiu no lugar. Os apps de {peer} pararam aqui e não sobem mais. Para voltar a ter uma cópia, peça uma nova oferta a quem assumiu, com --from-copy-of {peer} (os dados daqui ficam guardados no disco).",
          "mirrorVia": "pelo servidor {who}",
          "mirrorPromotedDesc": "Os apps dele estão rodando aqui. Quando ele voltar, siga a aba “Devolver apps”.",
          "btnPromote": "Assumir os apps",
          "btnHandback": "Devolver os apps",
          "mirrorFenced": "Bloqueado",
          "mirrorFencedDesc": "Outro servidor assumiu os dados deste enquanto ele estava fora. Os apps daqui ficam parados até a devolução, para não gravar dados diferentes.",
          "mirrorOfferTitle": "Oferecer cópia ao outro servidor",
          "mirrorOfferDesc": "Gera um convite. Cole-o no outro servidor, no quadro ao lado.",
          "lblPeerName": "Nome do outro servidor",
          "lblPeerIp": "Endereço do outro servidor no Tailscale",
          "lblFromCopyOf": "Devolução: cópia de qual servidor? (deixe vazio no uso normal)",
          "btnMirrorOffer": "🔑 Gerar convite",
          "mirrorAcceptTitle": "Receber cópia do outro servidor",
          "mirrorAcceptDesc": "Cole o convite gerado no outro servidor.",
          "lblInvite": "Convite",
          "lblRejoin": "Este servidor caiu e está voltando (recebe os dados novos do outro)",
          "btnMirrorAccept": "🤝 Receber cópia",
          "mirrorAccepted": "Cópia iniciada.",
          "mirrorPromoted": "Apps assumidos.",
          "mirrorHandedBack": "Apps devolvidos. Agora assuma-os no outro servidor.",
          "autoGoJudge": "Ver o juiz",
          "judgeTitle": "⚖️ Juiz",
          "judgeDesc": "Um terceiro aparelho que dá o voto de desempate na troca automática. Ele não guarda apps nem dados: só ouve os servidores e anota quem cuida dos dados de quem.",
          "judgeState_none": "Não configurado",
          "judgeState_ok": "Respondendo",
          "judgeState_err": "Sem resposta",
          "judgeNoneDesc": "Sem juiz, a troca automática fica desligada: se um servidor cair, você assume os apps dele à mão (aba “Cópia ao vivo”). Para configurar, siga os 3 passos abaixo.",
          "judgeAddress": "Endereço",
          "judgeWhere": "Onde roda",
          "judgeOldArbiter": "versão antiga do juiz: rode de novo o comando do passo 2 no aparelho dele para ver o nome",
          "judgeSince": "Ligado desde",
          "judgeLatency": "Tempo de resposta",
          "judgeLastWatch": "Último contato do vigia daqui",
          "judgeWatchNever": "nunca: ligue o vigia (aba “Troca automática”, passo 2)",
          "judgeWatchErr": "última falha {when}: {err}",
          "judgeHears": "Servidores que ele ouve",
          "judgeHeardNone": "nenhum ainda",
          "judgeHeardAgo": "{who} {when}",
          "judgeClusters": "Pares de servidores que ele atende",
          "judgeHowTitle": "Como o juiz decide",
          "judgeHow1": "Cada servidor avisa o juiz que está vivo a cada 15 segundos. Quem faz isso é o vigia de cada servidor.",
          "judgeHow2": "Se um servidor some por mais de 1 minuto, o outro só assume os apps dele se o juiz também parou de ouvi-lo e a cópia parou de chegar. Se só a conexão entre os dois caiu, o juiz ainda ouve os dois e a troca não acontece.",
          "judgeHow3": "O juiz deixa um único servidor assumir. Cada troca recebe um número maior que a anterior, e um pedido com número velho é recusado.",
          "judgeHow4": "Quando o servidor que caiu volta, ele pergunta ao juiz, vê que outro assumiu e para os próprios apps até a devolução. Assim os dois nunca gravam dados diferentes.",
          "judgeOwnersTitle": "Quem cuida dos dados agora",
          "judgeOwnersNone": "Nenhuma troca registrada: cada servidor cuida dos próprios dados.",
          "judgeOwnerLine": "Dados de {data}: com {owner} (troca nº {epoch})",
          "judgeOwnerHome": "Dados de {data}: de volta com {owner} (troca nº {epoch})",
          "judgeSetupTitle": "Configurar o juiz",
          "judgeSetupRedo": "Trocar ou reinstalar o juiz",
          "judgeBefore": "Antes de começar: os dois servidores precisam estar conectados (aba “Conectar”) e os três aparelhos na mesma rede Tailscale. Faça os passos uma vez, nesta ordem.",
          "btnArbCmd": "Gerar comando de instalação",
          "autoStep2After": "No fim, o comando mostra o endereço do juiz. Use-o no passo 3. A chave dentro do comando só serve para o juiz (não abre senhas, apps nem dados), mas não a passe para outras pessoas: quem tem a chave pode confundir o juiz.",
          "autoPrereqTitle": "O aparelho ainda não tem Node.js ou Tailscale?",
          "autoPrereqDesc": "O juiz precisa de Node.js 20 ou mais novo, git e o Tailscale na mesma conta dos servidores. Em Ubuntu ou Debian, estes comandos instalam o que falta:",
          "autoTitle": "Troca automática",
          "autoDesc": "Se o outro servidor sumir por mais de 1 minuto, este assume os apps dele sozinho. Para isso precisa de um juiz: um terceiro aparelho que dá o voto de desempate. Sem juiz, se só a conexão entre os dois cair, cada um acharia que o outro morreu e os dois gravariam dados diferentes.",
          "autoBefore": "Antes: a cópia precisa estar funcionando (aba “Cópia ao vivo”) e o juiz configurado e respondendo.",
          "autoStep1": "1. Escolha o aparelho do juiz",
          "autoStep1Desc": "Qualquer aparelho ligado 24 horas que não seja nenhum dos dois servidores: uma VM pequena na nuvem (como as gratuitas da Oracle), um Raspberry Pi ou um PC velho. De preferência em outro lugar ou outra internet. Não precisa de Docker e quase não usa memória.",
          "autoStep2": "2. Instale o juiz no terceiro aparelho",
          "autoStep2Desc": "Gere o comando abaixo, já com a chave deste par de servidores, e cole-o no terminal do aparelho do juiz. Ele baixa o PaaSMCP e deixa o juiz rodando como serviço: volta sozinho depois de reiniciar e atende só no endereço Tailscale do aparelho, porta 4097. Se o aparelho já é juiz de outro par de servidores, use o mesmo comando: o outro par continua.",
          "autoStep3": "3. Informe o endereço do juiz (neste servidor e no outro)",
          "autoStep3Desc": "É o endereço que o comando do passo 2 mostrou no fim, por exemplo http://100.64.0.9:4097. Clique em Testar: tem que aparecer “O juiz respondeu”. Depois Salvar. Faça o mesmo no painel do outro servidor, com o mesmo endereço.",
          "autoStep3Check": "Para conferir no próprio aparelho do juiz, rode o comando abaixo. Se responder {&quot;ok&quot;:true}, o juiz está no ar.",
          "btnArbTest": "Testar",
          "btnArbSave": "Salvar",
          "autoStep5": "1. Escolha qual servidor este pode substituir",
          "autoStep5Desc": "É o servidor cujos apps este vai assumir se ele cair. A lista mostra só os servidores dos quais este já guarda uma cópia. Ao ligar, o painel pede para digitar o nome para confirmar. Se a cópia é nos dois sentidos e você quer que qualquer um assuma o outro, faça este passo também no outro servidor.",
          "lblAutoPeer": "Servidor que este pode substituir",
          "autoNoCopy": "Nenhuma cópia recebida ainda (use “Receber cópia”, na aba “Cópia ao vivo”)",
          "autoNoPeer": "Escolha o servidor na lista. Se ela estiver vazia, este servidor ainda não guarda cópia de nenhum outro.",
          "autoStep6": "2. Ligue o vigia (nos dois servidores)",
          "autoStep6Desc": "O vigia conversa com o juiz a cada 15 segundos. É ele que avisa o juiz que o servidor está vivo, troca sozinho quando precisa e bloqueia o servidor que volta depois de ter sido substituído. Rode o comando abaixo no terminal de cada um dos dois servidores.",
          "autoStep7": "3. Confira se está funcionando",
          "autoStep7Desc": "O quadro no topo deste cartão mostra o que o juiz está ouvindo. Está pronto quando tudo fica verde: o juiz respondeu, ouviu este servidor e o outro há menos de 1 minuto, o vigia está rodando aqui e a troca está ligada. Se o outro servidor não aparece ou aparece com tempo alto, falta informar o juiz (aba “Juiz”) ou ligar o vigia nele.",
          "btnArbRefresh": "Verificar de novo",
          "arbNotSet": "Juiz ainda não configurado (aba “Juiz”).",
          "arbOk": "O juiz respondeu e aceitou a chave",
          "arbThisServer": "este servidor",
          "arbHeard": "O juiz ouviu {who} há {s} s",
          "arbHeardOld": "mais de 1 minuto: o vigia está ligado nele?",
          "arbPeerUnknown": "O juiz nunca ouviu {who}. Em {who}, informe o endereço do juiz (aba “Juiz”) e ligue o vigia (passo 2 daqui). Enquanto isso, se a cópia parar, este servidor assume.",
          "arbWatchOn": "Vigia rodando neste servidor",
          "arbWatchOff": "Vigia desligado neste servidor (passo 2 da troca automática)",
          "arbAutoOn": "Troca automática ligada para: {who}",
          "arbAutoOff": "Troca automática desligada neste servidor (passo 1 da troca automática)",
          "arbAutoTag": "troca ligada",
          "arbReady": "✅ Troca automática pronta",
          "arbNotReady": "Ainda falta algo:",
          "arbErr_badUrl": "Endereço inválido. Use http://<IP do Tailscale do juiz>:4097",
          "arbErr_badKey": "O juiz respondeu, mas recusou a chave. Rode de novo, no aparelho do juiz, o comando do passo 2 (aba “Juiz”).",
          "arbErr_clock": "O juiz respondeu, mas o relógio dele está mais de 1 minuto diferente. Ligue o horário automático nos aparelhos.",
          "arbErr_notPaired": "Este servidor ainda não foi pareado com o outro: faça isso em Segundo servidor, aba “Conectar”.",
          "arbErr_notArbiter": "Algo respondeu nesse endereço, mas não é o juiz. Confira a porta (padrão 4097).",
          "arbErr_unreachable": "O juiz não respondeu. Confira se ele está ligado (passo 2 da aba “Juiz”), se o IP é o do Tailscale dele e se a porta é 4097.",
          "lblArbiter": "Endereço do juiz",
          "btnAutoOn": "Ligar",
          "btnAutoOff": "Desligar",
          "failbackTitle": "Devolver os apps quando o servidor que caiu voltar",
          "failback1": "Aqui: em “Oferecer cópia”, preencha a devolução com o nome do servidor que caiu e gere o convite.",
          "failback2": "No servidor que voltou: cole o convite e marque “Este servidor caiu e está voltando”.",
          "failback3": "Aqui: clique em “Devolver os apps”.",
          "failback4": "No servidor que voltou: clique em “Assumir os apps”.",
          "mirrorTech": "Replicação física do PostgreSQL (streaming) com slot limitado a 10 GB. Cada troca aumenta a época; o servidor com época menor fica bloqueado (fencing). O juiz só autoriza a troca se também não ouvir o servidor caído.",
          "updatesTitle": "⬆️ Atualizações",
          "updatesDesc": "O painel só instala correções que não mudam o formato dos dados. Antes de atualizar ele faz uma cópia de segurança e, se algo der errado em 1 minuto, volta sozinho para a versão anterior.",
          "btnCheckUpdates": "🔍 Procurar atualizações",
          "checking": "Procurando…",
          "upToDate": "Em dia",
          "btnUpdate": "Atualizar",
          "updateDone": "Atualizado para",
          "updateRolledBack": "A atualização não funcionou e tudo voltou como estava:",
          "compPostgres": "Banco de dados (PostgreSQL)",
          "compRedis": "Cache (Redis)",
          "compGarage": "Arquivos (Garage)",
          "updatesMajorQ": "E as versões grandes (ex.: PostgreSQL 17)?",
          "updatesMajorA": "Mudam o formato dos dados e precisam de migração própria. O painel não instala sozinho."
    });
    Object.assign(I18N.en, {
          "sidebarSubtitle": "Your app server",
          "navHome": "Home",
          "navOverview": "Applications",
          "navDatabases": "Databases",
          "navVault": "Secrets & keys",
          "navEmail": "Email",
          "navMirror": "Second Server",
          "navUpdates": "Updates",
          "navDoctor": "Diagnostics",
          "navAgents": "Connect AI",
          "navPool": "Helpers",
          "homeTitle": "Server summary",
          "appsTitle": "📦 Your apps",
          "appsDesc": "Each app runs isolated on the server. From here you see memory use, open logs, go back to the previous version or stop the app. When a new commit arrives, the app's row shows the new version being built and tested; the current version stays live until the new one passes the test.",
          "deployTitle": "➕ Publish an app",
          "deployDesc": "Enter the GitHub repository (or a folder on the server). The dashboard detects the language and builds everything. App passwords live in Passwords & keys.",
          "exposeTitle": "🌐 Make an app reachable",
          "exposeDesc": "Choose who can open it: anyone on the internet, only allowed emails, or only your private network (Tailscale). No router port is opened.",
          "dbDesc": "Each app gets its own database, separate from the others. The connection address (<code>DATABASE_URL</code> or <code>REDIS_URL</code>) goes into the app's passwords automatically.",
          "backupsDesc": "Encrypted copies of app databases and files. Use “Test” to check a backup opens before you need it.",
          "fedTitle": "🔗 Connect another server",
          "fedDesc": "First step to a second server: both exchange a trust key. Then use the “Live copy” tab to copy the data.",
          "optFedActive": "Both serve together (apps without their own data)",
          "optFedWarm": "Standby: copy apps and passwords to the other server",
          "btnGenInvite": "🔑 Create invite (valid 15 min)",
          "btnExportSync": "📦 Send apps and passwords to the other",
          "lblJoinPeer": "Join as second server (paste the invite):",
          "btnJoinPeer": "🤝 Connect",
          "whTitle": "⚡ Publish on every git push (webhook)",
          "whDesc": "Optional, and the dashboard must be reachable from the internet. Without that, tick “Update by itself” when publishing: the server checks GitHub every 2 minutes.",
          "doctorTitle": "🩺 Diagnostics",
          "doctorDesc": "Looks for apps out of memory, restarting in a loop or stopped with an error, and checks the server around them: DNS, Watchtower, Docker networks and the tunnel. Says what to do in each case.",
          "doctorServer": "🖥️ This server",
          "agentsTitle": "🤖 Connect your AI",
          "agentsDesc": "Any MCP-compatible AI (Claude Code, Codex, Gemini CLI, Cursor, VS Code, local models) can run the server for you: publish apps, make backups, find what went wrong. Risky actions always wait for your approval on Home.",
          "homeDesc": "Server summary, requests waiting for you and next steps.",
          "optional": "optional",
          "done": "Done",
          "openStep": "Do it now",
          "never": "Never",
          "notConfigured": "Not set up",
          "off": "Off",
          "tileApps": "Apps",
          "tileAppsNote": "running on this server",
          "tileAppsNone": "No apps yet",
          "tileBackup": "Last backup",
          "tileBackupOff": "Also stored off the server",
          "tileBackupLocal": "Only on this server",
          "tileBackupNone": "No backups yet",
          "tileMirror": "Second server",
          "tileMirrorOn": "On",
          "tileMirrorOff": "Not used",
          "tileMirrorNote": "Live copy of the data",
          "tileMirrorWith": "Live copy with {who}",
          "tileMirrorStopped": "Stopped",
          "tileMirrorStoppedNote": "The copy with {who} is not flowing right now",
          "tileMirrorPairedOnly": "Paired with {who}, no data copy",
          "pairedWith": "Paired with",
          "pairedNobody": "Nobody",
          "footerPaired": "Paired with: {who}",
          "footerUnpaired": "No paired server",
          "peerViaCopy": "Paired through the live copy",
          "peerSending": "this server sends the copy",
          "peerReceiving": "this server receives the copy",
          "tileEmail": "Email",
          "tileEmailNote": "Apps cannot send email yet",
          "detailsTech": "Technical details",
          "offsiteTitle": "☁️ Backups off the server",
          "offsiteDesc": "Every night the server makes backups and sends them to external storage. Local copies are only deleted after they arrive there.",
          "offsiteTech": "Backups leave this server already encrypted (AES-256-GCM), so the service only keeps unreadable data. The destination lives in the vault, system scope (BACKUP_S3_*). From the command line: paasmcp backup target set <provider>. Nightly schedule: paasmcp backup install-timer. Keys made here belong to this server's Garage and only work over Tailscale.",
          "btnSyncOffsite": "☁️ Send backups now",
          "offsiteDone": "Backups sent:",
          "offsiteFailed": "failed:",
          "ofsSendTitle": "Where this server's backups go",
          "ofsPickProvider": "Pick where you have an account. Only the fields that service needs show up: just copy and paste.",
          "ofsProvPaasmcp": "Another PaaSMCP",
          "ofsProvCustom": "Other (MinIO, S3 compatible)",
          "ofsF_accountId": "Account ID",
          "ofsF_region": "Region",
          "ofsF_endpoint": "Server address",
          "ofsF_bucket": "Bucket name",
          "ofsF_accessKeyId": "Access Key ID",
          "ofsF_secretAccessKey": "Secret Access Key",
          "ofsF_code": "Access code",
          "ofsF_prefix": "Folder inside the bucket",
          "ofsF_gcs_accessKeyId": "Access key (HMAC)",
          "ofsF_gcs_secretAccessKey": "Secret (HMAC)",
          "ofsF_b2_accessKeyId": "keyID",
          "ofsF_b2_secretAccessKey": "applicationKey",
          "ofsF_custom_region": "Region (if the service asks)",
          "ofsHint_r2": "In the Cloudflare dashboard, under R2: the account ID is on the R2 page (you can paste the whole \\"S3 API\\" address). The key comes from Manage API tokens > Create token, with object read and write on this bucket.",
          "ofsHint_s3": "In the AWS console, under IAM > Users > Security credentials > Create access key. Give the user access to this bucket only.",
          "ofsHint_gcs": "In Google Cloud, under Cloud Storage > Settings > Interoperability: create an HMAC key for a service account that can use this bucket.",
          "ofsHint_b2": "At Backblaze, under Application Keys > Add a New Application Key, for this bucket only. The region is the middle of the bucket's Endpoint (s3.us-west-004.backblazeb2.com → us-west-004).",
          "ofsHint_wasabi": "In the Wasabi console, under Access Keys > Create New Access Key. The region is the bucket's.",
          "ofsHint_paasmcp": "Paste the code the other PaaSMCP made under \\"Keep another computer's backups here\\". Both must be on the same Tailscale account.",
          "ofsHint_custom": "Any S3-compatible service, like MinIO or Garage. Use https://, or http:// only inside your network or Tailscale.",
          "ofsMore": "More options",
          "ofsBtnSave": "Test and save",
          "ofsBtnCancel": "Cancel",
          "ofsTesting": "Testing: writing, reading and deleting a tiny file at the destination…",
          "ofsSaved": "✅ Destination tested and saved. Backups go there every night.",
          "ofsNoDelete": "(The key can write but not delete; backups work anyway.)",
          "ofsTestOk": "✅ The destination answered: it saved and read the test file.",
          "ofsActive": "Active",
          "ofsFolder": "folder",
          "ofsKey": "key",
          "ofsTestedAt": "tested",
          "ofsBtnTest": "Test",
          "ofsBtnChange": "Change destination",
          "ofsBtnStop": "Stop sending",
          "ofsSending": "Sending…",
          "ofsGiveTitle": "Keep another computer's backups here",
          "ofsGiveDesc": "Makes a key that another PaaSMCP, a computer or an app uses to keep backups in a bucket of its own on this server, over Tailscale. It sees nothing else here, and you can revoke the key any time.",
          "ofsGrantName": "Name of who will use it",
          "ofsGrantGb": "Limit in GB (empty = no limit)",
          "ofsBtnGrant": "Make key",
          "ofsNeedName": "Give it a name, for example laptop or home-server.",
          "ofsGrantReady": "Key created.",
          "ofsGrantOnce": "It shows only now: copy it before closing. If you lose it, revoke it and make another.",
          "ofsGrantCodeLabel": "For another PaaSMCP: paste this code there, under \\"Another PaaSMCP\\"",
          "ofsCopyCode": "Copy code",
          "ofsCopy": "Copy",
          "ofsDoneHide": "Copied, hide it",
          "ofsGrantFields": "For another program (rclone, restic, an app): the separate fields",
          "ofsGrantInternal": "An app on this same server uses the internal address:",
          "ofsStored": "storing",
          "ofsLimit": "limit",
          "ofsRevoked": "Revoked",
          "ofsBtnRevoke": "Revoke",
          "ofsRevokedMsg": "{name}'s key no longer works. What it already stored stays here.",
          "storageTitle": "🗂️ App files",
          "storageDesc": "Space for photos, PDFs and uploads. Each app gets its own, with its own key; common libraries (boto3, AWS SDK) work without code changes.",
          "storageNone": "No app has file space yet.",
          "btnStorage": "+ Create file space",
          "storageDone": "Space created. Publish the app again so it uses it.",
          "lblAppName": "App name",
          "lblDepPoll": "Update by itself when I change the code (checks every 2 min)",
          "lblDepStorage": "Create file space",
          "lblDepEmail": "Let the app send email",
          "emailTitle": "✉️ Email sending",
          "emailDesc": "Email sent straight from home lands in spam or never leaves. So the dashboard uses a sending service, set up once for all apps.",
          "emailTip": "Tip: Brevo has a free plan with 300 emails a day. Create the account, verify your domain and copy the SMTP details. The password is encrypted and only sent over a secure connection.",
          "lblEmHost": "SMTP server",
          "lblEmPort": "Port",
          "lblEmUser": "User",
          "lblEmPass": "Password or key",
          "lblEmDomain": "Your sending domain",
          "btnSave": "💾 Save",
          "saved": "Saved.",
          "keepSaved": "(leave empty to keep the saved one)",
          "emailOn": "Set up:",
          "emailTestTitle": "Send a test email",
          "lblEmTo": "To",
          "btnEmailTest": "📨 Send test",
          "emailSent": "Test email accepted by the service.",
          "emailAppTitle": "Allow an app to send email",
          "emailAppDesc": "Puts the sending details into the app's passwords. Publish the app again so it uses them.",
          "btnEmailApp": "Allow",
          "emailAppDone": "Done. Sender:",
          "mirrorTitle": "🔁 Second server",
          "mirrorDesc": "Both servers keep a live copy of each other. If one goes down, the other can take over its apps with data up to the last second. First connect both in the “Connect” tab.",
          "mirrorNone": "No copy set up yet. Use the two boxes below: one server offers, the other receives.",
          "aaTitle": "⚖️ App on both servers",
          "aaDesc": "The app runs here and on the other server at the same time, and both take visits. Data is still written to one database, this server's: the other one writes to it over Tailscale. If this server goes down, automatic takeover (“Automatic takeover” tab) keeps the other one going alone.",
          "hostReadyNote": "Before testing, open Diagnostics: it warns if this server has no fallback DNS, if Watchtower may restart PaaSMCP's containers in the middle of the test, or if Docker's networks are getting close to your home network.",
          "aaNone": "No app runs on both servers yet.",
          "aaOrigin": "created here, runs on both",
          "aaCopy": "comes from {peer}, also runs here",
          "aaRunning": "version here",
          "aaWanted": "version asked",
          "aaStep1": "1. First: copy and watchdog",
          "aaStep1Desc": "This server must send a copy to the other one (“Offer a copy” in the “Live copy” tab, with the Tailscale IP), and the watchdog must run on the other server (step 6 of automatic failover). The watchdog keeps the other server's app on this server's version within 15 seconds.",
          "aaStep2": "2. Pick the app and check it",
          "aaStep2Desc": "Only apps created on this server are listed. The box says what is missing and what is worth fixing before turning it on.",
          "aaReady": "Ready to run on both",
          "aaIsOn": "Already running on both",
          "aaStep3": "3. Turn it on",
          "aaStep3Desc": "Turning it on asks for confirmation, redeploys the same version here and tells the other server, which starts the app next. Turning it off makes the other server stop its copy of the app.",
          "btnAaOn": "Run on both",
          "btnAaOff": "Run here only",
          "aaSwitched": "Done. The other server follows within 15 seconds.",
          "aaStep4": "4. Choose where visits come in",
          "aaStep4Desc": "Use either entry, or both.",
          "aaTunnel": "With Cloudflare Tunnel: turn on the tunnel for both servers. PaaSMCP creates a tunnel just for these apps, runs it here and on the other server, and moves each address's DNS once the copy on the other server answers. Other apps stay on the current tunnel. If a server's copy becomes unhealthy, that server steps out of the tunnel by itself until it recovers. This needs “paasmcp mirror watch” running on both servers.",
          "btnAaTunnelOn": "Turn on the tunnel for both servers",
          "btnAaTunnelOff": "Turn off the tunnel for both servers",
          "aaTunOn": "Tunnel for both servers on",
          "aaTunOff": "Tunnel for both servers off",
          "aaTunCopy": "This server runs the other server's tunnel",
          "aaTunNoCf": "Cloudflare is not configured on this server.",
          "aaTunHere": "connector here",
          "aaTunRunning": "in the tunnel",
          "aaTunStopped": "out of the tunnel",
          "aaTunAbsent": "not started",
          "aaTunHosts": "Addresses in the tunnel",
          "aaTunSick": "unhealthy",
          "aaEdge": "Without a cloud: on a server with a public IP (usually the VPS), start the self-hosted entry from the terminal with the command below. It opens ports 80 and 443, gets HTTPS by itself and checks every 5 seconds whether the app answers on each server. Then add the site here and point its DNS (A record) at that server's public IP.",
          "lblAaHost": "Site address",
          "btnAaSite": "Add site to the self-hosted entry",
          "aaEdgeOff": "The self-hosted entry is not running on this server.",
          "aaEdgeOn": "Self-hosted entry on",
          "aaEdgeStopped": "Self-hosted entry installed but stopped",
          "aaHere": "this server",
          "aaFiles": "files copied at {time}",
          "aaFilesErr": "file copy failed",
          "aaFilesPending": "the rest continues on the next round",
          "aaFilesBig": "{n} file(s) over 512 MB not copied",
          "aaRemove": "Remove",
          "aaDns": "Site added. Now create a DNS A record for {host} pointing at this server's public IP.",
          "mirrorAuto": "Automatic takeover",
          "mirrorArbiter": "Arbiter",
          "mirrorSendingTo": "Sending copy to",
          "connected": "Connected",
          "waitingPeer": "Waiting for the other server",
          "mirrorLost": "The other server was away too long and needs a fresh copy: offer again.",
          "mirrorCopyOf": "Copy of",
          "mirrorUpToDate": "Up to date",
          "mirrorNotStreaming": "Stopped",
          "mirrorServingHere": "Apps running here",
          "mirrorPromoteDesc": "If that server goes down, you can take over its apps here.",
          "btnRetire": "Stop following",
          "mirrorRetireDesc": "If another server already took over {peer} by hand, use Stop following here: this copy is behind and must not take over.",
          "mirrorRetired": "This server stopped following.",
          "mirrorBehind": "Behind",
          "mirrorBehindBy": "Server {who} took over this data.",
          "mirrorBehindManual": "You marked that another server took over this data.",
          "mirrorBehindDesc": "This copy receives nothing more and never takes over on its own. To rebuild it, ask for a new offer from whoever holds the data now: {peer}, if it comes back, or the server that took over, with --from-copy-of {peer} (the old copy stays on disk).",
          "mirrorLostDesc": "This server had taken over the data of {peer}, was away for over a minute, and another one took over instead. The apps of {peer} stopped here and won't start again. To hold a copy again, ask the server that took over for a new offer, with --from-copy-of {peer} (the data here stays on disk).",
          "mirrorVia": "through server {who}",
          "mirrorPromotedDesc": "Its apps run here. When it comes back, follow the “Give apps back” tab.",
          "btnPromote": "Take over the apps",
          "btnHandback": "Hand the apps back",
          "mirrorFenced": "Blocked",
          "mirrorFencedDesc": "Another server took over this one's data while it was away. Apps here stay stopped until the hand-back, so no different data is written.",
          "mirrorOfferTitle": "Offer a copy to the other server",
          "mirrorOfferDesc": "Creates an invite. Paste it on the other server, in the box next to this one.",
          "lblPeerName": "Other server's name",
          "lblPeerIp": "Other server's Tailscale address",
          "lblFromCopyOf": "Hand-back: copy of which server? (leave empty normally)",
          "btnMirrorOffer": "🔑 Create invite",
          "mirrorAcceptTitle": "Receive a copy from the other server",
          "mirrorAcceptDesc": "Paste the invite created on the other server.",
          "lblInvite": "Invite",
          "lblRejoin": "This server went down and is coming back (receives the new data from the other)",
          "btnMirrorAccept": "🤝 Receive copy",
          "mirrorAccepted": "Copy started.",
          "mirrorPromoted": "Apps taken over.",
          "mirrorHandedBack": "Apps handed back. Now take them over on the other server.",
          "autoGoJudge": "See the arbiter",
          "judgeTitle": "⚖️ Arbiter",
          "judgeDesc": "A third device that casts the deciding vote for automatic takeover. It holds no apps or data: it only listens to the servers and records who looks after whose data.",
          "judgeState_none": "Not set up",
          "judgeState_ok": "Answering",
          "judgeState_err": "Not answering",
          "judgeNoneDesc": "Without an arbiter, automatic takeover stays off: if a server goes down, you take over its apps by hand (“Live copy” tab). To set it up, follow the 3 steps below.",
          "judgeAddress": "Address",
          "judgeWhere": "Runs on",
          "judgeOldArbiter": "older arbiter: run the step 2 command again on its device to see its name",
          "judgeSince": "Running since",
          "judgeLatency": "Response time",
          "judgeLastWatch": "Last contact from this server's watchdog",
          "judgeWatchNever": "never: turn on the watchdog (“Automatic takeover” tab, step 2)",
          "judgeWatchErr": "last failure {when}: {err}",
          "judgeHears": "Servers it hears",
          "judgeHeardNone": "none yet",
          "judgeHeardAgo": "{who} {when}",
          "judgeClusters": "Pairs of servers it serves",
          "judgeHowTitle": "How the arbiter decides",
          "judgeHow1": "Each server tells the arbiter it is alive every 15 seconds. Each server's watchdog does that.",
          "judgeHow2": "If a server disappears for more than 1 minute, the other one only takes over its apps if the arbiter stopped hearing it too and the copy stopped arriving. If only the link between the two broke, the arbiter still hears both and no takeover happens.",
          "judgeHow3": "The arbiter lets a single server take over. Each takeover gets a higher number than the last, and a request with an old number is refused.",
          "judgeHow4": "When the server that went down comes back, it asks the arbiter, sees another one took over and stops its own apps until the handback. So the two never write different data.",
          "judgeOwnersTitle": "Who looks after the data now",
          "judgeOwnersNone": "No takeover recorded: each server looks after its own data.",
          "judgeOwnerLine": "Data of {data}: with {owner} (takeover no. {epoch})",
          "judgeOwnerHome": "Data of {data}: back with {owner} (takeover no. {epoch})",
          "judgeSetupTitle": "Set up the arbiter",
          "judgeSetupRedo": "Change or reinstall the arbiter",
          "judgeBefore": "Before you start: both servers must be connected (“Connect” tab) and all three devices on the same Tailscale network. Do the steps once, in this order.",
          "btnArbCmd": "Generate install command",
          "autoStep2After": "At the end, the command prints the arbiter address. Use it in step 3. The key in the command only works for the arbiter (it opens no passwords, apps or data), but don't hand it to other people: whoever has it can confuse the arbiter.",
          "autoPrereqTitle": "The device has no Node.js or Tailscale yet?",
          "autoPrereqDesc": "The arbiter needs Node.js 20 or newer, git and Tailscale on the same account as the servers. On Ubuntu or Debian, these commands install what is missing:",
          "autoTitle": "Automatic takeover",
          "autoDesc": "If the other server disappears for more than 1 minute, this one takes over its apps. That needs an arbiter: a third device that casts the deciding vote. Without it, if only the link between the two breaks, each would think the other died and both would write different data.",
          "autoBefore": "Before: the copy must already work (“Live copy” tab) and the arbiter must be set up and answering.",
          "autoStep1": "1. Pick the arbiter device",
          "autoStep1Desc": "Any device that stays on 24/7 and is neither of the two servers: a small cloud VM (like Oracle's free ones), a Raspberry Pi or an old PC. Ideally somewhere else or on another internet link. No Docker, and it barely uses memory.",
          "autoStep2": "2. Install the arbiter on the third device",
          "autoStep2Desc": "Generate the command below, with this pair's key already in it, and paste it in the arbiter device's terminal. It downloads PaaSMCP and keeps the arbiter running as a service: it comes back after a reboot and only answers on the device's Tailscale address, port 4097. If the device is already the arbiter for another pair of servers, use the same command: that pair keeps working.",
          "autoStep3": "3. Enter the arbiter address (on this server and the other)",
          "autoStep3Desc": "It is the address the step 2 command printed at the end, for example http://100.64.0.9:4097. Click Test: it must say “The arbiter answered”. Then Save. Do the same on the other server's dashboard, with the same address.",
          "autoStep3Check": "To check on the arbiter device itself, run the command below. If it answers {&quot;ok&quot;:true}, the arbiter is up.",
          "btnArbTest": "Test",
          "btnArbSave": "Save",
          "autoStep5": "1. Choose which server this one may replace",
          "autoStep5Desc": "The server whose apps this one takes over if it goes down. The list only shows servers this one already holds a copy of. Turning it on asks you to type the name to confirm. If the copy goes both ways and either should replace the other, do this step on the other server too.",
          "lblAutoPeer": "Server this one may replace",
          "autoNoCopy": "No copy received yet (use “Receive a copy”, in the “Live copy” tab)",
          "autoNoPeer": "Pick the server in the list. If it is empty, this server holds no copy of another one yet.",
          "autoStep6": "2. Turn on the watchdog (on both servers)",
          "autoStep6Desc": "The watchdog talks to the arbiter every 15 seconds. It tells the arbiter the server is alive, takes over when needed and blocks a server that comes back after being replaced. Run the command below in the terminal of each of the two servers.",
          "autoStep7": "3. Check that it works",
          "autoStep7Desc": "The box at the top of this card shows what the arbiter hears. It is ready when everything is green: the arbiter answered, heard this server and the other one less than 1 minute ago, the watchdog runs here and the takeover is on. If the other server is missing or shows a long time, it still needs the arbiter address (“Arbiter” tab) or its watchdog.",
          "btnArbRefresh": "Check again",
          "arbNotSet": "No arbiter set up yet (“Arbiter” tab).",
          "arbOk": "The arbiter answered and accepted the key",
          "arbThisServer": "this server",
          "arbHeard": "The arbiter heard {who} {s} s ago",
          "arbHeardOld": "over 1 minute: is the watchdog on there?",
          "arbPeerUnknown": "The arbiter never heard {who}. On {who}, enter the arbiter address (“Arbiter” tab) and turn on the watchdog (step 2 here). Meanwhile, if the copy stops, this server takes over.",
          "arbWatchOn": "Watchdog running on this server",
          "arbWatchOff": "Watchdog off on this server (automatic takeover, step 2)",
          "arbAutoOn": "Automatic takeover on for: {who}",
          "arbAutoOff": "Automatic takeover off on this server (automatic takeover, step 1)",
          "arbAutoTag": "takeover on",
          "arbReady": "✅ Automatic takeover ready",
          "arbNotReady": "Something is still missing:",
          "arbErr_badUrl": "Invalid address. Use http://<arbiter Tailscale IP>:4097",
          "arbErr_badKey": "The arbiter answered but refused the key. Run the step 2 command (“Arbiter” tab) again on the arbiter device.",
          "arbErr_clock": "The arbiter answered but its clock is more than 1 minute off. Turn on automatic time on the devices.",
          "arbErr_notPaired": "This server is not paired with the other one yet: do it under Second server, in the “Connect” tab.",
          "arbErr_notArbiter": "Something answered at that address, but it is not the arbiter. Check the port (default 4097).",
          "arbErr_unreachable": "The arbiter did not answer. Check that it is on (step 2 of the “Arbiter” tab), that the IP is its Tailscale IP and that the port is 4097.",
          "lblArbiter": "Arbiter address",
          "btnAutoOn": "Turn on",
          "btnAutoOff": "Turn off",
          "failbackTitle": "Hand the apps back when the failed server returns",
          "failback1": "Here: in “Offer a copy”, fill the hand-back field with the failed server's name and create the invite.",
          "failback2": "On the returning server: paste the invite and tick “This server went down and is coming back”.",
          "failback3": "Here: click “Hand the apps back”.",
          "failback4": "On the returning server: click “Take over the apps”.",
          "mirrorTech": "PostgreSQL physical streaming replication with a slot capped at 10 GB. Each takeover raises the epoch; the server with the lower epoch is blocked (fencing). The arbiter only grants a takeover if it cannot hear the failed server either.",
          "updatesTitle": "⬆️ Updates",
          "updatesDesc": "The dashboard only installs fixes that keep the data format. Before updating it makes a backup and, if something fails within 1 minute, goes back to the previous version by itself.",
          "btnCheckUpdates": "🔍 Check for updates",
          "checking": "Checking…",
          "upToDate": "Up to date",
          "btnUpdate": "Update",
          "updateDone": "Updated to",
          "updateRolledBack": "The update did not work and everything is back as it was:",
          "compPostgres": "Database (PostgreSQL)",
          "compRedis": "Cache (Redis)",
          "compGarage": "Files (Garage)",
          "updatesMajorQ": "What about big versions (e.g. PostgreSQL 17)?",
          "updatesMajorA": "They change the data format and need their own migration. The dashboard does not install them by itself."
    });

    Object.assign(I18N.pt, {
          "aiIntro": "Primeiro diga onde a IA está.",
          "aiRemoteTitle": "Em outro computador",
          "aiRemoteDesc": "Seu notebook ou desktop, na mesma rede Tailscale do servidor. Precisa de um acesso (token).",
          "aiLocalTitle": "Neste servidor",
          "aiLocalDesc": "A IA roda no próprio servidor (ex.: Claude Code ou Codex pelo SSH). Não precisa de token.",
          "aiStep1": "1. Criar um acesso",
          "aiStep1Desc": "Cada computador ou IA ganha o seu, e você pode revogar quando quiser.",
          "aiTokName": "Nome do acesso",
          "aiLvlRead": "<strong>Só olhar</strong>: ver status, logs e listas. Não muda nada.",
          "aiLvlDeploy": "<strong>Publicar e cuidar</strong>: publicar apps, criar bancos, fazer cópias. Ações arriscadas pedem sua aprovação no Início.",
          "aiLvlDestroy": "<strong>Também pedir para apagar</strong>: pode pedir exclusões, e cada uma espera você aprovar.",
          "aiLvlReadShort": "Só olhar",
          "aiLvlDeployShort": "Publicar e cuidar",
          "aiLvlDestroyShort": "Também apagar",
          "aiBtnCreate": "🔑 Criar acesso",
          "aiTokenOnce": "Copie agora: este token aparece só uma vez (já foi copiado).",
          "aiTokensTitle": "Acessos criados",
          "aiLastUsed": "Último uso:",
          "aiRevoke": "Revogar",
          "aiRevokeConfirm": "Revogar este acesso? A IA que o usa deixa de conectar.",
          "aiStep2": "2. Ligar o acesso pela rede (uma vez)",
          "aiStep2Desc": "No terminal do servidor, rode o comando abaixo. Ele deixa o PaaSMCP atendendo IAs no endereço Tailscale do servidor, porta 4098, e volta sozinho depois de reiniciar. Nunca fica aberto na internet.",
          "aiStep3": "3. Adicionar na sua IA",
          "aiClient": "Sua IA",
          "aiOther": "Outra (LM Studio, Claude Desktop com ponte, etc.)",
          "aiHost": "Endereço Tailscale do servidor",
          "aiHostPh": "IP-TAILSCALE-DO-SERVIDOR",
          "aiTokenPh": "SEU_TOKEN",
          "aiCopy": "📋 Copiar",
          "aiFileTerminal": "Cole no terminal do computador onde a IA está:",
          "aiFileCursor": "Cole em ~/.cursor/mcp.json (Cursor › Settings › MCP › Add):",
          "aiFileVscode": "Cole em .vscode/mcp.json do projeto (ou MCP: Add Server na paleta de comandos):",
          "aiFileGemini": "Cole em ~/.gemini/settings.json:",
          "aiFileOther": "A maioria dos apps aceita este formato no arquivo de configuração de MCP. Se o app só aceitar comando, use a ponte: npx mcp-remote <endereço> --header \\"Authorization: Bearer <token>\\".",
          "aiStep4": "4. Testar",
          "aiStep4Desc": "Abra a IA e peça: “mostra o status do servidor PaaSMCP”. Se ela responder com o nome do servidor e os apps, está conectada.",
          "aiWebNote": "Os conectores dos sites claude.ai e chatgpt.com ainda não funcionam: eles exigem endereço público com login OAuth, que está nos próximos passos do projeto.",
          "promptEx1Title": "💬 Publicar",
          "promptEx1Desc": "“Publica o repositório <code>voce/meu-app</code> com banco de dados e deixa só na minha rede.”",
          "promptEx2Title": "💬 Cópias",
          "promptEx2Desc": "“Faz uma cópia de segurança do app <code>meu-app</code> agora e testa se ela abre.”",
          "promptEx3Title": "💬 Problemas",
          "promptEx3Desc": "“Por que o app <code>blog</code> parou? Roda o diagnóstico e me diz o que fazer.”"
    });
    Object.assign(I18N.en, {
          "aiIntro": "First tell where the AI is.",
          "aiRemoteTitle": "On another computer",
          "aiRemoteDesc": "Your laptop or desktop, on the same Tailscale network as the server. Needs an access token.",
          "aiLocalTitle": "On this server",
          "aiLocalDesc": "The AI runs on the server itself (e.g. Claude Code or Codex over SSH). No token needed.",
          "aiStep1": "1. Create an access",
          "aiStep1Desc": "Each computer or AI gets its own, and you can revoke it any time.",
          "aiTokName": "Access name",
          "aiLvlRead": "<strong>Look only</strong>: see status, logs and lists. Changes nothing.",
          "aiLvlDeploy": "<strong>Publish and maintain</strong>: publish apps, create databases, make backups. Risky actions wait for your approval on Home.",
          "aiLvlDestroy": "<strong>Also ask to delete</strong>: may request deletions, each one waits for your approval.",
          "aiLvlReadShort": "Look only",
          "aiLvlDeployShort": "Publish and maintain",
          "aiLvlDestroyShort": "Also delete",
          "aiBtnCreate": "🔑 Create access",
          "aiTokenOnce": "Copy it now: this token is shown only once (already copied).",
          "aiTokensTitle": "Accesses",
          "aiLastUsed": "Last used:",
          "aiRevoke": "Revoke",
          "aiRevokeConfirm": "Revoke this access? The AI using it can no longer connect.",
          "aiStep2": "2. Turn on network access (once)",
          "aiStep2Desc": "In the server's terminal, run the command below. It makes PaaSMCP answer AIs on the server's Tailscale address, port 4098, and comes back by itself after a reboot. It is never open to the internet.",
          "aiStep3": "3. Add it to your AI",
          "aiClient": "Your AI",
          "aiOther": "Other (LM Studio, Claude Desktop via bridge, etc.)",
          "aiHost": "Server's Tailscale address",
          "aiHostPh": "SERVER-TAILSCALE-IP",
          "aiTokenPh": "YOUR_TOKEN",
          "aiCopy": "📋 Copy",
          "aiFileTerminal": "Paste into the terminal of the computer where the AI runs:",
          "aiFileCursor": "Paste into ~/.cursor/mcp.json (Cursor › Settings › MCP › Add):",
          "aiFileVscode": "Paste into the project's .vscode/mcp.json (or MCP: Add Server in the command palette):",
          "aiFileGemini": "Paste into ~/.gemini/settings.json:",
          "aiFileOther": "Most apps accept this format in their MCP config file. If the app only takes a command, use the bridge: npx mcp-remote <address> --header \\"Authorization: Bearer <token>\\".",
          "aiStep4": "4. Test",
          "aiStep4Desc": "Open the AI and ask: “show the PaaSMCP server status”. If it answers with the server name and apps, it is connected.",
          "aiWebNote": "The claude.ai and chatgpt.com website connectors do not work yet: they need a public address with OAuth login, which is on the project's next steps.",
          "promptEx1Title": "💬 Publish",
          "promptEx1Desc": "“Publish the repository <code>you/my-app</code> with a database and keep it on my network only.”",
          "promptEx2Title": "💬 Backups",
          "promptEx2Desc": "“Back up the app <code>my-app</code> now and test that the backup opens.”",
          "promptEx3Title": "💬 Problems",
          "promptEx3Desc": "“Why did the app <code>blog</code> stop? Run diagnostics and tell me what to do.”"
    });

    Object.assign(I18N.pt, {
          "scaleTitle": "📈 Uso nas últimas 24 h e escala automática",
          "scaleDesc": "O PaaSMCP mede a CPU, a memória, o tráfego, as visitas e o tempo de resposta de cada app e guarda 24 horas. Com a escala automática desligada, a regra só é <strong>ensaiada</strong>: o diário anota o que ela faria, sem subir nem desligar nada. Ligada, ela age de verdade nos seus PCs ajudantes.",
          "scaleNoTimer": "A medição ainda não está ligada. No servidor, rode <code>sudo paasmcp scale install-timer</code>. Ela mede a cada 15 s e não deixa nenhum programa rodando entre uma medição e outra.",
          "scaleTimerOn": "Medindo a cada {n} s.",
          "scaleNoApps": "Nenhum app para medir ainda.",
          "lblScaleApp": "App",
          "scaleNoData": "Ainda sem medições deste app.",
          "scaleStale": "Sem medição recente: o app está parado ou a medição foi desligada.",
          "scaleOfLimit": "do limite de {n} CPU",
          "scaleOfCore": "de um núcleo, porque o app não tem limite de CPU",
          "scaleMem": "memória",
          "scaleLat": "resposta",
          "scaleNoAnswer": "não respondeu",
          "scaleNet": "tráfego",
          "scaleNowLbl": "agora",
          "scale24hAgo": "24 h atrás",
          "scaleMax": "máx.",
          "scaleLast": "última",
          "scaleTargetLegend": "tracejado: alvo por cópia",
          "scaleWould1": "O ensaio rodaria 1 cópia agora",
          "scaleWouldN": "O ensaio rodaria {n} cópias agora",
          "scaleChartCpu": "CPU em %",
          "scaleChartLat": "Tempo de resposta (ms)",
          "scaleChartNet": "Tráfego (kB/s)",
          "scaleChartMem": "Memória (MB)",
          "scaleChartRps": "Visitas por segundo",
          "scaleChartCopies": "Cópias rodando",
          "scaleRps": "visitas",
          "scaleRuleTitle": "Regra da escala",
          "scaleRuleDesc": "A carga do app é dividida pelas cópias: a CPU e, se você der um alvo, as visitas por segundo. Sobe uma cópia quando uma das duas passa do alvo nas medições seguidas escolhidas, e desce uma quando as duas ficam abaixo da metade do alvo pelo tempo escolhido. Depois de cada passo, espera antes do próximo, para não ficar subindo e descendo. As visitas só são contadas com o app no balanceador (com cópias ou com a escala automática), e só as que chegam pelo Cloudflare Tunnel. Com a escala automática ligada, subir o máximo pede confirmação.",
          "lblScaleMin": "Mínimo de cópias",
          "lblScaleMax": "Máximo de cópias",
          "lblScaleTarget": "Alvo de CPU por cópia (%)",
          "lblScaleTargetRps": "Alvo de visitas/s por cópia (0 = sem)",
          "lblScaleUp": "Subir depois de (medições)",
          "lblScaleDown": "Descer depois de (min)",
          "lblScaleCooldown": "Espera entre passos (s)",
          "scaleRuleSaved": "Regra salva. Vale a partir da próxima medição.",
          "scaleCapTitle": "Teste de capacidade",
          "scaleCapDesc": "Descobre quantas visitas por segundo uma cópia aguenta e o que trava primeiro (a CPU do app ou o banco). Como põe carga de verdade no app, ele roda pelo terminal do servidor e pede confirmação.",
          "scaleCapNone": "Este app ainda não foi testado.",
          "scaleCapResult": "Em {date}, uma cópia aguentou <strong>{rps} visitas/s</strong> em <code>{path}</code>, com {c} pedidos ao mesmo tempo (p95 de {p95} ms). O que travou: {bn}.",
          "scaleCapSuggest": "Até uns {s} visitas/s por cópia, sobra folga (70% do medido).",
          "scaleCapUse": "Usar como alvo de visitas",
          "scaleBn_app_cpu": "a CPU do app",
          "scaleBn_database": "o banco de dados",
          "scaleBn_client": "o próprio teste, porque o servidor não conseguiu gerar mais carga",
          "scaleBn_errors": "o app começou a dar erro",
          "scaleBn_latency": "o tempo de resposta passou de 2 s",
          "scaleBn_none": "nada, até a carga máxima testada",
          "scaleBn_unknown": "não identificado (talvez disco, rede ou um limite do próprio app)",
          "scaleDiaryTitle": "Diário do decisor",
          "scaleDiaryDesc": "Cada decisão com o motivo: as do ensaio e, com a escala automática ligada, os passos de verdade. A IA lê o mesmo diário pelo MCP para responder, por exemplo, “por que o app está com 3 cópias?”.",
          "scaleDiaryNone": "Nada anotado ainda.",
          "lblScaleLang": "Idioma do diário no terminal, no log e na IA",
          "scaleLangSaved": "Idioma do diário salvo."
    });
    Object.assign(I18N.en, {
          "scaleTitle": "📈 Last 24 h of use and automatic scaling",
          "scaleDesc": "PaaSMCP measures each app's CPU, memory, traffic, visits and response time and keeps 24 hours. With automatic scaling off, the rule is only <strong>rehearsed</strong>: the diary writes down what it would do, without starting or stopping anything. On, it acts for real on your helper PCs.",
          "scaleNoTimer": "Measuring is not on yet. On the server, run <code>sudo paasmcp scale install-timer</code>. It measures every 15 s and leaves no program running between rounds.",
          "scaleTimerOn": "Measuring every {n} s.",
          "scaleNoApps": "No app to measure yet.",
          "lblScaleApp": "App",
          "scaleNoData": "No measurements for this app yet.",
          "scaleStale": "No recent measurement: the app is stopped or measuring was turned off.",
          "scaleOfLimit": "of its {n} CPU limit",
          "scaleOfCore": "of one core, since the app has no CPU limit",
          "scaleMem": "memory",
          "scaleLat": "response",
          "scaleNoAnswer": "no answer",
          "scaleNet": "traffic",
          "scaleNowLbl": "now",
          "scale24hAgo": "24 h ago",
          "scaleMax": "max",
          "scaleLast": "last",
          "scaleTargetLegend": "dashed: target per copy",
          "scaleWould1": "The rehearsal would run 1 copy now",
          "scaleWouldN": "The rehearsal would run {n} copies now",
          "scaleChartCpu": "CPU in %",
          "scaleChartLat": "Response time (ms)",
          "scaleChartNet": "Traffic (kB/s)",
          "scaleChartMem": "Memory (MB)",
          "scaleChartRps": "Visits per second",
          "scaleChartCopies": "Copies running",
          "scaleRps": "visits",
          "scaleRuleTitle": "Scaling rule",
          "scaleRuleDesc": "The app's load is spread over its copies: CPU and, if you give a target, visits per second. A copy is added when either is above its target for the measurements in a row you choose, and one is removed when both stay below half their target for the time you choose. After each step it waits before the next, so it does not keep going up and down. Visits are counted only while the app is behind the balancer (with copies or automatic scaling), and only those that come through Cloudflare Tunnel. With automatic scaling on, raising the maximum asks for confirmation.",
          "lblScaleMin": "Fewest copies",
          "lblScaleMax": "Most copies",
          "lblScaleTarget": "CPU target per copy (%)",
          "lblScaleTargetRps": "Visits/s target per copy (0 = none)",
          "lblScaleUp": "Add after (measurements)",
          "lblScaleDown": "Remove after (min)",
          "lblScaleCooldown": "Wait between steps (s)",
          "scaleRuleSaved": "Rule saved. It applies from the next measurement.",
          "scaleCapTitle": "Capacity test",
          "scaleCapDesc": "Finds how many requests per second one copy handles and what chokes first (the app's CPU or the database). Since it puts real load on the app, it runs from the server's terminal and asks for confirmation.",
          "scaleCapNone": "This app has not been tested yet.",
          "scaleCapResult": "On {date}, one copy handled <strong>{rps} requests/s</strong> on <code>{path}</code> with {c} requests at once (p95 {p95} ms). What choked: {bn}.",
          "scaleCapSuggest": "Up to about {s} requests/s per copy there is room to spare (70% of the measured value).",
          "scaleCapUse": "Use as visits target",
          "scaleBn_app_cpu": "the app's CPU",
          "scaleBn_database": "the database",
          "scaleBn_client": "the test itself, since the server could not generate more load",
          "scaleBn_errors": "the app started returning errors",
          "scaleBn_latency": "response time went over 2 s",
          "scaleBn_none": "nothing, up to the highest load tested",
          "scaleBn_unknown": "not identified (maybe disk, network or a limit inside the app)",
          "scaleDiaryTitle": "Decision diary",
          "scaleDiaryDesc": "Each decision with its reason: the rehearsal's and, with automatic scaling on, the real steps. The AI reads the same diary over MCP to answer, for example, “why does the app have 3 copies?”.",
          "scaleDiaryNone": "Nothing written yet.",
          "lblScaleLang": "Diary language in the terminal, the log and the AI",
          "scaleLangSaved": "Diary language saved."
    });

    Object.assign(I18N.pt, {
          "aaP_pool": "O app usa PCs ajudantes (cópias ou escala automática): use “Parar tudo” na escala dele primeiro. Por enquanto, um app usa ajudantes ou os dois servidores, não as duas coisas.",
          "poolTitle": "🖥️ PCs ajudantes",
          "poolDesc": "Seus próprios computadores podem rodar cópias extras dos apps deste servidor. Este servidor continua dono de tudo: guarda as senhas, monta a imagem, recebe as visitas e as divide entre a cópia daqui e as dos ajudantes. Num ajudante sem cópias, nenhum programa do PaaSMCP fica ligado.",
          "btnPoolCheck": "🔄 Verificar agora",
          "poolNone": "Nenhum PC ajudante ainda. Para adicionar o primeiro, veja a aba “Adicionar um PC”.",
          "poolSt_available": "disponível",
          "poolSt_working": "trabalhando",
          "poolSt_paused": "pausado",
          "poolSt_gone": "sem resposta",
          "poolSt_unknown": "ainda não verificado",
          "poolGives": "cede {cpus} CPU e {mem} MB",
          "poolUsing": "em uso {cpus} CPU e {mem} MB",
          "poolDisk": "{gb} GB livres no disco",
          "poolLoad": "carga {l}",
          "poolSeen": "última resposta {date}",
          "poolCopiesOn": "Cópias: {list}",
          "poolNoCopies": "Sem cópias agora.",
          "poolSecretsDisk": "A pasta em memória das variáveis não está pronta neste PC, então ele recusa cópias. Rode <code>sudo systemd-tmpfiles --create</code> nele.",
          "poolPausedNote": "Pausado: não recebe cópias. As que tinha foram para outros ajudantes ou pararam.",
          "poolSt_busy": "dono usando",
          "poolOwnerCpu": "dono usa {p}% da CPU",
          "poolOwnerOld": "Este PC ainda não mede o uso do dono. Para o modo cortês funcionar, atualize o PaaSMCP nele e rode <code>sudo paasmcp pool update-worker</code>.",
          "poolBusyAuto": "O dono está usando este PC desde {date} (CPU fora das cópias em {p}%). As cópias saíram dele e foram para outros PCs, ou esperam ele liberar. Voltam depois de {m} min com o PC livre.",
          "poolBusyWarn": "O dono está usando este PC desde {date} (CPU fora das cópias em {p}%). Modo com aviso: as cópias ficam, mas nenhuma nova vai para lá.",
          "lblCourtesy": "Modo cortês",
          "courtesy_auto": "automático",
          "courtesy_warn": "com aviso",
          "courtesy_off": "desligado",
          "lblCourtesyCpu": "limite (%)",
          "btnCourtesySave": "Salvar",
          "courtesyHint": "Conta como uso do dono a CPU do PC fora das cópias, medida a cada minuto. Acima do limite duas vezes seguidas, as cópias saem (automático) ou só ficam avisadas no diário (com aviso).",
          "poolJob_courtesy": "mudar o modo cortês de {s}",
          "poolSt_asleep": "dormindo",
          "poolSt_waking": "acordando",
          "lblWake": "Acordar pela rede (Wake-on-LAN)",
          "wakeOnLine": "ligado · placa {mac} · pacote para {to}",
          "wakeOffLine": "desligado",
          "btnWakeOn": "Ligar",
          "btnWakeOff": "Desligar",
          "btnWakeNow": "Acordar agora",
          "wakeHint": "Com isto ligado, este servidor acorda o PC quando uma cópia precisa rodar e nenhum ajudante acordado tem espaço. Ele leva de 30 s a 1 min para ligar, então serve para carga que dura. Precisa de cabo de rede, do PC na mesma rede que este servidor e de <code>sudo paasmcp pool wake-setup</code> rodado uma vez nele.",
          "wakeNoLan": "Este PC ainda não informou a placa de rede. Atualize o PaaSMCP nele e rode <code>sudo paasmcp pool update-worker</code>.",
          "wakeWifi": "Este PC usa Wi-Fi ({iface}). Acordar pela rede quase nunca funciona por Wi-Fi: ligue-o por cabo.",
          "wakeNotArmed": "A placa ainda não foi preparada: rode <code>sudo paasmcp pool wake-setup</code> uma vez no PC.",
          "wakeWaking": "Pedido para acordar enviado {date} ({n}ª tentativa).",
          "wakeGaveUp": "Não acordou depois de {n} tentativas. O servidor parou de tentar até o PC responder de novo ou alguém usar “Acordar agora”.",
          "wakeSent": "Pacote enviado para {to}. Um PC que acorda costuma responder em até 1 min.",
          "btnPoolPause": "Pausar",
          "btnPoolResume": "Retomar",
          "btnPoolRemove": "Remover",
          "poolAppsTitle": "Apps com cópias em ajudantes",
          "poolAppsDesc": "O número de cópias de cada app se escolhe em Aplicações, aba “Escala automática”, à mão ou pela escala automática.",
          "poolAutoBadge": "escala automática",
          "poolAppsNone": "Nenhum app usa ajudantes ainda.",
          "poolAppLine": "{running} de {wanted} cópias rodando",
          "poolCopyNoAnswer": "{helper}: sem resposta",
          "poolAppStopped": "app parado: as cópias dos ajudantes também pararam",
          "poolAddTitle": "Adicionar um PC",
          "poolAddDesc": "São cinco passos, dois deles no próprio PC. Leva uns 10 minutos.",
          "poolStep1": "1. Prepare o PC",
          "poolStep1Desc": "O PC precisa de Linux com Docker, o servidor OpenSSH, a Tailscale conectada na mesma conta deste servidor e o Node.js 20 ou mais novo instalado para todos os usuários (pelo pacote da distribuição ou do NodeSource, não pelo nvm). Depois, baixe e compile o PaaSMCP nele. Não rode o <code>init</code> nem o <code>install.sh</code> lá: o PC não vira um servidor.",
          "poolStep2": "2. Crie o convite aqui",
          "poolStep2Desc": "Dê um nome ao PC. O convite serve para um PC só e vale por 15 minutos.",
          "lblPoolName": "Nome do PC",
          "btnPoolInvite": "Criar convite",
          "poolInviteExp": "Rode este comando no PC, dentro da pasta do PaaSMCP, até {time}:",
          "poolStep3": "3. Rode o comando no PC",
          "poolStep3Desc": "Ele mostra qual servidor vai dar as ordens e pergunta antes de mudar algo. Por padrão o PC cede metade das CPUs e da memória; para escolher, acrescente <code>--cpus 2 --memory 4g</code> no fim. Ao terminar, ele mostra o IP Tailscale do PC, que vai no próximo passo.",
          "poolStep4": "4. Conclua aqui",
          "poolStep4Desc": "Com o nome e o IP Tailscale do PC, este servidor se conecta a ele, confere que ele tem o convite e passa a reconhecer só aquele PC com esse nome. Faça isso em até uma hora depois de criar o convite.",
          "lblPoolIp": "IP Tailscale do PC",
          "btnPoolAdd": "Adicionar PC",
          "poolAdded": "PC {name} adicionado: cede {cpus} CPU e {mem} MB para cópias.",
          "poolStep5": "5. Feche a rede (recomendado)",
          "poolStep5Desc": "Sem isto, um ajudante alcança tudo na sua Tailscale. Rode o primeiro comando em cada ajudante e cole as regras abaixo no painel da Tailscale, em Access controls. Com elas, este servidor fala com os ajudantes só por SSH e pelas portas dos apps, e os ajudantes alcançam só o banco, o Redis e o S3 daqui.",
          "poolHowTitle": "O que fica no PC e o que acontece quando ele some",
          "poolHow1": "O PC recebe a imagem do app e as variáveis dele, inclusive senhas. As variáveis ficam só na memória do PC e somem quando a cópia para ou o PC desliga. Mesmo assim, quem controla o PC consegue lê-las enquanto a cópia roda: use como ajudante só um PC em que você confia tanto quanto neste servidor.",
          "poolHow2": "Este servidor confere cada cópia a cada 3 segundos. Se um ajudante dorme, desliga ou perde a rede, as visitas param de ir para ele em uns 6 segundos, e as que estavam a caminho são reenviadas para outra cópia. Com o Wake-on-LAN ligado no PC, este servidor o acorda enquanto a cópia dele ainda for necessária.",
          "poolHow3": "Quando o dono usa o PC para algo pesado, o modo cortês automático tira as cópias dele sozinho, em 1 ou 2 minutos: elas terminam as visitas em curso e vão para outro ajudante, se houver. Pausar aqui faz o mesmo na hora. Remover também apaga a chave deste servidor no PC.",
          "poolHow4": "Só vão para ajudantes os apps de um contêiner só, com verificação de saúde por HTTP e que rodam só neste servidor. O banco continua aqui: mais cópias aliviam a CPU do app, não o banco.",
          "poolJobRunning": "Em andamento: {what}",
          "poolJobDone": "Concluído: {what}",
          "poolJobFailed": "Falhou: {what}",
          "poolJob_copies": "ajustar as cópias de {s}",
          "poolJob_off": "voltar {s} a uma cópia",
          "poolJob_pause": "pausar {s}",
          "poolJob_resume": "retomar {s}",
          "poolJob_remove": "remover {s}",
          "poolJob_app": "atualizar as cópias de {s} nos ajudantes",
          "copiesTitle": "Cópias agora",
          "copiesDesc": "Cópias deste app nos seus PCs ajudantes (tela Ajudantes). A cópia deste servidor fica sempre ligada e as visitas se dividem entre todas. “Parar tudo” desliga a escala automática e volta o app a uma cópia, só aqui.",
          "lblCopiesN": "Cópias no total",
          "btnCopiesApply": "Aplicar",
          "btnCopiesOff": "Parar tudo",
          "copiesRunning1": "Rodando agora: 1 cópia, só neste servidor.",
          "copiesRunningN": "Rodando agora: {n} cópias, a deste servidor e {h} em ajudantes ({list}).",
          "copiesWanted": "Pedidas: {n}.",
          "copiesError": "Último problema: {e}",
          "copiesBlocked": "Este app ainda não pode ter cópias em ajudantes:",
          "copiesWarn": "Antes de pôr cópias, vale saber:",
          "copiesStarted": "Ajustando as cópias. Acompanhe aqui ou na tela Ajudantes.",
          "copiesAutoNote": "Com a escala automática ligada, o número de cópias é decidido sozinho. Para mudar, ajuste o mínimo e o máximo da regra abaixo.",
          "poolJob_auto": "ligar a escala automática de {s}",
          "scaleAutoTitle": "Escala automática",
          "scaleAutoDesc": "Ligada, o PaaSMCP põe uma cópia num PC ajudante quando o app passa do alvo da regra abaixo e tira quando ele acalma, sem sair do mínimo e do máximo. Antes de desligar uma cópia, ele espera as visitas em curso terminarem. Não sobe cópias com o Postgres perto do limite de conexões, e se um passo falha (sem espaço nos ajudantes, cópia que não responde), tenta de novo mais tarde, esperando cada vez mais. Ligar pede confirmação, porque cada ajudante recebe a imagem e as variáveis do app.",
          "btnScaleAutoOn": "Ligar a escala automática",
          "btnScaleAutoOff": "Desligar",
          "autoOn": "Ligada",
          "autoWaiting": "Ligada, mas em espera: o app está parado ou este servidor não serve os dados agora",
          "autoOff": "Desligada: você escolhe o número de cópias e a regra só é ensaiada.",
          "autoSince": "desde {date}",
          "autoLimits": "Entre {min} e {max} cópias, pela regra abaixo.",
          "autoNoTimer": "A medição não está ligada, então nada decide ainda (veja o aviso no alto do quadro).",
          "autoStarting": "Ligando a escala automática. Acompanhe aqui.",
          "autoOffDone": "Escala automática desligada. As cópias ficaram como estavam.",
          "poolP_dashboard": "O painel controla este servidor e nunca roda em ajudantes.",
          "poolP_trashed": "O app está na lixeira.",
          "poolP_fromPeer": "Este app veio de outro servidor: escolha as cópias lá.",
          "poolP_activeActive": "O app roda nos dois servidores. Por enquanto, ajudantes só recebem apps que rodam só neste servidor (desligue o modo dos dois servidores antes).",
          "poolP_ownCompose": "O app traz o próprio docker-compose.yml (vários serviços, talvez um banco próprio): só apps de um contêiner rodam em ajudantes.",
          "poolP_trusted": "O app está marcado como confiável (campos privilegiados no compose) e nunca roda em ajudantes.",
          "poolP_noHealthcheck": "O app não tem verificação de saúde por HTTP, e o balanceador precisa dela para parar de mandar visitas a uma cópia que não responde.",
          "poolP_notDeployed": "Faça o deploy do app antes.",
          "poolP_fenced": "Este servidor está bloqueado: outro servidor serve os dados dele agora.",
          "poolW_rootHealthPath": "Use um caminho de saúde que consulte o banco (por exemplo /healthz). Com '/', uma cópia que perdeu o banco continua recebendo visitas.",
          "poolW_noLimits": "O app não tem limite de CPU ou de memória, então cada cópia num ajudante usa tudo o que o PC cede. Com limites (novo deploy com CPU e RAM), cabem mais cópias.",
          "poolW_zeroTrustBypass": "O app fica atrás do login da Cloudflare (zero-trust). As cópias nos ajudantes ficam no IP Tailscale deles, onde aparelhos da sua Tailscale chegam sem esse login. Mantenha o login do próprio app ou feche a rede (passo 5 da tela Ajudantes).",
          "poolW_localRefs": "Estas variáveis apontam para esta máquina ou para contêineres que só existem aqui, e não vão funcionar num ajudante: {v}.",
          "poolW_noHelpers": "Nenhum PC ajudante ainda: adicione um na tela Ajudantes."
    });
    Object.assign(I18N.en, {
          "aaP_pool": "The app uses helper PCs (copies or automatic scaling): use “Stop everything” in its scaling first. For now an app uses either helpers or both servers, not both.",
          "poolTitle": "🖥️ Helper PCs",
          "poolDesc": "Your own computers can run extra copies of this server's apps. This server stays in charge of everything: it keeps the passwords, builds the image, receives the visits and splits them between its own copy and the helpers'. A helper with no copies runs no PaaSMCP program at all.",
          "btnPoolCheck": "🔄 Check now",
          "poolNone": "No helper PC yet. To add the first one, see the “Add a PC” tab.",
          "poolSt_available": "available",
          "poolSt_working": "working",
          "poolSt_paused": "paused",
          "poolSt_gone": "not answering",
          "poolSt_unknown": "not checked yet",
          "poolGives": "gives {cpus} CPU and {mem} MB",
          "poolUsing": "in use {cpus} CPU and {mem} MB",
          "poolDisk": "{gb} GB free on disk",
          "poolLoad": "load {l}",
          "poolSeen": "last answer {date}",
          "poolCopiesOn": "Copies: {list}",
          "poolNoCopies": "No copies now.",
          "poolSecretsDisk": "The in-memory folder for app variables is not ready on this PC, so it refuses copies. Run <code>sudo systemd-tmpfiles --create</code> there.",
          "poolPausedNote": "Paused: it takes no copies. The ones it had moved to other helpers or stopped.",
          "poolSt_busy": "owner using it",
          "poolOwnerCpu": "owner uses {p}% of the CPU",
          "poolOwnerOld": "This PC does not measure its owner's use yet. For courteous mode to work, update PaaSMCP there and run <code>sudo paasmcp pool update-worker</code>.",
          "poolBusyAuto": "The owner has been using this PC since {date} (CPU outside the copies at {p}%). Its copies left for other PCs, or wait for it to be free. They come back after {m} min with the PC free.",
          "poolBusyWarn": "The owner has been using this PC since {date} (CPU outside the copies at {p}%). Warn mode: the copies stay, but no new one goes there.",
          "lblCourtesy": "Courteous mode",
          "courtesy_auto": "automatic",
          "courtesy_warn": "warn only",
          "courtesy_off": "off",
          "lblCourtesyCpu": "limit (%)",
          "btnCourtesySave": "Save",
          "courtesyHint": "The owner's use is the PC's CPU outside the copies, measured every minute. Above the limit twice in a row, the copies leave (automatic) or it is only noted in the diary (warn only).",
          "poolJob_courtesy": "change the courteous mode of {s}",
          "poolSt_asleep": "asleep",
          "poolSt_waking": "waking up",
          "lblWake": "Wake over the network (Wake-on-LAN)",
          "wakeOnLine": "on · card {mac} · packet to {to}",
          "wakeOffLine": "off",
          "btnWakeOn": "Turn on",
          "btnWakeOff": "Turn off",
          "btnWakeNow": "Wake now",
          "wakeHint": "With this on, this server wakes the PC when a copy must run and no awake helper has room. It takes 30 s to a minute to start, so it helps load that lasts. Needs a network cable, the PC on the same network as this server, and <code>sudo paasmcp pool wake-setup</code> run once on it.",
          "wakeNoLan": "This PC has not reported its network card yet. Update PaaSMCP on it and run <code>sudo paasmcp pool update-worker</code>.",
          "wakeWifi": "This PC uses Wi-Fi ({iface}). Waking over the network almost never works over Wi-Fi: connect it by cable.",
          "wakeNotArmed": "The card is not prepared yet: run <code>sudo paasmcp pool wake-setup</code> once on the PC.",
          "wakeWaking": "Wake-up sent {date} (try {n}).",
          "wakeGaveUp": "Did not wake after {n} tries. The server stopped trying until the PC answers again or someone uses “Wake now”.",
          "wakeSent": "Packet sent to {to}. A PC that wakes usually answers within a minute.",
          "btnPoolPause": "Pause",
          "btnPoolResume": "Resume",
          "btnPoolRemove": "Remove",
          "poolAppsTitle": "Apps with copies on helpers",
          "poolAppsDesc": "Each app's number of copies is set under Applications, in the “Automatic scaling” tab, by hand or by automatic scaling.",
          "poolAutoBadge": "automatic scaling",
          "poolAppsNone": "No app uses helpers yet.",
          "poolAppLine": "{running} of {wanted} copies running",
          "poolCopyNoAnswer": "{helper}: not answering",
          "poolAppStopped": "app stopped: its copies on helpers stopped too",
          "poolAddTitle": "Add a PC",
          "poolAddDesc": "Five steps, two of them on the PC itself. About 10 minutes.",
          "poolStep1": "1. Prepare the PC",
          "poolStep1Desc": "The PC needs Linux with Docker, the OpenSSH server, Tailscale logged in to the same account as this server, and Node.js 20 or newer installed for all users (from your distribution or NodeSource, not nvm). Then download and build PaaSMCP there. Do not run <code>init</code> or <code>install.sh</code> on it: the PC does not become a server.",
          "poolStep2": "2. Create the invite here",
          "poolStep2Desc": "Name the PC. The invite works for one PC only, for 15 minutes.",
          "lblPoolName": "PC name",
          "btnPoolInvite": "Create invite",
          "poolInviteExp": "Run this on the PC, in the PaaSMCP folder, before {time}:",
          "poolStep3": "3. Run the command on the PC",
          "poolStep3Desc": "It shows which server will give the orders and asks before changing anything. By default the PC gives half its CPUs and memory; to choose, add <code>--cpus 2 --memory 4g</code> at the end. When it finishes, it shows the PC's Tailscale IP for the next step.",
          "poolStep4": "4. Finish here",
          "poolStep4Desc": "With the PC's name and Tailscale IP, this server connects to it, checks that it holds the invite and from then on accepts only that PC under that name. Do it within an hour of creating the invite.",
          "lblPoolIp": "PC's Tailscale IP",
          "btnPoolAdd": "Add PC",
          "poolAdded": "PC {name} added: it gives {cpus} CPU and {mem} MB to copies.",
          "poolStep5": "5. Fence the network (recommended)",
          "poolStep5Desc": "Without this, a helper reaches everything in your Tailnet. Run the first command on each helper and paste the rules below into the Tailscale admin console, under Access controls. With them, this server talks to helpers only over SSH and the apps' ports, and helpers reach only the database, Redis and S3 here.",
          "poolHowTitle": "What stays on the PC and what happens when it goes away",
          "poolHow1": "The PC receives the app's image and its variables, passwords included. The variables stay only in the PC's memory and are gone when the copy stops or the PC turns off. Even so, whoever controls the PC can read them while the copy runs: only use a PC you trust as much as this server.",
          "poolHow2": "This server checks each copy every 3 seconds. If a helper sleeps, shuts down or loses the network, visits stop going to it within about 6 seconds, and those on their way are retried on another copy. With Wake-on-LAN on for the PC, this server wakes it while its copy is still needed.",
          "poolHow3": "When the owner uses the PC for something heavy, automatic courteous mode takes its copies off by itself within 1 or 2 minutes: they finish the visits in progress and move to another helper, if there is one. Pausing here does the same at once. Removing also deletes this server's key from the PC.",
          "poolHow4": "Only single-container apps with an HTTP health check that run only on this server go to helpers. The database stays here: more copies relieve the app's CPU, not the database.",
          "poolJobRunning": "In progress: {what}",
          "poolJobDone": "Done: {what}",
          "poolJobFailed": "Failed: {what}",
          "poolJob_copies": "set the copies of {s}",
          "poolJob_off": "bring {s} back to one copy",
          "poolJob_pause": "pause {s}",
          "poolJob_resume": "resume {s}",
          "poolJob_remove": "remove {s}",
          "poolJob_app": "update the copies of {s} on helpers",
          "copiesTitle": "Copies now",
          "copiesDesc": "Copies of this app on your helper PCs (Helpers screen). This server's copy always stays on and visits are split among all of them. “Stop everything” turns automatic scaling off and brings the app back to one copy, here only.",
          "lblCopiesN": "Copies in total",
          "btnCopiesApply": "Apply",
          "btnCopiesOff": "Stop everything",
          "copiesRunning1": "Running now: 1 copy, on this server only.",
          "copiesRunningN": "Running now: {n} copies, this server's and {h} on helpers ({list}).",
          "copiesWanted": "Asked for: {n}.",
          "copiesError": "Last problem: {e}",
          "copiesBlocked": "This app cannot have copies on helpers yet:",
          "copiesWarn": "Worth knowing before adding copies:",
          "copiesStarted": "Setting the copies. Follow along here or on the Helpers screen.",
          "copiesAutoNote": "With automatic scaling on, the number of copies is decided by itself. To change it, adjust the rule's minimum and maximum below.",
          "poolJob_auto": "turn on automatic scaling for {s}",
          "scaleAutoTitle": "Automatic scaling",
          "scaleAutoDesc": "On, PaaSMCP puts a copy on a helper PC when the app goes over the rule's target below and removes it when the app calms down, never past the minimum and maximum. Before stopping a copy, it lets the visits in progress finish. It adds no copy while Postgres is near its connection limit, and when a step fails (no room on helpers, a copy that does not answer) it tries again later, waiting longer each time. Turning it on asks for confirmation, since each helper receives the app's image and variables.",
          "btnScaleAutoOn": "Turn on automatic scaling",
          "btnScaleAutoOff": "Turn off",
          "autoOn": "On",
          "autoWaiting": "On, but waiting: the app is stopped or this server does not serve the data now",
          "autoOff": "Off: you choose the number of copies and the rule is only rehearsed.",
          "autoSince": "since {date}",
          "autoLimits": "Between {min} and {max} copies, by the rule below.",
          "autoNoTimer": "Measuring is not on, so nothing decides yet (see the note at the top of this card).",
          "autoStarting": "Turning on automatic scaling. Follow along here.",
          "autoOffDone": "Automatic scaling turned off. The copies stay as they were.",
          "poolW_localRefs": "These variables point at this machine or at containers that only exist here, so they will not work on a helper: {v}."
    });

    // Side menu, folder tabs, counter tips and the quick health box.
    Object.assign(I18N.pt, {
          "navSecApps": "Apps",
          "navSecServers": "Servidores",
          "navSecIntegrations": "Integrações",
          "navSecSystem": "Sistema",
          "navCollapse": "Recolher menu",
          "navExpand": "Expandir menu",
          "sub_overview_list": "Seus apps",
          "sub_overview_deploy": "Publicar um app",
          "sub_overview_expose": "Deixar acessível",
          "sub_overview_scale": "Escala automática",
          "sub_overview_diary": "Diário do decisor",
          "sub_overview_webhook": "Publicar a cada push",
          "sub_databases_dbs": "Bancos",
          "sub_databases_backups": "Cópias de segurança",
          "sub_databases_offsite": "Cópias fora do servidor",
          "sub_databases_files": "Arquivos dos apps",
          "sub_mirror_connect": "Conectar",
          "sub_mirror_copy": "Cópia ao vivo",
          "sub_mirror_judge": "Juiz",
          "sub_mirror_auto": "Troca automática",
          "sub_mirror_aa": "App nos dois",
          "sub_mirror_back": "Devolver apps",
          "sub_pool_list": "PCs ajudantes",
          "sub_pool_add": "Adicionar um PC",
          "sub_pool_how": "Como funciona",
          "sub_agents_connect": "Conectar",
          "sub_agents_examples": "Exemplos de pedidos",
          "aiExamplesTitle": "💬 Exemplos de pedidos",
          "aiExamplesDesc": "Depois de conectar, peça em linguagem comum. Alguns pedidos que funcionam:",
          "cntApps": "{n} apps publicados",
          "cntAppsOne": "1 app publicado",
          "cntDbs": "{n} bancos criados",
          "cntDbsOne": "1 banco criado",
          "cntVault": "{n} chaves do sistema guardadas",
          "cntVaultOne": "1 chave do sistema guardada",
          "cntMirror": "{n} servidores conectados",
          "cntMirrorOne": "1 servidor conectado",
          "cntPool": "{n} PCs ajudantes",
          "cntPoolOne": "1 PC ajudante",
          "cntAgents": "{n} ferramentas MCP disponíveis",
          "cntAgentsOne": "1 ferramenta MCP disponível",
          "resTitle": "Uso de Recursos",
          "resCpu": "Processador agora",
          "resMem": "Memória",
          "resDisk": "Disco",
          "resPaas": "PaaSMCP",
          "resOthers": "Outros",
          "resFree": "{v} livres",
          "resCores": "{n} núcleos",
          "resCoreOne": "1 núcleo",
          "resHint": "PaaSMCP soma seus apps, os bancos e o próprio painel. Outros é o resto do servidor: o sistema e programas fora do PaaSMCP.",
          "resTopTip": "Quem mais usa memória:",
          "resMeasuring": "Medindo o servidor...",
          "resMeasuringShort": "medindo...",
          "resSnapshots": "Instantâneos",
          "resSnapshotsOne": "1 cópia",
          "resSnapshotsN": "{n} cópias",
          "healthTitle": "Saúde rápida",
          "healthBackup": "Última cópia",
          "healthOffsite": "Cópia fora do servidor",
          "healthMirror": "Segundo servidor",
          "healthEmail": "E-mail",
          "healthOn": "Ligado",
          "healthOff": "Não usado",
          "lead_home": "Por onde começar e o que configurar na primeira vez.",
          "lead_overview": "Publique, deixe acessível e acompanhe os apps deste servidor.",
          "lead_databases": "Cada app ganha o seu próprio banco, separado dos outros, com cópias cifradas.",
          "lead_vault": "As senhas e chaves que seus apps usam, cifradas no disco.",
          "lead_mirror": "Os dois servidores guardam uma cópia ao vivo um do outro. Se um cair, o outro assume.",
          "lead_pool": "PCs da casa que emprestam força quando o servidor aperta.",
          "lead_agents": "Qualquer IA compatível com MCP pode cuidar do servidor por você. Ações arriscadas pedem sua confirmação.",
          "lead_email": "Um serviço de envio configurado uma vez para todos os apps.",
          "lead_doctor": "Procura problemas nos apps e no servidor em volta e diz o que fazer em cada caso.",
          "lead_updates": "Atualizações seguras do PaaSMCP: cópia antes e volta sozinho se algo falhar."
    });
    Object.assign(I18N.en, {
          "navSecApps": "Apps",
          "navSecServers": "Servers",
          "navSecIntegrations": "Integrations",
          "navSecSystem": "System",
          "navCollapse": "Collapse menu",
          "navExpand": "Expand menu",
          "sub_overview_list": "Your apps",
          "sub_overview_deploy": "Publish an app",
          "sub_overview_expose": "Make reachable",
          "sub_overview_scale": "Automatic scaling",
          "sub_overview_diary": "Decision diary",
          "sub_overview_webhook": "Publish on every push",
          "sub_databases_dbs": "Databases",
          "sub_databases_backups": "Backups",
          "sub_databases_offsite": "Off-server backups",
          "sub_databases_files": "App files",
          "sub_mirror_connect": "Connect",
          "sub_mirror_copy": "Live copy",
          "sub_mirror_judge": "Arbiter",
          "sub_mirror_auto": "Automatic takeover",
          "sub_mirror_aa": "App on both",
          "sub_mirror_back": "Give apps back",
          "sub_pool_list": "Helper PCs",
          "sub_pool_add": "Add a PC",
          "sub_pool_how": "How it works",
          "sub_agents_connect": "Connect",
          "sub_agents_examples": "Example requests",
          "aiExamplesTitle": "💬 Example requests",
          "aiExamplesDesc": "Once connected, ask in plain words. A few requests that work:",
          "cntApps": "{n} published apps",
          "cntAppsOne": "1 published app",
          "cntDbs": "{n} databases",
          "cntDbsOne": "1 database",
          "cntVault": "{n} system keys stored",
          "cntVaultOne": "1 system key stored",
          "cntMirror": "{n} connected servers",
          "cntMirrorOne": "1 connected server",
          "cntPool": "{n} helper PCs",
          "cntPoolOne": "1 helper PC",
          "cntAgents": "{n} MCP tools available",
          "cntAgentsOne": "1 MCP tool available",
          "resTitle": "Resource Usage",
          "resCpu": "Processor now",
          "resMem": "Memory",
          "resDisk": "Disk",
          "resPaas": "PaaSMCP",
          "resOthers": "Others",
          "resFree": "{v} free",
          "resCores": "{n} cores",
          "resCoreOne": "1 core",
          "resHint": "PaaSMCP adds up your apps, the databases and the dashboard itself. Others is the rest of the server: the system and programs outside PaaSMCP.",
          "resTopTip": "Using the most memory:",
          "resMeasuring": "Measuring the server...",
          "resMeasuringShort": "measuring...",
          "resSnapshots": "Snapshots",
          "resSnapshotsOne": "1 backup",
          "resSnapshotsN": "{n} backups",
          "healthTitle": "Quick health",
          "healthBackup": "Last backup",
          "healthOffsite": "Off-server backup",
          "healthMirror": "Second server",
          "healthEmail": "Email",
          "healthOn": "On",
          "healthOff": "Not used",
          "lead_home": "Where to start and what to set up the first time.",
          "lead_overview": "Publish, make reachable and follow the apps on this server.",
          "lead_databases": "Each app gets its own database, separate from the others, with encrypted backups.",
          "lead_vault": "The passwords and keys your apps use, encrypted on disk.",
          "lead_mirror": "Both servers keep a live copy of each other. If one goes down, the other takes over.",
          "lead_pool": "PCs at home that lend power when the server is busy.",
          "lead_agents": "Any MCP-compatible AI can run the server for you. Risky actions ask for your confirmation.",
          "lead_email": "One sending service, set up once for every app.",
          "lead_doctor": "Looks for problems in the apps and the server around them and says what to do.",
          "lead_updates": "Safe PaaSMCP updates: a backup first, and an automatic roll back if something fails."
    });

    function t(key) {
      const dict = I18N[currentLang] || I18N.pt;
      return dict[key] !== undefined ? dict[key] : (I18N.pt[key] !== undefined ? I18N.pt[key] : key);
    }

    const I18N_KEYS = [
      'btnNewApp', 'dbTitle', 'optDbPg', 'optDbRedis', 'backupsTitle', 'lblBakApp', 'lblBakEngine', 'optBakPg', 'optBakRedis', 'optBakVol', 'btnCreateBackup', 'lblDbApp', 'lblDbEngine', 'btnCreateDb',
      'setupGithubDocsLink',
      'setupLocalDesc',
      'setupWebhookNote',
      'sidebarSubtitle', 'navHome', 'navEmail', 'navMirror', 'navPool', 'navUpdates', 'homeTitle', 'navOverview', 'navVault', 'navDatabases', 'navDoctor', 'navAgents', 'navConnect',
      'topHealthBadge', 'btnLogout',
      'appsTitle', 'appsDesc', 'thApp', 'thStack', 'thMetrics', 'thPort', 'thDomains', 'thActions',
      'deployTitle', 'deployDesc', 'lblQuickFillDeploy', 'lblDepApp', 'lblDepRepo', 'lblDepBranch', 'lblDepMem', 'lblDepCpu', 'lblDepPg', 'lblDepRedis', 'btnDeploy',
      'exposeTitle', 'exposeDesc', 'lblExpApp', 'lblExpMode', 'optPublic', 'optZT', 'optTS', 'lblExpSub', 'btnExpose',
      'vaultTitle', 'vaultDesc', 'lblSecScope', 'lblSecKey', 'lblSecVal', 'btnSaveSecret',
      'dbTitle', 'dbDesc', 'lblDbApp', 'lblDbEngine', 'optDbPg', 'optDbRedis', 'btnCreateDb',
      'backupsTitle', 'backupsDesc', 'lblBakApp', 'lblBakEngine', 'optBakPg', 'optBakRedis', 'btnCreateBackup',
      'fedTitle', 'fedDesc', 'lblFedUrl', 'lblFedMode', 'optFedActive', 'optFedWarm', 'btnGenInvite', 'btnExportSync', 'lblJoinPeer', 'btnJoinPeer',
      'whTitle', 'whDesc', 'btnRevealWhSecret', 'lblSshKey', 'btnCopySsh',
      'doctorTitle', 'doctorDesc', 'btnRunDoctor',
      'presetSaas', 'presetDjango', 'presetFastapi', 'presetNode', 'presetGo', 'presetDotnet', 'presetCompose', 'presetSpa', 'presetDockerfile',
      'promptEx1Title', 'promptEx1Desc', 'promptEx2Title', 'promptEx2Desc', 'promptEx3Title', 'promptEx3Desc',
      'agentsTitle', 'agentsDesc', 'logsTitle', 'btnCloseLogs',
    ];

    Object.assign(I18N.pt, {
      "navConnect": "Conexões",
      "lead_connect": "Ligue a Cloudflare e o GitHub uma vez, aqui mesmo. Nada de terminal nem de IDs para copiar.",
      "sub_connect_cloudflare": "Domínio (Cloudflare)",
      "sub_connect_github": "GitHub",
      "cntConnect": "{n} conexões ligadas",
      "cntConnectOne": "1 conexão ligada",
      "cnCfTitle": "Seu domínio pela Cloudflare",
      "cnCfDesc": "Para abrir os apps num endereço como app.seudominio.com, com HTTPS e sem abrir portas no roteador. O domínio precisa estar na Cloudflare (o plano grátis serve).",
      "cnCfStep1": "1. Crie um token na Cloudflare",
      "cnCfStep1Desc": "O link abre a Cloudflare com as permissões já marcadas. Confira se aparecem Cloudflare Tunnel, DNS e Access: Apps and Policies, todos com Edit (inclua o que faltar). Clique em Continue to summary, depois em Create Token, e copie o valor.",
      "cnCfTokenLink": "Abrir a Cloudflare com as permissões marcadas ↗",
      "cnCfStep2": "2. Cole o token aqui",
      "cnCfToken": "Token da Cloudflare",
      "cnBtnCheck": "Verificar",
      "cnCfStep3": "3. Confira o que o painel encontrou",
      "cnCfAccount": "Conta",
      "cnCfDomain": "Domínio",
      "cnCfTunnel": "Túnel",
      "cnCfRunHere": "Rodar este túnel neste servidor",
      "cnCfEmails": "Quem pode abrir os apps protegidos (opcional)",
      "cnCfEmailsHint": "Só vale para apps publicados no modo “Só e-mails autorizados”: a pessoa recebe um código no e-mail para entrar. Separe com vírgula.",
      "cnBtnCfSave": "Salvar e conectar",
      "cnChecking": "Verificando...",
      "cnSaving": "Salvando... criar um túnel leva até um minuto.",
      "cnFound": "Encontrei {a} conta(s) e {z} domínio(s).",
      "cnMiss_account": "O token não enxerga nenhuma conta: inclua a conta em Account Resources.",
      "cnMiss_zone": "O token não enxerga nenhum domínio: inclua o seu em Zone Resources (e confira se o domínio já está na Cloudflare).",
      "cnMiss_tunnel": "Falta a permissão Cloudflare Tunnel: Edit.",
      "cnMiss_access": "Sem a permissão Access: Apps and Policies, o modo “Só e-mails autorizados” não vai funcionar (o resto funciona).",
      "cnNoZoneHere": "Nenhum domínio nesta conta",
      "cnNewTunnel": "Criar um túnel novo (recomendado)",
      "cnNewTunnelNote": "O painel cria o túnel na sua conta e o liga aqui. Ele volta sozinho depois de reiniciar o servidor.",
      "cnTunLocal": "configurado por arquivo",
      "cnTunLocalNote": "Este túnel é configurado por um arquivo no computador onde roda, então o PaaSMCP não consegue colocar endereços nele. Prefira criar um túnel novo.",
      "cnTunIdleNote": "Este túnel não está ligado em lugar nenhum. Deixe marcado para o painel ligá-lo aqui.",
      "cnTunLiveNote": "Este túnel já está ligado em algum computador. Se for este servidor, ou se você não sabe, deixe desmarcado.",
      "cnTun_healthy": "ligado",
      "cnTun_degraded": "ligado com falhas",
      "cnTun_down": "desligado",
      "cnTun_inactive": "nunca ligado",
      "cnSaved": "Pronto. Agora publique um endereço em Apps → Deixar acessível.",
      "cnSavedNew": "Pronto: túnel criado e ligado neste servidor. Agora publique um endereço em Apps → Deixar acessível.",
      "cnCfReady": "Conectado",
      "cnCfReadyDesc": "Os apps podem ganhar endereços em {domain}.",
      "cnCfEmailsNow": "Podem entrar nos apps protegidos:",
      "cnConnRunning": "O túnel roda neste servidor.",
      "cnConnStopped": "O túnel deste servidor está parado: clique em Trocar e salve de novo para religar.",
      "cnCfNone": "Sem isso, os apps abrem só pela Tailscale ou na rede de casa.",
      "cnCfHalf": "O token está guardado, mas falta escolher domínio e túnel.",
      "cnGoExpose": "Publicar um endereço",
      "cnChange": "Trocar",
      "cnGhTitle": "Código no GitHub",
      "cnGhDesc": "Repositório público não precisa de nada. Para um privado, use uma das duas opções abaixo.",
      "cnGhKeyTitle": "Opção 1: chave de leitura (mais segura)",
      "cnGhKeyDesc": "No GitHub, abra o repositório, Settings → Deploy keys → Add deploy key, cole a chave abaixo e deixe “Allow write access” desmarcado. Repita em cada repositório privado.",
      "cnBtnCopyKey": "Copiar chave",
      "cnGhTokenTitle": "Opção 2: token (mais prático)",
      "cnGhTokenDesc": "Crie um token “fine-grained”, escolha só os repositórios que vai publicar e dê a permissão Contents: Read-only. Com ele, Publicar um app mostra a lista dos seus repositórios e o painel baixa o código privado sozinho, sem colar chave em cada repositório. Quer publicar a cada push sem copiar nada? Dê também Webhooks: Read and write.",
      "cnGhTokenLink": "Criar token no GitHub ↗",
      "cnGhToken": "Token do GitHub",
      "cnBtnGhSave": "Testar e salvar",
      "cnGhOk": "Token salvo. Ele é da conta @{login}.",
      "cnGhSaved": "Token salvo",
      "cnGhSavedDesc": "Publicar um app já mostra a lista dos seus repositórios.",
      "cnGhNoToken": "Sem token",
      "cnGhNoTokenDesc": "Tudo bem para código público ou com a chave de leitura (opção 1).",
      "exposeNeedCf": "Para publicar com o seu domínio, ligue a Cloudflare em Conexões primeiro. O modo Tailscale funciona sem ela.",
      "exposeOpenConnect": "Abrir Conexões"
    });
    Object.assign(I18N.en, {
      "navConnect": "Connections",
      "lead_connect": "Connect Cloudflare and GitHub once, right here. No terminal, no ids to copy.",
      "sub_connect_cloudflare": "Domain (Cloudflare)",
      "sub_connect_github": "GitHub",
      "cntConnect": "{n} connections on",
      "cntConnectOne": "1 connection on",
      "cnCfTitle": "Your domain through Cloudflare",
      "cnCfDesc": "To open apps at an address like app.yourdomain.com, with HTTPS and no router port opened. The domain must be on Cloudflare (the free plan works).",
      "cnCfStep1": "1. Create a Cloudflare token",
      "cnCfStep1Desc": "The link opens Cloudflare with the permissions already ticked. Check that Cloudflare Tunnel, DNS and Access: Apps and Policies show, all with Edit (add what is missing). Click Continue to summary, then Create Token, and copy the value.",
      "cnCfTokenLink": "Open Cloudflare with the permissions ticked ↗",
      "cnCfStep2": "2. Paste the token here",
      "cnCfToken": "Cloudflare token",
      "cnBtnCheck": "Check",
      "cnCfStep3": "3. Check what the dashboard found",
      "cnCfAccount": "Account",
      "cnCfDomain": "Domain",
      "cnCfTunnel": "Tunnel",
      "cnCfRunHere": "Run this tunnel on this server",
      "cnCfEmails": "Who may open protected apps (optional)",
      "cnCfEmailsHint": "Only for apps published as “Allowed emails only”: the person gets a code by email to get in. Separate with commas.",
      "cnBtnCfSave": "Save and connect",
      "cnChecking": "Checking...",
      "cnSaving": "Saving... creating a tunnel takes up to a minute.",
      "cnFound": "Found {a} account(s) and {z} domain(s).",
      "cnMiss_account": "The token sees no account: add the account under Account Resources.",
      "cnMiss_zone": "The token sees no domain: add yours under Zone Resources (and check the domain is already on Cloudflare).",
      "cnMiss_tunnel": "The Cloudflare Tunnel: Edit permission is missing.",
      "cnMiss_access": "Without Access: Apps and Policies, “Allowed emails only” will not work (everything else does).",
      "cnNoZoneHere": "No domain in this account",
      "cnNewTunnel": "Create a new tunnel (recommended)",
      "cnNewTunnelNote": "The dashboard creates the tunnel in your account and runs it here. It comes back by itself after a reboot.",
      "cnTunLocal": "configured by a file",
      "cnTunLocalNote": "This tunnel is configured by a file on the computer that runs it, so PaaSMCP cannot add addresses to it. Prefer creating a new tunnel.",
      "cnTunIdleNote": "This tunnel runs nowhere. Leave it ticked so the dashboard runs it here.",
      "cnTunLiveNote": "This tunnel already runs on some computer. If it is this server, or you are not sure, leave it unticked.",
      "cnTun_healthy": "running",
      "cnTun_degraded": "running with errors",
      "cnTun_down": "stopped",
      "cnTun_inactive": "never ran",
      "cnSaved": "Done. Now publish an address under Apps → Make reachable.",
      "cnSavedNew": "Done: tunnel created and running on this server. Now publish an address under Apps → Make reachable.",
      "cnCfReady": "Connected",
      "cnCfReadyDesc": "Apps can get addresses on {domain}.",
      "cnCfEmailsNow": "May open protected apps:",
      "cnConnRunning": "The tunnel runs on this server.",
      "cnConnStopped": "This server's tunnel is stopped: click Change and save again to restart it.",
      "cnCfNone": "Without it, apps open only over Tailscale or on the home network.",
      "cnCfHalf": "The token is saved, but the domain and tunnel are not chosen yet.",
      "cnGoExpose": "Publish an address",
      "cnChange": "Change",
      "cnGhTitle": "Code on GitHub",
      "cnGhDesc": "A public repository needs nothing. For a private one, use one of the two options below.",
      "cnGhKeyTitle": "Option 1: read-only key (safest)",
      "cnGhKeyDesc": "On GitHub, open the repository, Settings → Deploy keys → Add deploy key, paste the key below and leave “Allow write access” unticked. Repeat for each private repository.",
      "cnBtnCopyKey": "Copy key",
      "cnGhTokenTitle": "Option 2: token (easiest)",
      "cnGhTokenDesc": "Create a fine-grained token, pick only the repositories you will publish and give it Contents: Read-only. With it, Publish an app lists your repositories and the dashboard fetches private code by itself, with no key to paste in each repository. Want to publish on every push with nothing to copy? Also give Webhooks: Read and write.",
      "cnGhTokenLink": "Create a token on GitHub ↗",
      "cnGhToken": "GitHub token",
      "cnBtnGhSave": "Test and save",
      "cnGhOk": "Token saved. It belongs to @{login}.",
      "cnGhSaved": "Token saved",
      "cnGhSavedDesc": "Publish an app now lists your repositories.",
      "cnGhNoToken": "No token",
      "cnGhNoTokenDesc": "Fine for public code or with the read-only key (option 1).",
      "exposeNeedCf": "To publish on your domain, connect Cloudflare under Connections first. Tailscale mode works without it.",
      "exposeOpenConnect": "Open Connections"
    });

    Object.assign(I18N.pt, {
      "sub_home_start": "Resumo",
      "sub_home_tutorial": "Tutorial",
      "stepsTitle": "Próximo passo",
      "stepsDesc": "O que mais vale a pena fazer agora.",
      "tutTitle": "O que você já fez e o que ainda pode fazer",
      "tutDesc": "Os itens se marcam sozinhos quando o painel vê que estão prontos. Os guias explicam passo a passo, numa página própria.",
      "tutCount": "{n} de {t} feitos",
      "tutGuide": "Ver o guia",
      "tutOpen": "Abrir",
      "tutSeeAll": "Ver o tutorial completo",
      "tutAllEssential": "O essencial está pronto. Veja no tutorial o que mais dá para fazer.",
      "tutGroup_essential": "Essencial",
      "tutGroup_essentialDesc": "Para ter um app no ar, com endereço e com os dados guardados fora do servidor.",
      "tutGroup_recommended": "Recomendado",
      "tutGroup_recommendedDesc": "Deixa o dia a dia mais fácil e evita sustos.",
      "tutGroup_grow": "Quando precisar de mais",
      "tutGroup_growDesc": "Mais segurança contra queda, mais força ou ajuda de uma IA.",
      "tut_app": "Publicar o primeiro app",
      "tut_appDesc": "Informe o repositório do GitHub, ou instale um app pronto sem código, e o painel monta e liga o app.",
      "tut_address": "Dar um endereço ao app",
      "tut_addressDesc": "Pelo seu domínio (Cloudflare) ou só para você e sua família (Tailscale).",
      "tut_offsite": "Guardar cópias fora do servidor",
      "tut_offsiteDesc": "Se o servidor quebrar ou for roubado, os dados continuam salvos em outro lugar.",
      "tut_autoupdate": "Atualizar o app sozinho quando o código muda",
      "tut_autoupdateDesc": "Você manda o código para o GitHub e o app se atualiza, sem abrir o painel.",
      "tut_email": "Configurar o envio de e-mails",
      "tut_emailDesc": "Para os apps mandarem “esqueci a senha” e avisos. Leva 5 minutos com uma conta grátis.",
      "tut_backup": "Fazer uma cópia e testar",
      "tut_backupDesc": "O painel já faz uma cópia toda noite. Use “Testar” numa delas para ver se ela abre antes de precisar.",
      "tut_doctor": "Rodar o diagnóstico",
      "tut_doctorDesc": "Procura problemas no servidor e nos apps e diz o que fazer. Vale rodar de vez em quando.",
      "tut_github": "Ligar o GitHub para código privado",
      "tut_githubDesc": "Só se o seu repositório for privado.",
      "tut_mirror": "Ligar um segundo servidor",
      "tut_mirrorDesc": "Guarda uma cópia ao vivo de tudo e pode assumir se este cair.",
      "tut_pool": "Emprestar força de outros PCs",
      "tut_poolDesc": "PCs da casa rodam cópias extras dos apps quando o servidor aperta.",
      "tut_ai": "Conectar sua IA",
      "tut_aiDesc": "Peça em português: “publica meu app”, “faz uma cópia agora”.",
      "guideCrumb": "Guia",
      "guideOpenScreen": "Abrir esta tela",
      "guideOthers": "Outros guias:",
      "guideBack": "← Voltar ao tutorial",
      "guide_firstapp": "Publicar o primeiro app",
      "guide_firstapp_lead": "Uns 5 minutos. Você precisa só do endereço do repositório no GitHub.",
      "guide_firstapp_s1": "Abra “Publicar um app”",
      "guide_firstapp_s1Desc": "Se o seu projeto parece com um dos modelos (Next.js, Django, Node...), clique nele para preencher os campos. Senão, deixe sem modelo: o painel descobre a linguagem sozinho.",
      "guide_firstapp_s2": "Código privado? Ligue o GitHub antes",
      "guide_firstapp_s2Desc": "Repositório público não precisa de nada. Se for privado, siga a tela Conexões → GitHub (leva 2 minutos).",
      "guide_firstapp_s3": "Preencha nome e repositório",
      "guide_firstapp_s3Desc": "O nome vira o endereço do app (use letras minúsculas e hífen, por exemplo <code>minha-loja</code>). O repositório é <code>dono/nome</code>, como aparece no GitHub. Marque PostgreSQL ou Redis se o app usa banco: o endereço do banco entra no app sozinho.",
      "guide_firstapp_s4": "Clique em Publicar e acompanhe",
      "guide_firstapp_s4Desc": "A linha do app mostra cada fase: baixando, montando, testando, no ar. Se algo falhar, o painel mostra o motivo, e uma versão que já estava no ar continua funcionando.",
      "guide_firstapp_s5": "Senhas do app ficam em Senhas e chaves",
      "guide_firstapp_s5Desc": "Chaves como a da Stripe vão em Senhas e chaves, com o nome do app. Depois publique de novo para o app usar.",
      "guide_address": "Dar um endereço ao app",
      "guide_address_lead": "Escolha quem pode abrir o app. Não precisa abrir porta no roteador.",
      "guide_address_s1": "Decida quem vai usar",
      "guide_address_s1Desc": "Qualquer pessoa na internet: modo Público, com o seu domínio. Só pessoas convidadas: “Só e-mails autorizados”, que pede um código enviado por e-mail. Só você e sua família: Tailscale, que funciona sem domínio.",
      "guide_address_s2": "Com domínio: ligue a Cloudflare",
      "guide_address_s2Desc": "Em Conexões → Domínio, cole um token e escolha o domínio. O painel cria o túnel sozinho. (Com Tailscale, pule este passo: instale o app Tailscale no servidor e no seu celular ou computador, com a mesma conta, e no site do Tailscale, em DNS, ligue “HTTPS Certificates”.)",
      "guide_address_s3": "Publique o endereço",
      "guide_address_s3Desc": "Em “Deixar acessível”, escolha o app, o modo e o começo do endereço (por exemplo <code>loja</code> vira <code>loja.seudominio.com</code>).",
      "guide_address_s4": "Teste no celular",
      "guide_address_s4Desc": "Abra o endereço fora do Wi-Fi de casa. O endereço aparece também na linha do app. O HTTPS já vem pronto.",
      "guide_offsite": "Guardar cópias fora do servidor",
      "guide_offsite_lead": "Uns 10 minutos. Depois disso o servidor manda as cópias toda noite, sozinho.",
      "guide_offsite_s1": "Escolha onde guardar",
      "guide_offsite_s1Desc": "Cloudflare R2 e Backblaze B2 têm 10 GB grátis e servem para a maioria. Se você já usa Amazon, Google ou Wasabi, use o que já tem. Outro PaaSMCP (de um amigo, ou seu em outra casa) também serve.",
      "guide_offsite_s2": "Crie o lugar e a chave no serviço",
      "guide_offsite_s2Desc": "No serviço escolhido, crie um “bucket” (uma pasta para as cópias) e uma chave de acesso só para ele. A tela de cópias mostra onde fica cada coisa no serviço que você escolher.",
      "guide_offsite_s3": "Cole os campos e clique em Testar e salvar",
      "guide_offsite_s3Desc": "O painel grava, lê e apaga um arquivo de teste antes de salvar. Se der errado, ele diz qual campo conferir.",
      "guide_offsite_s4": "Confira a primeira cópia",
      "guide_offsite_s4Desc": "No dia seguinte, o quadro “Última cópia” no Início diz “Guardada também fora do servidor”. Para não esperar, faça uma cópia agora na aba Cópias de segurança e clique em “Enviar agora”.",
      "guide_autoupdate": "Atualizar o app sozinho",
      "guide_autoupdate_lead": "Você manda o código para o GitHub e o app se atualiza. Duas formas: escolha uma.",
      "guide_autoupdate_s1": "Mais simples: marque “Atualizar sozinho”",
      "guide_autoupdate_s1Desc": "Ao publicar o app, marque “Atualizar sozinho quando eu mudar o código”. O servidor olha o GitHub a cada 2 minutos. Funciona em qualquer rede, sem configurar mais nada.",
      "guide_autoupdate_s2": "Mais rápido: aviso do GitHub (webhook)",
      "guide_autoupdate_s2Desc": "O GitHub avisa o servidor na hora. Só funciona se o painel tiver um endereço na internet. Com o GitHub ligado em Conexões, a tela “Publicar a cada push” cria o aviso com um clique; sem isso, ela mostra o endereço e o segredo para colar no GitHub.",
      "guide_autoupdate_s3": "Nada quebra no meio",
      "guide_autoupdate_s3Desc": "A versão nova só entra depois de responder ao teste. Se falhar, a atual continua no ar e a linha do app mostra o motivo.",
      "guide_email": "Configurar o envio de e-mails",
      "guide_email_lead": "Uns 5 minutos com uma conta grátis. Vale para todos os apps.",
      "guide_email_s1": "Crie uma conta num serviço de envio",
      "guide_email_s1Desc": "O Brevo tem plano grátis com 300 e-mails por dia. Outros (Resend, Mailgun, Amazon SES) também servem. E-mail mandado direto de casa cai no spam, por isso o serviço.",
      "guide_email_s2": "Confirme o seu domínio no serviço",
      "guide_email_s2Desc": "O serviço pede para criar alguns registros no DNS do domínio. Se o domínio está na Cloudflare, cole os registros lá, em DNS → Records.",
      "guide_email_s3": "Copie os dados SMTP para o painel",
      "guide_email_s3Desc": "Servidor, porta, usuário e senha (ou chave SMTP) ficam na área SMTP do serviço. Cole na tela E-mail e salve. Mande um e-mail de teste para você.",
      "guide_email_s4": "Libere o envio para cada app",
      "guide_email_s4Desc": "Na mesma tela, em “Permitir que um app envie e-mail”, escreva o nome do app. Depois publique o app de novo.",
      "guide_github": "Ligar o GitHub para código privado",
      "guide_github_lead": "Só para repositórios privados. Uns 2 minutos.",
      "guide_github_s1": "Escolha entre chave e token",
      "guide_github_s1Desc": "A chave de leitura é a mais segura: o servidor só consegue ler aquele repositório. O token poupa o trabalho de colar a chave em cada repositório e mostra a lista dos seus repositórios ao publicar.",
      "guide_github_s2": "Com chave: cole no repositório",
      "guide_github_s2Desc": "Copie a chave em Conexões → GitHub. No GitHub, abra o repositório, Settings → Deploy keys → Add deploy key, cole e deixe “Allow write access” desmarcado.",
      "guide_github_s3": "Com token: crie e teste",
      "guide_github_s3Desc": "Crie um token fine-grained só com os repositórios que vai publicar e a permissão Contents: Read-only. Cole em Conexões → GitHub e clique em Testar e salvar. Pronto: Publicar um app passa a mostrar a lista dos seus repositórios.",
      "lead_guide": ""
    });
    Object.assign(I18N.en, {
      "sub_home_start": "Summary",
      "sub_home_tutorial": "Tutorial",
      "stepsTitle": "Next step",
      "stepsDesc": "What is most worth doing now.",
      "tutTitle": "What you have done and what you can still do",
      "tutDesc": "Items tick themselves when the dashboard sees they are ready. The guides explain step by step, on a page of their own.",
      "tutCount": "{n} of {t} done",
      "tutGuide": "See the guide",
      "tutOpen": "Open",
      "tutSeeAll": "See the full tutorial",
      "tutAllEssential": "The essentials are ready. See the tutorial for what else you can do.",
      "tutGroup_essential": "Essential",
      "tutGroup_essentialDesc": "To have an app online, with an address and its data kept off the server.",
      "tutGroup_recommended": "Recommended",
      "tutGroup_recommendedDesc": "Makes day to day easier and avoids scares.",
      "tutGroup_grow": "When you need more",
      "tutGroup_growDesc": "More safety against outages, more power, or help from an AI.",
      "tut_app": "Publish your first app",
      "tut_appDesc": "Enter the GitHub repository, or install a ready-made app with no code, and the dashboard builds and starts it.",
      "tut_address": "Give the app an address",
      "tut_addressDesc": "On your domain (Cloudflare) or only for you and your family (Tailscale).",
      "tut_offsite": "Keep backups off the server",
      "tut_offsiteDesc": "If the server breaks or is stolen, the data is still safe elsewhere.",
      "tut_autoupdate": "Update the app by itself when the code changes",
      "tut_autoupdateDesc": "You push code to GitHub and the app updates, without opening the dashboard.",
      "tut_email": "Set up email sending",
      "tut_emailDesc": "So apps can send “forgot password” and notices. Takes 5 minutes with a free account.",
      "tut_backup": "Make a backup and test it",
      "tut_backupDesc": "The dashboard already makes a copy every night. Use “Test” on one to check it opens before you need it.",
      "tut_doctor": "Run diagnostics",
      "tut_doctorDesc": "Looks for problems in the server and apps and says what to do. Worth running now and then.",
      "tut_github": "Connect GitHub for private code",
      "tut_githubDesc": "Only if your repository is private.",
      "tut_mirror": "Add a second server",
      "tut_mirrorDesc": "Keeps a live copy of everything and can take over if this one goes down.",
      "tut_pool": "Borrow power from other PCs",
      "tut_poolDesc": "Home PCs run extra copies of the apps when the server is busy.",
      "tut_ai": "Connect your AI",
      "tut_aiDesc": "Ask in plain words: “publish my app”, “back up now”.",
      "guideCrumb": "Guide",
      "guideOpenScreen": "Open this screen",
      "guideOthers": "Other guides:",
      "guideBack": "← Back to the tutorial",
      "guide_firstapp": "Publish your first app",
      "guide_firstapp_lead": "About 5 minutes. You only need the repository's address on GitHub.",
      "guide_firstapp_s1": "Open “Publish an app”",
      "guide_firstapp_s1Desc": "If your project looks like one of the presets (Next.js, Django, Node...), click it to fill in the fields. Otherwise leave it: the dashboard detects the language by itself.",
      "guide_firstapp_s2": "Private code? Connect GitHub first",
      "guide_firstapp_s2Desc": "A public repository needs nothing. If it is private, follow Connections → GitHub (takes 2 minutes).",
      "guide_firstapp_s3": "Fill in the name and repository",
      "guide_firstapp_s3Desc": "The name becomes the app's address (use lowercase letters and hyphens, e.g. <code>my-shop</code>). The repository is <code>owner/name</code>, as shown on GitHub. Tick PostgreSQL or Redis if the app uses a database: its address goes into the app by itself.",
      "guide_firstapp_s4": "Click Publish and follow along",
      "guide_firstapp_s4Desc": "The app's row shows each phase: fetching, building, testing, live. If something fails, the dashboard shows why, and a version already live keeps working.",
      "guide_firstapp_s5": "App passwords live in Secrets & keys",
      "guide_firstapp_s5Desc": "Keys such as Stripe's go in Secrets & keys, under the app's name. Then publish again so the app uses them.",
      "guide_address": "Give the app an address",
      "guide_address_lead": "Choose who can open the app. No router port needs opening.",
      "guide_address_s1": "Decide who will use it",
      "guide_address_s1Desc": "Anyone on the internet: Public mode, on your domain. Only invited people: “Allowed emails only”, which asks for a code sent by email. Only you and your family: Tailscale, which needs no domain.",
      "guide_address_s2": "With a domain: connect Cloudflare",
      "guide_address_s2Desc": "Under Connections → Domain, paste a token and pick the domain. The dashboard creates the tunnel by itself. (With Tailscale, skip this: install the Tailscale app on the server and on your phone or computer, same account, and on the Tailscale website, under DNS, turn on “HTTPS Certificates”.)",
      "guide_address_s3": "Publish the address",
      "guide_address_s3Desc": "Under “Make reachable”, pick the app, the mode and the start of the address (e.g. <code>shop</code> becomes <code>shop.yourdomain.com</code>).",
      "guide_address_s4": "Test it on your phone",
      "guide_address_s4Desc": "Open the address off your home Wi-Fi. The address also shows on the app's row. HTTPS comes ready.",
      "guide_offsite": "Keep backups off the server",
      "guide_offsite_lead": "About 10 minutes. After that the server sends backups every night by itself.",
      "guide_offsite_s1": "Pick where to keep them",
      "guide_offsite_s1Desc": "Cloudflare R2 and Backblaze B2 have 10 GB free and suit most people. If you already use Amazon, Google or Wasabi, use what you have. Another PaaSMCP (a friend's, or yours in another house) works too.",
      "guide_offsite_s2": "Create the bucket and key on the service",
      "guide_offsite_s2Desc": "On the chosen service, create a “bucket” (a folder for the backups) and an access key just for it. The backups screen shows where each thing is on the service you pick.",
      "guide_offsite_s3": "Paste the fields and click Test and save",
      "guide_offsite_s3Desc": "The dashboard writes, reads and deletes a test file before saving. If it fails, it says which field to check.",
      "guide_offsite_s4": "Check the first backup",
      "guide_offsite_s4Desc": "The next day, the “Last backup” tile on Home says “Also stored off the server”. To skip the wait, make a backup now on the Backups tab and click “Send now”.",
      "guide_autoupdate": "Update the app by itself",
      "guide_autoupdate_lead": "You push code to GitHub and the app updates. Two ways: pick one.",
      "guide_autoupdate_s1": "Simplest: tick “Update by itself”",
      "guide_autoupdate_s1Desc": "When publishing, tick “Update by itself when I change the code”. The server checks GitHub every 2 minutes. Works on any network, nothing else to set up.",
      "guide_autoupdate_s2": "Faster: GitHub notice (webhook)",
      "guide_autoupdate_s2Desc": "GitHub tells the server right away. Only works if the dashboard has an internet address. With GitHub connected under Connections, the “Publish on every push” screen creates the notice in one click; without it, it shows the address and the secret to paste into GitHub.",
      "guide_autoupdate_s3": "Nothing breaks halfway",
      "guide_autoupdate_s3Desc": "The new version only goes live after it answers the test. If it fails, the current one stays live and the app's row shows why.",
      "guide_email": "Set up email sending",
      "guide_email_lead": "About 5 minutes with a free account. Works for every app.",
      "guide_email_s1": "Create an account on a sending service",
      "guide_email_s1Desc": "Brevo has a free plan with 300 emails a day. Others (Resend, Mailgun, Amazon SES) work too. Email sent straight from home lands in spam, hence the service.",
      "guide_email_s2": "Verify your domain on the service",
      "guide_email_s2Desc": "The service asks you to create a few DNS records. If the domain is on Cloudflare, paste them there under DNS → Records.",
      "guide_email_s3": "Copy the SMTP details into the dashboard",
      "guide_email_s3Desc": "Server, port, user and password (or SMTP key) are in the service's SMTP area. Paste them on the Email screen and save. Send yourself a test email.",
      "guide_email_s4": "Allow each app to send",
      "guide_email_s4Desc": "On the same screen, under “Allow an app to send email”, type the app's name. Then publish the app again.",
      "guide_github": "Connect GitHub for private code",
      "guide_github_lead": "Only for private repositories. About 2 minutes.",
      "guide_github_s1": "Choose between key and token",
      "guide_github_s1Desc": "The read-only key is safest: the server can only read that repository. The token saves pasting the key into each repository and lists your repositories when publishing.",
      "guide_github_s2": "With a key: paste it into the repository",
      "guide_github_s2Desc": "Copy the key under Connections → GitHub. On GitHub, open the repository, Settings → Deploy keys → Add deploy key, paste it and leave “Allow write access” unticked.",
      "guide_github_s3": "With a token: create and test",
      "guide_github_s3Desc": "Create a fine-grained token with only the repositories you will publish and Contents: Read-only. Paste it under Connections → GitHub and click Test and save. Done: Publish an app now lists your repositories.",
      "lead_guide": ""
    });

    Object.assign(I18N.pt, {
      "secSystemScope": "Painel e integrações (system)",
      "secSystemNote": "Chaves do próprio painel (Cloudflare, GitHub, cópias fora do servidor). Os apps não enxergam estas. Para mudar uma conexão, prefira a tela Conexões.",
      "secApplyNote": "O app lê estas variáveis quando é publicado. Depois de mudar algo, publique de novo.",
      "secApplyChanged": "Você mudou variáveis deste app. Elas valem depois de publicar de novo.",
      "secListTitle": "Salvas",
      "secAddTitle": "Adicionar ou trocar uma",
      "secChange": "Trocar",
      "secPasteTitle": "Colar um arquivo .env inteiro",
      "secPasteDesc": "Cole o conteúdo do seu .env (uma linha NOME=valor por variável). Comentários com # e aspas funcionam. Variáveis com o mesmo nome são trocadas; as outras ficam como estão.",
      "secPasteBtn": "Salvar todas",
      "secPasteOk": "{n} variáveis salvas.",
      "secPasteSkipped": "Ficaram de fora (não pareciam NOME=valor): linha {lines}.",
      "actionRedeploy": "Publicar de novo",
      "redeployTitle": "Monta e publica de novo o mesmo repositório e branch, com as variáveis atuais. A versão no ar continua até a nova passar no teste.",
      "redeployConfirm": "Publicar {app} de novo com as variáveis atuais? A versão no ar continua funcionando até a nova passar no teste."
    });
    Object.assign(I18N.en, {
      "secSystemScope": "Dashboard and integrations (system)",
      "secSystemNote": "The dashboard's own keys (Cloudflare, GitHub, off-server backups). Apps do not see these. To change a connection, prefer the Connections screen.",
      "secApplyNote": "The app reads these variables when it is published. After changing something, publish again.",
      "secApplyChanged": "You changed this app's variables. They take effect after publishing again.",
      "secListTitle": "Saved",
      "secAddTitle": "Add or change one",
      "secChange": "Change",
      "secPasteTitle": "Paste a whole .env file",
      "secPasteDesc": "Paste your .env content (one NAME=value line per variable). # comments and quotes work. Variables with the same name are replaced; the others stay as they are.",
      "secPasteBtn": "Save all",
      "secPasteOk": "{n} variables saved.",
      "secPasteSkipped": "Left out (not NAME=value): line {lines}.",
      "actionRedeploy": "Publish again",
      "redeployTitle": "Builds and publishes the same repository and branch again, with the current variables. The live version stays until the new one passes the test.",
      "redeployConfirm": "Publish {app} again with the current variables? The live version keeps working until the new one passes the test."
    });

    Object.assign(I18N.pt, {
      "lblQuickFillDeploy": "Parecido com:",
      "lblDepApp": "Nome do app",
      "lblDepRepo": "Repositório (dono/nome) ou pasta do servidor",
      "lblDepBranch": "Branch",
      "lblDepMem": "Memória máxima",
      "lblDepCpu": "Processadores (CPUs) no máximo",
      "lblDepPg": "Banco PostgreSQL (o app recebe <code>DATABASE_URL</code>)",
      "lblDepRedis": "Cache Redis (o app recebe <code>REDIS_URL</code>)",
      "btnDeploy": "🚀 Publicar",
      "lblDepHealth": "Página que o teste abre",
      "lblDepNoHealth": "Não é um site (pular o teste antes de trocar)",
      "depMore": "Mais opções",
      "depMoreDesc": "Pode deixar em branco. Antes de trocar a versão no ar, o painel abre uma página do app para ver se ele responde (por padrão, a página inicial).",
      "presetSaas": "Next.js + banco",
      "presetCompose": "Vários serviços (docker-compose)",
      "presetSpa": "Site estático (React, Vue...)",
      "presetDjango": "Django + banco",
      "presetFastapi": "FastAPI + banco",
      "presetNode": "Node / Express",
      "presetGo": "Go",
      "presetDotnet": "C# / ASP.NET + banco",
      "presetDockerfile": "Dockerfile próprio (Rails, Laravel…)",
      "btnNewApp": "+ Publicar um app",
      "appSearch": "Buscar por nome, linguagem ou porta...",
      "appsCount": "{n} apps",
      "appsCountOne": "1 app",
      "lblPort": "Porta",
      "depPhase_live": "No ar",
      "actionExpose": "Endereço",
      "lblExpApp": "App",
      "lblExpMode": "Quem pode abrir",
      "optPublic": "Qualquer pessoa (público)",
      "optZT": "Só e-mails autorizados",
      "optTS": "Só a minha rede (Tailscale)",
      "lblExpSub": "Começo do endereço",
      "btnExpose": "🔗 Publicar endereço",
      "expHint_public": "Bom para sites e apps com login próprio. Qualquer pessoa com o endereço abre.",
      "expHint_zero-trust": "A pessoa digita o e-mail e recebe um código. Só entra quem está na lista de Conexões → Domínio. Bom para painéis e ferramentas internas.",
      "expHint_tailscale": "Só abre em aparelhos com o Tailscale ligado na sua conta. Não precisa de domínio.",
      "expPreview": "Vai ficar:",
      "whLblUrl": "Endereço para colar no GitHub (Settings → Webhooks → Add webhook, campo Payload URL; Content type: application/json; evento: Just the push event)",
      "whLblSecret": "Segredo (campo Secret do mesmo formulário)",
      "btnRevealWhSecret": "👁️ Mostrar e copiar",
      "lblSshKey": "Chave de leitura para repositório privado (só se não usar o token do GitHub)",
      "whAutoTitle": "Ligar pelo painel",
      "whAutoNoteOn": "O painel cria o aviso no GitHub de cada repositório que tem app publicado aqui, sem copiar nada. O token precisa da permissão Webhooks: Read and write, além de Contents: Read-only. Dá para acrescentar editando o token no GitHub, sem criar outro.",
      "whAutoNoteOff": "Ligue o GitHub em Conexões → GitHub e o painel faz isto sozinho. Sem isso, use o passo a passo abaixo.",
      "whLblAddress": "Endereço do painel na internet",
      "whBtnCheck": "Conferir repositórios",
      "whChecking": "Conferindo no GitHub...",
      "whNoRepos": "Nenhum app daqui vem de um repositório do GitHub ainda.",
      "whStOn": "Ligado",
      "whStOff": "Desligado",
      "whStDenied": "Sem acesso",
      "whStError": "Não deu para conferir",
      "whDeniedHint": "O token não alcança este repositório ou não tem a permissão Webhooks: Read and write.",
      "whLastFail": "A última chamada do GitHub não chegou ao painel (código {code}).",
      "whBtnOn": "Ligar",
      "whBtnRedo": "Ligar de novo",
      "whBtnAll": "Ligar em todos",
      "whWorking": "Ligando em {repo} e testando...",
      "whOk": "Pronto: o GitHub avisou o painel e ele respondeu. Cada push em {repo} publica sozinho.",
      "whUnreachable": "O aviso foi criado em {repo}, mas o teste do GitHub não chegou ao painel (código {code}). Confira se o endereço abre de fora de casa. Se o painel está publicado como “Só e-mails autorizados”, o GitHub fica barrado no login: use “Atualizar sozinho” ao publicar o app.",
      "whUnknown": "O aviso foi criado em {repo}. O GitHub ainda não mostrou o resultado do teste: confira de novo em alguns segundos.",
      "whManualTitle": "Fazer à mão no GitHub",
      "btnCopySsh": "📋 Copiar chave",
      "dbTitle": "🗄️ Criar um banco de dados",
      "lblDbApp": "App",
      "lblDbEngine": "Tipo",
      "optDbPg": "PostgreSQL (banco de dados)",
      "optDbRedis": "Redis (cache e filas)",
      "btnCreateDb": "+ Criar banco",
      "emptyDbs": "Nenhum banco ainda.",
      "backupsTitle": "🛡️ Cópias de segurança",
      "lblBakApp": "App",
      "lblBakEngine": "O que copiar",
      "optBakPg": "Banco PostgreSQL",
      "optBakRedis": "Cache Redis",
      "optBakVol": "Arquivos do app (volumes do Docker)",
      "btnCreateBackup": "📸 Fazer uma cópia agora",
      "emptyBackups": "Nenhuma cópia ainda.",
      "btnRunDoctor": "🔍 Rodar diagnóstico",
      "sev_healthy": "Tudo certo",
      "sev_warning": "Atenção",
      "sev_critical": "Problema"
    });
    Object.assign(I18N.en, {
      "lblQuickFillDeploy": "Looks like:",
      "lblDepApp": "App name",
      "lblDepRepo": "Repository (owner/name) or server folder",
      "lblDepBranch": "Branch",
      "lblDepMem": "Maximum memory",
      "lblDepCpu": "Maximum processors (CPUs)",
      "lblDepPg": "PostgreSQL database (the app gets <code>DATABASE_URL</code>)",
      "lblDepRedis": "Redis cache (the app gets <code>REDIS_URL</code>)",
      "btnDeploy": "🚀 Publish",
      "lblDepHealth": "Page the test opens",
      "lblDepNoHealth": "Not a website (skip the test before switching)",
      "depMore": "More options",
      "depMoreDesc": "You can leave these empty. Before replacing the live version, the dashboard opens a page of the app to see that it answers (the home page by default).",
      "presetSaas": "Next.js + database",
      "presetCompose": "Several services (docker-compose)",
      "presetSpa": "Static site (React, Vue...)",
      "presetDjango": "Django + database",
      "presetFastapi": "FastAPI + database",
      "presetNode": "Node / Express",
      "presetGo": "Go",
      "presetDotnet": "C# / ASP.NET + database",
      "presetDockerfile": "Own Dockerfile (Rails, Laravel…)",
      "btnNewApp": "+ Publish an app",
      "appSearch": "Search by name, language or port...",
      "appsCount": "{n} apps",
      "appsCountOne": "1 app",
      "lblPort": "Port",
      "depPhase_live": "Live",
      "actionExpose": "Address",
      "lblExpApp": "App",
      "lblExpMode": "Who can open it",
      "optPublic": "Anyone (public)",
      "optZT": "Allowed emails only",
      "optTS": "Only my network (Tailscale)",
      "lblExpSub": "Start of the address",
      "btnExpose": "🔗 Publish address",
      "expHint_public": "Good for sites and apps with their own login. Anyone with the address can open it.",
      "expHint_zero-trust": "The person types their email and gets a code. Only people on the list in Connections → Domain get in. Good for admin panels and internal tools.",
      "expHint_tailscale": "Only opens on devices with Tailscale on, in your account. No domain needed.",
      "expPreview": "It will be:",
      "whLblUrl": "Address to paste on GitHub (Settings → Webhooks → Add webhook, Payload URL field; Content type: application/json; event: Just the push event)",
      "whLblSecret": "Secret (the Secret field on the same form)",
      "btnRevealWhSecret": "👁️ Show and copy",
      "lblSshKey": "Read-only key for a private repository (only if you do not use the GitHub token)",
      "whAutoTitle": "Turn on from the dashboard",
      "whAutoNoteOn": "The dashboard creates the notice on GitHub for each repository with an app published here, with nothing to copy. The token needs the Webhooks: Read and write permission, besides Contents: Read-only. You can add it by editing the token on GitHub, no new token needed.",
      "whAutoNoteOff": "Connect GitHub under Connections → GitHub and the dashboard does this by itself. Without it, use the steps below.",
      "whLblAddress": "Dashboard's internet address",
      "whBtnCheck": "Check repositories",
      "whChecking": "Checking on GitHub...",
      "whNoRepos": "No app here comes from a GitHub repository yet.",
      "whStOn": "On",
      "whStOff": "Off",
      "whStDenied": "No access",
      "whStError": "Could not check",
      "whDeniedHint": "The token does not reach this repository or lacks the Webhooks: Read and write permission.",
      "whLastFail": "GitHub's last call did not reach the dashboard (code {code}).",
      "whBtnOn": "Turn on",
      "whBtnRedo": "Turn on again",
      "whBtnAll": "Turn on for all",
      "whWorking": "Turning on for {repo} and testing...",
      "whOk": "Done: GitHub called the dashboard and it answered. Every push to {repo} publishes by itself.",
      "whUnreachable": "The notice was created on {repo}, but GitHub's test did not reach the dashboard (code {code}). Check that the address opens from outside your home network. If the dashboard is published as “Only allowed emails”, GitHub is stopped at the login: use “Update by itself” when publishing the app.",
      "whUnknown": "The notice was created on {repo}. GitHub has not shown the test result yet: check again in a few seconds.",
      "whManualTitle": "Do it by hand on GitHub",
      "btnCopySsh": "📋 Copy key",
      "dbTitle": "🗄️ Create a database",
      "lblDbApp": "App",
      "lblDbEngine": "Type",
      "optDbPg": "PostgreSQL (database)",
      "optDbRedis": "Redis (cache and queues)",
      "btnCreateDb": "+ Create database",
      "emptyDbs": "No databases yet.",
      "backupsTitle": "🛡️ Backups",
      "lblBakApp": "App",
      "lblBakEngine": "What to back up",
      "optBakPg": "PostgreSQL database",
      "optBakRedis": "Redis cache",
      "optBakVol": "App files (Docker volumes)",
      "btnCreateBackup": "📸 Back up now",
      "emptyBackups": "No backups yet.",
      "btnRunDoctor": "🔍 Run diagnostics",
      "sev_healthy": "All good",
      "sev_warning": "Warning",
      "sev_critical": "Problem"
    });

    Object.assign(I18N.pt, {
      "pickLabel": "Ou escolha da sua lista do GitHub",
      "pickChoose": "Escolha um repositório...",
      "pickPrivate": "privado",
      "pickPrivateNote": "Repositório privado: o painel baixa o código com o token salvo em Conexões.",
      "pickLoading": "Buscando seus repositórios no GitHub...",
      "pickEmpty": "O token do GitHub não enxerga nenhum repositório. Em Conexões → GitHub, crie um token com acesso aos repositórios que vai publicar.",
      "pickNoToken": "Quer escolher da lista ou publicar código privado?",
      "pickConnect": "Ligue o GitHub em Conexões"
    });
    Object.assign(I18N.en, {
      "pickLabel": "Or pick from your GitHub list",
      "pickChoose": "Pick a repository...",
      "pickPrivate": "private",
      "pickPrivateNote": "Private repository: the dashboard fetches the code with the token saved under Connections.",
      "pickLoading": "Fetching your GitHub repositories...",
      "pickEmpty": "The GitHub token sees no repository. Under Connections → GitHub, create a token with access to the repositories you will publish.",
      "pickNoToken": "Want to pick from a list, or publish private code?",
      "pickConnect": "Connect GitHub under Connections"
    });

    Object.assign(I18N.pt, {
      "df_healthcheck": "A nova versão não respondeu e não foi para o ar.",
      "dfh_healthcheck": "A versão anterior continua funcionando. O erro do app está nos detalhes. Se ele não é um site (um robô ou uma tarefa de fundo), marque “Não é um site” em Mais opções.",
      "df_access": "Não consegui baixar o código.",
      "dfh_access": "Confira o nome do repositório (dono/nome). Se ele é privado, conecte o GitHub.",
      "df_branch": "Esse branch não existe no repositório.",
      "dfh_branch": "Confira o nome do branch. Normalmente é main ou master.",
      "df_stack": "Não reconheci o tipo do projeto.",
      "dfh_stack": "O painel monta sozinho projetos Node, Python, Go, .NET e sites estáticos. Para outros, coloque um Dockerfile no repositório.",
      "df_memory": "Faltou memória para montar ou rodar o app.",
      "dfh_memory": "Aumente a memória máxima em Mais opções (por exemplo 1g) e publique de novo.",
      "df_build": "A montagem do app falhou.",
      "dfh_build": "Costuma ser um erro no código ou numa dependência. As últimas linhas dos detalhes mostram onde. Corrija no repositório e publique de novo.",
      "df_network": "O servidor não conseguiu acessar a internet.",
      "dfh_network": "Confira a conexão do servidor e tente de novo em alguns minutos.",
      "df_trash": "Esse app está na lixeira.",
      "dfh_trash": "Restaure ou apague de vez na lista Seus apps antes de publicar com esse nome.",
      "df_name": "Já existe um app com esse nome.",
      "dfh_name": "Escolha outro nome. O app que já existe continua como está.",
      "df_other": "Não deu para publicar.",
      "dfh_other": "O erro está nos detalhes. Se não ficar claro, o Diagnóstico confere o servidor.",
      "dfDetails": "Detalhes técnicos",
      "dfAct_github": "Conectar o GitHub",
      "dfAct_options": "Abrir Mais opções",
      "dfAct_guide": "Ver o guia",
      "dfAct_trash": "Ver Seus apps",
      "dfAct_doctor": "Abrir o Diagnóstico",
      "dfOkTitle": "Publicado: {app}",
      "dfOkNext": "Próximo passo: dar um endereço para abrir o app de qualquer lugar.",
      "dfOkLive": "O app está no ar em:",
      "dfOkExpose": "Dar um endereço",
      "dfOkList": "Ver Seus apps"
    });
    Object.assign(I18N.en, {
      "df_healthcheck": "The new version did not answer and was not put live.",
      "dfh_healthcheck": "The previous version is still running. The app's error is in the details. If it is not a website (a bot or a background task), tick “Not a website” under More options.",
      "df_access": "Could not download the code.",
      "dfh_access": "Check the repository name (owner/name). If it is private, connect GitHub.",
      "df_branch": "That branch does not exist in the repository.",
      "dfh_branch": "Check the branch name. It is usually main or master.",
      "df_stack": "Could not tell what kind of project this is.",
      "dfh_stack": "The dashboard builds Node, Python, Go, .NET and static sites by itself. For anything else, add a Dockerfile to the repository.",
      "df_memory": "Ran out of memory while building or running the app.",
      "dfh_memory": "Raise the maximum memory under More options (for example 1g) and publish again.",
      "df_build": "Building the app failed.",
      "dfh_build": "This is usually an error in the code or in a dependency. The last lines of the details show where. Fix it in the repository and publish again.",
      "df_network": "The server could not reach the internet.",
      "dfh_network": "Check the server's connection and try again in a few minutes.",
      "df_trash": "This app is in the trash.",
      "dfh_trash": "Restore it or delete it for good in Your apps before publishing with this name.",
      "df_name": "An app with this name already exists.",
      "dfh_name": "Pick another name. The existing app stays as it is.",
      "df_other": "Could not publish.",
      "dfh_other": "The error is in the details. If it is not clear, Diagnostics checks the server.",
      "dfDetails": "Technical details",
      "dfAct_github": "Connect GitHub",
      "dfAct_options": "Open More options",
      "dfAct_guide": "See the guide",
      "dfAct_trash": "See Your apps",
      "dfAct_doctor": "Open Diagnostics",
      "dfOkTitle": "Published: {app}",
      "dfOkNext": "Next step: give it an address so you can open it from anywhere.",
      "dfOkLive": "The app is live at:",
      "dfOkExpose": "Give it an address",
      "dfOkList": "See Your apps"
    });

    Object.assign(I18N.pt, {
      "life_restart": "{app} foi reiniciado.",
      "life_stop": "{app} foi parado.",
      "life_start": "{app} foi ligado.",
      "life_rollback": "{app} voltou para a versão anterior.",
      "life_destroy": "{app} foi para a lixeira. Dá para restaurar na lista Seus apps.",
      "life_restore": "{app} saiu da lixeira e está ligado.",
      "life_purge": "{app} foi apagado de vez.",
      "lifePoolUpdating": "As cópias nos PCs ajudantes estão sendo atualizadas.",
      "lifePoolFailed": "As cópias nos PCs ajudantes não foram atualizadas (veja a tela Ajudantes).",
      "lifeErrNoPrevious": "Ainda não existe uma versão anterior guardada desse app. Ela aparece depois da próxima publicação.",
      "lifeErr": "Não deu para fazer isso agora.",
      "logsEmpty": "O app ainda não escreveu nada.",
      "logsHint": "As linhas mais recentes ficam no fim. Erros costumam aparecer com Error, Exception ou Traceback.",
      "actionRollbackTip": "Volta para a versão publicada antes desta, em segundos"
    });
    Object.assign(I18N.en, {
      "life_restart": "{app} was restarted.",
      "life_stop": "{app} was stopped.",
      "life_start": "{app} was started.",
      "life_rollback": "{app} is back on the previous version.",
      "life_destroy": "{app} went to the trash. You can restore it in Your apps.",
      "life_restore": "{app} left the trash and is running.",
      "life_purge": "{app} was deleted for good.",
      "lifePoolUpdating": "Copies on helper PCs are being updated.",
      "lifePoolFailed": "Copies on helper PCs were not updated (see the Helpers screen).",
      "lifeErrNoPrevious": "There is no earlier version of this app saved yet. One appears after the next publish.",
      "lifeErr": "Could not do that right now.",
      "logsEmpty": "The app has not written anything yet.",
      "logsHint": "The newest lines are at the end. Errors usually show up with Error, Exception or Traceback.",
      "actionRollbackTip": "Goes back to the version published before this one, in seconds"
    });

    Object.assign(I18N.pt, {
      "appNoAddressTip": "Este app ainda não tem endereço. Clique para dar um.",
      "pillLocalOnly": "Só neste servidor",
      "mode_public": "público",
      "mode_zero-trust": "só e-mails autorizados",
      "mode_tailscale": "só a minha rede",
      "mode_local": "rede de casa",
      "limitsLabel": "Limite: {mem} de memória, {cpu} CPU",
      "expListTitle": "Endereços publicados",
      "btnUnexpose": "Tirar do ar",
      "toastUnexposed": "Endereço tirado do ar: "
    });
    Object.assign(I18N.en, {
      "appNoAddressTip": "This app has no address yet. Click to give it one.",
      "pillLocalOnly": "Only on this server",
      "mode_public": "public",
      "mode_zero-trust": "authorized emails only",
      "mode_tailscale": "my network only",
      "mode_local": "home network",
      "limitsLabel": "Limit: {mem} memory, {cpu} CPU",
      "expListTitle": "Published addresses",
      "btnUnexpose": "Take offline",
      "toastUnexposed": "Address taken offline: "
    });

    Object.assign(I18N.pt, {
      "doc_app_registered": "Registrado, respondendo só neste servidor (porta {port}).",
      "doc_app_ok": "Ligado e saudável (porta {port} neste servidor).",
      "doc_app_oom": "O app foi derrubado por falta de memória.",
      "docr_app_oom": "Aumente a memória máxima em Publicar um app → Mais opções e publique de novo, ou reduza o uso de memória do app.",
      "doc_app_down": "O app não está rodando (estado {status}, código de saída {exitCode}).",
      "docr_app_down": "Abra os Logs do app para ver o erro. Confira as Variáveis (falta alguma senha?) ou use Voltar versão.",
      "doc_app_restarts": "O app está ligado, mas já reiniciou sozinho {count} vezes.",
      "docr_app_restarts": "Abra os Logs para ver por que ele cai de vez em quando.",
      "doc_app_missing": "O app não foi encontrado no Docker.",
      "docr_app_missing": "Use Publicar de novo na lista Seus apps para recriá-lo.",
      "doc_app_missing_stopped": "O app está parado e não existe no Docker agora.",
      "doc_dns_ok": "O servidor resolve nomes da internet (DNS funcionando).",
      "doc_dns_fail": "O servidor não consegue resolver nomes da internet (DNS). Sem isso, endereço público, publicação e PCs ajudantes param.",
      "docr_dns_fail": "Se o DNS roda nesta mesma máquina (AdGuard Home, Pi-hole), confira se ele está ligado e dê ao servidor um DNS reserva: em /etc/systemd/resolved.conf coloque FallbackDNS=1.1.1.1 9.9.9.9 e faça o /etc/resolv.conf apontar para o systemd-resolved.",
      "doc_wt_label_mode": "O Watchtower roda aqui, mas só atualiza o que foi marcado para ele, então não mexe no PaaSMCP.",
      "doc_wt_all_labeled": "O Watchtower roda aqui e todos os contêineres do PaaSMCP estão marcados para ele pular.",
      "doc_wt_unlabeled": "O Watchtower roda aqui e pode reiniciar sozinho {count} contêiner(es) do PaaSMCP: {names}. Um reinício surpresa do banco ou de um app parece uma queda.",
      "docr_wt_unlabeled": "Os contêineres novos já saem marcados; esses antigos ganham a marca na próxima publicação. Até lá, o mais simples: rode o Watchtower com WATCHTOWER_LABEL_ENABLE=true e marque só o que você quer que ele atualize.",
      "doc_net_clash": "Uma rede do Docker cobre uma rede deste servidor ({clash}). O tráfego para esses endereços vai para o Docker em vez da rede de casa ou do Tailscale.",
      "docr_net_clash": "Dê ao Docker uma faixa própria: em /etc/docker/daemon.json adicione \\"default-address-pools\\": [{\\"base\\": \\"10.200.0.0/16\\", \\"size\\": 24}], reinicie o Docker num momento calmo e recrie a rede que conflita.",
      "doc_net_pool": "O Docker já usou {used} das suas {total} redes padrão. As próximas vêm de 192.168.x.0/20, que pode cobrir a rede de casa.",
      "docr_net_pool": "Antes disso, dê ao Docker uma faixa própria: em /etc/docker/daemon.json adicione \\"default-address-pools\\": [{\\"base\\": \\"10.200.0.0/16\\", \\"size\\": 24}] e reinicie o Docker num momento calmo. Só vale para redes criadas depois.",
      "doc_tunnel_net": "O contêiner do Cloudflare Tunnel ({names}) não está na rede {network}, então os endereços públicos responderiam com erro 502.",
      "docr_tunnel_net": "Ligue-o à rede: docker network connect {network} {first} (e adicione a rede no compose dele para continuar depois de reiniciar)."
    });
    Object.assign(I18N.en, {
      "doc_app_registered": "Registered, answering only on this server (port {port}).",
      "doc_app_ok": "Running and healthy (port {port} on this server).",
      "doc_app_oom": "The app was stopped for running out of memory.",
      "docr_app_oom": "Raise the maximum memory under Publish an app → More options and publish again, or make the app use less memory.",
      "doc_app_down": "The app is not running (state {status}, exit code {exitCode}).",
      "docr_app_down": "Open the app's Logs to see the error. Check its Variables (a missing password?) or use Roll back.",
      "doc_app_restarts": "The app is running, but has restarted on its own {count} times.",
      "docr_app_restarts": "Open the Logs to see why it falls over now and then.",
      "doc_app_missing": "The app was not found in Docker.",
      "docr_app_missing": "Use Publish again in Your apps to recreate it.",
      "doc_app_missing_stopped": "The app is stopped and does not exist in Docker right now.",
      "doc_dns_ok": "This server resolves internet names (DNS works).",
      "doc_dns_fail": "This server cannot resolve internet names (DNS). Without it, public addresses, publishing and helper PCs stop working.",
      "docr_dns_fail": "If the DNS server runs on this same machine (AdGuard Home, Pi-hole), check that it is up and give the server a fallback: in /etc/systemd/resolved.conf set FallbackDNS=1.1.1.1 9.9.9.9 and make /etc/resolv.conf point to systemd-resolved.",
      "doc_wt_label_mode": "Watchtower runs here, but only updates what is marked for it, so it leaves PaaSMCP alone.",
      "doc_wt_all_labeled": "Watchtower runs here and every PaaSMCP container is marked for it to skip.",
      "doc_wt_unlabeled": "Watchtower runs here and may restart {count} PaaSMCP container(s) on its own: {names}. A surprise restart of the database or an app looks like an outage.",
      "docr_wt_unlabeled": "New containers are already marked; these older ones get the mark on their next publish. Until then, the simplest fix: run Watchtower with WATCHTOWER_LABEL_ENABLE=true and mark only what you want it to update.",
      "doc_net_clash": "A Docker network covers one of this server's networks ({clash}). Traffic to those addresses goes into Docker instead of the home network or Tailscale.",
      "docr_net_clash": "Give Docker a range of its own: in /etc/docker/daemon.json add \\"default-address-pools\\": [{\\"base\\": \\"10.200.0.0/16\\", \\"size\\": 24}], restart Docker in a quiet moment, then recreate the clashing network.",
      "doc_net_pool": "Docker has used {used} of its {total} default networks. The next ones come from 192.168.x.0/20, which can cover a home network.",
      "docr_net_pool": "Before that happens, give Docker a range of its own: in /etc/docker/daemon.json add \\"default-address-pools\\": [{\\"base\\": \\"10.200.0.0/16\\", \\"size\\": 24}] and restart Docker in a quiet moment. It only affects networks created afterwards.",
      "doc_tunnel_net": "The Cloudflare Tunnel container ({names}) is not on the {network} network, so public addresses would answer with error 502.",
      "docr_tunnel_net": "Connect it: docker network connect {network} {first} (and add the network to its compose file so it stays after a restart)."
    });

    // A doctor finding in the screen's language when it carries a known code; the server's English text otherwise.
    function docText(d, field) {
      const key = (field === 'summary' ? 'doc_' : 'docr_') + (d.code || '');
      if (!d.code || !I18N.en['doc_' + d.code]) return field === 'summary' ? d.summary : d.recommendation;
      if (!I18N.en[key]) return field === 'summary' ? d.summary : '';
      let txt = t(key);
      for (const [k, v] of Object.entries(d.vars || {})) txt = txt.split('{' + k + '}').join(String(v));
      return txt;
    }

    Object.assign(I18N.pt, {
      "sub_connect_alerts": "Avisos",
      "ntTitle": "🔔 Avisos no celular ou no chat",
      "ntDesc": "O painel avisa quando uma publicação automática (git push ou atualização sozinha) falha e quando um app para sozinho, e de novo quando ele volta. Assim você fica sabendo sem abrir o painel.",
      "ntHow": "Cole um destes endereços:",
      "ntHowNtfy": "Celular: instale o app ntfy (grátis), assine um tópico com um nome difícil de adivinhar e cole https://ntfy.sh/seu-topico.",
      "ntHowDiscord": "Discord: no canal, Editar canal → Integrações → Webhooks → Novo webhook → Copiar URL.",
      "ntHowSlack": "Slack: crie um app com Incoming Webhooks e copie a Webhook URL.",
      "ntUrl": "Endereço dos avisos",
      "ntOnSuccess": "Avisar também quando a publicação automática der certo",
      "ntSave": "Mandar teste e salvar",
      "ntSending": "Mandando um aviso de teste...",
      "ntSaved": "Aviso de teste enviado e endereço salvo.",
      "ntOn": "Avisos ligados",
      "ntOnDesc": "Para {host}. Publicações que falharem e apps que pararem vão gerar um aviso{success}.",
      "ntOnSuccessShort": ", e as automáticas que derem certo também",
      "ntChange": "Trocar endereço",
      "ntOff": "Desligar avisos",
      "ntOffConfirm": "Desligar os avisos?",
      "tut_alerts": "Receber avisos quando algo falhar",
      "tut_alertsDesc": "No celular (ntfy), no Discord ou no Slack."
    });
    Object.assign(I18N.en, {
      "sub_connect_alerts": "Notices",
      "ntTitle": "🔔 Notices on your phone or chat",
      "ntDesc": "The dashboard tells you when an automatic publish (git push or self-update) fails and when an app stops on its own, and again when it is back, so you know without opening the dashboard.",
      "ntHow": "Paste one of these addresses:",
      "ntHowNtfy": "Phone: install the ntfy app (free), subscribe to a topic with a hard-to-guess name and paste https://ntfy.sh/your-topic.",
      "ntHowDiscord": "Discord: in the channel, Edit channel → Integrations → Webhooks → New webhook → Copy URL.",
      "ntHowSlack": "Slack: create an app with Incoming Webhooks and copy the Webhook URL.",
      "ntUrl": "Notice address",
      "ntOnSuccess": "Also tell me when an automatic publish works",
      "ntSave": "Send a test and save",
      "ntSending": "Sending a test notice...",
      "ntSaved": "Test notice sent and address saved.",
      "ntOn": "Notices on",
      "ntOnDesc": "To {host}. Failed publishes and apps that stop send a notice{success}.",
      "ntOnSuccessShort": ", and so do automatic ones that work",
      "ntChange": "Change address",
      "ntOff": "Turn notices off",
      "ntOffConfirm": "Turn notices off?",
      "tut_alerts": "Get a notice when something fails",
      "tut_alertsDesc": "On your phone (ntfy), Discord or Slack."
    });

    Object.assign(I18N.pt, {
      "tplTitle": "📦 Apps prontos",
      "tplDesc": "Sem repositório: escolha um app conhecido e o painel instala a versão testada, com os dados guardados entre atualizações.",
      "tpl_uptime-kuma": "Uptime Kuma",
      "tpl_uptime-kumaDesc": "Vigia seus sites e serviços e avisa quando algum cai.",
      "tpl_memos": "Memos",
      "tpl_memosDesc": "Anotações rápidas e privadas, como um Twitter só seu.",
      "tpl_it-tools": "IT Tools",
      "tpl_it-toolsDesc": "Dezenas de ferramentas úteis no navegador: gerar senhas, converter formatos, QR code.",
      "tplInstall": "Instalar",
      "tplInstalling": "Instalando...",
      "tplSite": "Site do projeto",
      "tplNamePrompt": "Nome do app (letras minúsculas, números e hífen):",
      "tplFirstAdmin": "Atenção: na primeira visita, quem abrir cria a conta de administrador. Crie a sua logo, ou dê o endereço “Só e-mails autorizados”."
    });
    Object.assign(I18N.en, {
      "tplTitle": "📦 Ready-made apps",
      "tplDesc": "No repository needed: pick a well-known app and the dashboard installs the tested version, with its data kept across updates.",
      "tpl_uptime-kuma": "Uptime Kuma",
      "tpl_uptime-kumaDesc": "Watches your sites and services and tells you when one goes down.",
      "tpl_memos": "Memos",
      "tpl_memosDesc": "Quick private notes, like a Twitter of your own.",
      "tpl_it-tools": "IT Tools",
      "tpl_it-toolsDesc": "Dozens of handy browser tools: password generator, format converters, QR codes.",
      "tplInstall": "Install",
      "tplInstalling": "Installing...",
      "tplSite": "Project site",
      "tplNamePrompt": "App name (lowercase letters, numbers and hyphens):",
      "tplFirstAdmin": "Heads up: on the first visit, whoever opens it creates the admin account. Create yours right away, or give it the “Authorized emails only” address."
    });

    let tplData = null;
    async function renderTemplates() {
      const box = document.getElementById('tplList');
      if (!box) return;
      if (!tplData) {
        const res = await fetch('/api/templates');
        if (!res.ok) return;
        tplData = (await res.json()).templates || [];
      }
      box.innerHTML = tplData.map(function (tp) {
        return '<div class="tpl-item"><strong>' + esc(t('tpl_' + tp.id) || tp.id) + '</strong><p>' + esc(t('tpl_' + tp.id + 'Desc')) + '</p>' +
          '<div class="tpl-row"><a href="' + esc(tp.homepage) + '" target="_blank" rel="noopener noreferrer">' + esc(t('tplSite')) + ' ↗</a>' +
          '<button class="secondary" data-tpl="' + esc(tp.id) + '" onclick="installTemplate(this.dataset.tpl, this)">' + esc(t('tplInstall')) + '</button></div></div>';
      }).join('');
    }
    async function installTemplate(id, btn) {
      const tp = (tplData || []).find(function (x) { return x.id === id; });
      if (!tp) return;
      const name = (prompt(t('tplNamePrompt'), id) || '').trim().toLowerCase();
      if (!name) return;
      const box = document.getElementById('tplResult');
      box.innerHTML = '';
      const label = btn.textContent;
      btn.textContent = t('tplInstalling');
      btn.disabled = true;
      try {
        setTimeout(pollDeploys, 800);
        const res = await fetch('/api/templates/deploy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, appName: name }) });
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok && !data.failure && !data.error) data.error = 'HTTP ' + res.status;
        box.innerHTML = deployResultHtml(res.ok, name, data) + (res.ok && tp.firstVisitAdmin ? '<p class="ofs-note" style="margin-top:8px;">⚠️ ' + esc(t('tplFirstAdmin')) + '</p>' : '');
        if (res.ok) { showToast(t('toastDeployDone') + name); loadAll(); }
        box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } finally {
        btn.textContent = label;
        btn.disabled = false;
      }
    }

    Object.assign(I18N.pt, {
      "nbNone": "🌙 Cópia automática: uma por noite, a partir das 3h30 (horário do servidor), de todos os bancos e dados dos apps. Ainda não houve nenhuma.",
      "nbRunning": "🌙 Cópia automática em andamento desde {when}.",
      "nbOk": "🌙 Última cópia automática: {when}, {n} arquivo(s).",
      "nbErr": "🌙 Última cópia automática: {when}, com {n} erro(s). Primeiro: {first}",
      "nbOffsiteOk": "Enviada para fora do servidor.",
      "nbOffsiteFailed": "O envio para fora do servidor falhou.",
      "nbOffsiteNone": "Ficou só neste servidor: configure “Cópias fora do servidor” para não perder tudo se ele quebrar.",
      "nbNext": "Próxima: toda noite, a partir das 3h30."
    });
    Object.assign(I18N.en, {
      "nbNone": "🌙 Automatic copy: one per night, from 3:30 (server time), of every database and app data. None yet.",
      "nbRunning": "🌙 Automatic copy running since {when}.",
      "nbOk": "🌙 Last automatic copy: {when}, {n} file(s).",
      "nbErr": "🌙 Last automatic copy: {when}, with {n} error(s). First: {first}",
      "nbOffsiteOk": "Sent off the server.",
      "nbOffsiteFailed": "Sending it off the server failed.",
      "nbOffsiteNone": "It stayed only on this server: set up “Off-server backups” so a broken server does not take everything.",
      "nbNext": "Next: every night, from 3:30."
    });

    function renderNightly(nb) {
      const box = document.getElementById('bakNightly');
      if (!box) return;
      const when = function (iso) { try { return new Date(iso).toLocaleString(currentLang === 'pt' ? 'pt-BR' : 'en-US', { dateStyle: 'short', timeStyle: 'short' }); } catch { return iso; } };
      let html;
      let err = false;
      if (!nb) html = esc(t('nbNone'));
      else if (!nb.finishedAt) html = esc(t('nbRunning').split('{when}').join(when(nb.startedAt)));
      else {
        const errs = nb.errors || [];
        err = errs.length > 0 || nb.offsite === 'failed';
        html = esc(errs.length
          ? t('nbErr').split('{when}').join(when(nb.finishedAt)).split('{n}').join(String(errs.length)).split('{first}').join(String(errs[0]).slice(0, 200))
          : t('nbOk').split('{when}').join(when(nb.finishedAt)).split('{n}').join(String(nb.created || 0)));
        const off = nb.offsite === 'ok' ? t('nbOffsiteOk') : nb.offsite === 'failed' ? t('nbOffsiteFailed') : t('nbOffsiteNone');
        html += ' ' + esc(off) + (nb.offsite === 'not-configured' ? ' <a href="#databases/offsite">→</a>' : '') + '<br><span style="color:var(--muted);">' + esc(t('nbNext')) + '</span>';
      }
      box.className = 'bak-nightly' + (err ? ' err' : '');
      box.innerHTML = html;
    }

    Object.assign(I18N.pt, { "logsRefresh": "↻ Atualizar" });
    Object.assign(I18N.en, { "logsRefresh": "↻ Refresh" });

    Object.assign(I18N.pt, {
      "bkKind_postgres": "banco PostgreSQL",
      "bkKind_redis": "cache Redis",
      "bkKind_volume": "arquivos do app",
      "bkTest_checked": "A cópia abre: conferida e decifrada.",
      "bkTest_pg_ok": "A cópia abre: carregada num banco temporário, {n} tabela(s).",
      "bkTest_volume_ok": "A cópia abre: {n} arquivo(s) e pasta(s).",
      "bkTest_redis_ok": "A cópia do Redis abre.",
      "bkTest_redis_bad": "Essa cópia não parece um arquivo do Redis.",
      "bkRestoredDb": "Banco restaurado.",
      "bkRestoredVolume": "Arquivos do app restaurados.",
      "bkSafety": "Antes, o painel guardou uma cópia de como estava, para desfazer se preciso.",
      "bkErr": "Não deu para fazer isso agora."
    });
    Object.assign(I18N.en, {
      "bkKind_postgres": "PostgreSQL database",
      "bkKind_redis": "Redis cache",
      "bkKind_volume": "app files",
      "bkTest_checked": "The copy opens: checked and decrypted.",
      "bkTest_pg_ok": "The copy opens: loaded into a temporary database, {n} table(s).",
      "bkTest_volume_ok": "The copy opens: {n} file(s) and folder(s).",
      "bkTest_redis_ok": "The Redis copy opens.",
      "bkTest_redis_bad": "This copy does not look like a Redis file.",
      "bkRestoredDb": "Database restored.",
      "bkRestoredVolume": "App files restored.",
      "bkSafety": "First, the dashboard kept a copy of how it was, to undo if needed.",
      "bkErr": "Could not do that right now."
    });

    Object.assign(I18N.pt, {
      "dbGetsPg": "O app já recebe o endereço do banco em DATABASE_URL (em Variáveis). A senha fica guardada e cifrada.",
      "dbGetsRedis": "O app já recebe o endereço do cache em REDIS_URL (em Variáveis).",
      "dbRedeployNote": "Banco criado. Para {app} passar a usá-lo, publique de novo (leva o mesmo tempo de uma atualização)."
    });
    Object.assign(I18N.en, {
      "dbGetsPg": "The app already gets the database address in DATABASE_URL (under Variables). The password is kept encrypted.",
      "dbGetsRedis": "The app already gets the cache address in REDIS_URL (under Variables).",
      "dbRedeployNote": "Database created. For {app} to use it, publish it again (takes as long as an update)."
    });

    function fmtWhen(iso) {
      try { return new Date(iso).toLocaleString(currentLang === 'pt' ? 'pt-BR' : 'en-US', { dateStyle: 'short', timeStyle: 'short' }); } catch { return String(iso || ''); }
    }
    function fmtSize(bytes) {
      const n = Number(bytes) || 0;
      if (n < 1024) return n + ' B';
      if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
      if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
      return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    }

    function esc(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function getBaseDomain() {
      const configured = lastStatus && lastStatus.cloudflare && lastStatus.cloudflare.baseDomain;
      if (configured && configured !== "-" && configured !== "example.com") return configured;
      const host = window.location.hostname;
      const parts = host.split(".");
      if (parts.length >= 2 && host !== "localhost" && !/^[0-9.]+$/.test(host)) {
        return parts.slice(1).join(".");
      }
      return currentLang === "pt" ? "seudominio.com" : "yourdomain.com";
    }

    function showToast(msg) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.style.display = 'block';
      clearTimeout(window.__toastTimer);
      window.__toastTimer = setTimeout(() => { el.style.display = 'none'; }, 3200);
    }

    function copyText(text) {
      navigator.clipboard.writeText(text || '');
      showToast(currentLang === 'pt' ? '✅ Copiado para a área de transferência!' : '✅ Copied to clipboard!');
    }

    function copySshKey() {
      copyText(document.getElementById('sshKeyBox').textContent);
    }

    // Pages with more than one part get folder tabs on top and nested items in the side menu.
    const PAGE_SUBS = {
      home: ['start', 'tutorial'],
      overview: ['list', 'deploy', 'expose', 'scale', 'diary', 'webhook'],
      databases: ['dbs', 'backups', 'offsite', 'files'],
      mirror: ['connect', 'copy', 'judge', 'auto', 'aa', 'back'],
      pool: ['list', 'add', 'how'],
      agents: ['connect', 'examples'],
      connect: ['cloudflare', 'github', 'alerts'],
    };
    let activeSubs = {};
    try { activeSubs = JSON.parse(localStorage.getItem('paasmcp_active_subs') || '{}') || {}; } catch { activeSubs = {}; }
    let currentTab = '';
    let navInitDone = false;

    function navBtnFor(tab) { return document.getElementById('nav' + tab.charAt(0).toUpperCase() + tab.slice(1)); }
    function currentSub(tab) {
      const subs = PAGE_SUBS[tab];
      if (!subs) return '';
      return subs.indexOf(activeSubs[tab]) !== -1 ? activeSubs[tab] : subs[0];
    }

    function renderSubNav() {
      Object.keys(PAGE_SUBS).forEach(function (tab) {
        const subs = PAGE_SUBS[tab];
        const cur = currentSub(tab);
        const holder = document.querySelector('.nav-subs[data-subs-for="' + tab + '"]');
        if (holder) {
          holder.innerHTML = subs.map(function (sub) {
            return '<button class="nav-sub' + (sub === cur ? ' active' : '') + '" data-go-tab="' + tab + '" data-go-sub="' + sub + '">' + esc(t('sub_' + tab + '_' + sub)) + '</button>';
          }).join('');
        }
        const pane = document.getElementById('tab-' + tab);
        if (!pane) return;
        let bar = pane.querySelector(':scope > .page-tabs');
        if (!bar) {
          bar = document.createElement('div');
          bar.className = 'page-tabs';
          bar.setAttribute('role', 'tablist');
          pane.prepend(bar);
          const head = pane.querySelector(':scope > .page-head');
          if (head) head.after(bar);
        }
        bar.innerHTML = subs.map(function (sub) {
          const on = sub === cur;
          return '<button class="page-tab' + (on ? ' active' : '') + '" role="tab" aria-selected="' + on + '" data-go-tab="' + tab + '" data-go-sub="' + sub + '">' + esc(t('sub_' + tab + '_' + sub)) + '</button>';
        }).join('');
        pane.querySelectorAll('[data-sub]').forEach(function (el) {
          el.classList.toggle('sub-hidden', el.getAttribute('data-sub') !== cur);
        });
        // On narrow screens the tab row scrolls sideways: keep the open tab in view.
        const act = bar.querySelector('.page-tab.active');
        if (act && bar.scrollWidth > bar.clientWidth) bar.scrollLeft = Math.max(0, act.offsetLeft - (bar.clientWidth - act.offsetWidth) / 2);
      });
      // Page title (same icon and name as the menu item), like a repository page on GitHub.
      document.querySelectorAll('.console-main > .tab-pane').forEach(function (pane) {
        const tab = pane.id.replace(/^tab-/, '');
        const btn = navBtnFor(tab);
        if (!btn) return;
        let head = pane.querySelector(':scope > .page-head');
        if (!head) {
          head = document.createElement('div');
          head.className = 'page-head';
          pane.prepend(head);
        }
        const icon = btn.querySelector('.nav-icon');
        const label = btn.querySelector('.nav-label');
        const counter = btn.querySelector('.nav-counter');
        const name = label ? label.textContent : '';
        const subs = PAGE_SUBS[tab];
        const part = subs ? t('sub_' + tab + '_' + currentSub(tab)) : '';
        head.innerHTML =
          '<div class="page-crumb">' + esc(name) + (part ? ' <span aria-hidden="true">/</span> ' + esc(part) : '') + '</div>' +
          '<h1>' + (icon ? icon.outerHTML : '') + '<span>' + esc(name) + '</span>' +
          (counter && !counter.hidden ? '<span class="nav-counter" data-tip="' + esc(counter.getAttribute('data-tip') || '') + '">' + esc(counter.textContent) + '</span>' : '') + '</h1>' +
          '<p class="page-lead">' + esc(t('lead_' + tab)) + '</p>';
      });
      // Icon-only menu (collapsed or narrow screen): the name shows on hover.
      document.querySelectorAll('.console-sidenav .nav-item').forEach(function (btn) {
        const label = btn.querySelector('.nav-label');
        const counter = btn.querySelector('.nav-counter');
        btn.removeAttribute('title');
        btn.setAttribute('data-tip', (label ? label.textContent : '') + (counter && !counter.hidden && counter.getAttribute('data-tip') ? ' · ' + counter.getAttribute('data-tip') : ''));
      });
    }

    // Menu sections (Apps, Servers, ...) open and close; the choice is remembered.
    let closedSections = {};
    try { closedSections = JSON.parse(localStorage.getItem('paasmcp_nav_closed') || '{}') || {}; } catch { closedSections = {}; }
    function applyNavSections() {
      document.querySelectorAll('.console-sidenav button.nav-section').forEach(function (btn) {
        const name = btn.getAttribute('data-section');
        const closed = Boolean(closedSections[name]);
        btn.setAttribute('aria-expanded', closed ? 'false' : 'true');
        const group = document.getElementById('navGroup-' + name);
        if (group) group.classList.toggle('closed', closed);
      });
    }
    function toggleNavSection(name) {
      closedSections[name] = !closedSections[name];
      try { localStorage.setItem('paasmcp_nav_closed', JSON.stringify(closedSections)); } catch {}
      applyNavSections();
    }
    function openSectionOf(tab) {
      const btn = navBtnFor(tab);
      const group = btn ? btn.closest('.nav-group') : null;
      if (!group) return;
      const name = group.id.replace(/^navGroup-/, '');
      if (closedSections[name]) { closedSections[name] = false; try { localStorage.setItem('paasmcp_nav_closed', JSON.stringify(closedSections)); } catch {} applyNavSections(); }
    }

    function goTo(tab, sub, mode) {
      if (!document.getElementById('tab-' + tab)) tab = 'overview';
      const subs = PAGE_SUBS[tab];
      const prevSub = currentSub(tab);
      if (subs && sub && subs.indexOf(sub) !== -1) {
        activeSubs[tab] = sub;
        try { localStorage.setItem('paasmcp_active_subs', JSON.stringify(activeSubs)); } catch {}
      }
      const moved = tab !== currentTab || currentSub(tab) !== prevSub || (tab === 'guide' && sub !== currentGuide);
      if (tab !== currentTab) switchTab(tab, navBtnFor(tab));
      if (mode !== 'init') openSectionOf(tab);
      currentTab = tab;
      renderSubNav();
      if (tab === 'guide') { if (sub) currentGuide = sub; renderGuide(); }
      if (tab === 'overview' && currentSub('overview') === 'webhook' && (moved || mode === 'init')) loadHooks();
      const hash = '#' + tab + (subs ? '/' + currentSub(tab) : tab === 'guide' && currentGuide ? '/' + currentGuide : '');
      if (mode !== 'hash' && location.hash !== hash) {
        try {
          if (mode === 'init') history.replaceState(null, '', hash);
          else history.pushState(null, '', hash);
        } catch {}
      }
      toggleNavDrawer(false);
      if (moved && mode !== 'init' && mode !== 'keep-scroll') window.scrollTo(0, 0);
    }

    function routeFromHash() {
      const m = (location.hash || '').match(/^#([a-z]+)(?:\\/([a-z]+))?$/);
      return m ? { tab: m[1], sub: m[2] || '' } : null;
    }
    window.addEventListener('popstate', function () { const r = routeFromHash(); if (r) goTo(r.tab, r.sub, 'hash'); });
    window.addEventListener('hashchange', function () { const r = routeFromHash(); if (r) goTo(r.tab, r.sub, 'hash'); });
    document.addEventListener('click', function (e) {
      const b = e.target.closest ? e.target.closest('[data-go-tab]') : null;
      if (b) goTo(b.getAttribute('data-go-tab'), b.getAttribute('data-go-sub') || '');
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') toggleNavDrawer(false); });

    // Shows the element's page and part, then scrolls to it.
    function revealEl(id) {
      const el = document.getElementById(id);
      if (!el) return null;
      const pane = el.closest('.tab-pane');
      const part = el.closest('[data-sub]');
      if (pane) goTo(pane.id.replace(/^tab-/, ''), part ? part.getAttribute('data-sub') : '', 'keep-scroll');
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return el;
    }

    function toggleNavCollapsed() {
      const box = document.getElementById('consoleContainer');
      const on = !box.classList.contains('nav-collapsed');
      box.classList.toggle('nav-collapsed', on);
      try { localStorage.setItem('paasmcp_nav_collapsed', on ? '1' : '0'); } catch {}
      applyNavCollapseLabel();
    }
    function applyNavCollapseLabel() {
      const box = document.getElementById('consoleContainer');
      const btn = document.getElementById('navCollapseBtn');
      if (!box || !btn) return;
      const label = box.classList.contains('nav-collapsed') ? t('navExpand') : t('navCollapse');
      btn.setAttribute('data-tip', label);
      btn.setAttribute('aria-label', label);
    }
    function toggleNavDrawer(open) {
      const box = document.getElementById('consoleContainer');
      if (!box) return;
      box.classList.toggle('nav-open', Boolean(open));
      const btn = document.getElementById('navToggleMobile');
      if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    try { if (localStorage.getItem('paasmcp_nav_collapsed') === '1') document.getElementById('consoleContainer').classList.add('nav-collapsed'); } catch {}

    // Small tooltip for anything with data-tip (menu counters, icon buttons, the icon-only menu).
    (function () {
      const tip = document.createElement('div');
      tip.className = 'ui-tip';
      tip.setAttribute('role', 'tooltip');
      document.body.appendChild(tip);
      let target = null;
      function show(el) {
        const text = el.getAttribute('data-tip');
        if (!text) return;
        // A menu item only needs its tooltip when its name is hidden (icon-only menu).
        if (el.classList.contains('nav-item')) { const lb = el.querySelector('.nav-label'); if (lb && lb.offsetWidth > 20) return; }
        target = el;
        tip.textContent = text;
        tip.classList.add('show');
        const r = el.getBoundingClientRect();
        const tw = tip.offsetWidth, th = tip.offsetHeight;
        let x = r.left + r.width / 2 - tw / 2;
        let y = r.bottom + 6;
        if (el.classList.contains('nav-item')) { x = r.right + 8; y = r.top + r.height / 2 - th / 2; }
        x = Math.max(8, Math.min(x, window.innerWidth - tw - 8));
        if (y + th > window.innerHeight - 8) y = r.top - th - 6;
        tip.style.left = x + 'px';
        tip.style.top = y + 'px';
      }
      function hide() { target = null; tip.classList.remove('show'); }
      document.addEventListener('mouseover', function (e) {
        const el = e.target.closest ? e.target.closest('[data-tip]') : null;
        if (el && el !== target) show(el); else if (!el && target) hide();
      });
      document.addEventListener('focusin', function (e) { const el = e.target.closest ? e.target.closest('[data-tip]') : null; if (el) show(el); });
      document.addEventListener('focusout', hide);
      window.addEventListener('scroll', hide, true);
    })();

    // Menu counters: hidden at zero; hovering says what is being counted.
    function setNavCounter(id, n, tipKey) {
      const el = document.getElementById(id);
      if (!el) return;
      const num = Number(n) || 0;
      el.textContent = num > 0 ? String(num) : '';
      el.hidden = num <= 0;
      const tip = t(tipKey + (num === 1 ? 'One' : '')).replace('{n}', String(num));
      el.removeAttribute('title');
      el.setAttribute('data-tip', tip);
      el.setAttribute('aria-label', tip);
    }

    function switchTab(tabName, btnEl) {
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(b => { b.classList.remove('active'); b.removeAttribute('aria-current'); });
      const pane = document.getElementById('tab-' + tabName);
      if (pane) pane.classList.add('active');
      if (btnEl) { btnEl.classList.add('active'); btnEl.setAttribute('aria-current', 'page'); }
      currentTab = tabName;
      try { localStorage.setItem('paasmcp_active_tab', tabName); } catch {}
      if (tabName === 'doctor') runDoctor();
      if (tabName === 'email') loadEmail();
      if (tabName === 'agents') { renderAi(); loadAiTokens(); }
      if (tabName === 'connect') loadConnections();
      if (tabName === 'home') loadTutorialExtra();
      if (tabName === 'mirror') loadMirror();
      if (tabName === 'updates' && !updatesLoaded) loadUpdates();
      if (tabName === 'databases') { loadStorage(); loadOffsite(); }
      if (tabName === 'overview') loadScale();
      if (tabName === 'pool') loadPool(true);
    }

    function filterApps(query) {
      const q = (query || '').toLowerCase().trim();
      document.querySelectorAll('#appsTable .app-entry-row').forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = (!q || text.includes(q)) ? '' : 'none';
      });
    }

    function toggleTheme() {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      localStorage.setItem('paasmcp_theme', currentTheme);
      applyPreferences();
    }

    function toggleLang() {
      currentLang = currentLang === 'pt' ? 'en' : 'pt';
      localStorage.setItem('paasmcp_lang', currentLang);
      applyPreferences();
      if (scaleData) loadScale();
    }

    function applyPreferences() {
      const isPt = currentLang === 'pt';
      document.documentElement.setAttribute('data-theme', currentTheme);
      const sunSvg = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4.5"></circle><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"></path></svg>';
      const moonSvg = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
      const themeBtn = document.getElementById('themeBtn');
      const themeTip = currentTheme === 'dark' ? (isPt ? 'Mudar para o tema claro' : 'Switch to light theme') : (isPt ? 'Mudar para o tema escuro' : 'Switch to dark theme');
      themeBtn.innerHTML = currentTheme === 'dark' ? sunSvg : moonSvg;
      themeBtn.setAttribute('data-tip', themeTip);
      themeBtn.setAttribute('aria-label', themeTip);
      document.getElementById('langBtn').innerHTML = isPt ? '🇧🇷 <span class="btn-text">PT-BR</span>' : '🇺🇸 <span class="btn-text">EN</span>';
      document.getElementById('langBtn').setAttribute('data-tip', isPt ? 'Idioma (Language)' : 'Language (Idioma)');
      const btnLogout = document.getElementById('btnLogout');
      if (btnLogout) btnLogout.textContent = isPt ? 'Sair' : 'Log out';
      const refreshBtn = document.getElementById('btnRefresh');
      if (refreshBtn) {
        refreshBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>';
        refreshBtn.setAttribute('data-tip', isPt ? 'Atualizar os dados' : 'Refresh data');
        refreshBtn.setAttribute('aria-label', isPt ? 'Atualizar os dados' : 'Refresh data');
      }
      document.getElementById('webhookUrlBox').textContent = window.location.origin + '/api/webhooks/github';
      const fedUrlEl = document.getElementById('fedUrl');
      if (fedUrlEl && !fedUrlEl.value) fedUrlEl.value = window.location.origin;

      document.querySelectorAll('[data-i18n]').forEach(el => { el.innerHTML = t(el.getAttribute('data-i18n')); });
      renderHome();
      renderExposeHint();
      renderRepoPick();
      renderTemplates();
      const search = document.getElementById('appSearchInput');
      if (search) search.placeholder = t('appSearch');
      renderAi();
      for (const k of I18N_KEYS) {
        const el = document.getElementById(k);
        if (el) {
          const val = t(k);
          const labelSpan = el.querySelector('.nav-label');
          if (labelSpan) {
            labelSpan.textContent = val;
          } else {
            const counter = el.querySelector('.nav-counter');
            if (counter) {
              el.innerHTML = '<span>' + esc(val) + '</span> ' + counter.outerHTML;
            } else if (val.indexOf('<') !== -1 && val.indexOf('>') !== -1) {
              el.innerHTML = val;
            } else {
              el.textContent = val;
            }
          }
        }
      }

      // Side menu: page names, nested parts, collapse button and counter tips follow the language.
      applyNavCollapseLabel();
      applyNavSections();
      setNavCounter('tabCountAgents', (lastStatus && lastStatus.mcpToolCount) || 0, 'cntAgents');
      if (!navInitDone) {
        navInitDone = true;
        let savedTab = 'overview';
        try { savedTab = localStorage.getItem('paasmcp_active_tab') || 'overview'; } catch {}
        const r = routeFromHash();
        goTo(r ? r.tab : savedTab, r ? r.sub : '', 'init');
      } else {
        renderSubNav();
      }


      const placeholders = {
        pt: {
          depApp: "ex: meu-saas",
          depRepo: "ex: seu-usuario/meu-repo",
          depMem: "ex: 512m ou 1g",
          depCpu: "ex: 0.5 ou 1.0",
          expApp: "ex: meu-saas",
          expSub: "ex: app",
          secKey: "ex: STRIPE_SECRET_KEY",
          dbApp: "ex: meu-saas",
          bakApp: "ex: meu-saas",
          fedUrl: "https://paas.seudominio.com"
        },
        en: {
          depApp: "e.g.: my-saas",
          depRepo: "e.g.: your-user/my-repo",
          depMem: "e.g.: 512m or 1g",
          depCpu: "e.g.: 0.5 or 1.0",
          expApp: "e.g.: my-saas",
          expSub: "e.g.: app",
          secKey: "e.g.: STRIPE_SECRET_KEY",
          dbApp: "e.g.: my-saas",
          bakApp: "e.g.: my-saas",
          fedUrl: "https://paas.yourdomain.com"
        }
      };
      const phMap = placeholders[currentLang] || placeholders.pt;
      for (const [id, val] of Object.entries(phMap)) {
        const inputEl = document.getElementById(id);
        if (inputEl) inputEl.placeholder = val;
      }

      renderDeployPresetHint();
      if (lastStatus) renderStatusData(lastStatus);
      loadSecrets();
    }

    // Deploy presets only fill the form; the build still detects the stack from the repository.
    const DEPLOY_PRESETS = {
      saas: ['meu-saas', 'seu-usuario/meu-saas', true, false, '512m', '1.0'],
      django: ['meu-django', 'seu-usuario/meu-django', true, false, '512m', '1.0'],
      fastapi: ['minha-api', 'seu-usuario/minha-api', true, false, '256m', '0.5'],
      node: ['api-node', 'seu-usuario/api-node', false, false, '256m', '0.5'],
      go: ['api-go', 'seu-usuario/api-go', false, false, '128m', '0.5'],
      dotnet: ['api-dotnet', 'seu-usuario/api-dotnet', true, false, '512m', '1.0'],
      compose: ['api-worker', 'seu-usuario/api-compose', true, true, '1g', '2.0'],
      spa: ['landing', 'seu-usuario/landing', false, false, '256m', '0.5'],
      dockerfile: ['meu-app', 'seu-usuario/meu-app', true, false, '512m', '1.0'],
    };
    let selectedDeployPreset = '';

    function renderDeployPresetHint() {
      const hint = document.getElementById('deployPresetHint');
      if (!hint) return;
      hint.innerHTML = selectedDeployPreset ? t('presetHint_' + selectedDeployPreset) : '';
      hint.classList.toggle('show', Boolean(selectedDeployPreset));
    }

    function fillDeployPreset(key, btn) {
      const p = DEPLOY_PRESETS[key];
      if (!p) return;
      fillDeployExample(p[0], p[1], 'main', p[2], p[3], p[4], p[5]);
      selectedDeployPreset = key;
      if (btn && btn.parentElement) btn.parentElement.querySelectorAll('button.chip').forEach(b => b.classList.toggle('selected', b === btn));
      renderDeployPresetHint();
    }

    function fillDeployExample(app, repo, branch, pg, redis, mem, cpu) {
      document.getElementById('depApp').value = app;
      document.getElementById('depRepo').value = repo;
      document.getElementById('depBranch').value = branch;
      document.getElementById('depPg').checked = Boolean(pg);
      document.getElementById('depRedis').checked = Boolean(redis);
      document.getElementById('depMem').value = mem || '';
      document.getElementById('depCpu').value = cpu || '';
    }

    function fillExposeMode(mode) {
      document.getElementById('expMode').value = mode;
      renderExposeHint();
    }

    function setVaultScope(scope) {
      fillScopeSelect(Object.values((lastStatus && lastStatus.apps) || {}));
      document.getElementById('secScope').value = scope;
      loadSecrets();
      goTo('vault');
    }

    function selectAppForExpose(appName) {
      document.getElementById('expApp').value = appName;
      document.getElementById('expSub').value = appName.replace(/^paasmcp-/, '');
      renderExposeHint();
      revealEl('expApp');
    }

    // Deploy progress: /api/deploys is read every few seconds (faster while a deploy runs).
    let deployState = null;
    let deployStateJson = '';
    let deployPollTimer = null;
    function relTime(iso) {
      const ts = Date.parse(iso || '');
      if (!ts) return '';
      const sec = Math.max(0, (Date.now() - ts) / 1000);
      if (sec < 60) return t('relNow');
      if (sec < 3600) return t('relMin').replace('{n}', Math.floor(sec / 60));
      if (sec < 172800) return t('relHour').replace('{n}', Math.floor(sec / 3600));
      return t('relDay').replace('{n}', Math.floor(sec / 86400));
    }
    function relSpan(iso) {
      return iso ? \`<span class="rel-time" data-ts="\${esc(iso)}" title="\${esc(iso.replace('T', ' ').slice(0, 19))}">\${esc(relTime(iso))}</span>\` : '';
    }
    function refreshRelTimes() {
      document.querySelectorAll('.rel-time').forEach(el => { el.textContent = relTime(el.dataset.ts); });
    }
    function commitHtml(c, url) {
      if (!c || !c.short) return '';
      const code = \`<code>\${esc(c.short)}</code>\`;
      const link = url ? \`<a href="\${esc(url)}" target="_blank" rel="noopener noreferrer">\${code}</a>\` : code;
      const msg = c.message ? \` <span class="dep-msg" title="\${esc(c.message)}\${c.author ? ' · ' + esc(c.author) : ''}">\${esc(c.message)}</span>\` : '';
      const when = c.date ? \` · \${esc(t('depCommitted'))} \${relSpan(c.date)}\` : '';
      return link + msg + when;
    }
    function deployStatusHtml(d, hasApp) {
      if (!d) return '';
      if (d.active) {
        const r = d.active;
        const target = r.commit ? \`<div class="dep-line">→ \${commitHtml(r.commit, r.commitUrl)}</div>\` : '';
        return \`<div class="dep-line active">\${esc(t('depPhase_' + r.phase))}</div>\${target}
          <div class="dep-line">\${esc(t('depStarted'))} \${relSpan(r.startedAt)} · \${esc(t('depTrig_' + r.trigger))}\${hasApp ? '' : ' · ' + esc(t('depFirstDeploy'))}</div>\`;
      }
      const r = d.last;
      if (!r) return '';
      if (r.phase === 'failed') {
        const details = (r.error || '') + (r.log ? '\\n\\n' + r.log : '');
        const target = r.commit ? \`<div class="dep-line">→ \${commitHtml(r.commit, r.commitUrl)}</div>\` : '';
        return \`<div class="dep-line failed">\${esc(t('depPhase_failed'))} \${relSpan(r.finishedAt)}</div>\${target}
          \${hasApp ? \`<div class="dep-line">\${esc(t('depOldStillLive'))}</div>\` : ''}
          \${details ? \`<details class="dep-err"><summary>\${esc(t('depShowError'))}</summary><pre>\${esc(details)}</pre></details>\` : ''}\`;
      }
      return \`<div class="dep-line">\${esc(t('depPhase_live'))} · \${esc(t('depDeployed'))} \${relSpan(r.finishedAt)}</div>\`;
    }
    async function pollDeploys() {
      clearTimeout(deployPollTimer);
      let next = 10000;
      try {
        if (document.visibilityState === 'visible') {
          const res = await rawFetch('/api/deploys');
          if (res.ok) {
            const data = await res.json();
            const before = deployState || (lastStatus && lastStatus.deploys) || {};
            const now = data.deploys || {};
            const json = JSON.stringify(now);
            if (json !== deployStateJson) {
              deployStateJson = json;
              deployState = now;
              const finished = Object.keys(before).some(k => before[k].active && !(now[k] && now[k].active));
              if (finished) loadAll();
              else if (lastStatus) renderStatusData(lastStatus);
            }
            if (Object.values(now).some(d => d.active)) next = 2500;
          } else if (res.status === 401) {
            next = 30000;
          }
        }
      } catch {
        // offline for a moment: try again later
      }
      deployPollTimer = setTimeout(pollDeploys, next);
    }
    setInterval(refreshRelTimes, 20000);

    // Line icons for buttons, same stroke style as the side menu (no emoji mixed in).
    const BTN_ICONS = {
      globe: '<circle cx="12" cy="12" r="10"></circle><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>',
      lock: '<rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>',
      logs: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><path d="M14 2v6h6M8 13h8M8 17h5"></path>',
      restart: '<path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>',
      back: '<path d="M1 4v6h6"></path><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>',
      sync: '<path d="M17 1l4 4-4 4"></path><path d="M3 11V9a4 4 0 0 1 4-4h14"></path><path d="M7 23l-4-4 4-4"></path><path d="M21 13v2a4 4 0 0 1-4 4H3"></path>',
    };
    function btnIcon(name) {
      return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (BTN_ICONS[name] || '') + '</svg>';
    }

    // Who this server is paired with. The invite side of 'node invite/join' never hears back from the
    // joiner, so its own pairing list stays empty: the live copy (offers sent, copies received) is what
    // actually names the other server there. Both sources are merged, by name.
    // The same server can carry two names (the pairing keeps the generic "primary-node", the copy its
    // hostname): entries with the same node id are one server, shown by its more specific name.
    function pairedServers(s) {
      const byKey = {};
      const add = function (key, name, how) {
        if (!name) return;
        const e = byKey[key] = byKey[key] || { name: name };
        if (e.name === 'primary-node' && name !== 'primary-node') e.name = name;
        e[how] = true;
      };
      Object.values(s.federation?.peers || {}).forEach(function (p) { add(p.nodeId ? 'id:' + p.nodeId : 'name:' + p.name, p.name, 'paired'); });
      const m = s.mirror || {};
      Object.values(m.replicas || {}).forEach(function (r) { add(r.peerNodeId ? 'id:' + r.peerNodeId : 'name:' + r.peerName, r.peerName, 'receiving'); });
      Object.entries(m.offers || {}).forEach(function ([k, o]) {
        const name = o.peer || k;
        const same = Object.keys(byKey).find(function (key) { return byKey[key].name === name; });
        add(same || 'name:' + name, name, 'sending');
      });
      const out = {};
      Object.values(byKey).forEach(function (e) { out[e.name] = Object.assign(out[e.name] || {}, e); });
      return out;
    }
    // Live state of the copy (GET /api/mirror asks Postgres), refreshed at most every 30 s.
    let mirrorLive = null;
    let mirrorLiveAt = 0;
    let mirrorLiveBusy = false;
    function refreshMirrorLive(s) {
      const m = s.mirror || {};
      if (!Object.keys(m.offers || {}).length && !Object.keys(m.replicas || {}).length) { mirrorLive = null; return; }
      if (mirrorLiveBusy || Date.now() - mirrorLiveAt < 30000) return;
      mirrorLiveBusy = true;
      mirrorLiveAt = Date.now();
      fetch('/api/mirror').then(function (r) { return r.ok ? r.json() : null; }).then(function (live) {
        mirrorLiveBusy = false;
        if (!live) return;
        mirrorLive = live;
        mirrorLiveAt = Date.now();
        if (lastStatus) renderStatusData(lastStatus);
        renderHome();
      }).catch(function () { mirrorLiveBusy = false; });
    }
    // The second server in one line: 'none' | 'paired' (no copy) | 'on' | 'stopped' | 'fenced'.
    function mirrorSummary(s) {
      const m = s.mirror || {};
      const peers = pairedServers(s);
      const names = Object.keys(peers);
      const copyNames = names.filter(function (n) { return peers[n].sending || peers[n].receiving; });
      if (m.fenced) return { state: 'fenced', names: names, copyNames: copyNames, down: [] };
      if (!copyNames.length) return { state: names.length ? 'paired' : 'none', names: names, copyNames: copyNames, down: [] };
      const down = [];
      if (mirrorLive) {
        (mirrorLive.sending || []).forEach(function (o) { if (o.error || !o.connected) down.push(o.peer); });
        (mirrorLive.receiving || []).forEach(function (r) { if (r.error || r.supersededBy || !(r.streaming || r.promotedAt)) down.push(r.peer); });
      }
      return { state: down.length ? 'stopped' : 'on', names: names, copyNames: copyNames, down: down.filter(function (n, i) { return down.indexOf(n) === i; }) };
    }

    // Resource usage card: whole server, split into PaaSMCP's containers and everything else.
    // Live numbers come from /api/resources every 15 s while the page is visible.
    let liveResources = null;
    function fmtResBytes(b) {
      if (b === null || b === undefined) return '-';
      if (b >= 1e12) return fmtNum(b / 1e12, 1) + ' TB';
      if (b >= 1e9) return fmtNum(b / 1e9, 1) + ' GB';
      return fmtNum(b / 1e6, 0) + ' MB';
    }
    function pctNum(n) { return fmtNum(n, n < 10 ? 1 : 0) + '%'; }
    function toneOf(pct) { return pct > 85 ? 'var(--danger)' : pct > 70 ? 'var(--warning)' : 'var(--text)'; }
    function stackedBar(paasPct, otherPct) {
      const p = Math.max(0, Math.min(100, paasPct));
      const o = Math.max(0, Math.min(100 - p, otherPct));
      return '<div class="progress-track stacked"><div class="seg paas" style="width:' + p.toFixed(1) + '%;"></div>' +
        '<div class="seg other" style="width:' + o.toFixed(1) + '%;"></div></div>';
    }
    function resourcesCardHtml(s) {
      const r = (liveResources && liveResources.resources) || s.resources;
      const backupsCount = s.backupsCount || 0;
      const head = '<div class="telemetry-card" id="resourcesCard"><div class="telemetry-title"><span>' + esc(t('resTitle')) + '</span>' +
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg></div>';
      const snapshots = '<div class="telemetry-item"><span>' + esc(t('resSnapshots')) + '</span><span class="telemetry-val">' +
        esc(t(backupsCount === 1 ? 'resSnapshotsOne' : 'resSnapshotsN').replace('{n}', String(backupsCount))) + '</span></div>';
      if (!r) return head + '<div class="res-hint">' + esc(t('resMeasuring')) + '</div>' + snapshots + '</div>';
      const top = (r.top || []).filter(function (c) { return c.memBytes; })
        .map(function (c) { return c.name.replace(/^paasmcp-/, '') + ': ' + fmtResBytes(c.memBytes); }).join(' · ');
      const legend = function (paas, other, extra) {
        return '<div class="res-legend">' +
          '<span' + (top ? ' title="' + esc(t('resTopTip') + ' ' + top) + '"' : '') + '><span class="res-dot paas"></span>' + esc(t('resPaas')) + ' ' + esc(paas) + '</span>' +
          '<span><span class="res-dot other"></span>' + esc(t('resOthers')) + ' ' + esc(other) + '</span>' +
          (extra ? '<span>' + esc(extra) + '</span>' : '') + '</div>';
      };
      let html = head;

      // Processor
      const cpu = r.cpu || {};
      const cpuPct = cpu.usedPercent;
      html += '<div class="telemetry-item" style="border-bottom:none;padding-bottom:2px;"><span>' + esc(t('resCpu')) + '</span>' +
        '<span class="telemetry-val" style="color:' + (cpuPct === null || cpuPct === undefined ? 'var(--muted)' : toneOf(cpuPct)) + ';">' +
        esc(cpuPct === null || cpuPct === undefined ? t('resMeasuringShort') : pctNum(cpuPct)) + '</span></div>';
      const coresTxt = t(cpu.cores === 1 ? 'resCoreOne' : 'resCores').replace('{n}', String(cpu.cores || '-'));
      if (cpu.split) {
        html += stackedBar(cpu.split.paasmcp, cpu.split.others) + legend(pctNum(cpu.split.paasmcp), pctNum(cpu.split.others), coresTxt);
      } else {
        html += stackedBar(0, cpuPct || 0) + '<div class="res-legend"><span>' + esc(coresTxt) + '</span></div>';
      }

      // Memory
      const mem = r.memory || {};
      const memPct = mem.totalBytes ? (mem.usedBytes / mem.totalBytes) * 100 : 0;
      html += '<div class="telemetry-item" style="border-bottom:none;padding-bottom:2px;"><span>' + esc(t('resMem')) + ' (' + esc(fmtResBytes(mem.usedBytes)) + ' / ' + esc(fmtResBytes(mem.totalBytes)) + ')</span>' +
        '<span class="telemetry-val" style="color:' + toneOf(memPct) + ';">' + esc(pctNum(memPct)) + '</span></div>';
      const freeTxt = t('resFree').replace('{v}', fmtResBytes(mem.availableBytes));
      if (mem.split && mem.totalBytes) {
        html += stackedBar((mem.split.paasmcp / mem.totalBytes) * 100, (mem.split.others / mem.totalBytes) * 100) +
          legend(fmtResBytes(mem.split.paasmcp), fmtResBytes(mem.split.others), freeTxt);
      } else {
        html += stackedBar(0, memPct) + '<div class="res-legend"><span>' + esc(freeTxt) + '</span></div>';
      }

      // Disk (the one holding the apps' data)
      const d = r.disk;
      if (d) {
        html += '<div class="telemetry-item" style="border-bottom:none;padding-bottom:2px;"><span>' + esc(t('resDisk')) + ' (' + esc(fmtResBytes(d.usedBytes)) + ' / ' + esc(fmtResBytes(d.totalBytes)) + ')</span>' +
          '<span class="telemetry-val" style="color:' + toneOf(d.usedPercent) + ';">' + esc(d.usedPercent + '%') + '</span></div>' +
          '<div class="progress-track"><div class="progress-fill ' + (d.usedPercent > 85 ? 'danger' : d.usedPercent > 70 ? 'warning' : '') + '" style="width:' + d.usedPercent + '%;"></div></div>' +
          '<div class="res-legend"><span>' + esc(t('resFree').replace('{v}', fmtResBytes(d.freeBytes))) + '</span></div>';
      }
      if (cpu.split || mem.split) html += '<div class="res-hint">' + esc(t('resHint')) + '</div>';
      return html + snapshots + '</div>';
    }
    let resourcesTimer = null;
    async function pollResources() {
      clearTimeout(resourcesTimer);
      try {
        if (document.visibilityState === 'visible' && lastStatus) {
          const res = await rawFetch('/api/resources');
          if (res.ok) {
            liveResources = await res.json();
            const card = document.getElementById('resourcesCard');
            if (card) card.outerHTML = resourcesCardHtml(lastStatus);
          }
        }
      } catch {
        // offline for a moment: try again later
      }
      resourcesTimer = setTimeout(pollResources, 15000);
    }

    // "Quick health" box in the telemetry column: one line per thing that needs care, each opens its page.
    function healthCardHtml(s) {
      const backups = (s.backups || []).slice().sort(function (a, b) { return String(b.createdAt).localeCompare(String(a.createdAt)); });
      const last = backups[0];
      const offsiteOn = Boolean((s.systemSecretsConfigured || {}).BACKUP_S3_ENDPOINT);
      const ms = mirrorSummary(s);
      const row = function (label, value, tone, tab, sub) {
        const color = tone === 'ok' ? 'var(--success)' : tone === 'warn' ? 'var(--warning)' : 'var(--text)';
        return '<button class="telemetry-item health-row" data-go-tab="' + tab + '" data-go-sub="' + sub + '">' +
          '<span>' + esc(label) + '</span><span class="telemetry-val" style="color:' + color + ';">' + esc(value) + '</span></button>';
      };
      const lastAge = last ? relTime(last.createdAt) : '';
      return '<div class="telemetry-card">' +
        '<div class="telemetry-title"><span>' + esc(t('healthTitle')) + '</span></div>' +
        row(t('healthBackup'), last ? (lastAge || new Date(last.createdAt).toLocaleString()) : t('never'), last ? 'ok' : 'warn', 'databases', 'backups') +
        row(t('healthOffsite'), offsiteOn ? t('healthOn') : t('notConfigured'), offsiteOn ? 'ok' : 'warn', 'databases', 'offsite') +
        row(t('healthMirror'),
          ms.state === 'fenced' ? t('mirrorFenced') : ms.state === 'on' ? t('healthOn') : ms.state === 'stopped' ? t('tileMirrorStopped') : t('healthOff'),
          ms.state === 'on' ? 'ok' : (ms.state === 'fenced' || ms.state === 'stopped') ? 'warn' : '', 'mirror', ms.copyNames.length ? 'copy' : 'connect') +
        row(t('healthEmail'), emailRelay ? t('healthOn') : t('notConfigured'), emailRelay ? 'ok' : '', 'email', '') +
        '</div>';
    }

    function renderStatusData(s) {
      const isPt = currentLang === 'pt';
      const domain = getBaseDomain();
      document.getElementById('topDomainBadge').innerHTML = \`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg> <span>\${isPt ? 'Domínio' : 'Domain'}: <strong>\${esc(domain)}</strong></span>\`;
      const pairedNames = Object.keys(pairedServers(s));
      refreshMirrorLive(s);
      document.getElementById('nodeRoleFooter').textContent = pairedNames.length ? t('footerPaired').replace('{who}', pairedNames.join(', ')) : t('footerUnpaired');

      const elHostname = document.getElementById('topHostname');
      if (elHostname) elHostname.textContent = s.hostname || '-';

      const elHealth = document.getElementById('topHealthBadge');
      if (elHealth) elHealth.textContent = isPt ? 'Sistema Online' : 'System Online';

      // Counters in the side menu
      setNavCounter('tabCountApps', Object.keys(s.apps || {}).length, 'cntApps');
      setNavCounter('tabCountDbs', Object.keys(s.databases || {}).length, 'cntDbs');
      // systemSecretsConfigured is an object (key -> masked value), not a list.
      setNavCounter('tabCountVault', Object.keys(s.systemSecretsConfigured || {}).length, 'cntVault');
      setNavCounter('tabCountMirror', pairedNames.length, 'cntMirror');
      setNavCounter('tabCountPool', Object.keys(s.pool || {}).length, 'cntPool');
      setNavCounter('tabCountAgents', s.mcpToolCount || 0, 'cntAgents');
      renderSubNav();

      const tailscaleVal = s.tailscaleDomain || (s.federation?.peers ? (isPt ? 'Rede Ativa' : 'Tailnet Active') : '127.0.0.1');
      const dockerVal = isPt ? 'Ativo' : 'Running';

      document.getElementById('statsGrid').innerHTML = \`
        <div class="telemetry-card">
          <div class="telemetry-title">
            <span>\${isPt ? 'Telemetria do Host' : 'Host Telemetry'}</span>
            <span class="status-dot"></span>
          </div>
          <div class="telemetry-item">
            <span>Host</span>
            <span class="telemetry-val">\${esc(s.hostname)}</span>
          </div>
          <div class="telemetry-item">
            <span>Tailscale</span>
            <span class="telemetry-val">\${esc(tailscaleVal)}</span>
          </div>
          <div class="telemetry-item">
            <span>\${isPt ? 'Motor Docker' : 'Docker Engine'}</span>
            <span class="telemetry-val" style="color:var(--success);font-weight:600;">\${dockerVal}</span>
          </div>
          <div class="telemetry-item">
            <span>\${isPt ? 'Plataforma' : 'Platform'}</span>
            <span class="telemetry-val" style="font-size:11px;" title="\${esc(s.platform)}">\${esc((s.platform || '').split(' ')[0])}</span>
          </div>
          <div class="telemetry-item">
            <span>\${isPt ? 'Impressão SSH' : 'SSH Fingerprint'}</span>
            <span class="telemetry-val" style="font-size:11px;">\${esc((s.sshKeyFingerprint || '').slice(0, 16))}...</span>
          </div>
          <div class="telemetry-item">
            <span>\${esc(t('pairedWith'))}</span>
            <span class="telemetry-val">\${esc(pairedNames.length ? pairedNames.join(', ') : t('pairedNobody'))}</span>
          </div>
        </div>

        \${resourcesCardHtml(s)}
        \${healthCardHtml(s)}
      \`;

      document.getElementById('sshKeyBox').textContent = s.sshPublicKey || '';
      document.getElementById('webhookSecretBox').textContent = s.webhookSecretMasked || '••••••••';

      const apps = Object.values(s.apps || {});
      const metricsMap = s.containerMetrics || {};
      document.getElementById('appsBadgeCount').textContent = t(apps.length === 1 ? 'appsCountOne' : 'appsCount').split('{n}').join(String(apps.length));

      document.getElementById('hostedAppsList').innerHTML = apps.map(a => \`<option value="\${esc(a.name)}"></option>\`).join('');
      fillScopeSelect(apps);
      renderAddresses();

      const deploys = deployState || s.deploys || {};
      const tbody = document.getElementById('appsTable');
      // First deploy of a new app: it has no record yet, only its progress.
      const pendingRows = Object.entries(deploys)
        .filter(([name, d]) => d.active && !(s.apps || {})[name])
        .map(([name, d]) => \`
            <div class="app-entry-row">
              <div class="app-row-top">
                <div class="app-row-main-identity">
                  <span class="status-dot deploying"></span>
                  <span class="app-row-name-link">\${esc(name)}</span>
                  <span class="app-badge-pill status-deploying">● \${esc(t('depPhase_' + d.active.phase) || 'Deploying...')}</span>
                </div>
                <div style="color:var(--muted);font-size:12px;">\${d.source ? \`🐙 <a href="\${esc(d.source.url)}" target="_blank" rel="noopener noreferrer">\${esc(d.source.name)}</a>\` : ''}</div>
              </div>
              <div style="font-size:12px;">\${deployStatusHtml(d, false)}</div>
            </div>\`).join('');

      if (apps.length === 0 && !pendingRows) {
        tbody.innerHTML = \`<div style="padding:28px;text-align:center;color:var(--muted);font-size:13px;">\${esc(t('emptyApps'))}</div>\`;
      } else {
        tbody.innerHTML = pendingRows + apps.map(a => {
          const d = deploys[a.name];
          const dotClass = a.status === 'stopped' ? 'stopped' : d && d.active ? 'deploying' : d && !d.active && d.last && d.last.phase === 'failed' ? 'failed' : '';
          const statusText = a.status === 'stopped' ? t('stoppedStatus') : (d && d.active ? t('depPhase_' + d.active.phase) : (d && d.last && d.last.phase === 'failed' ? t('depPhase_failed') : t('depPhase_live')));
          const statusBadgeClass = a.status === 'stopped' ? 'status-stopped' : (d && d.active ? 'status-deploying' : (d && d.last && d.last.phase === 'failed' ? 'status-stopped' : 'status-live'));

          // Main domain / access link
          const mainDomain = (a.domains || [])[0];
          // Without an address, 127.0.0.1 only opens on the server itself: elsewhere the name leads to "Endereço".
          const onServer = /^(127\\.|localhost$|\\[::1\\]$)/.test(location.hostname);
          const appLink = mainDomain ? mainDomain.url : (onServer ? \`http://127.0.0.1:\${a.localPort}\` : '');

          // Language dot color
          let langColor = '#8b949e';
          const rt = (a.runtimeType || '').toLowerCase();
          if (rt.includes('python') || rt.includes('django') || rt.includes('fastapi')) langColor = '#3572A5';
          else if (rt.includes('node') || rt.includes('next') || rt.includes('ts') || rt.includes('express')) langColor = '#3178c6';
          else if (rt.includes('go')) langColor = '#00ADD8';
          else if (rt.includes('dotnet') || rt.includes('c#')) langColor = '#512BD4';
          else if (rt.includes('docker') || rt.includes('compose')) langColor = '#384d54';
          else if (rt.includes('control-plane')) langColor = '#2f81f7';
          else if (rt.includes('spa') || rt.includes('static')) langColor = '#e34c26';

          const src = d && d.source;
          const sourceHtml = src
            ? \`<span>🐙 <a href="\${esc(src.url)}" target="_blank" rel="noopener noreferrer">\${esc(src.name)}</a> · <a href="\${esc(src.branchUrl)}" target="_blank" rel="noopener noreferrer">\${esc(a.branch)}</a></span>\`
            : '';
          const running = d && d.running;
          const commitLine = running
            ? \`<span>\${commitHtml(running, running.commitUrl)}</span>\`
            : (a.lastCommit ? \`<span>commit: <code>\${esc(a.lastCommit)}</code></span>\` : '');
          const m = metricsMap[a.containerName];
          const metricHtml = m
            ? \`<span><strong>CPU:</strong> \${esc(m.cpuPercent)}</span> · <span><strong>RAM:</strong> \${esc(m.memUsage)}</span>\`
            : \`<span style="color:var(--muted);">\${esc(a.status === 'stopped' ? t('stoppedStatus') : t('onDemandStatus'))}</span>\`;
          const limitsHtml = (a.memoryLimit || a.cpuLimit)
            ? \`<span>\${esc(t('limitsLabel').split('{mem}').join(a.memoryLimit || '-').split('{cpu}').join(a.cpuLimit || '-'))}</span>\`
            : '';
          const cp = s.controlPlane || {};
          const followBtn = a.runtimeType === 'paasmcp-control-plane'
            ? \`<button class="secondary" style="\${cp.enabled ? 'border-color:var(--success, #16a34a);' : ''}" onclick="toggleFollow(\${cp.enabled ? 'false' : 'true'})" title="\${esc(cp.enabled ? t('followOnTitle').replace('{branch}', cp.branch || 'main') : t('followOffTitle'))}">\${btnIcon('sync')}\${esc(cp.enabled ? t('followOn') : t('followOff'))}</button>\`
            : '';
          const followErr = a.runtimeType === 'paasmcp-control-plane' && cp.enabled && cp.lastError
            ? \`<div style="font-size:11px;color:var(--danger, #dc2626);margin-top:2px;">\${esc(t('followFailed').replace('{step}', cp.lastError.step).replace('{commit}', String(cp.lastError.commit).slice(0, 7)))}</div>\`
            : '';
          const rollbackBtn = a.previousImageTag
            ? \`<button class="secondary" onclick="appAction('\${esc(a.name)}','rollback')" title="\${esc(t('actionRollbackTip'))}">\${btnIcon('back')}\${esc(t('actionRollback'))}</button>\`
            : '';

          const domainPills = (a.domains || []).map(dom => \`
            <span class="app-badge-pill">
              <a href="\${esc(dom.url)}" target="_blank" rel="noopener noreferrer">\${btnIcon('globe')} \${esc(dom.url)}</a>
              <span class="badge" style="padding:1px 5px;font-size:9.5px;">\${esc(I18N.en['mode_' + dom.mode] ? t('mode_' + dom.mode) : dom.mode)}</span>
            </span>
          \`).join('') || \`<span class="app-badge-pill" title="127.0.0.1:\${esc(a.localPort)}">🔒 \${esc(t('pillLocalOnly'))}</span>\`;

          const dbPills = (a.databases || []).map(db => \`
            <span class="app-badge-pill" style="font-size:11px;">🗄️ \${esc(db)}</span>
          \`).join('');

          return \`
            <div class="app-entry-row">
              <div class="app-row-top">
                <div class="app-row-main-identity">
                  <a \${appLink ? \`href="\${esc(appLink)}" target="_blank" rel="noopener noreferrer"\` : \`href="#" onclick="selectAppForExpose('\${esc(a.name)}'); return false;" title="\${esc(t('appNoAddressTip'))}"\`} class="app-row-name-link">
                    <span class="status-dot \${dotClass}"></span>
                    <span>\${esc(a.name)}</span>
                  </a>
                  <span class="app-badge-pill \${statusBadgeClass}">● \${esc(statusText)}</span>
                  \${domainPills}
                  \${dbPills}
                </div>
                <div class="app-actions-group">
                  <button class="secondary" onclick="selectAppForExpose('\${esc(a.name)}')">\${btnIcon('globe')}\${esc(t('actionExpose'))}</button>
                  <button class="secondary" onclick="setVaultScope('\${esc(a.name)}')">\${btnIcon('lock')}\${esc(t('actionEnv'))}</button>
                  <button class="secondary" onclick="appAction('\${esc(a.name)}','logs')">\${btnIcon('logs')}\${esc(t('actionLogs'))}</button>
                  <button class="secondary" onclick="appAction('\${esc(a.name)}','restart')">\${btnIcon('restart')}\${esc(t('actionRestart'))}</button>
                  \${a.repoUrl && a.runtimeType !== 'paasmcp-control-plane' ? \`<button class="secondary" onclick="redeployApp('\${esc(a.name)}')" title="\${esc(t('redeployTitle'))}">\${btnIcon('sync')}\${esc(t('actionRedeploy'))}</button>\` : ''}
                  \${rollbackBtn}
                  \${followBtn}
                  \${a.trashedAt
                    ? \`<span style="font-size:11px;color:var(--muted);">\${esc(t('trashedStatus') + a.trashedAt.slice(0, 10) + (a.trashDeleteOn ? t('trashDeleteOn') + new Date(a.trashDeleteOn).toLocaleDateString() : ''))}</span>
                       <button class="secondary" onclick="appAction('\${esc(a.name)}','restore')">\${esc(t('actionRestore'))}</button>
                       <button class="danger" onclick="appAction('\${esc(a.name)}','purge')">\${esc(t('actionPurge'))}</button>\`
                    : \`<button class="danger" onclick="appAction('\${esc(a.name)}','destroy')">\${esc(t('actionDelete'))}</button>\`}
                </div>
              </div>

              \${(sourceHtml || commitLine || followErr) ? \`
              <div class="app-row-commit-bar">
                \${sourceHtml}
                \${commitLine ? '· ' + commitLine : ''}
                \${followErr}
              </div>\` : ''}

              <div class="app-row-meta-bar">
                <span class="runtime-tag">
                  <span class="lang-dot" style="background:\${langColor};"></span>
                  <code>\${esc(a.runtimeType)}</code>
                </span>
                <span>\${esc(t('lblPort'))}: <code>\${esc(a.localPort)}</code></span>
                <span>\${metricHtml} \${limitsHtml}</span>
                \${deployStatusHtml(d, true)}
                \${a.lastWebhookAt ? \`<span style="color:var(--muted)">⚡ Webhook: \${esc(a.lastWebhookAt.slice(0,19))}</span>\` : ''}
              </div>
            </div>
          \`;
        }).join('');
      }

      const searchVal = document.getElementById('appSearchInput')?.value;
      if (searchVal) filterApps(searchVal);

      const dbs = Object.values(s.databases || {});
      document.getElementById('dbList').innerHTML = dbs.length
        ? dbs.map(d => \`<div style="margin-bottom:6px;padding:8px 10px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12.5px;" title="\${esc(d.dbName)} / \${esc(d.dbUser)}">🗄️ <strong>\${esc(d.appName)}</strong> · \${esc(t('bkKind_' + d.engine) || d.engine)}<br/><span style="color:var(--muted);">\${esc(t(d.engine === 'redis' ? 'dbGetsRedis' : 'dbGetsPg'))}</span></div>\`).join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('emptyDbs')) + '</span>';

      renderNightly(s.nightlyBackup);
      const backups = s.backups || [];
      document.getElementById('backupsList').innerHTML = backups.length
        ? backups.map(b => \`
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;padding:8px 10px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12px;gap:8px;flex-wrap:wrap;">
            <div>
              🔒 <strong>\${esc(b.appName)}</strong> · \${esc(t('bkKind_' + b.engine) || b.engine)}\${b.engine === 'volume' ? ' (' + esc(b.databaseName) + ')' : ''} · \${esc(fmtWhen(b.createdAt))}<br/>
              <span style="color:var(--muted);" title="\${esc(b.id)} · SHA256 \${esc(b.sha256 || '')}">\${esc(fmtSize(b.sizeBytes))}\${b.offsiteKey ? ' · ☁️ ' + esc(t('offsiteLabel')) : ''}</span>
            </div>
            <span>
              <button class="secondary" style="padding:4px 9px;font-size:11px;" onclick="testBackup('\${esc(b.id)}')">\${esc(t('btnTestRestore'))}</button>
              <button class="secondary" style="padding:4px 9px;font-size:11px;" onclick="restoreBackup('\${esc(b.id)}')">\${esc(t('btnRestoreDump'))}</button>
            </span>
          </div>
        \`).join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('emptyBackups')) + '</span>';

      const peers = Object.values(s.federation?.peers || {});
      const fedNames = peers.map(p => p.name);
      const allPeers = pairedServers(s);
      // Servers known only through the live copy (the invite side never hears back from 'node join').
      const copyOnly = Object.keys(allPeers).filter(n => fedNames.indexOf(n) === -1);
      const copyOnlyHtml = copyOnly.map(n => '<div style="padding:8px 10px;margin-bottom:6px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12.5px;">' +
        '🤝 <strong>' + esc(n) + '</strong> — <span class="badge success">' + esc(t('peerViaCopy')) + '</span><br/>' +
        '<span style="color:var(--muted);font-size:11.5px;">' + esc([allPeers[n].sending ? t('peerSending') : '', allPeers[n].receiving ? t('peerReceiving') : ''].filter(Boolean).join(' · ')) + '</span></div>').join('');
      document.getElementById('fedPeersList').innerHTML = copyOnlyHtml + (peers.length
        ? peers.map(p => \`
          <div style="padding:8px 10px;margin-bottom:6px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12.5px;">
            🤝 <strong>\${esc(p.name)}</strong> (<code>\${esc(p.nodeId)}</code>) — <span class="badge success">\${esc(p.mode)}</span><br/>
            <span style="color:var(--muted);font-size:11.5px;">Endpoint: \${esc(p.endpointUrl)} · Key: <code>\${esc(p.publicKeyFingerprint)}</code></span>
          </div>
        \`).join('')
        : copyOnly.length ? '' : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('emptyPeers')) + '</span>');
    }

    // Server answers 409 for risky actions: show its warning, ask the person, and resend with the confirmation.
    const rawFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const res = await rawFetch(input, init);
      if (res.status !== 409 || !init || typeof init.body !== 'string') return res;
      const info = await res.clone().json().catch(() => ({}));
      if (!info.confirmationRequired) return res;
      const warning = (info.warning && (info.warning[currentLang] || info.warning.en)) || '';
      const body = JSON.parse(init.body);
      if (info.level === 'strong') {
        const typed = prompt(warning + '\\n\\n' + t('typeNameToConfirm') + info.subject);
        if (typed === null) return res;
        body.confirmName = typed.trim();
      } else if (!confirm(warning)) {
        return res;
      }
      body.confirmed = true;
      return rawFetch(input, { ...init, body: JSON.stringify(body) });
    };

    async function loadApprovals() {
      const res = await fetch('/api/approvals');
      if (!res.ok) return;
      const data = await res.json();
      const items = data.approvals || [];
      document.getElementById('approvalsCard').style.display = items.length ? 'block' : 'none';
      document.getElementById('approvalsList').innerHTML = items.map(a => \`
        <div style="padding:12px 14px;margin-bottom:8px;border-radius:10px;background:var(--bg-subtle);border:1px solid var(--border);">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
            <strong>\${esc(a.id)} · \${esc(a.action)} · \${esc(a.subject)}</strong>
            <span class="badge \${a.level === 'strong' ? 'danger' : 'warning'}">\${esc(a.level)}</span>
          </div>
          <div style="font-size:13px;margin:6px 0;">\${esc(a.warning[currentLang] || a.warning.en)}</div>
          <button onclick="decideApproval('\${esc(a.id)}', true, '\${esc(a.level)}', '\${esc(a.subject)}')">\${esc(t('btnApprove'))}</button>
          <button class="secondary" onclick="decideApproval('\${esc(a.id)}', false)">\${esc(t('btnReject'))}</button>
        </div>\`).join('');
    }

    async function decideApproval(id, approve, level, subject) {
      let confirmName;
      if (approve && level === 'strong') {
        confirmName = prompt(t('typeNameToConfirm') + subject);
        if (confirmName === null) return;
      }
      const res = await fetch('/api/approvals/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, approve, confirmName: confirmName && confirmName.trim() })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      loadApprovals();
    }

    // ---- Home, e-mail, second server, updates, storage (plain-language screens) ----
    let emailRelay = null;
    let updatesLoaded = false;
    const card = (inner) => '<div style="padding:12px 14px;margin-bottom:8px;border-radius:10px;background:var(--bg-subtle);border:1px solid var(--border);font-size:13px;">' + inner + '</div>';
    const badge = (cls, text) => '<span class="badge ' + cls + '">' + esc(text) + '</span>';
    function goTab(name, sub) { goTo(name, sub || ''); }
    async function postJson(url, body) {
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { if (!data.confirmationRequired) alert(data.error || ('HTTP ' + res.status)); return null; }
      return data;
    }

    function renderHome() {
      const tiles = document.getElementById('homeTiles');
      if (!tiles) return;
      const s = lastStatus || {};
      const apps = Object.values(s.apps || {});
      const backups = (s.backups || []).slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
      const last = backups[0];
      const offsiteOn = Boolean((s.systemSecretsConfigured || {}).BACKUP_S3_ENDPOINT);
      const ms = mirrorSummary(s);
      const msWho = ms.copyNames.join(', ');
      const tile = (title, value, note) => '<div class="arch-box"><h3>' + esc(title) + '</h3><p style="font-size:18px;font-weight:700;color:var(--text);margin:4px 0;">' + esc(value) + '</p><p>' + esc(note) + '</p></div>';
      tiles.innerHTML =
        tile(t('tileApps'), String(apps.length), apps.length ? t('tileAppsNote') : t('tileAppsNone')) +
        tile(t('tileBackup'), last ? new Date(last.createdAt).toLocaleString() : t('never'), last ? (last.offsiteAt ? t('tileBackupOff') : t('tileBackupLocal')) : t('tileBackupNone')) +
        tile(t('tileMirror'),
          ms.state === 'fenced' ? t('mirrorFenced') : ms.state === 'on' ? t('tileMirrorOn') : ms.state === 'stopped' ? t('tileMirrorStopped') : t('tileMirrorOff'),
          ms.state === 'on' ? t('tileMirrorWith').replace('{who}', msWho)
            : ms.state === 'stopped' ? t('tileMirrorStoppedNote').replace('{who}', ms.down.join(', '))
            : ms.state === 'paired' ? t('tileMirrorPairedOnly').replace('{who}', ms.names.join(', '))
            : t('tileMirrorNote')) +
        tile(t('tileEmail'), emailRelay ? emailRelay.host : t('notConfigured'), emailRelay ? emailRelay.fromDomain : t('tileEmailNote'));
      renderNextStep();
      renderTutorial();
      if (!tutExtra.loaded && (currentTab === 'home')) loadTutorialExtra();
    }

    // ---- Tutorial: what is done and what can still be done, with step-by-step guides on their own pages ----
    let tutExtra = { pool: 0, ai: 0, loaded: false };
    let currentGuide = '';
    async function loadTutorialExtra() {
      try {
        const [p, k] = await Promise.all([fetch('/api/pool'), fetch('/api/tokens')]);
        const pool = p.ok ? await p.json() : {};
        const tok = k.ok ? await k.json() : {};
        tutExtra = { pool: (pool.helpers || []).length, ai: (tok.tokens || []).length, loaded: true };
      } catch { tutExtra.loaded = true; }
      renderHome();
    }
    function tutorialItems() {
      const s = lastStatus || {};
      const apps = Object.values(s.apps || {});
      const sys = s.systemSecretsConfigured || {};
      const m = s.mirror || {};
      return [
        { id: 'app', group: 'essential', done: apps.length > 0, go: ['overview', 'deploy'], guide: 'firstapp' },
        { id: 'address', group: 'essential', done: apps.some(function (a) { return (a.domains || []).length > 0; }), go: ['overview', 'expose'], guide: 'address' },
        { id: 'offsite', group: 'essential', done: Boolean(sys.BACKUP_S3_ENDPOINT), go: ['databases', 'offsite'], guide: 'offsite' },
        { id: 'autoupdate', group: 'recommended', done: apps.some(function (a) { return Boolean(a.autoDeploy); }), go: ['overview', 'deploy'], guide: 'autoupdate' },
        { id: 'email', group: 'recommended', done: Boolean(emailRelay), go: ['email', ''], guide: 'email' },
        { id: 'backup', group: 'recommended', done: (s.backups || []).length > 0, go: ['databases', 'backups'] },
        { id: 'doctor', group: 'recommended', done: false, go: ['doctor', ''], always: true },
        { id: 'github', group: 'recommended', done: Boolean(sys.GITHUB_TOKEN), go: ['connect', 'github'], guide: 'github', optional: true },
        { id: 'alerts', group: 'recommended', done: Boolean(sys.NOTIFY_URL), go: ['connect', 'alerts'] },
        { id: 'mirror', group: 'grow', done: Object.keys(m.replicas || {}).length + Object.keys(m.offers || {}).length > 0, go: ['mirror', 'connect'] },
        { id: 'pool', group: 'grow', done: tutExtra.pool > 0, go: ['pool', 'add'] },
        { id: 'ai', group: 'grow', done: tutExtra.ai > 0, go: ['agents', 'connect'] },
      ];
    }
    function tutRow(it) {
      const guide = it.guide ? ' <a href="#guide/' + it.guide + '" class="tut-guide">' + esc(t('tutGuide')) + '</a>' : '';
      const action = it.done
        ? badge('success', t('done'))
        : '<button class="secondary" data-go-tab="' + it.go[0] + '" data-go-sub="' + it.go[1] + '">' + esc(t(it.always ? 'tutOpen' : 'openStep')) + '</button>';
      return '<div class="tut-row' + (it.done ? ' tut-done' : '') + '">' +
        '<span class="tut-check" aria-hidden="true">' + (it.done ? '✓' : '') + '</span>' +
        '<div class="tut-text"><strong>' + esc(t('tut_' + it.id)) + '</strong>' + (it.optional ? ' <span style="color:var(--muted)">(' + esc(t('optional')) + ')</span>' : '') +
        '<div class="tut-desc">' + esc(t('tut_' + it.id + 'Desc')) + guide + '</div></div>' +
        '<div class="tut-act">' + action + '</div></div>';
    }
    function tutCountText() {
      const items = tutorialItems().filter(function (it) { return !it.always; });
      return t('tutCount').split('{n}').join(String(items.filter(function (it) { return it.done; }).length)).split('{t}').join(String(items.length));
    }
    function renderTutorial() {
      const box = document.getElementById('tutList');
      if (!box) return;
      const items = tutorialItems().filter(function (it) { return !it.always; });
      const done = items.filter(function (it) { return it.done; }).length;
      const bar = document.getElementById('tutProgress');
      if (bar) bar.innerHTML = '<div class="tut-bar" role="progressbar" aria-valuemin="0" aria-valuemax="' + items.length + '" aria-valuenow="' + done + '"><span style="width:' + Math.round(done * 100 / items.length) + '%"></span></div>' +
        '<div class="tut-count">' + esc(tutCountText()) + '</div>';
      box.innerHTML = ['essential', 'recommended', 'grow'].map(function (g) {
        return '<h3 class="ofs-h">' + esc(t('tutGroup_' + g)) + '</h3><p class="ofs-note">' + esc(t('tutGroup_' + g + 'Desc')) + '</p>' +
          tutorialItems().filter(function (it) { return it.group === g; }).map(tutRow).join('');
      }).join('');
    }
    function renderNextStep() {
      const box = document.getElementById('homeSteps');
      if (!box) return;
      const next = tutorialItems().filter(function (it) { return !it.done && !it.always && !it.optional; }).slice(0, 2);
      box.innerHTML = (next.length ? next.map(tutRow).join('') : card(badge('success', t('done')) + ' ' + esc(t('tutAllEssential')))) +
        '<div style="margin-top:8px;"><a href="#home/tutorial">' + esc(t('tutSeeAll')) + '</a> <span style="color:var(--muted);font-size:12.5px;">· ' + esc(tutCountText()) + '</span></div>';
    }

    const GUIDES = {
      firstapp: { steps: 5, go: [['overview', 'deploy'], ['connect', 'github'], ['overview', 'deploy'], ['overview', 'list'], ['vault', '']] },
      address: { steps: 4, go: [null, ['connect', 'cloudflare'], ['overview', 'expose'], ['overview', 'expose']] },
      offsite: { steps: 4, go: [null, null, ['databases', 'offsite'], ['databases', 'backups']] },
      autoupdate: { steps: 3, go: [['overview', 'deploy'], ['overview', 'webhook'], null] },
      email: { steps: 4, go: [null, null, ['email', ''], ['email', '']] },
      github: { steps: 3, go: [null, ['connect', 'github'], ['connect', 'github']] },
    };
    function renderGuide() {
      const pane = document.getElementById('tab-guide');
      if (!pane) return;
      const id = GUIDES[currentGuide] ? currentGuide : 'firstapp';
      const g = GUIDES[id];
      const k = 'guide_' + id;
      let steps = '';
      for (let i = 1; i <= g.steps; i++) {
        const go = g.go[i - 1];
        steps += '<li class="guide-step"><strong>' + esc(t(k + '_s' + i)) + '</strong><div class="tut-desc">' + t(k + '_s' + i + 'Desc') + '</div>' +
          (go ? '<button class="secondary" style="margin-top:6px;" data-go-tab="' + go[0] + '" data-go-sub="' + go[1] + '">' + esc(t('guideOpenScreen')) + '</button>' : '') + '</li>';
      }
      const others = Object.keys(GUIDES).filter(function (x) { return x !== id; })
        .map(function (x) { return '<a href="#guide/' + x + '">' + esc(t('guide_' + x)) + '</a>'; }).join(' · ');
      pane.innerHTML =
        '<div class="page-head"><div class="page-crumb"><a href="#home/tutorial">' + esc(t('sub_home_tutorial')) + '</a> <span aria-hidden="true">/</span> ' + esc(t('guideCrumb')) + '</div>' +
        '<h1><span>' + esc(t(k)) + '</span></h1><p class="page-lead">' + esc(t(k + '_lead')) + '</p></div>' +
        '<div class="card"><ol class="guide-steps">' + steps + '</ol>' +
        '<p class="ofs-note" style="margin-top:14px;">' + esc(t('guideOthers')) + ' ' + others + '</p>' +
        '<a href="#home/tutorial">' + esc(t('guideBack')) + '</a></div>';
    }

    async function loadEmail() {
      const res = await fetch('/api/email');
      if (!res.ok) return;
      emailRelay = (await res.json()).relay;
      const st = document.getElementById('emailStatus');
      if (st) st.innerHTML = emailRelay ? badge('success', t('emailOn') + ' ' + emailRelay.host) : badge('warning', t('notConfigured'));
      if (emailRelay) {
        document.getElementById('emHost').value = emailRelay.host;
        document.getElementById('emPort').value = emailRelay.port;
        document.getElementById('emUser').value = emailRelay.user;
        document.getElementById('emDomain').value = emailRelay.fromDomain;
        document.getElementById('emPass').placeholder = t('keepSaved');
      }
      renderHome();
    }
    async function saveEmail() {
      const ok = await postJson('/api/email', {
        host: document.getElementById('emHost').value.trim(),
        port: Number(document.getElementById('emPort').value || 587),
        user: document.getElementById('emUser').value.trim(),
        password: document.getElementById('emPass').value,
        fromDomain: document.getElementById('emDomain').value.trim(),
      });
      if (ok) { document.getElementById('emPass').value = ''; showToast(t('saved')); loadEmail(); }
    }
    async function testEmail() {
      const r = await postJson('/api/email/test', { to: document.getElementById('emTo').value.trim() });
      if (r) showToast(t('emailSent'));
    }
    async function provisionEmailUi() {
      const appName = document.getElementById('emApp').value.trim();
      if (!appName) return;
      const r = await postJson('/api/email/provision', { appName });
      if (r) showToast(t('emailAppDone') + ' ' + r.from);
    }

    async function loadMirror() {
      const res = await fetch('/api/mirror');
      if (!res.ok) { loadArbiterStatus(); return; }
      const m = await res.json();
      mirrorLive = m;
      mirrorLiveAt = Date.now();
      let html = '';
      if (m.fenced) html += card(badge('danger', t('mirrorFenced')) + '<div style="margin-top:6px;">' + esc(t('mirrorFencedDesc')) + '</div>');
      html += card('<strong>' + esc(t('mirrorAuto')) + ':</strong> ' + ((m.auto || []).length ? badge('success', (m.auto || []).join(', ')) : badge('', t('off'))) +
        ' · <strong>' + esc(t('mirrorArbiter')) + ':</strong> ' + (m.arbiterUrl ? esc(m.arbiterUrl) : esc(t('notConfigured'))) +
        ' · <a href="javascript:void(0)" data-go-tab="mirror" data-go-sub="judge">' + esc(t(m.arbiterUrl ? 'autoGoJudge' : 'judgeSetupTitle')) + '</a>');
      (m.sending || []).forEach(o => {
        html += card('<strong>' + esc(t('mirrorSendingTo')) + ' ' + esc(o.peer) + '</strong> ' +
          (o.error ? badge('danger', o.error) : o.connected ? badge('success', t('connected')) : badge('warning', t('waitingPeer'))) +
          (o.walStatus === 'lost' ? '<div style="margin-top:6px;">' + esc(t('mirrorLost')) + '</div>' : ''));
      });
      (m.receiving || []).forEach(r => {
        const via = r.servedBy ? ' (' + t('mirrorVia').replace('{who}', r.servedBy.name || r.servedBy.nodeId) + ')' : '';
        if (r.supersededBy) {
          // Another server took over this peer's data: this copy only waits to be rebuilt (or, if this
          // server had taken it over before, its apps for it stopped here).
          const by = r.supersededBy.nodeId === 'manual' ? t('mirrorBehindManual') : t('mirrorBehindBy').replace('{who}', r.supersededBy.name || r.supersededBy.nodeId);
          const desc = r.promotedAt ? t('mirrorLostDesc') : t('mirrorBehindDesc');
          html += card('<strong>' + esc(t('mirrorCopyOf')) + ' ' + esc(r.peer) + esc(via) + '</strong> ' + badge('warning', t('mirrorBehind')) +
            '<div style="color:var(--muted);margin-top:4px;">' + esc(by) + ' ' + esc(desc.split('{peer}').join(r.peer)) + '</div>');
          return;
        }
        const state = r.error ? badge('danger', r.error)
          : r.promotedAt ? badge('warning', t('mirrorServingHere'))
          : r.streaming ? badge('success', t('mirrorUpToDate') + (r.secondsSinceLastChangeApplied != null ? ' (' + r.secondsSinceLastChangeApplied + ' s)' : ''))
          : badge('warning', t('mirrorNotStreaming'));
        const action = r.promotedAt
          ? '<button class="secondary" onclick="mirrorHandback(&#39;' + esc(r.peer) + '&#39;)">' + esc(t('btnHandback')) + '</button>'
          : '<button class="danger" onclick="mirrorPromote(&#39;' + esc(r.peer) + '&#39;)">' + esc(t('btnPromote')) + '</button>' +
            // A stopped copy: if another server already took over by hand, this one should step aside.
            (!r.streaming && !r.error ? ' <button class="secondary" onclick="mirrorRetire(&#39;' + esc(r.peer) + '&#39;)">' + esc(t('btnRetire')) + '</button>' : '');
        html += card('<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;"><div><strong>' + esc(t('mirrorCopyOf')) + ' ' + esc(r.peer) + esc(via) + '</strong> ' + state +
          '<div style="color:var(--muted);margin-top:4px;">' + esc(r.promotedAt ? t('mirrorPromotedDesc') : t('mirrorPromoteDesc')) + '</div>' +
          (!r.promotedAt && !r.streaming && !r.error ? '<div style="color:var(--muted);margin-top:4px;">' + esc(t('mirrorRetireDesc').split('{peer}').join(r.peer)) + '</div>' : '') +
          '</div><div style="display:flex;gap:6px;flex-wrap:wrap;">' + action + '</div></div>');
      });
      if (!(m.sending || []).length && !(m.receiving || []).length) html += card(esc(t('mirrorNone')));
      document.getElementById('mirrorStatusBox').innerHTML = html;
      // Step 5 only offers peers this server holds a copy of (the ones it could take over).
      const sel = document.getElementById('mAutoPeer');
      const keep = sel.value;
      const peers = (m.receiving || []).filter(r => !r.promotedAt && !r.supersededBy).map(r => r.peer);
      sel.innerHTML = peers.length
        ? peers.map(p => '<option value="' + esc(p) + '">' + esc(p) + ((m.auto || []).includes(p) ? ' · ' + esc(t('arbAutoTag')) : '') + '</option>').join('')
        : '<option value="">' + esc(t('autoNoCopy')) + '</option>';
      if (keep && peers.includes(keep)) sel.value = keep;
      if (m.arbiterUrl && !document.getElementById('mArbiter').value) document.getElementById('mArbiter').value = m.arbiterUrl;
      loadArbiterStatus();
      loadActive();
    }
    async function mirrorOffer() {
      const r = await postJson('/api/mirror/offer', {
        peer: document.getElementById('mOfferPeer').value.trim(),
        peerIp: document.getElementById('mOfferIp').value.trim(),
        fromCopyOf: document.getElementById('mOfferFrom').value.trim() || undefined,
      });
      if (!r) return;
      const box = document.getElementById('mOfferToken');
      box.style.display = 'block';
      box.textContent = r.token;
      copyText(r.token);
      loadMirror();
    }
    async function mirrorAccept() {
      const r = await postJson('/api/mirror/accept', { token: document.getElementById('mAcceptToken').value.trim(), rejoin: document.getElementById('mRejoin').checked });
      if (r) { showToast(t('mirrorAccepted')); loadMirror(); }
    }
    async function mirrorPromote(peer) { if (await postJson('/api/mirror/promote', { peer })) { showToast(t('mirrorPromoted')); loadMirror(); loadAll(); } }
    async function mirrorRetire(peer) { if (await postJson('/api/mirror/retire', { peer })) { showToast(t('mirrorRetired')); loadMirror(); loadAll(); } }
    async function mirrorHandback(peer) { if (await postJson('/api/mirror/handback', { peer })) { showToast(t('mirrorHandedBack')); loadMirror(); loadAll(); } }
    async function mirrorAuto(on) {
      const peer = document.getElementById('mAutoPeer').value.trim();
      if (!peer) { alert(t('autoNoPeer')); return; }
      const r = await postJson('/api/mirror/auto', { peer, on, arbiterUrl: document.getElementById('mArbiter').value.trim() || undefined });
      if (r) { showToast(t('saved')); loadMirror(); }
    }
    // Step 2 of the Arbiter tab: the install command with this pair's key already in it.
    async function arbiterInstallCmd() {
      const btn = document.getElementById('btnArbCmd');
      btn.disabled = true;
      try {
        const r = await postJson('/api/mirror/arbiter/install', {});
        if (!r) return;
        document.getElementById('arbInstallCmd').textContent = r.command;
        document.getElementById('arbInstallBox').style.display = 'block';
      } finally { btn.disabled = false; }
    }
    // Arbiter tab: state, where it runs, last contact, what it hears and who looks after whose data.
    function renderJudge(c) {
      const info = document.getElementById('judgeInfoBox');
      const owners = document.getElementById('judgeOwnersBox');
      if (!info) return;
      const row = (k, v) => '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:4px 0;"><span style="color:var(--muted);min-width:180px;">' + esc(k) + '</span><span>' + v + '</span></div>';
      const ago = (sec) => relTime(new Date(Date.now() - sec * 1000).toISOString());
      const setup = document.getElementById('judgeSetup');
      const ready = c.configured && c.ok;
      if (setup && !setup.dataset.touched) setup.open = !ready;
      document.getElementById('judgeSetupTitle').textContent = t(c.configured ? 'judgeSetupRedo' : 'judgeSetupTitle');
      if (!c.configured) {
        info.innerHTML = card(badge('', t('judgeState_none')) + '<div style="margin-top:6px;">' + esc(t('judgeNoneDesc')) + '</div>');
        owners.innerHTML = '';
        return;
      }
      let html = badge(c.ok ? 'success' : 'danger', t(c.ok ? 'judgeState_ok' : 'judgeState_err'));
      if (!c.ok) html += '<div style="margin-top:6px;">' + esc(t('arbErr_' + (c.errorCode || 'unreachable'))) + '</div>';
      html += '<div style="margin-top:8px;">' + row(t('judgeAddress'), esc(c.url || ''));
      if (c.ok) {
        const a = c.about;
        html += row(t('judgeWhere'), a ? '<strong>' + esc(a.host) + '</strong>' + (a.version ? ' · PaaSMCP ' + esc(a.version) : '') : esc(t('judgeOldArbiter')));
        if (a && a.startedAt) html += row(t('judgeSince'), esc(new Date(a.startedAt).toLocaleString()));
        if (c.latencyMs != null) html += row(t('judgeLatency'), esc(c.latencyMs + ' ms'));
        const heard = (c.nodes || []).map(n => esc(t('judgeHeardAgo').replace('{who}', n.isMe ? t('arbThisServer') + ' (' + n.name + ')' : n.name).replace('{when}', n.isMe ? t('relNow') : ago(n.secondsAgo))));
        html += row(t('judgeHears'), heard.length ? heard.join('<br>') : esc(t('judgeHeardNone')));
        if (a && a.clusters > 1) html += row(t('judgeClusters'), esc(String(a.clusters)));
      }
      const w = c.watch || {};
      let watch = w.okAt ? relSpan(w.okAt) : esc(t('judgeWatchNever'));
      if (w.errorAt && (!w.okAt || w.errorAt > w.okAt)) watch += '<br>' + badge('warning', '!') + ' ' + esc(t('judgeWatchErr').replace('{when}', relTime(w.errorAt)).replace('{err}', w.error || ''));
      html += row(t('judgeLastWatch'), watch) + '</div>';
      info.innerHTML = card(html);
      if (!c.ok) { owners.innerHTML = ''; return; }
      const list = c.owners || [];
      owners.innerHTML = card('<strong>' + esc(t('judgeOwnersTitle')) + '</strong><div style="margin-top:4px;">' +
        (list.length ? list.map(o => esc(t(o.owner === o.dataOf ? 'judgeOwnerHome' : 'judgeOwnerLine').replace('{data}', o.dataOf).replace('{owner}', o.owner).replace('{epoch}', String(o.epoch)))).join('<br>') : esc(t('judgeOwnersNone'))) + '</div>');
    }
    // Explains one arbiter check (GET /api/mirror/arbiter) in plain words: one line per thing to verify.
    function renderArbiterCheck(c, opts) {
      const ok = (txt) => '<div style="margin:3px 0;">' + badge('success', '✓') + ' ' + esc(txt) + '</div>';
      const warn = (txt) => '<div style="margin:3px 0;">' + badge('warning', '!') + ' ' + esc(txt) + '</div>';
      const bad = (txt) => '<div style="margin:3px 0;">' + badge('danger', '✗') + ' ' + esc(txt) + '</div>';
      if (!c.configured) return card(warn(t('arbNotSet')));
      let html = '';
      if (!c.ok) {
        html += bad(t('arbErr_' + (c.errorCode || 'unreachable'))) + '<div style="color:var(--muted);font-size:12px;margin-top:4px;">' + esc(c.url || '') + (c.detail ? ' · ' + esc(c.detail) : '') + '</div>';
        return card(html);
      }
      html += ok(t('arbOk') + ' (' + c.url + ')');
      const auto = c.auto || [];
      (c.nodes || []).forEach(n => {
        const who = n.isMe ? t('arbThisServer') + ' (' + n.name + ')' : n.name;
        const line = t('arbHeard').replace('{who}', who).replace('{s}', String(n.secondsAgo));
        html += n.isMe || n.secondsAgo <= 60 ? ok(line) : warn(line + ' · ' + t('arbHeardOld'));
      });
      if (!opts || !opts.testOnly) {
        auto.forEach(p => {
          const n = (c.nodes || []).find(x => !x.isMe && x.name === p);
          if (!n) html += warn(t('arbPeerUnknown').split('{who}').join(p));
        });
        if (c.watchActive === true) html += ok(t('arbWatchOn'));
        else if (c.watchActive === false) html += (auto.length ? bad : warn)(t('arbWatchOff'));
        html += auto.length ? ok(t('arbAutoOn').replace('{who}', auto.join(', '))) : warn(t('arbAutoOff'));
        const ready = c.ok && c.watchActive !== false && auto.length && auto.every(p => (c.nodes || []).some(x => !x.isMe && x.name === p && x.secondsAgo <= 60));
        html = '<div style="font-weight:600;margin-bottom:6px;">' + esc(ready ? t('arbReady') : t('arbNotReady')) + '</div>' + html;
      }
      return card(html);
    }
    async function loadArbiterStatus() {
      const box = document.getElementById('arbStatusBox');
      box.innerHTML = card(esc(t('checking')));
      const jb = document.getElementById('judgeInfoBox');
      if (jb && !jb.innerHTML) jb.innerHTML = card(esc(t('checking')));
      const res = await fetch('/api/mirror/arbiter');
      const c = await res.json().catch(() => ({}));
      if (!res.ok) {
        box.innerHTML = card(badge('danger', c.error || 'error'));
        if (jb) jb.innerHTML = box.innerHTML;
        return;
      }
      box.innerHTML = renderArbiterCheck(c);
      renderJudge(c);
      const input = document.getElementById('mArbiter');
      if (c.url && !input.value) input.value = c.url;
    }
    async function arbiterTest() {
      const url = document.getElementById('mArbiter').value.trim();
      const box = document.getElementById('arbTestBox');
      if (!url) { box.innerHTML = card(esc(t('arbNotSet'))); return; }
      const btn = document.getElementById('btnArbTest');
      btn.disabled = true;
      box.innerHTML = card(esc(t('checking')));
      try {
        const res = await fetch('/api/mirror/arbiter?url=' + encodeURIComponent(url));
        const c = await res.json().catch(() => ({}));
        box.innerHTML = res.ok ? renderArbiterCheck(c, { testOnly: true }) : card(badge('danger', c.error || 'error'));
      } finally { btn.disabled = false; }
    }
    async function arbiterSave() {
      const url = document.getElementById('mArbiter').value.trim();
      if (!url) return;
      if (await postJson('/api/mirror/arbiter', { url })) { showToast(t('saved')); loadMirror(); }
    }

    // ---- App on both servers (active-active) and the self-hosted entry ----
    let activeData = null;
    // Translated text for a code, or the server's English text when there is none.
    const tr = (key, fallback) => { const d = I18N[currentLang] || I18N.pt; return d[key] !== undefined ? d[key] : fallback; };
    async function loadActive() {
      const res = await fetch('/api/active');
      if (!res.ok) return;
      activeData = await res.json();
      const box = document.getElementById('activeStatusBox');
      box.innerHTML = (activeData.apps || []).length
        ? activeData.apps.map(a => card('<strong>' + esc(a.app) + '</strong> ' +
            (a.error ? badge('danger', a.error) : badge('success', a.role === 'origin' ? t('aaOrigin') : t('aaCopy').replace('{peer}', (activeData.peers || [])[0] || '?'))) +
            '<div style="color:var(--muted);margin-top:4px;">' + esc(t('aaRunning')) + ': ' + esc(a.commit || '?') +
            (a.wanted ? ' · ' + esc(t('aaWanted')) + ': ' + esc(a.wanted) : '') +
            (a.files ? ' · ' + (a.files.error ? badge('danger', t('aaFilesErr') + ': ' + a.files.error) : esc(t('aaFiles').replace('{time}', new Date(a.files.at).toLocaleTimeString()))) : '') +
            (a.files && a.files.pending && !a.files.error ? ' · ' + esc(t('aaFilesPending')) : '') +
            (a.files && a.files.tooLarge ? ' · ' + badge('warning', t('aaFilesBig').replace('{n}', String(a.files.tooLarge))) : '') + '</div>')).join('')
        : card(esc(t('aaNone')));
      const sel = document.getElementById('aaApp');
      const keep = sel.value;
      sel.innerHTML = (activeData.candidates || []).map(c => '<option value="' + esc(c.app) + '">' + esc(c.app) + (c.on ? ' · ' + esc(t('aaIsOn')) : '') + '</option>').join('');
      if (keep && (activeData.candidates || []).some(c => c.app === keep)) sel.value = keep;
      renderActiveCheck();
      renderEdge();
      renderTunnel();
    }
    function renderTunnel() {
      const tu = (activeData && activeData.tunnel) || {};
      const box = document.getElementById('aaTunnelBox');
      const conn = tu.connector && tu.connector !== 'none'
        ? ' · ' + esc(t('aaTunHere')) + ': ' + badge(tu.connector === 'running' ? 'success' : tu.connector === 'stopped' ? 'warning' : '', t(tu.connector === 'running' ? 'aaTunRunning' : tu.connector === 'stopped' ? 'aaTunStopped' : 'aaTunAbsent'))
        : '';
      const sick = tu.watch && (tu.watch.apps || []).filter(a => !a.healthy).map(a => a.app);
      let html = '<div>' + (tu.on ? badge('success', t('aaTunOn')) : tu.copyOf ? badge('success', t('aaTunCopy')) : esc(tu.configured ? t('aaTunOff') : t('aaTunNoCf'))) + conn +
        (sick && sick.length ? ' · ' + badge('danger', t('aaTunSick') + ': ' + sick.join(', ')) : '') + '</div>';
      if (tu.on && (tu.hostnames || []).length) html += '<div style="color:var(--muted);margin-top:4px;">' + esc(t('aaTunHosts')) + ': ' + esc(tu.hostnames.join(', ')) + '</div>';
      if (tu.configured && !tu.copyOf) {
        html += '<div style="margin-top:8px;">' + (tu.on
          ? '<button class="secondary" onclick="activeTunnel(false)">' + esc(t('btnAaTunnelOff')) + '</button>'
          : '<button onclick="activeTunnel(true)">' + esc(t('btnAaTunnelOn')) + '</button>') + '</div>';
      }
      box.innerHTML = card(html);
    }
    async function activeTunnel(on) {
      const r = await postJson('/api/active/tunnel', { on });
      if (r) { showToast(t('saved')); loadActive(); }
    }
    function renderActiveCheck() {
      const box = document.getElementById('aaCheckBox');
      const c = ((activeData && activeData.candidates) || []).find(x => x.app === document.getElementById('aaApp').value);
      if (!c) { box.innerHTML = ''; return; }
      const line = (cls, sym, txt) => '<div style="margin:3px 0;">' + badge(cls, sym) + ' ' + esc(txt) + '</div>';
      box.innerHTML = card(
        '<div style="font-weight:600;margin-bottom:6px;">' + esc(c.on ? t('aaIsOn') : c.ok ? t('aaReady') : t('arbNotReady')) + '</div>' +
        (c.problemCodes || []).map((code, i) => line('danger', '✗', tr('aaP_' + code, c.problems[i]))).join('') +
        (c.warningCodes || []).map((w, i) => line('warning', '!', tr('aaW_' + w.code, c.warnings[i]).replace('{v}', w.value || ''))).join(''));
    }
    async function activeSwitch(on) {
      const appName = document.getElementById('aaApp').value;
      if (!appName) return;
      const r = await postJson('/api/active', { appName, on });
      if (r) { showToast(r.warning ? r.warning : t('aaSwitched')); loadActive(); }
    }
    function renderEdge() {
      const e = (activeData && activeData.edge) || { installed: false, sites: [] };
      let html = card(e.installed ? (e.running === false ? badge('warning', t('aaEdgeStopped')) : badge('success', t('aaEdgeOn'))) : esc(t('aaEdgeOff')));
      (e.sites || []).forEach(site => {
        html += card('<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;"><div><strong>' + esc(site.hostname) + '</strong> → ' + esc(site.app) +
          '<div style="margin-top:4px;">' + (site.backends || []).map(b => badge(b.healthy === false ? 'danger' : b.healthy ? 'success' : '', (b.where === 'here' ? t('aaHere') : b.where) + (b.detail ? ' · ' + b.detail : ''))).join(' ') + '</div></div>' +
          '<button class="secondary" onclick="edgeRemoveSite(&#39;' + esc(site.hostname) + '&#39;)">' + esc(t('aaRemove')) + '</button></div>');
      });
      document.getElementById('edgeStatusBox').innerHTML = html;
    }
    async function edgeAddSite() {
      const appName = document.getElementById('aaApp').value;
      const hostname = document.getElementById('aaHost').value.trim();
      if (!appName || !hostname) return;
      const r = await postJson('/api/edge/site', { appName, hostname });
      if (r) { showToast(t('aaDns').replace('{host}', r.hostname)); loadActive(); }
    }
    async function edgeRemoveSite(hostname) {
      if (await postJson('/api/edge/site', { hostname, remove: true })) loadActive();
    }

    async function loadUpdates() {
      const box = document.getElementById('updatesList');
      box.innerHTML = card(esc(t('checking')));
      const res = await fetch('/api/updates');
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { box.innerHTML = card(badge('danger', data.error || 'error')); return; }
      updatesLoaded = true;
      const names = { postgres: t('compPostgres'), redis: t('compRedis'), garage: t('compGarage') };
      box.innerHTML = (data.updates || []).map(u => card('<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;"><div><strong>' + esc(names[u.component] || u.component) + '</strong><div style="color:var(--muted);margin-top:4px;">' + esc(u.running) +
        (u.available ? ' → ' + esc(u.available) : '') + (u.note ? ' · ' + esc(u.note) : '') + '</div></div>' +
        (u.available ? '<button onclick="applyUpdateUi(&#39;' + esc(u.component) + '&#39;, &#39;' + esc(u.available) + '&#39;)">' + esc(t('btnUpdate')) + '</button>' : badge('success', t('upToDate'))) + '</div>')).join('');
    }
    async function applyUpdateUi(component, image) {
      const r = await postJson('/api/updates/apply', { component, image });
      if (!r) return;
      if (r.rolledBack) alert(t('updateRolledBack') + ' ' + r.rolledBack);
      else showToast(t('updateDone') + ' ' + r.to);
      loadUpdates();
    }

    async function loadStorage() {
      const res = await fetch('/api/storage');
      if (!res.ok) return;
      const items = (await res.json()).storage || [];
      document.getElementById('storageList').innerHTML = items.length
        ? items.map(i => card('<strong>' + esc(i.appName) + '</strong> · <code>' + esc(i.bucket) + '</code>')).join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('storageNone')) + '</span>';
    }
    async function provisionStorageUi() {
      const appName = document.getElementById('stoApp').value.trim();
      if (!appName) return;
      const r = await postJson('/api/storage', { appName });
      if (r) { showToast(t('storageDone')); loadStorage(); }
    }
    // ---- Off-site backups: one form per provider, secrets typed here and never shown back ----
    // Fields each provider needs, in order. Labels and hints are in I18N (ofsF_<field>, ofsHint_<provider>).
    const OFS_PROVIDERS = [
      ['r2', 'Cloudflare R2', ['accountId', 'bucket', 'accessKeyId', 'secretAccessKey']],
      ['s3', 'Amazon S3', ['region', 'bucket', 'accessKeyId', 'secretAccessKey']],
      ['gcs', 'Google Cloud', ['bucket', 'accessKeyId', 'secretAccessKey']],
      ['b2', 'Backblaze B2', ['region', 'bucket', 'accessKeyId', 'secretAccessKey']],
      ['wasabi', 'Wasabi', ['region', 'bucket', 'accessKeyId', 'secretAccessKey']],
      ['paasmcp', null, ['code']],
      ['custom', null, ['endpoint', 'region', 'bucket', 'accessKeyId', 'secretAccessKey']],
    ];
    const OFS_PLACEHOLDER = { r2: { accountId: '0123456789abcdef0123456789abcdef' }, s3: { region: 'us-east-1' }, b2: { region: 'us-west-004' }, wasabi: { region: 'us-east-1' }, custom: { endpoint: 'https://minio.example.com', region: 'us-east-1' } };
    let ofsProvider = 'r2';
    let ofsData = null;

    function ofsLabel(p, f) {
      const specific = t('ofsF_' + p + '_' + f);
      return specific !== 'ofsF_' + p + '_' + f ? specific : t('ofsF_' + f);
    }
    function ofsMsg(id, text, kind) {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text || '';
      el.className = 'ofs-msg' + (kind ? ' ' + kind : '');
    }
    // Same as postJson, but the error goes next to the button instead of a browser pop-up.
    async function ofsPost(url, body, msgId) {
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { if (!data.confirmationRequired) ofsMsg(msgId, (currentLang === 'pt' && data.errorPt) || data.error || ('HTTP ' + res.status), 'err'); return null; }
      return data;
    }

    // ---- Connections (Cloudflare and GitHub from the dashboard: no terminal, no ids to copy) ----
    let cnData = null;
    let cfFound = null;
    const CF_TOKEN_TEMPLATE = 'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
      encodeURIComponent(JSON.stringify([{ key: 'argotunnel', type: 'edit' }, { key: 'dns', type: 'edit' }, { key: 'access', type: 'edit' }])) +
      '&accountId=*&zoneId=all&name=PaaSMCP';
    function renderExposeHint() {
      const el = document.getElementById('exposeCfHint');
      if (!el) return;
      const c = (lastStatus && lastStatus.cloudflare) || {};
      const cfs = (lastStatus && lastStatus.systemSecretsConfigured) || {};
      const ready = Boolean(c.accountId && c.tunnelId && c.baseDomain && c.baseDomain !== 'example.com' && cfs.CF_API_TOKEN);
      const mode = (document.getElementById('expMode') || {}).value || 'public';
      el.innerHTML = ready || mode === 'tailscale' ? '' : '<div class="preset-hint show" style="margin:0 0 12px;">' + esc(t('exposeNeedCf')) +
        ' <a href="#connect/cloudflare">' + esc(t('exposeOpenConnect')) + '</a></div>';
      const hint = document.getElementById('expModeHint');
      if (hint) hint.textContent = t('expHint_' + mode);
      const line = document.getElementById('expPreviewLine');
      const sub = ((document.getElementById('expSub') || {}).value || '').trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
      if (line) line.textContent = sub && mode !== 'tailscale' && c.baseDomain && c.baseDomain !== 'example.com' ? t('expPreview') + ' https://' + sub + '.' + c.baseDomain : '';
      const subBox = document.getElementById('expSubBox');
      if (subBox) subBox.style.display = mode === 'tailscale' ? 'none' : '';
      renderAddresses();
    }
    // Choosing an app suggests the start of the address from its name (until the person types their own).
    let expAutoSub = '';
    function expAppChanged() {
      const app = document.getElementById('expApp').value.trim();
      const subEl = document.getElementById('expSub');
      if (!subEl.value || subEl.value === expAutoSub) {
        expAutoSub = app.toLowerCase().replace(/^paasmcp-/, '').replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
        subEl.value = expAutoSub;
      }
      renderExposeHint();
    }
    function renderAddresses() {
      const box = document.getElementById('expList');
      if (!box) return;
      const rows = [];
      Object.values((lastStatus && lastStatus.apps) || {}).forEach(function (a) {
        (a.domains || []).forEach(function (d) {
          if (d && d.url && ['public', 'zero-trust', 'tailscale'].indexOf(d.mode) !== -1) rows.push({ app: a.name, d: d });
        });
      });
      box.innerHTML = rows.length
        ? '<h3 style="font-size:14px;margin:0 0 8px;">' + esc(t('expListTitle')) + '</h3>' + rows.map(function (r) {
            return '<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:8px 10px;margin-bottom:6px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:13px;">'
              + '<a href="' + esc(r.d.url) + '" target="_blank" rel="noopener" style="font-weight:600;word-break:break-all;">' + esc(r.d.url.replace(/^https?:[/][/]/, '')) + '</a>'
              + '<span style="color:var(--muted);">' + esc(r.app) + ' · ' + esc(t('mode_' + r.d.mode)) + '</span>'
              + '<button class="secondary" style="margin-left:auto;padding:4px 10px;font-size:12px;" data-app="' + esc(r.app) + '" data-host="' + esc(r.d.hostname) + '" onclick="removeAddress(this)">' + esc(t('btnUnexpose')) + '</button>'
              + '</div>';
          }).join('')
        : '';
    }
    async function removeAddress(btn) {
      btn.disabled = true;
      const res = await fetch('/api/unexpose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName: btn.getAttribute('data-app'), hostname: btn.getAttribute('data-host') })
      });
      const data = await res.json().catch(function () { return {}; });
      btn.disabled = false;
      if (!res.ok) { if (!data.confirmationRequired) alert((currentLang === 'pt' && data.errorPt) || data.error || ('HTTP ' + res.status)); return; }
      showToast(t('toastUnexposed') + data.removed);
      loadAll();
    }
    async function loadConnections() {
      const link = document.getElementById('cfTokenLink');
      if (link) link.href = CF_TOKEN_TEMPLATE;
      const res = await fetch('/api/connections');
      if (!res.ok) return;
      cnData = await res.json();
      renderConnections();
      renderNotify();
    }
    function renderConnections() {
      if (!cnData) return;
      const c = cnData.cloudflare || {};
      const st = document.getElementById('cfStatus');
      if (st) {
        const conn = c.connectorHere === 'running' ? t('cnConnRunning') : c.connectorHere === 'stopped' ? t('cnConnStopped') : '';
        st.innerHTML = c.ready
          ? card(badge('success', t('cnCfReady')) + ' <strong>' + esc(c.baseDomain) + '</strong>' +
              '<div style="color:var(--muted);margin-top:4px;">' + esc(t('cnCfReadyDesc').split('{domain}').join(c.baseDomain)) + (conn ? ' ' + esc(conn) : '') + '</div>' +
              ((c.zeroTrustEmails || []).length ? '<div style="color:var(--muted);margin-top:4px;">' + esc(t('cnCfEmailsNow')) + ' ' + esc(c.zeroTrustEmails.join(', ')) + '</div>' : '') +
              '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;"><button class="secondary" onclick="goTo(&#39;overview&#39;, &#39;expose&#39;)">' + esc(t('cnGoExpose')) + '</button>' +
              '<button class="secondary" onclick="cfShowForm()">' + esc(t('cnChange')) + '</button></div>')
          : card(badge('warning', t('notConfigured')) + ' <span style="color:var(--muted);">' + esc(c.tokenSaved ? t('cnCfHalf') : t('cnCfNone')) + '</span>');
      }
      const form = document.getElementById('cfForm');
      if (form && !form.dataset.forced) form.style.display = c.ready ? 'none' : '';
      const tok = document.getElementById('cfToken');
      if (tok) tok.placeholder = c.tokenSaved ? t('keepSaved') : '';
      if (c.zeroTrustEmails && document.getElementById('cfEmails') && !document.getElementById('cfEmails').value) document.getElementById('cfEmails').value = c.zeroTrustEmails.join(', ');
      const g = cnData.github || {};
      const gs = document.getElementById('ghStatus');
      if (gs) gs.innerHTML = card(g.tokenSaved ? badge('success', t('cnGhSaved')) + ' <span style="color:var(--muted);">' + esc(t('cnGhSavedDesc')) + '</span>'
        : badge('', t('cnGhNoToken')) + ' <span style="color:var(--muted);">' + esc(t('cnGhNoTokenDesc')) + '</span>');
      const key = document.getElementById('ghSshKey');
      if (key && lastStatus) key.textContent = lastStatus.sshPublicKey || '';
      setNavCounter('tabCountConnect', (c.ready ? 1 : 0) + (g.tokenSaved ? 1 : 0), 'cntConnect');
    }
    function cfShowForm() {
      const form = document.getElementById('cfForm');
      form.dataset.forced = '1';
      form.style.display = '';
      document.getElementById('cfToken').focus();
    }
    async function cfDiscover() {
      ofsMsg('cfMsg', t('cnChecking'), '');
      document.getElementById('cfChoose').style.display = 'none';
      const r = await ofsPost('/api/connections/cloudflare/discover', { token: document.getElementById('cfToken').value.trim() }, 'cfMsg');
      if (!r) return;
      cfFound = r;
      const miss = (r.missing || []).map(function (m) { return t('cnMiss_' + m); });
      if (!r.accounts.length || !r.zones.length) { ofsMsg('cfMsg', miss.join(' '), 'err'); return; }
      ofsMsg('cfMsg', t('cnFound').split('{a}').join(String(r.accounts.length)).split('{z}').join(String(r.zones.length)) + (miss.length ? ' ' + miss.join(' ') : ''), miss.length ? 'err' : 'ok');
      const prev = (cnData && cnData.cloudflare) || {};
      document.getElementById('cfAccount').innerHTML = r.accounts.map(function (a) {
        return '<option value="' + esc(a.id) + '"' + (a.id === prev.accountId ? ' selected' : '') + '>' + esc(a.name) + '</option>';
      }).join('');
      cfFillChoices();
      document.getElementById('cfChoose').style.display = '';
    }
    function cfFillChoices() {
      if (!cfFound) return;
      const accId = document.getElementById('cfAccount').value;
      const acc = cfFound.accounts.find(function (a) { return a.id === accId; }) || { tunnels: [] };
      const prev = (cnData && cnData.cloudflare) || {};
      const zones = cfFound.zones.filter(function (z) { return !z.accountId || z.accountId === accId; });
      document.getElementById('cfDomain').innerHTML = zones.length
        ? zones.map(function (z) { return '<option value="' + esc(z.name) + '"' + (z.name === prev.baseDomain ? ' selected' : '') + '>' + esc(z.name) + '</option>'; }).join('')
        : '<option value="">' + esc(t('cnNoZoneHere')) + '</option>';
      const opts = ['<option value="new">' + esc(t('cnNewTunnel')) + '</option>'].concat(acc.tunnels.map(function (tu) {
        return '<option value="' + esc(tu.id) + '"' + (tu.id === prev.tunnelId ? ' selected' : '') + '>' + esc(tu.name) + ' (' + esc(t('cnTun_' + tu.status) || tu.status) + (tu.remote ? '' : ', ' + t('cnTunLocal')) + ')</option>';
      }));
      document.getElementById('cfTunnel').innerHTML = opts.join('');
      cfTunnelHint();
    }
    function cfTunnelHint() {
      const accId = document.getElementById('cfAccount').value;
      const acc = (cfFound && cfFound.accounts.find(function (a) { return a.id === accId; })) || { tunnels: [] };
      const id = document.getElementById('cfTunnel').value;
      const tu = acc.tunnels.find(function (x) { return x.id === id; });
      const note = document.getElementById('cfTunnelNote');
      const row = document.getElementById('cfRunHereRow');
      if (!tu) { note.textContent = t('cnNewTunnelNote'); row.style.display = 'none'; return; }
      if (!tu.remote) { note.textContent = t('cnTunLocalNote'); row.style.display = 'none'; return; }
      const idle = tu.status === 'inactive' || tu.status === 'down';
      note.textContent = idle ? t('cnTunIdleNote') : t('cnTunLiveNote');
      row.style.display = 'flex';
      document.getElementById('cfRunHere').checked = idle;
    }
    async function cfSave() {
      ofsMsg('cfSaveMsg', t('cnSaving'), '');
      const btn = document.getElementById('btnCfSave');
      btn.disabled = true;
      try {
        const r = await ofsPost('/api/connections/cloudflare', {
          token: document.getElementById('cfToken').value.trim(),
          accountId: document.getElementById('cfAccount').value,
          baseDomain: document.getElementById('cfDomain').value,
          tunnelId: document.getElementById('cfTunnel').value,
          runHere: document.getElementById('cfRunHereRow').style.display !== 'none' && document.getElementById('cfRunHere').checked,
          zeroTrustEmails: document.getElementById('cfEmails').value,
        }, 'cfSaveMsg');
        if (!r) { if (document.getElementById('cfSaveMsg').textContent === t('cnSaving')) ofsMsg('cfSaveMsg', '', ''); return; }
        ofsMsg('cfSaveMsg', r.created ? t('cnSavedNew') : t('cnSaved'), 'ok');
        document.getElementById('cfToken').value = '';
        document.getElementById('cfChoose').style.display = 'none';
        delete document.getElementById('cfForm').dataset.forced;
        cnData = r.summary;
        loadAll();
        renderConnections();
      } finally {
        btn.disabled = false;
      }
    }
    function renderNotify() {
      const n = (cnData && cnData.notify) || { configured: false };
      const st = document.getElementById('ntStatus');
      const form = document.getElementById('ntForm');
      if (!st || !form) return;
      st.innerHTML = n.configured
        ? card(badge('success', t('ntOn')) + ' <span style="color:var(--muted);">' + esc(t('ntOnDesc').split('{host}').join(n.host || '?').split('{success}').join(n.onSuccess ? t('ntOnSuccessShort') : '')) + '</span>' +
            '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;"><button class="secondary" onclick="ntShowForm()">' + esc(t('ntChange')) + '</button>' +
            '<button class="secondary" onclick="ntClear()">' + esc(t('ntOff')) + '</button></div>')
        : '';
      if (!form.dataset.forced) form.style.display = n.configured ? 'none' : '';
      document.getElementById('ntSuccess').checked = Boolean(n.onSuccess);
    }
    function ntShowForm() {
      const form = document.getElementById('ntForm');
      form.dataset.forced = '1';
      form.style.display = '';
      document.getElementById('ntUrl').focus();
    }
    async function ntSave() {
      const url = document.getElementById('ntUrl').value.trim();
      if (!url) return;
      ofsMsg('ntMsg', t('ntSending'), '');
      const r = await ofsPost('/api/connections/notify', { url, onSuccess: document.getElementById('ntSuccess').checked, lang: currentLang }, 'ntMsg');
      if (!r) return;
      document.getElementById('ntUrl').value = '';
      delete document.getElementById('ntForm').dataset.forced;
      ofsMsg('ntMsg', t('ntSaved'), 'ok');
      loadConnections();
      loadAll();
    }
    async function ntClear() {
      if (!confirm(t('ntOffConfirm'))) return;
      await fetch('/api/connections/notify', { method: 'DELETE' });
      ofsMsg('ntMsg', '', '');
      loadConnections();
      loadAll();
    }

    async function ghSave() {
      ofsMsg('ghMsg', t('cnChecking'), '');
      const r = await ofsPost('/api/connections/github', { token: document.getElementById('ghToken').value.trim() }, 'ghMsg');
      if (!r) return;
      document.getElementById('ghToken').value = '';
      ofsMsg('ghMsg', t('cnGhOk').split('{login}').join(r.login), 'ok');
      ghRepos = null;
      loadConnections();
      loadAll();
    }


    // ---- Push notices: the saved GitHub token creates the webhook on each app's repository ----
    let whRepos = null;
    let whBusy = false;
    function whAddress() {
      const el = document.getElementById('whAddress');
      if (el && !el.value && location.protocol === 'https:') el.value = location.origin;
      return el ? el.value.trim() : '';
    }
    async function loadHooks() {
      const note = document.getElementById('whAutoNote');
      if (!note) return;
      if (!cnData) { const r = await fetch('/api/connections'); if (r.ok) cnData = await r.json(); }
      const on = Boolean(cnData && cnData.github && cnData.github.tokenSaved);
      note.innerHTML = esc(t(on ? 'whAutoNoteOn' : 'whAutoNoteOff')) + (on ? '' : ' <a href="#connect/github" data-go-tab="connect" data-go-sub="github">' + esc(currentLang === 'pt' ? 'Abrir Conexões → GitHub' : 'Open Connections → GitHub') + '</a>');
      document.querySelector('#whAuto .wh-form').style.display = on ? '' : 'none';
      document.getElementById('whManual').open = !on;
      if (!on) { document.getElementById('whRepos').innerHTML = ''; return; }
      const address = whAddress();
      if (!address) { ofsMsg('whMsg', '', ''); return; }
      ofsMsg('whMsg', t('whChecking'), '');
      const res = await fetch('/api/connections/github/webhooks?address=' + encodeURIComponent(address));
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { ofsMsg('whMsg', (currentLang === 'pt' && data.errorPt) || data.error || ('HTTP ' + res.status), 'err'); whRepos = null; renderHooks(); return; }
      ofsMsg('whMsg', '', '');
      whRepos = data.repos || [];
      renderHooks();
    }
    function renderHooks() {
      const box = document.getElementById('whRepos');
      if (!box) return;
      if (!whRepos) { box.innerHTML = ''; return; }
      if (!whRepos.length) { box.innerHTML = '<p class="ofs-note">' + esc(t('whNoRepos')) + '</p>'; return; }
      const kind = { on: 'success', off: 'warning', denied: 'danger', error: 'warning' };
      const label = { on: 'whStOn', off: 'whStOff', denied: 'whStDenied', error: 'whStError' };
      const rows = whRepos.map(function (r) {
        const failed = r.state === 'on' && typeof r.lastCode === 'number' && (r.lastCode < 200 || r.lastCode >= 300);
        const hint = r.state === 'denied' ? t('whDeniedHint') : failed ? t('whLastFail').split('{code}').join(String(r.lastCode)) : '';
        const btn = r.state === 'denied' ? '' : '<button class="secondary" ' + (whBusy ? 'disabled ' : '') + 'onclick="hookOn(' + esc(JSON.stringify(r.repo)).split('"').join('&quot;') + ')">' + esc(t(r.state === 'on' ? 'whBtnRedo' : 'whBtnOn')) + '</button>';
        return '<div style="display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);">' +
          '<div style="flex:1 1 220px;min-width:0;"><strong style="overflow-wrap:anywhere;">' + esc(r.repo) + '</strong> ' + badge(failed ? 'warning' : kind[r.state] || 'warning', t(label[r.state] || 'whStError')) +
          '<div style="color:var(--muted);font-size:12px;">' + esc((r.apps || []).join(', ')) + '</div>' +
          (hint ? '<div style="color:var(--muted);font-size:12px;margin-top:2px;">' + esc(hint) + '</div>' : '') + '</div>' + btn + '</div>';
      }).join('');
      const pending = whRepos.filter(function (r) { return r.state === 'off'; }).length;
      box.innerHTML = rows +
        (pending > 1 ? '<button style="margin-top:10px;" ' + (whBusy ? 'disabled ' : '') + 'onclick="hookAll()">' + esc(t('whBtnAll')) + '</button>' : '');
    }
    async function hookOn(repo) {
      if (whBusy) return false;
      whBusy = true; renderHooks();
      ofsMsg('whMsg', t('whWorking').split('{repo}').join(repo), '');
      let ok = false;
      try {
        const r = await ofsPost('/api/connections/github/webhooks', { repo: repo, address: whAddress() }, 'whMsg');
        if (r) {
          ok = r.reach === 'ok';
          const key = r.reach === 'ok' ? 'whOk' : r.reach === 'unreachable' ? 'whUnreachable' : 'whUnknown';
          ofsMsg('whMsg', t(key).split('{repo}').join(repo).split('{code}').join(String(r.code || 0)), r.reach === 'ok' ? 'ok' : 'err');
        }
      } finally { whBusy = false; }
      const msg = document.getElementById('whMsg');
      const keep = msg ? [msg.textContent, msg.className] : null;
      await loadHooks();
      if (keep && msg) { msg.textContent = keep[0]; msg.className = keep[1]; }
      return ok;
    }
    async function hookAll() {
      const list = (whRepos || []).filter(function (r) { return r.state === 'off'; }).map(function (r) { return r.repo; });
      for (const repo of list) { if (!(await hookOn(repo)) && document.getElementById('whMsg').className.indexOf('err') !== -1) break; }
    }

    async function loadOffsite() {
      const res = await fetch('/api/offsite');
      if (!res.ok) return;
      ofsData = await res.json();
      renderOffsiteCurrent();
      renderGrants();
    }

    function renderOffsiteCurrent() {
      const box = document.getElementById('ofsCurrent');
      const tg = (ofsData && ofsData.target) || { configured: false };
      if (!tg.configured) {
        box.innerHTML = '';
        openOffsiteForm(false);
        return;
      }
      const name = tg.provider === 'paasmcp' ? t('ofsProvPaasmcp') : tg.provider === 'custom' ? t('ofsProvCustom') : tg.providerName;
      box.innerHTML = card(
        '<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;">' +
        '<div><strong>' + esc(name) + '</strong> · ' + esc(tg.bucket) + ' <span style="color:var(--muted)">(' + esc(tg.host) + ')</span>' +
        '<div style="color:var(--muted);margin-top:4px;">' + esc(t('ofsFolder')) + ' <code>' + esc(tg.prefix) + '/</code> · ' + esc(t('ofsKey')) + ' <code>' + esc(tg.accessKeyHint) + '</code>' +
        (tg.testedAt ? ' · ' + esc(t('ofsTestedAt')) + ' ' + esc(new Date(tg.testedAt).toLocaleString()) : '') + '</div></div>' +
        badge('success', t('ofsActive')) + '</div>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">' +
        '<button onclick="syncOffsiteNow()" id="btnSyncOffsite">' + esc(t('btnSyncOffsite')) + '</button>' +
        '<button class="secondary" onclick="testOffsiteUi()" id="btnOfsTest">' + esc(t('ofsBtnTest')) + '</button>' +
        '<button class="secondary" onclick="openOffsiteForm(true)">' + esc(t('ofsBtnChange')) + '</button>' +
        '<button class="danger" onclick="clearOffsiteUi()">' + esc(t('ofsBtnStop')) + '</button></div>' +
        '<div class="ofs-msg" id="ofsCurMsg" role="status" aria-live="polite"></div>');
      document.getElementById('ofsForm').style.display = 'none';
    }

    function openOffsiteForm(changing) {
      document.getElementById('ofsForm').style.display = 'block';
      document.getElementById('btnOfsCancel').style.display = changing ? '' : 'none';
      const tg = ofsData && ofsData.target;
      if (changing && tg && tg.provider) ofsProvider = tg.provider;
      renderOffsiteProviders();
      ofsMsg('ofsMsg', '');
    }
    function closeOffsiteForm() { document.getElementById('ofsForm').style.display = 'none'; ofsMsg('ofsMsg', ''); }

    function renderOffsiteProviders() {
      document.getElementById('ofsProviders').innerHTML = OFS_PROVIDERS.map(([id, name]) =>
        '<button type="button" class="chip' + (id === ofsProvider ? ' selected' : '') + '" aria-pressed="' + (id === ofsProvider) + '" onclick="pickOffsiteProvider(&#39;' + id + '&#39;)">' +
        esc(name || (id === 'paasmcp' ? t('ofsProvPaasmcp') : t('ofsProvCustom'))) + '</button>').join('');
      renderOffsiteFields();
    }
    function pickOffsiteProvider(id) { ofsProvider = id; renderOffsiteProviders(); ofsMsg('ofsMsg', ''); }

    function renderOffsiteFields() {
      const def = OFS_PROVIDERS.find((x) => x[0] === ofsProvider);
      const ph = OFS_PLACEHOLDER[ofsProvider] || {};
      const field = (f) => {
        const id = 'ofs_' + f;
        const label = '<label class="field-label" for="' + id + '">' + esc(ofsLabel(ofsProvider, f)) + '</label>';
        if (f === 'code') return '<div style="grid-column:1/-1;">' + label + '<textarea id="' + id + '" rows="3" autocomplete="off" spellcheck="false" placeholder="paasmcp-backup:1:…"></textarea></div>';
        const secret = f === 'secretAccessKey';
        return '<div>' + label + '<input id="' + id + '" ' + (secret ? 'type="password" autocomplete="new-password"' : 'autocomplete="off"') +
          ' spellcheck="false" placeholder="' + esc(ph[f] || '') + '" /></div>';
      };
      document.getElementById('ofsFields').innerHTML =
        '<p class="ofs-note">' + esc(t('ofsHint_' + ofsProvider)) + '</p>' +
        '<div class="form-grid">' + def[2].map(field).join('') + '</div>' +
        (ofsProvider === 'paasmcp' ? '' : '<details style="margin-top:6px;font-size:12.5px;"><summary style="color:var(--muted)">' + esc(t('ofsMore')) + '</summary>' +
          '<div style="margin-top:8px;max-width:420px;"><label class="field-label" for="ofs_prefix">' + esc(t('ofsF_prefix')) + '</label><input id="ofs_prefix" autocomplete="off" spellcheck="false" placeholder="paasmcp/' + esc((lastStatus && lastStatus.hostname) || 'servidor') + '" /></div></details>');
    }

    async function saveOffsiteUi() {
      const def = OFS_PROVIDERS.find((x) => x[0] === ofsProvider);
      const body = { provider: ofsProvider };
      for (const f of def[2].concat(['prefix'])) {
        const el = document.getElementById('ofs_' + f);
        if (el && el.value.trim()) body[f] = el.value.trim();
      }
      const btn = document.getElementById('btnOfsSave');
      btn.disabled = true;
      ofsMsg('ofsMsg', t('ofsTesting'));
      try {
        const r = await ofsPost('/api/offsite/target', body, 'ofsMsg');
        if (!r) { if (document.getElementById('ofsMsg').textContent === t('ofsTesting')) ofsMsg('ofsMsg', ''); return; }
        // Typed secrets leave the page as soon as they are saved.
        document.querySelectorAll('#ofsFields input, #ofsFields textarea').forEach((el) => { el.value = ''; });
        showToast(t('ofsSaved') + (r.test && !r.test.deleted ? ' ' + t('ofsNoDelete') : ''));
        await loadOffsite();
        loadAll();
      } finally { btn.disabled = false; }
    }

    async function testOffsiteUi() {
      const btn = document.getElementById('btnOfsTest');
      btn.disabled = true;
      ofsMsg('ofsCurMsg', t('ofsTesting'));
      try {
        const r = await ofsPost('/api/offsite/test', {}, 'ofsCurMsg');
        if (r) { await loadOffsite(); ofsMsg('ofsCurMsg', t('ofsTestOk') + (r.test && !r.test.deleted ? ' ' + t('ofsNoDelete') : ''), 'ok'); }
      } finally { if (document.getElementById('btnOfsTest')) document.getElementById('btnOfsTest').disabled = false; }
    }

    async function clearOffsiteUi() {
      const r = await ofsPost('/api/offsite/clear', {}, 'ofsCurMsg');
      if (r) { await loadOffsite(); loadAll(); }
    }

    async function syncOffsiteNow() {
      const btn = document.getElementById('btnSyncOffsite');
      if (btn) btn.disabled = true;
      ofsMsg('ofsCurMsg', t('ofsSending'));
      try {
        const r = await ofsPost('/api/backups/sync', {}, 'ofsCurMsg');
        if (r) ofsMsg('ofsCurMsg', t('offsiteDone') + ' ' + r.uploaded.length + (r.failed.length ? ' · ' + t('offsiteFailed') + ' ' + r.failed.length + ' (' + r.failed[0].error + ')' : ''), r.failed.length ? 'err' : 'ok');
      } finally { if (btn) btn.disabled = false; }
    }

    function fmtBytes(n) {
      if (typeof n !== 'number') return '';
      const u = ['B', 'KB', 'MB', 'GB', 'TB'];
      let i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
      return (i ? n.toFixed(1) : String(n)) + ' ' + u[i];
    }

    function renderGrants() {
      const grants = (ofsData && ofsData.grants) || [];
      document.getElementById('ofsGrants').innerHTML = grants.map((g) => card(
        '<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;">' +
        '<div><strong>' + esc(g.name) + '</strong> · <code>' + esc(g.bucket) + '</code>' +
        '<div style="color:var(--muted);margin-top:4px;">' + esc(t('ofsKey')) + ' <code>' + esc(String(g.accessKeyId).slice(0, 6)) + '…</code>' +
        (typeof g.bytes === 'number' ? ' · ' + esc(t('ofsStored')) + ' ' + esc(fmtBytes(g.bytes)) + (g.maxGb ? ' / ' + esc(g.maxGb) + ' GB' : '') : (g.maxGb ? ' · ' + esc(t('ofsLimit')) + ' ' + esc(g.maxGb) + ' GB' : '')) +
        ' · ' + esc(new Date(g.createdAt).toLocaleDateString()) + '</div></div>' +
        (g.revokedAt ? badge('warning', t('ofsRevoked')) : '<button class="danger" onclick="revokeGrantUi(&#39;' + esc(g.name) + '&#39;)">' + esc(t('ofsBtnRevoke')) + '</button>') +
        '</div>')).join('');
    }

    async function createGrantUi() {
      const name = document.getElementById('ofsGrantName').value.trim();
      const gb = document.getElementById('ofsGrantGb').value.trim();
      if (!name) { ofsMsg('ofsGrantMsg', t('ofsNeedName'), 'err'); return; }
      const btn = document.getElementById('btnOfsGrant');
      btn.disabled = true;
      ofsMsg('ofsGrantMsg', '');
      try {
        const r = await ofsPost('/api/offsite/grants', { name, maxGb: gb || undefined }, 'ofsGrantMsg');
        if (!r) return;
        document.getElementById('ofsGrantName').value = '';
        const a = r.access;
        const row = (k, v) => '<span class="k">' + esc(k) + '</span><code>' + esc(v) + '</code><button class="secondary chip" onclick="copyText(this.dataset.v)" data-v="' + esc(v) + '">' + esc(t('ofsCopy')) + '</button>';
        document.getElementById('ofsGrantResult').innerHTML = card(
          '<strong>' + esc(t('ofsGrantReady')) + '</strong>' +
          '<p class="ofs-note" style="margin-top:6px;">' + esc(t('ofsGrantOnce')) + '</p>' +
          '<div class="field-label">' + esc(t('ofsGrantCodeLabel')) + '</div>' +
          '<div class="ofs-secret" id="ofsGrantCode">' + esc(r.code) + '</div>' +
          '<div style="display:flex;gap:8px;flex-wrap:wrap;"><button onclick="copyText(document.getElementById(&#39;ofsGrantCode&#39;).textContent)">' + esc(t('ofsCopyCode')) + '</button>' +
          '<button class="secondary" onclick="document.getElementById(&#39;ofsGrantResult&#39;).innerHTML=&#39;&#39;">' + esc(t('ofsDoneHide')) + '</button></div>' +
          '<details style="margin-top:10px;"><summary style="color:var(--muted);font-size:12.5px;">' + esc(t('ofsGrantFields')) + '</summary><div class="ofs-kv" style="margin-top:8px;">' +
          row('Endpoint', a.endpoint) + row('Bucket', a.bucket) + row('Access Key ID', a.accessKeyId) + row('Secret Access Key', a.secretAccessKey) + row(t('ofsF_region'), a.region) +
          '</div><p class="ofs-note" style="margin-top:8px;">' + esc(t('ofsGrantInternal')) + ' <code>' + esc(r.internalEndpoint) + '</code></p></details>');
        await loadOffsite();
      } finally { btn.disabled = false; }
    }

    async function revokeGrantUi(name) {
      const r = await ofsPost('/api/offsite/grants/revoke', { name }, 'ofsGrantMsg');
      if (r) { ofsMsg('ofsGrantMsg', t('ofsRevokedMsg').replace('{name}', name), 'ok'); loadOffsite(); }
    }

    // ---- Scale: 24 h of measurements and the decision rehearsal ----
    let scaleData = null;
    async function loadScale() {
      const sel = document.getElementById('scaleApp');
      const app = sel ? sel.value : '';
      const res = await fetch('/api/scale?lang=' + currentLang + (app ? '&app=' + encodeURIComponent(app) : ''));
      if (!res.ok) return;
      scaleData = await res.json();
      renderScale();
    }
    function fmtDate(iso) {
      return new Date(iso).toLocaleString(currentLang === 'en' ? 'en-US' : 'pt-BR', { dateStyle: 'short', timeStyle: 'short' });
    }
    function fmtNum(n, digits) {
      return Number(n).toLocaleString(currentLang === 'en' ? 'en-US' : 'pt-BR', { maximumFractionDigits: digits ?? 0 });
    }
    function fmtRate(bytes) {
      if (bytes === null || bytes === undefined) return '-';
      if (bytes >= 1048576) return fmtNum(bytes / 1048576, 1) + ' MB/s';
      return fmtNum(bytes / 1024, 1) + ' kB/s';
    }
    // Small line chart (inline SVG, no library): last 24 h, gaps where nothing was measured.
    function scaleChart(title, points, valueOf, opts) {
      const W = 300, H = 90, now = Date.now(), from = now - 24 * 3600 * 1000;
      const vals = points.map(p => ({ t: p.t, v: valueOf(p) })).filter(p => p.v !== null && p.v !== undefined && isFinite(p.v));
      const top = Math.max(1, opts.top || 0, ...vals.map(p => p.v), opts.target ? opts.target * 1.25 : 0);
      const x = t => ((t - from) / (now - from)) * W;
      const y = v => H - (v / top) * (H - 6);
      const segs = [];
      let cur = [];
      vals.forEach((p, i) => {
        if (i && p.t - vals[i - 1].t > 12 * 60 * 1000) { segs.push(cur); cur = []; }
        // Steps (copies): the line stays flat until the value changes.
        else if (i && opts.step) cur.push(x(p.t).toFixed(1) + ',' + y(vals[i - 1].v).toFixed(1));
        cur.push(x(p.t).toFixed(1) + ',' + y(p.v).toFixed(1));
      });
      segs.push(cur);
      const lines = segs.filter(sg => sg.length).map(sg => sg.length === 1
        ? '<circle cx="' + sg[0].split(',')[0] + '" cy="' + sg[0].split(',')[1] + '" r="1.8" style="fill:var(--accent)"/>'
        : '<polyline points="' + sg.join(' ') + '" style="fill:none;stroke:var(--accent);stroke-width:1.6"/>').join('');
      const target = opts.target ? '<line x1="0" x2="' + W + '" y1="' + y(opts.target).toFixed(1) + '" y2="' + y(opts.target).toFixed(1) + '" style="stroke:var(--warning);stroke-width:1;stroke-dasharray:4 3"/>' : '';
      const last = vals.length ? vals[vals.length - 1].v : null;
      return '<div class="arch-box" style="padding:10px 12px;">'
        + '<div style="display:flex;justify-content:space-between;font-size:12px;gap:8px;"><strong>' + esc(title) + '</strong><span style="color:var(--muted)">' + esc(t('scaleMax')) + ' ' + esc(fmtNum(Math.max(0, ...vals.map(p => p.v)), 1)) + (last !== null ? ' · ' + esc(t('scaleLast')) + ' ' + esc(fmtNum(last, 1)) : '') + '</span></div>'
        + '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" style="width:100%;height:90px;display:block;margin-top:6px;border-bottom:1px solid var(--border)" role="img" aria-label="' + esc(title) + '">' + target + lines + '</svg>'
        + '<div style="display:flex;justify-content:space-between;font-size:10.5px;color:var(--muted);margin-top:3px;"><span>' + esc(t('scale24hAgo')) + '</span>' + (opts.target ? '<span>' + esc(t('scaleTargetLegend')) + '</span>' : '') + '<span>' + esc(t('scaleNowLbl')) + '</span></div>'
        + '</div>';
    }
    function renderScale() {
      const d = scaleData;
      if (!d) return;
      const note = document.getElementById('scaleTimerNote');
      note.innerHTML = d.timer
        ? '<p class="card-desc">' + esc(t('scaleTimerOn').replace('{n}', d.timer.seconds)) + '</p>'
        : '<div class="arch-box" style="border-color:var(--warning);margin-bottom:10px;font-size:13px;">' + t('scaleNoTimer') + '</div>';
      const sel = document.getElementById('scaleApp');
      sel.innerHTML = d.apps.map(a => '<option value="' + esc(a.app) + '"' + (a.app === d.app ? ' selected' : '') + '>' + esc(a.app) + '</option>').join('');
      const diarySel = document.getElementById('diaryApp');
      if (diarySel) diarySel.innerHTML = sel.innerHTML;
      document.getElementById('scaleLang').value = d.language;
      const a = d.apps.find(x => x.app === d.app);
      const body = document.getElementById('scaleBody');
      if (!a) {
        document.getElementById('scaleNow').innerHTML = '<p class="card-desc">' + esc(t('scaleNoApps')) + '</p>';
        document.getElementById('scaleCharts').innerHTML = '';
        document.getElementById('scaleDiary').innerHTML = '<p class="card-desc">' + esc(t('scaleNoApps')) + '</p>';
        body.style.display = 'none';
        return;
      }
      body.style.display = '';
      const ref = a.cpuReferenceCores;
      const cpuUnit = a.cpuLimited ? t('scaleOfLimit').replace('{n}', fmtNum(ref, 2)) : t('scaleOfCore');
      let now = '';
      if (!a.last) now = esc(t('scaleNoData'));
      else {
        const l = a.last;
        now = '<strong>' + esc(t('scaleNowLbl')) + ':</strong> CPU ' + esc(a.cpuOfLimit ?? '-') + '% ' + esc(cpuUnit)
          + ' · ' + esc(t('scaleMem')) + ' ' + esc(l.mem === null ? '-' : fmtNum(l.mem) + ' MB')
          + ' · ' + esc(t('scaleLat')) + ' ' + esc(l.lat === null ? (l.ok === false ? t('scaleNoAnswer') : '-') : fmtNum(l.lat) + ' ms')
          + ' · ' + esc(t('scaleNet')) + ' ' + esc(l.rx === null ? '-' : fmtRate((l.rx || 0) + (l.tx || 0)))
          + (a.rps !== undefined && a.rps !== null ? ' · ' + esc(t('scaleRps')) + ' ' + esc(fmtNum(a.rps, 1)) + '/s' : '');
        if (!a.measuring) now += '<div style="color:var(--warning);margin-top:4px;">' + esc(t('scaleStale')) + '</div>';
      }
      const copies = a.rehearsalCopies;
      now += '<div style="margin-top:6px;">' + (a.auto
        ? badge(a.auto.acting ? 'success' : 'warning', t('scaleAutoTitle') + ': ' + (a.auto.acting ? t('autoOn') : t('autoWaiting')))
        : '<span class="badge' + (copies > a.rule.min ? ' warning' : '') + '">' + esc((copies === 1 ? t('scaleWould1') : t('scaleWouldN')).replace('{n}', copies)) + '</span>') + '</div>';
      if (a.lastEvent) now += '<div style="margin-top:6px;font-size:12.5px;color:var(--muted);">' + esc(fmtDate(a.lastEvent.t)) + ' · ' + esc(a.lastEvent.text) + '</div>';
      document.getElementById('scaleNow').innerHTML = card(now);

      const pts = (d.history && d.history.points) || [];
      document.getElementById('scaleCharts').innerHTML =
        scaleChart(t('scaleChartCpu') + ' ' + cpuUnit, pts, p => p.cpu === null ? null : p.cpu / ref, { target: a.rule.targetCpu })
        + scaleChart(t('scaleChartLat'), pts, p => p.lat, {})
        + scaleChart(t('scaleChartNet'), pts, p => p.rx === null ? null : ((p.rx || 0) + (p.tx || 0)) / 1024, {})
        + scaleChart(t('scaleChartMem'), pts, p => p.mem, {})
        // Visits and copies: only for apps that have been behind the pool balancer.
        + (a.wantedCopies || pts.some(p => p.rps !== null && p.rps !== undefined)
          ? scaleChart(t('scaleChartRps'), pts, p => p.rps, { target: a.rule.targetRps || 0 })
            + scaleChart(t('scaleChartCopies'), pts, p => p.copies, { step: true, top: a.rule.max })
          : '');

      document.getElementById('scaleMin').value = a.rule.min;
      document.getElementById('scaleMax').value = a.rule.max;
      document.getElementById('scaleTarget').value = a.rule.targetCpu;
      document.getElementById('scaleTargetRps').value = a.rule.targetRps || 0;
      document.getElementById('scaleUp').value = a.rule.upRounds;
      document.getElementById('scaleDown').value = Math.round(a.rule.downAfterSeconds / 60);
      document.getElementById('scaleCooldown').value = a.rule.cooldownSeconds;
      renderAuto(a, d);
      renderCopies(a, d.pool);

      const cmd = '<code>sudo paasmcp scale test ' + esc(a.app) + '</code>';
      const c = a.capacity;
      document.getElementById('scaleCapacity').innerHTML = card(
        (c
          ? t('scaleCapResult').replace('{date}', esc(fmtDate(c.at))).replace('{rps}', esc(fmtNum(c.rps))).replace('{path}', esc(c.path))
              .replace('{c}', esc(c.concurrency)).replace('{p95}', esc(c.p95Ms)).replace('{bn}', esc(t('scaleBn_' + c.bottleneck)))
            + '<div style="margin-top:4px;color:var(--muted);font-size:12.5px;">' + esc(t('scaleCapSuggest').replace('{s}', fmtNum(c.suggestedTargetRps)))
            + (c.suggestedTargetRps > 0 ? ' <button class="secondary" style="padding:3px 8px;font-size:11.5px;" onclick="document.getElementById(&#39;scaleTargetRps&#39;).value=' + Number(c.suggestedTargetRps) + ';document.getElementById(&#39;scaleTargetRps&#39;).focus()">' + esc(t('scaleCapUse')) + '</button>' : '')
            + '</div>'
          : esc(t('scaleCapNone')))
        + '<div style="margin-top:6px;">' + cmd + '</div>');

      const diary = (d.diary || []).slice().reverse();
      document.getElementById('scaleDiary').innerHTML = diary.length
        ? diary.map(e => '<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:12.5px;"><span style="color:var(--muted)">' + esc(fmtDate(e.t)) + '</span> · ' + esc(e.text) + '</div>').join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('scaleDiaryNone')) + '</span>';
    }
    async function saveScaleRule() {
      const a = scaleData && scaleData.app;
      if (!a) return;
      const num = id => document.getElementById(id).value;
      const r = await postJson('/api/scale/rule', {
        appName: a,
        min: num('scaleMin'),
        max: num('scaleMax'),
        targetCpu: num('scaleTarget'),
        targetRps: num('scaleTargetRps'),
        upRounds: num('scaleUp'),
        downAfterSeconds: String(Math.round(Number(num('scaleDown')) * 60)),
        cooldownSeconds: num('scaleCooldown'),
      });
      if (r) { showToast(t('scaleRuleSaved')); loadScale(); }
    }
    function renderAuto(a, d) {
      const box = document.getElementById('autoBox');
      if (!box) return;
      const ready = d.pool && d.pool.readiness;
      let html;
      if (a.auto) {
        html = badge(a.auto.acting ? 'success' : 'warning', a.auto.acting ? t('autoOn') : t('autoWaiting'))
          + ' <span style="color:var(--muted);font-size:12.5px;">' + esc(t('autoSince').replace('{date}', fmtDate(a.auto.since))) + '</span>'
          + '<div style="margin-top:6px;font-size:12.5px;">' + esc(t('autoLimits').replace('{min}', a.rule.min).replace('{max}', a.rule.max)) + '</div>'
          + (d.timer ? '' : '<div style="color:var(--warning);margin-top:4px;font-size:12.5px;">' + esc(t('autoNoTimer')) + '</div>');
      } else {
        html = '<span style="font-size:12.5px;">' + esc(t('autoOff')) + '</span>';
      }
      box.innerHTML = '<div style="margin-bottom:8px;">' + html + '</div>';
      const on = document.getElementById('btnScaleAutoOn');
      on.style.display = a.auto ? 'none' : '';
      on.disabled = Boolean(ready && !ready.ok);
      document.getElementById('btnScaleAutoOff').style.display = a.auto ? '' : 'none';
    }
    async function setAuto(enabled) {
      const a = scaleData && scaleData.app;
      if (!a) return;
      const body = { appName: a, enabled };
      if (enabled) { body.min = document.getElementById('scaleMin').value; body.max = document.getElementById('scaleMax').value; }
      const r = await postJson('/api/scale/auto', body);
      if (!r) return;
      if (r.job) { showToast(t('autoStarting')); watchPoolJob(); }
      else { showToast(t('autoOffDone')); loadScale(); }
    }
    async function saveScaleLang() {
      const r = await postJson('/api/scale/language', { language: document.getElementById('scaleLang').value });
      if (r) showToast(t('scaleLangSaved'));
    }

    // ---- Helper PCs (pool) and manual copies ----
    let poolData = null;
    let poolJobTimer = null;
    async function loadPool(probe) {
      const res = await fetch('/api/pool' + (probe ? '?probe=1' : ''));
      if (!res.ok) return;
      poolData = await res.json();
      renderPool();
      if (poolData.job && !poolData.job.done) watchPoolJob();
    }
    function poolJobWhat(job) {
      return tr('poolJob_' + job.kind, t('poolJob_app')).replace('{s}', job.subject);
    }
    // Warnings and errors a finished task brought back (server sentences, shown as they are).
    function poolJobNotes(r) {
      const out = [];
      const walk = (x) => {
        if (!x || typeof x !== 'object') return;
        (x.warnings || []).forEach(w => out.push(['warning', String(w)]));
        (x.errors || []).forEach(e => out.push(['danger', (e.helper ? e.helper + ': ' : '') + String(e.error)]));
        if (x.note) out.push(['warning', String(x.note)]);
        (x.apps || []).forEach(walk);
      };
      walk(r);
      return out;
    }
    function renderPoolJob(job, boxId) {
      const box = document.getElementById(boxId);
      if (!box) return;
      if (!job) { box.innerHTML = ''; return; }
      const what = poolJobWhat(job);
      const head = !job.done ? badge('warning', t('poolJobRunning').replace('{what}', what))
        : job.error ? badge('danger', t('poolJobFailed').replace('{what}', what))
        : badge('success', t('poolJobDone').replace('{what}', what));
      const lines = job.log.slice(-8).map(l => esc(l)).join('<br/>');
      const notes = job.done ? poolJobNotes(job.result).map(n => '<div style="color:var(--' + n[0] + ');margin-top:4px;font-size:12.5px;white-space:pre-wrap;">' + esc(n[1]) + '</div>').join('') : '';
      const err = job.error ? '<div style="color:var(--danger);margin-top:6px;font-size:12.5px;white-space:pre-wrap;">' + esc(job.error) + '</div>' : '';
      box.innerHTML = card(head
        + (lines ? '<div style="font-family:monospace;font-size:11.5px;margin-top:6px;color:var(--muted);">' + lines + '</div>' : '')
        + err + notes);
    }
    function watchPoolJob() {
      if (poolJobTimer) return;
      const tick = async () => {
        const res = await fetch('/api/pool/job');
        const d = res.ok ? await res.json() : { job: null };
        renderPoolJob(d.job, 'poolJobBox');
        renderPoolJob(d.job, 'copiesJobBox');
        if (!d.job || d.job.done) {
          clearInterval(poolJobTimer);
          poolJobTimer = null;
          if (document.getElementById('tab-pool').classList.contains('active')) loadPool(false);
          if (scaleData) loadScale();
        }
      };
      poolJobTimer = setInterval(tick, 2000);
      tick();
    }
    function renderPool() {
      const d = poolData;
      if (!d) return;
      document.getElementById('poolAcl').textContent = d.acl ? d.acl.acl : '';
      renderPoolJob(d.job, 'poolJobBox');
      const stateCls = { available: 'success', working: 'success', paused: 'warning', busy: 'warning', gone: 'danger', asleep: '', waking: 'warning', unknown: '' };
      const hs = d.helpers || [];
      document.getElementById('poolHelpers').innerHTML = hs.length ? hs.map(h => {
        const facts = [
          h.ip, h.arch,
          t('poolGives').replace('{cpus}', fmtNum(h.give.cpus, 2)).replace('{mem}', fmtNum(h.give.memMb)),
          t('poolUsing').replace('{cpus}', fmtNum(h.used.cpus, 2)).replace('{mem}', fmtNum(h.used.memMb)),
          h.diskFreeGb !== null && h.diskFreeGb !== undefined ? t('poolDisk').replace('{gb}', fmtNum(h.diskFreeGb)) : '',
          h.load1 !== null && h.load1 !== undefined ? t('poolLoad').replace('{l}', fmtNum(h.load1, 2)) : '',
          h.owner && typeof h.owner.cpuPct === 'number' ? t('poolOwnerCpu').replace('{p}', fmtNum(h.owner.cpuPct)) : '',
        ].filter(Boolean).map(esc).join(' · ');
        const cm = (h.courtesy && h.courtesy.mode) || 'auto';
        const courtesy = '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;margin-top:8px;">'
          + '<div><label class="field-label" for="court_' + esc(h.name) + '">' + esc(t('lblCourtesy')) + '</label>'
          + '<select id="court_' + esc(h.name) + '">' + ['auto', 'warn', 'off'].map(m => '<option value="' + m + '"' + (m === cm ? ' selected' : '') + '>' + esc(t('courtesy_' + m)) + '</option>').join('') + '</select></div>'
          + '<div><label class="field-label" for="courtCpu_' + esc(h.name) + '">' + esc(t('lblCourtesyCpu')) + '</label>'
          + '<input id="courtCpu_' + esc(h.name) + '" type="number" min="10" max="95" step="5" style="width:80px;" value="' + esc(String((h.courtesy && h.courtesy.cpuPct) || 50)) + '" /></div>'
          + '<button class="secondary" data-helper="' + esc(h.name) + '" onclick="poolCourtesy(this.dataset.helper)">' + esc(t('btnCourtesySave')) + '</button>'
          + '</div><div style="color:var(--muted);font-size:12px;margin-top:4px;">' + esc(t('courtesyHint')) + '</div>';
        const wk = h.wake;
        const muted = (html) => '<div style="color:var(--muted);font-size:12px;margin-top:4px;">' + html + '</div>';
        const warnLine = (html) => '<div style="color:var(--warning);font-size:12.5px;margin-top:4px;">' + html + '</div>';
        const wake = '<div style="margin-top:8px;"><span class="field-label">' + esc(t('lblWake')) + '</span>'
          + '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:2px;">'
          + '<span style="font-size:12.5px;">' + esc(wk ? t('wakeOnLine').replace('{mac}', wk.mac).replace('{to}', wk.broadcast + ':' + wk.port) : t('wakeOffLine')) + '</span>'
          + (wk || h.lan ? '<button class="secondary" data-helper="' + esc(h.name) + '" data-action="' + (wk ? 'off' : 'on') + '" onclick="poolWake(this.dataset.helper, this.dataset.action)">' + esc(t(wk ? 'btnWakeOff' : 'btnWakeOn')) + '</button>' : '')
          + (wk ? '<button class="secondary" data-helper="' + esc(h.name) + '" data-action="now" onclick="poolWake(this.dataset.helper, this.dataset.action)">' + esc(t('btnWakeNow')) + '</button>' : '')
          + '</div>'
          + (h.waking && h.waking.gaveUp ? warnLine(esc(t('wakeGaveUp').replace('{n}', h.waking.tries)))
            : h.waking ? muted(esc(t('wakeWaking').replace('{date}', fmtDate(h.waking.since)).replace('{n}', h.waking.tries))) : '')
          + (!h.lan ? (wk ? warnLine(t('wakeNoLan')) : muted(t('wakeNoLan')))
            : !h.lan.wired ? warnLine(esc(t('wakeWifi').replace('{iface}', h.lan.iface)))
            : !h.lan.armed ? (wk ? warnLine(t('wakeNotArmed')) : '') : '')
          + '<div id="wakeBox_' + esc(h.name) + '"></div>'
          + muted(t('wakeHint')) + '</div>';
        const copies = h.copies.length ? t('poolCopiesOn').replace('{list}', h.copies.map(c => c.app).join(', ')) : t('poolNoCopies');
        const seen = h.lastSeenAt ? ' · <span style="color:var(--muted)">' + esc(t('poolSeen').replace('{date}', fmtDate(h.lastSeenAt))) + '</span>' : '';
        const extra = (h.secretsInMemory === false ? '<div style="color:var(--warning);font-size:12.5px;margin-top:4px;">' + t('poolSecretsDisk') + '</div>' : '')
          + (h.paused ? '<div style="color:var(--warning);font-size:12.5px;margin-top:4px;">' + esc(t('poolPausedNote')) + '</div>' : '')
          + (h.ownerBusy ? '<div style="color:var(--warning);font-size:12.5px;margin-top:4px;">' + esc(t(cm === 'warn' ? 'poolBusyWarn' : 'poolBusyAuto').replace('{date}', fmtDate(h.ownerBusy.since)).replace('{p}', fmtNum(h.ownerBusy.cpuPct)).replace('{m}', '5')) + '</div>' : '')
          + (h.owner && h.owner.why === 'old_worker' && cm !== 'off' ? '<div style="color:var(--muted);font-size:12.5px;margin-top:4px;">' + t('poolOwnerOld') + '</div>' : '')
          + (h.lastError ? '<div style="color:var(--danger);font-size:12px;margin-top:4px;white-space:pre-wrap;">' + esc(h.lastError) + '</div>' : '');
        const btns = '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;">'
          + '<button class="secondary" data-helper="' + esc(h.name) + '" onclick="poolPause(this.dataset.helper, ' + (h.paused ? 'false' : 'true') + ')">' + esc(t(h.paused ? 'btnPoolResume' : 'btnPoolPause')) + '</button>'
          + '<button class="danger" data-helper="' + esc(h.name) + '" onclick="poolRemove(this.dataset.helper)">' + esc(t('btnPoolRemove')) + '</button>'
          + '</div>';
        return card('<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;"><strong>🖥️ ' + esc(h.name) + '</strong>' + badge(stateCls[h.state] || '', t('poolSt_' + h.state)) + '</div>'
          + '<div style="color:var(--muted);font-size:12.5px;margin-top:4px;">' + facts + '</div>'
          + '<div style="font-size:12.5px;margin-top:4px;">' + esc(copies) + seen + '</div>'
          + extra + courtesy + wake + btns);
      }).join('') : '<p class="card-desc">' + esc(t('poolNone')) + '</p>';
      const apps = d.apps || [];
      document.getElementById('poolApps').innerHTML = apps.length ? apps.map(a => card('<strong>' + esc(a.app) + '</strong>' + (a.auto ? ' ' + badge('success', t('poolAutoBadge')) : '') + ' · '
        + esc(a.stoppedAt ? t('poolAppStopped') : t('poolAppLine').replace('{running}', a.running).replace('{wanted}', a.wanted))
        + (a.copies.length ? ' <span style="color:var(--muted)">(' + esc(a.copies.map(c => c.answering === false ? t('poolCopyNoAnswer').replace('{helper}', c.helper) : c.helper).join(', ')) + ')</span>' : '')
        + (a.lastError ? '<div style="color:var(--danger);font-size:12px;margin-top:4px;white-space:pre-wrap;">' + esc(a.lastError) + '</div>' : ''))).join('')
        : '<p class="card-desc">' + esc(t('poolAppsNone')) + '</p>';
    }
    async function poolInvite() {
      const name = document.getElementById('poolInviteName').value.trim();
      if (!name) return;
      const r = await postJson('/api/pool/invite', { name });
      if (!r) return;
      document.getElementById('poolInviteBox').style.display = '';
      document.getElementById('poolInviteExp').textContent = t('poolInviteExp').replace('{time}', fmtDate(r.expiresAt));
      document.getElementById('poolJoinCmd').textContent = r.joinCommand;
      document.getElementById('poolAddName').value = r.name;
    }
    async function poolAdd() {
      const name = document.getElementById('poolAddName').value.trim();
      const ip = document.getElementById('poolAddIp').value.trim();
      if (!name || !ip) return;
      document.getElementById('poolAddBox').innerHTML = '';
      const r = await postJson('/api/pool/add', { name, ip });
      if (!r) return;
      document.getElementById('poolAddBox').innerHTML = card(esc(t('poolAdded').replace('{name}', r.helper.name).replace('{cpus}', fmtNum(r.helper.give.cpus, 2)).replace('{mem}', fmtNum(r.helper.give.memMb)))
        + (r.warnings || []).map(w => '<div style="color:var(--warning);margin-top:4px;font-size:12.5px;">' + esc(w) + '</div>').join(''));
      document.getElementById('poolInviteBox').style.display = 'none';
      loadPool(false);
    }
    async function poolPause(name, paused) {
      const r = await postJson('/api/pool/pause', { name, paused });
      if (r) watchPoolJob();
    }
    async function poolCourtesy(name) {
      const mode = document.getElementById('court_' + name).value;
      const cpuPct = Number(document.getElementById('courtCpu_' + name).value);
      const r = await postJson('/api/pool/courtesy', { name, mode, cpuPct });
      if (r) watchPoolJob();
    }
    async function poolWake(name, action) {
      const r = await postJson('/api/pool/wake', { name, action });
      if (!r) return;
      await loadPool(false);
      const box = document.getElementById('wakeBox_' + name);
      if (!box) return;
      const lines = (r.warnings || []).map(w => '<div style="color:var(--warning);font-size:12.5px;margin-top:4px;">' + esc(w) + '</div>');
      if (r.sent) lines.unshift('<div style="font-size:12.5px;margin-top:4px;">' + esc(t('wakeSent').replace('{to}', r.to)) + '</div>');
      box.innerHTML = lines.join('');
    }
    async function poolRemove(name) {
      const r = await postJson('/api/pool/remove', { name });
      if (r) watchPoolJob();
    }
    function renderCopies(a, p) {
      const box = document.getElementById('copiesBox');
      if (!box || !p) return;
      const onHelpers = (p.copies || []).map(c => c.helper);
      let html = a.copies > 1
        ? esc(t('copiesRunningN').replace('{n}', a.copies).replace('{h}', a.copies - 1).replace('{list}', onHelpers.join(', ')))
        : esc(t('copiesRunning1'));
      if (a.wantedCopies && a.wantedCopies !== a.copies) html += ' ' + esc(t('copiesWanted').replace('{n}', a.wantedCopies));
      if (a.poolError) html += '<div style="color:var(--danger);margin-top:4px;font-size:12.5px;white-space:pre-wrap;">' + esc(t('copiesError').replace('{e}', a.poolError)) + '</div>';
      const r = p.readiness;
      if (r && !r.ok) {
        html += '<div style="margin-top:6px;font-size:12.5px;"><strong>' + esc(t('copiesBlocked')) + '</strong>'
          + r.problemCodes.map((c, i) => '<div>✗ ' + esc(tr('poolP_' + c, r.problems[i])) + '</div>').join('') + '</div>';
      } else if (r && r.warningCodes.length) {
        html += '<div style="margin-top:6px;font-size:12.5px;color:var(--muted);"><strong>' + esc(t('copiesWarn')) + '</strong>'
          + r.warningCodes.map((w, i) => '<div>• ' + esc(tr('poolW_' + w.code, r.warnings[i]).replace('{v}', w.value || '')) + '</div>').join('') + '</div>';
      }
      if (a.auto) html += '<div style="margin-top:6px;font-size:12.5px;color:var(--muted);">' + esc(t('copiesAutoNote')) + '</div>';
      box.innerHTML = card(html);
      const n = document.getElementById('copiesN');
      if (document.activeElement !== n) n.value = a.wantedCopies || a.copies;
      document.getElementById('copiesManual').style.display = a.auto ? 'none' : 'flex';
      document.getElementById('btnCopiesOff').style.display = a.wantedCopies || a.auto ? '' : 'none';
      renderPoolJob(p.job, 'copiesJobBox');
      if (p.job && !p.job.done) watchPoolJob();
    }
    async function applyCopies() {
      const a = scaleData && scaleData.app;
      if (!a) return;
      const r = await postJson('/api/scale/copies', { appName: a, copies: Number(document.getElementById('copiesN').value) });
      if (r) { showToast(t('copiesStarted')); watchPoolJob(); }
    }
    async function copiesOff() {
      const a = scaleData && scaleData.app;
      if (!a) return;
      const r = await postJson('/api/scale/off', { appName: a });
      if (r) { showToast(t('copiesStarted')); watchPoolJob(); }
    }

    // ---- Connect AI ----
    let aiLastToken = '';
    const NL = String.fromCharCode(10);
    function renderAi() {
      const where = (document.querySelector('input[name="aiWhere"]:checked') || {}).value || 'remote';
      document.querySelectorAll('.ai-remote').forEach(el => { el.style.display = where === 'remote' ? '' : 'none'; });
      const hostEl = document.getElementById('aiHost');
      if (!hostEl) return;
      if (!hostEl.value) {
        const h = window.location.hostname;
        if (/^100[.]/.test(h) || /[.]ts[.]net$/.test(h)) hostEl.value = h;
      }
      const host = hostEl.value.trim() || t('aiHostPh');
      const url = 'http://' + host + ':4098/mcp';
      const token = aiLastToken || t('aiTokenPh');
      const auth = { Authorization: 'Bearer ' + token };
      const remote = where === 'remote';
      const client = document.getElementById('aiClient').value;
      const json = (o) => JSON.stringify(o, null, 2);
      let text = '';
      let file = '';
      if (client === 'claude') {
        text = remote ? 'claude mcp add --transport http paasmcp ' + url + ' --header "Authorization: Bearer ' + token + '"' : 'claude mcp add paasmcp -- paasmcp-mcp';
        file = t('aiFileTerminal');
      } else if (client === 'codex') {
        text = remote ? ['export PAASMCP_TOKEN=' + token, 'codex mcp add paasmcp --url ' + url + ' --bearer-token-env-var PAASMCP_TOKEN'].join(NL) : 'codex mcp add paasmcp -- paasmcp-mcp';
        file = t('aiFileTerminal');
      } else if (client === 'vscode') {
        text = json({ servers: { paasmcp: remote ? { type: 'http', url, headers: auth } : { type: 'stdio', command: 'paasmcp-mcp' } } });
        file = t('aiFileVscode');
      } else if (client === 'gemini') {
        text = json({ mcpServers: { paasmcp: remote ? { httpUrl: url, headers: auth } : { command: 'paasmcp-mcp' } } });
        file = t('aiFileGemini');
      } else {
        text = json({ mcpServers: { paasmcp: remote ? { url, headers: auth } : { command: 'paasmcp-mcp' } } });
        file = client === 'cursor' ? t('aiFileCursor') : t('aiFileOther');
      }
      document.getElementById('aiSnippet').textContent = text;
      document.getElementById('aiWhereFile').textContent = file;
    }
    async function loadAiTokens() {
      const res = await fetch('/api/tokens');
      if (!res.ok) return;
      const items = (await res.json()).tokens || [];
      const names = { read: t('aiLvlReadShort'), deploy: t('aiLvlDeployShort'), destroy: t('aiLvlDestroyShort') };
      document.getElementById('aiTokens').innerHTML = items.length
        ? '<div class="field-label">' + esc(t('aiTokensTitle')) + '</div>' + items.map(k => card('<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;"><div><strong>' + esc(k.name) + '</strong> ' + badge('', names[k.level] || k.level) +
          '<div style="color:var(--muted);margin-top:4px;">' + esc(t('aiLastUsed')) + ' ' + esc(k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : t('never')) + '</div></div>' +
          '<button class="danger" onclick="revokeAiToken(&#39;' + esc(k.id) + '&#39;)">' + esc(t('aiRevoke')) + '</button></div>')).join('')
        : '';
    }
    async function createAiToken() {
      const level = (document.querySelector('input[name="aiLevel"]:checked') || {}).value || 'deploy';
      const r = await postJson('/api/tokens', { name: document.getElementById('aiTokName').value.trim() || 'ai', level });
      if (!r) return;
      aiLastToken = r.token;
      const box = document.getElementById('aiNewToken');
      box.style.display = 'block';
      box.innerHTML = card('<strong>' + esc(t('aiTokenOnce')) + '</strong><pre style="user-select:all;white-space:pre-wrap;word-break:break-all;margin:8px 0;">' + esc(r.token) + '</pre>');
      copyText(r.token);
      renderAi();
      loadAiTokens();
    }
    async function revokeAiToken(id) {
      if (!confirm(t('aiRevokeConfirm'))) return;
      const res = await fetch('/api/tokens', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
      if (res.ok) loadAiTokens();
    }

    async function loadAll() {
      loadApprovals();
      loadEmail();
      const res = await fetch('/api/status');
      if (!res.ok) return;
      lastStatus = await res.json();
      liveResources = null;
      applyPreferences();
      if (!resourcesTimer) resourcesTimer = setTimeout(pollResources, 15000);
    }

    // Which app's variables: a list of apps instead of typing a "scope". "system" holds the dashboard's own keys.
    const secChanged = {};
    function fillScopeSelect(apps) {
      const sel = document.getElementById('secScope');
      if (!sel) return;
      const cur = sel.value || 'system';
      const names = apps.map(function (a) { return a.name; }).sort();
      sel.innerHTML = names.map(function (n) { return '<option value="' + esc(n) + '">' + esc(n) + '</option>'; }).join('') +
        '<option value="system">' + esc(t('secSystemScope')) + '</option>';
      sel.value = names.indexOf(cur) !== -1 || cur === 'system' ? cur : (names[0] || 'system');
    }
    function renderSecApply() {
      const box = document.getElementById('secApply');
      if (!box) return;
      const scope = document.getElementById('secScope').value || 'system';
      const app = lastStatus && lastStatus.apps && lastStatus.apps[scope];
      if (scope === 'system') { box.innerHTML = '<p class="ofs-note">' + esc(t('secSystemNote')) + '</p>'; return; }
      const canRedeploy = app && app.repoUrl && app.runtimeType !== 'paasmcp-control-plane';
      box.innerHTML = '<div class="preset-hint show sec-apply' + (secChanged[scope] ? ' changed' : '') + '" style="margin:0 0 12px;">' +
        esc(t(secChanged[scope] ? 'secApplyChanged' : 'secApplyNote')) +
        (canRedeploy ? ' <button class="' + (secChanged[scope] ? '' : 'secondary') + '" style="margin-left:6px;padding:4px 10px;font-size:12px;" onclick="redeployApp(&#39;' + esc(scope) + '&#39;)">' + esc(t('actionRedeploy')) + '</button>' : '') + '</div>';
    }
    async function loadSecrets() {
      const scope = document.getElementById('secScope').value || 'system';
      renderSecApply();
      const res = await fetch('/api/secrets?scope=' + encodeURIComponent(scope));
      if (!res.ok) return;
      const data = await res.json();
      const entries = Object.entries(data.secrets || {});
      document.getElementById('secretsList').innerHTML = entries.length
        ? entries.map(function (e) {
            const k = e[0];
            return '<div class="sec-row"><span class="sec-k"><strong>' + esc(k) + '</strong> <code>' + esc(e[1]) + '</code></span>' +
              '<span class="sec-act"><button class="secondary" onclick="editSecret(&#39;' + esc(k) + '&#39;)">' + esc(t('secChange')) + '</button>' +
              '<button class="danger" onclick="delSecret(&#39;' + esc(scope) + '&#39;,&#39;' + esc(k) + '&#39;)">' + esc(t('btnRemoveSecret')) + '</button></span></div>';
          }).join('')
        : '<div style="color:var(--muted);font-size:12.5px">' + esc(t('emptySecrets')) + '</div>';
    }
    function editSecret(key) {
      document.getElementById('secKey').value = key;
      const v = document.getElementById('secVal');
      v.value = '';
      v.focus();
    }
    function markSecChanged(scope) {
      if (scope !== 'system') secChanged[scope] = true;
      renderSecApply();
    }

    async function saveSecret() {
      const scope = document.getElementById('secScope').value || 'system';
      const key = document.getElementById('secKey').value.trim();
      const value = document.getElementById('secVal').value;
      if (!key) return;
      const res = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope, key, value })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      document.getElementById('secKey').value = '';
      document.getElementById('secVal').value = '';
      showToast(t('toastSecretSaved'));
      markSecChanged(scope);
      loadSecrets();
    }

    async function saveDotenv() {
      const scope = document.getElementById('secScope').value || 'system';
      const box = document.getElementById('secDotenv');
      if (!box.value.trim()) return;
      const r = await ofsPost('/api/secrets', { scope: scope, dotenv: box.value }, 'secPasteMsg');
      if (!r) return;
      box.value = '';
      ofsMsg('secPasteMsg', t('secPasteOk').split('{n}').join(String(r.saved.length)) +
        (r.skipped && r.skipped.length ? ' ' + t('secPasteSkipped').split('{lines}').join(r.skipped.join(', ')) : ''), r.skipped && r.skipped.length ? 'err' : 'ok');
      markSecChanged(scope);
      loadSecrets();
    }

    async function delSecret(scope, key) {
      const res = await fetch('/api/secrets', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope, key })
      });
      if (res.ok) markSecChanged(scope);
      loadSecrets();
    }

    async function redeployApp(name) {
      if (!confirm(t('redeployConfirm').split('{app}').join(name))) return;
      showToast(t('toastDeploying'));
      setTimeout(pollDeploys, 800);
      const res = await fetch('/api/apps/redeploy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ appName: name }) });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        const kind = data.failure && I18N.en['df_' + data.failure.kind] ? data.failure.kind : 'other';
        alert(t('df_' + kind) + '\\n' + t('dfh_' + kind) + '\\n\\n' + String(data.error || ('HTTP ' + res.status)).slice(-1500));
        return;
      }
      delete secChanged[name];
      showToast(t('toastDeployDone') + name);
      loadAll();
      renderSecApply();
    }

    async function createDb() {
      const appName = document.getElementById('dbApp').value.trim();
      const engine = document.getElementById('dbEngine').value;
      if (!appName) return;
      const res = await fetch('/api/db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName, engine })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) return alert(t('bkErr') + '\\n\\n' + (data.error || ('HTTP ' + res.status)));
      showToast(t('toastDbCreated'));
      // The address reaches the app only when it is published again (variables are written at deploy).
      markSecChanged(appName);
      const app = lastStatus && lastStatus.apps && lastStatus.apps[appName];
      const box = document.getElementById('dbResult');
      if (box) box.innerHTML = app && app.repoUrl
        ? '<div class="dep-result ok" style="margin:0 0 14px;"><p style="margin:0 0 8px;">' + esc(t('dbRedeployNote').split('{app}').join(appName)) + '</p><div class="dep-result-actions"><button data-app="' + esc(appName) + '" onclick="redeployApp(this.dataset.app)">' + esc(t('actionRedeploy')) + '</button></div></div>'
        : '';
      loadAll();
    }

    async function createBackup() {
      const appName = document.getElementById('bakApp').value.trim();
      const engine = document.getElementById('bakEngine').value;
      if (!appName) return;
      const res = await fetch('/api/backups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName, engine })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      showToast(t('toastBackupSaved') + data.id);
      loadAll();
    }

    async function testBackup(backupId) {
      const res = await fetch('/api/backups/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backupId })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) return alert(t('bkErr') + '\\n\\n' + (data.error || ('HTTP ' + res.status)));
      const msg = I18N.en['bkTest_' + data.code] ? t('bkTest_' + data.code).split('{n}').join(String(data.count ?? '')) : data.detail;
      showToast((data.ok ? '✅ ' : '⚠️ ') + msg);
    }

    async function restoreBackup(backupId) {
      const res = await fetch('/api/backups/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backupId })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) { if (!data.confirmationRequired) alert(t('bkErr') + '\\n\\n' + (data.error || ('HTTP ' + res.status))); return; }
      const engine = data.backup && data.backup.engine;
      showToast('✅ ' + t(engine === 'volume' ? 'bkRestoredVolume' : 'bkRestoredDb') + (data.safetyBackupId ? ' ' + t('bkSafety') : ''));
      loadAll();
    }

    async function generateInvite() {
      const endpointUrl = document.getElementById('fedUrl').value.trim();
      const mode = document.getElementById('fedMode').value;
      const res = await fetch('/api/federation/invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpointUrl, mode })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      const box = document.getElementById('fedTokenBox');
      box.style.display = 'block';
      box.textContent = data.joinToken;
      copyText(data.joinToken);
      loadAll();
    }

    async function exportSyncBundle() {
      const res = await fetch('/api/federation/export', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      const box = document.getElementById('fedTokenBox');
      box.style.display = 'block';
      box.textContent = JSON.stringify(data, null, 2);
      showToast(t('toastBundleGen') + ' (' + data.scopesCount + ' scopes)!');
    }

    async function joinFederation() {
      const joinToken = document.getElementById('fedJoinInput').value.trim();
      if (!joinToken) return;
      const res = await fetch('/api/federation/join', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ joinToken })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      showToast(t('toastHandshakeDone'));
      loadAll();
    }

    async function revealWebhookSecret() {
      const res = await fetch('/api/webhook-secret');
      if (!res.ok) return;
      const data = await res.json();
      document.getElementById('webhookSecretBox').textContent = data.webhookSecret;
      copyText(data.webhookSecret);
    }

    async function runDoctor(showFeedback = false) {
      const btn = document.getElementById('btnRunDoctor');
      if (btn) {
        btn.disabled = true;
        btn.textContent = t('doctorChecking');
      }
      try {
        const res = await fetch('/api/doctor');
        if (!res.ok) return;
        const data = await res.json();
        const items = data.diagnostics || [];
        const checkedTime = data.checkedAt ? new Date(data.checkedAt).toLocaleTimeString() : '';
        document.getElementById('doctorReportBox').innerHTML = items.length
          ? \`<div style="font-size:11.5px;color:var(--muted);margin-bottom:10px;">\${esc(t('lastCheck'))} <strong>\${esc(checkedTime)}</strong> · \${esc(t('overallStatus'))} <span class="badge \${data.overallHealth === 'healthy' ? 'success' : data.overallHealth === 'warning' ? 'warning' : 'danger'}">\${esc(t('sev_' + (data.overallHealth || 'healthy')))}</span></div>\` +
            items.map(d => \`
            <div style="padding:12px 14px;margin-bottom:8px;border-radius:10px;background:var(--bg-subtle);border:1px solid var(--border);">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
                <strong>\${esc(d.target === 'server' ? t('doctorServer') : d.target)}</strong>
                <div style="display:flex;gap:6px;align-items:center;">
                  <span class="badge \${d.severity === 'healthy' ? 'success' : d.severity === 'warning' ? 'warning' : 'danger'}">\${esc(t('sev_' + d.severity))}</span>
                  \${d.severity !== 'healthy' && d.target !== 'server' ? \`<button class="secondary" style="padding:3px 9px;font-size:11px;" onclick="appAction('\${esc(d.target)}','restart')">\${esc(t('btnRestartContainer'))}</button>\` : ''}
                </div>
              </div>
              <div style="font-size:13px;margin-top:6px;">\${esc(docText(d, 'summary'))}</div>
              \${docText(d, 'recommendation') ? \`<div style="font-size:12px;color:var(--accent-text);margin-top:4px;">💡 \${esc(docText(d, 'recommendation'))}</div>\` : ''}
            </div>
          \`).join('')
          : '<div style="color:var(--muted);font-size:13px;">' + esc(t('emptyDoctor')) + '</div>';
        if (showFeedback) {
          showToast(t('doctorDoneToast') + ' (' + items.length + ' containers)!');
        }
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = t('btnRunDoctor');
        }
      }
    }

    // Publish screen: pick the repository from the GitHub list (like Vercel's import) when a token is saved.
    let ghRepos = null;
    let ghReposLoading = false;
    async function renderRepoPick() {
      const box = document.getElementById('depRepoPick');
      if (!box || !lastStatus) return;
      const hasToken = Boolean((lastStatus.systemSecretsConfigured || {}).GITHUB_TOKEN);
      if (!hasToken) {
        box.innerHTML = '<p class="ofs-note">' + esc(t('pickNoToken')) + ' <a href="#connect/github">' + esc(t('pickConnect')) + '</a></p>';
        return;
      }
      if (ghRepos === null && !ghReposLoading) {
        ghReposLoading = true;
        box.innerHTML = '<p class="ofs-note">' + esc(t('pickLoading')) + '</p>';
        try {
          const res = await fetch('/api/connections/github/repos');
          const data = await res.json().catch(function () { return {}; });
          if (!res.ok) { box.innerHTML = '<p class="ofs-note" style="color:var(--danger)">' + esc((currentLang === 'pt' && data.errorPt) || data.error || ('HTTP ' + res.status)) + '</p>'; ghReposLoading = false; return; }
          ghRepos = data.repos || [];
        } finally { ghReposLoading = false; }
      }
      if (!ghRepos) return;
      if (!ghRepos.length) { box.innerHTML = '<p class="ofs-note">' + esc(t('pickEmpty')) + '</p>'; return; }
      box.innerHTML = '<label class="field-label" for="depPick">' + esc(t('pickLabel')) + '</label>' +
        '<select id="depPick" onchange="pickRepo(this.value)"><option value="">' + esc(t('pickChoose')) + '</option>' +
        ghRepos.map(function (r) {
          return '<option value="' + esc(r.fullName) + '">' + esc(r.fullName) + (r.private ? ' · ' + esc(t('pickPrivate')) : '') + (r.language ? ' · ' + esc(r.language) : '') + '</option>';
        }).join('') + '</select><p class="ofs-note" id="depPickNote" style="margin-top:4px;"></p>';
    }
    function pickRepo(name) {
      const r = (ghRepos || []).find(function (x) { return x.fullName === name; });
      if (!r) return;
      document.getElementById('depRepo').value = r.fullName;
      document.getElementById('depBranch').value = r.defaultBranch || 'main';
      const app = document.getElementById('depApp');
      if (!app.value.trim()) app.value = r.fullName.split('/')[1].toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
      const note = document.getElementById('depPickNote');
      if (note) note.textContent = r.private ? t('pickPrivateNote') : '';
    }

    // Result of a publish, in plain words: what happened and the next step (or what to fix).
    function deployResultHtml(ok, appName, data) {
      if (ok) {
        const urls = ((data && data.app && data.app.domains) || []).map(function (d) { return d.url; }).filter(Boolean);
        const a = esc(JSON.stringify(appName));
        return '<div class="dep-result ok"><strong>' + esc(t('dfOkTitle').split('{app}').join(appName)) + '</strong>' +
          (urls.length
            ? '<p>' + esc(t('dfOkLive')) + ' ' + urls.map(function (u) { return '<a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(u) + '</a>'; }).join(', ') + '</p>'
            : '<p>' + esc(t('dfOkNext')) + '</p>') +
          '<div class="dep-result-actions">' +
          (urls.length ? '' : '<button onclick="exposeNext(' + a + ')">' + esc(t('dfOkExpose')) + '</button>') +
          '<button class="secondary" onclick="goTo(\\'overview\\', \\'list\\')">' + esc(t('dfOkList')) + '</button></div></div>';
      }
      const f = (data && data.failure) || {};
      const kind = I18N.en['df_' + f.kind] ? f.kind : 'other';
      const action = f.action || (kind === 'other' ? 'doctor' : '');
      const go = { github: "goTo('connect', 'github')", options: 'openDeployOptions()', guide: "goTo('guide', 'firstapp')", trash: "goTo('overview', 'list')", doctor: "goTo('doctor')" }[action];
      return '<div class="dep-result err"><strong>' + esc(t('df_' + kind)) + '</strong><p>' + esc(t('dfh_' + kind)) + '</p>' +
        (go ? '<div class="dep-result-actions"><button class="secondary" onclick="' + go + '">' + esc(t('dfAct_' + action)) + '</button></div>' : '') +
        '<details><summary>' + esc(t('dfDetails')) + '</summary><pre>' + esc((data && data.error) || '') + '</pre></details></div>';
    }
    function openDeployOptions() {
      const d = document.querySelector('#tab-overview details.dep-more');
      if (!d) return;
      d.open = true;
      d.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    function exposeNext(appName) {
      goTo('overview', 'expose');
      const el = document.getElementById('expApp');
      if (el) { el.value = appName; el.focus(); }
    }

    async function deployNewApp() {
      const appName = document.getElementById('depApp').value.trim();
      const repoSource = document.getElementById('depRepo').value.trim();
      const branch = document.getElementById('depBranch').value.trim() || 'main';
      const memoryLimit = document.getElementById('depMem').value.trim() || undefined;
      const cpuLimit = document.getElementById('depCpu').value.trim() || undefined;
      const withPostgres = document.getElementById('depPg').checked;
      const withRedis = document.getElementById('depRedis').checked;
      const healthcheckPath = document.getElementById('depHealth').value.trim() || undefined;
      // Only send the switch when ticked: an unticked box keeps what the app already has.
      const skipHealthcheck = document.getElementById('depNoHealth').checked ? true : undefined;
      if (!appName || !repoSource) return;
      // Storage and e-mail go into the app's vault first, so this deploy already starts with them.
      if (document.getElementById('depStorage').checked && !(await postJson('/api/storage', { appName }))) return;
      if (document.getElementById('depEmail').checked && !(await postJson('/api/email/provision', { appName }))) return;
      const btn = document.getElementById('btnDeploy');
      btn.textContent = t('toastDeploying');
      btn.disabled = true;
      document.getElementById('depResult').innerHTML = '';
      try {
        setTimeout(pollDeploys, 800);
        const res = await fetch('/api/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ appName, repoSource, branch, withPostgres, withRedis, memoryLimit, cpuLimit, healthcheckPath, skipHealthcheck })
        });
        const data = await res.json().catch(function () { return {}; });
        const box = document.getElementById('depResult');
        if (!res.ok) {
          if (!data.failure && !data.error) data.error = 'HTTP ' + res.status;
          box.innerHTML = deployResultHtml(false, appName, data);
        } else {
          if (document.getElementById('depPoll').checked) await postJson('/api/poll', { appName, on: true });
          box.innerHTML = deployResultHtml(true, appName, data);
          showToast(t('toastDeployDone') + appName);
          loadAll();
        }
        box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } finally {
        btn.textContent = t('btnDeploy');
        btn.disabled = false;
      }
    }

    async function exposeApp() {
      const appName = document.getElementById('expApp').value.trim();
      const mode = document.getElementById('expMode').value;
      const subdomain = document.getElementById('expSub').value.trim() || undefined;
      if (!appName) return;
      const res = await fetch('/api/expose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName, mode, subdomain })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) { if (!data.confirmationRequired) alert((currentLang === 'pt' && data.errorPt) || data.error || ('HTTP ' + res.status)); return; }
      showToast(t('toastExposed') + data.url);
      loadAll();
    }

    async function toggleFollow(on) {
      const data = await postJson('/api/poll', { appName: 'paasmcp-dashboard', on });
      if (!data) return;
      showToast(on ? t('followOn') : t('followOff'));
      loadAll();
    }

    let logsApp = '';
    async function appAction(appName, action) {
      const res = await fetch('/api/lifecycle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName, action })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        if (data.confirmationRequired) return;
        const err = String(data.error || ('HTTP ' + res.status));
        return alert(/No previous image snapshot/.test(err) ? t('lifeErrNoPrevious') : t('lifeErr') + '\\n\\n' + err);
      }
      if (action === 'logs') {
        logsApp = appName;
        const card = document.getElementById('logsCard');
        card.style.display = 'block';
        document.getElementById('logsTitle').textContent = t('logsTitle') + ' · ' + appName;
        const out = String(data.output || '').trim();
        document.getElementById('logsHint').textContent = out ? t('logsHint') : '';
        document.getElementById('logsBox').textContent = out || t('logsEmpty');
        card.scrollIntoView({ behavior: 'smooth' });
      } else {
        const msg = I18N.en['life_' + action] ? t('life_' + action).split('{app}').join(appName) : String(data.output || '');
        showToast('✅ ' + msg + (data.pool === 'updating' ? ' ' + t('lifePoolUpdating') : data.pool === 'failed' ? ' ' + t('lifePoolFailed') : ''));
        loadAll();
      }
    }

    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      location.reload();
    }

    applyPreferences();
    loadAll();
    pollDeploys();
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') pollDeploys(); });
  </script>
</body>
</html>`;
}

// Pinned base image; tools are installed once at build time, never on every start.
// The tailscale command talks to the server's tailscaled through its socket (mounted when present).
// It is optional: a mirror without it still builds the dashboard, and Tailscale then says how to do it by hand.
const DASHBOARD_DOCKERFILE = `FROM node:22.11.0-alpine3.20
RUN apk add --no-cache docker-cli docker-cli-compose git openssh-client
RUN apk add --no-cache tailscale || true
`;

/** Builds the dashboard image once per Dockerfile version (tag = content hash). */
export function ensureDashboardImage(): string {
  const tag = `paasmcp/dashboard:${crypto.createHash("sha256").update(DASHBOARD_DOCKERFILE).digest("hex").slice(0, 12)}`;
  try {
    execFileSync("docker", ["image", "inspect", tag], { stdio: "ignore" });
  } catch {
    execFileSync("docker", ["build", "-t", tag, "-"], { input: DASHBOARD_DOCKERFILE, stdio: ["pipe", "pipe", "pipe"] });
  }
  return tag;
}

export function ensureDashboardBackgroundService(
  port = 4099,
  /** Code to run; default: the followed release (dashboard follow), else this installation's folder. */
  code?: { dir: string; commit?: string; branch?: string }
): {
  url: string;
  localPort: number;
  containerName: string;
  codeDir: string;
} {
  ensureDockerNetwork();
  getOrCreateDashboardToken();
  const dashDir = path.join(PAAS_DATA_DIR, "dashboard-service");
  fs.mkdirSync(dashDir, { recursive: true, mode: 0o700 });

  const run = code || followedCode() || { dir: path.resolve(path.dirname(new URL(import.meta.url).pathname), "..") };
  const projectRoot = run.dir;

  const image = ensureDashboardImage();
  const tsDir = tailscaleSocketDir();
  const composePath = path.join(dashDir, "compose.yaml");
  const composeContent = `services:
  dashboard:
    image: ${image}
    container_name: paasmcp-dashboard
    restart: unless-stopped
${WATCHTOWER_OFF_COMPOSE}    working_dir: /app
    command: ["node", "dist/cli.js", "dashboard", "serve", "--port", "${port}", "--host", "0.0.0.0"]
    environment:
      PAASMCP_ROOT: "${HOMELAB_ROOT}"
      PAASMCP_IN_DASHBOARD: "1"
    ports:
      - "127.0.0.1:${port}:${port}"
    volumes:
      - ${projectRoot}:/app:ro
      - ${HOMELAB_ROOT}:${HOMELAB_ROOT}
      - /var/run/docker.sock:/var/run/docker.sock${tsDir ? `\n      - ${tsDir}:${tsDir}` : ""}
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`;
  fs.writeFileSync(composePath, composeContent, { mode: 0o600 });

  execFileSync("docker", ["compose", "-f", composePath, "up", "-d"], {
    cwd: dashDir,
    stdio: "pipe",
  });

  const state = loadState();
  const now = new Date().toISOString();
  state.apps["paasmcp-dashboard"] = {
    name: "paasmcp-dashboard",
    branch: run.branch || "main",
    ...(run.commit ? { lastCommit: run.commit.slice(0, 7), lastCommitSha: run.commit } : {}),
    localPort: port,
    internalPort: port,
    containerName: "paasmcp-dashboard",
    appDir: dashDir,
    runtimeType: "paasmcp-control-plane",
    databases: [],
    domains: state.apps["paasmcp-dashboard"]?.domains || [],
    createdAt: state.apps["paasmcp-dashboard"]?.createdAt || now,
    updatedAt: now,
    status: "running",
  };
  saveState(state);
  syncHomepageDashboard();

  return {
    url: `http://127.0.0.1:${port}`,
    localPort: port,
    containerName: "paasmcp-dashboard",
    codeDir: projectRoot,
  };
}
