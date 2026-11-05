import { backupAppVolumes, syncOffsite, testRestore } from "./backup.js";
import { deploySummary } from "./deploys.js";
import { getEmailRelay, provisionEmail, sendTestEmail, setEmailRelay } from "./email.js";
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
import { applyUpdate, checkUpdates, Component, PINNED } from "./updater.js";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DOCKER_NETWORK, HOMELAB_ROOT, PAAS_DATA_DIR, loadState, sanitizeSlug, saveState, withStateLock, WATCHTOWER_OFF_COMPOSE } from "./config.js";
import { getDashboardTotpSecret, isDashboardTwoFactorEnabled, verifyTotp } from "./totp.js";
import {
  authorizeHuman,
  ConfirmationRequiredError,
  decideApproval,
  DASHBOARD_APP_NAME,
  ForbiddenActionError,
  listApprovals,
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
import { exposeApplication } from "./exposure.js";
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
import { getSystemStatusSummary } from "./mcp-server.js";
import { followedCode, followStatus, originOf, setFollow } from "./selfupdate.js";
import { startPollLoop } from "./pollloop.js";
import {
  deleteSecretKey,
  getSecrets,
  listMaskedSecrets,
  setSecretEntries,
  timingSafeCompare,
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
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(status));
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

        if (pathname === "/api/deploy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const trusted = typeof body.trusted === "boolean" ? body.trusted : undefined;
          if (trusted && !loadState().apps[sanitizeSlug(String(body.appName))]?.trusted) {
            confirmFromBody("app.trust", { appName: sanitizeSlug(String(body.appName)) }, body);
          }
          const result = await deployApp({
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

        if (pathname === "/api/lifecycle" && req.method === "POST") {
          const body = await readJsonBody(req);
          const action = body.action as AppLifecycleAction;
          if (action === "destroy" || action === "purge") {
            confirmFromBody(`app.${action}`, { appName: String(body.appName) }, body);
          }
          const output = manageAppLifecycle(
            String(body.appName),
            action,
            body.tailLines ? Number(body.tailLines) : 120
          );
          // Copies on helper PCs follow this server's copy, in the background.
          let poolNote = "";
          const lifeSlug = sanitizeSlug(String(body.appName));
          if (loadState().apps[lifeSlug]?.pool && ["restart", "stop", "start", "rollback", "destroy"].includes(action)) {
            try {
              startPoolJob(action, lifeSlug, (log) => poolAfterLifecycle(lifeSlug, action, log));
              poolNote = "\nCopies on helper PCs are being updated (Helpers screen).";
            } catch (err) {
              poolNote = `\nCopies on helper PCs were not updated: ${err instanceof Error ? err.message : String(err)}`;
            }
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ output: output + poolNote }));
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
        res.writeHead(err instanceof ForbiddenActionError ? 403 : 500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: err instanceof Error ? err.message : String(err),
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
      --bg: #07090e;
      --bg-elevated: #0d1117;
      --bg-subtle: #131924;
      --card: #0d1117;
      --card-hover: #131926;
      --border: #1e2638;
      --border-strong: #2d384e;
      --text: #f1f5f9;
      --muted: #8896aa;
      --input-bg: #07090e;
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
      --code-bg: #05070b;
      --code-text: #00f0ff;
      --shadow: 0 4px 24px -2px rgba(0, 0, 0, 0.55);
    }
    [data-theme="light"] {
      --bg: #f8fafc;
      --bg-elevated: #ffffff;
      --bg-subtle: #f1f5f9;
      --card: #ffffff;
      --card-hover: #f8fafc;
      --border: #e2e8f0;
      --border-strong: #cbd5e1;
      --text: #0f172a;
      --muted: #64748b;
      --input-bg: #ffffff;
      --accent: #0284c7;
      --accent-hover: #0369a1;
      --accent-soft: rgba(2, 132, 199, 0.08);
      --accent-text: #0284c7;
      --success: #059669;
      --success-soft: rgba(5, 150, 105, 0.08);
      --warning: #d97706;
      --warning-soft: rgba(217, 119, 6, 0.08);
      --danger: #dc2626;
      --danger-soft: rgba(220, 38, 38, 0.08);
      --code-bg: #f1f5f9;
      --code-text: #0369a1;
      --shadow: 0 2px 14px rgba(0, 0, 0, 0.06);
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

    /* Horizontal Subnav Tabs */
    .console-subnav {
      background: var(--card);
      border-bottom: 1px solid var(--border);
      padding: 0 24px;
      display: flex;
      align-items: center;
      gap: 4px;
      overflow-x: auto;
      scrollbar-width: thin;
    }
    .nav-tab {
      display: flex;
      align-items: center;
      gap: 7px;
      padding: 12px 13px;
      font-size: 13px;
      font-weight: 500;
      color: var(--muted);
      border-bottom: 2px solid transparent;
      text-decoration: none;
      cursor: pointer;
      background: transparent;
      border-top: none;
      border-left: none;
      border-right: none;
      border-radius: 0;
      white-space: nowrap;
      transition: color 0.15s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.15s cubic-bezier(0.4, 0, 0.2, 1), transform 0.15s ease;
    }
    .nav-tab:hover {
      color: var(--text);
      background: transparent;
      transform: translateY(-1px);
    }
    .nav-tab.active {
      color: var(--accent);
      font-weight: 600;
      border-bottom-color: var(--accent);
      background: transparent;
      transform: none;
    }
    .nav-icon {
      width: 14px;
      height: 14px;
      flex-shrink: 0;
      stroke-width: 2;
      color: var(--muted);
      transition: color 0.15s ease, stroke 0.15s ease;
    }
    .nav-tab:hover .nav-icon {
      color: var(--text);
    }
    .nav-tab.active .nav-icon {
      color: var(--accent);
    }
    .nav-counter {
      padding: 1px 7px;
      font-size: 11px;
      font-weight: 600;
      line-height: 16px;
      border-radius: 10px;
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      color: var(--muted);
      transition: all 0.15s ease;
    }
    .nav-tab.active .nav-counter {
      color: var(--accent);
      border-color: var(--accent);
      background: var(--accent-soft);
    }

    /* Two-Column Workspace Container */
    .console-container {
      max-width: 1400px;
      margin: 22px auto;
      padding: 0 24px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 300px;
      gap: 24px;
      align-items: start;
    }
    @media (max-width: 980px) {
      .console-container {
        grid-template-columns: minmax(0, 1fr);
        padding: 0 16px;
      }
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
    }

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
      <span class="host-badge-capsule" id="topHostCapsule">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
        <span>Host: <strong id="topHostname" style="font-weight:600;">-</strong></span>
      </span>
      <span class="engine-status-pill">
        <span class="engine-status-dot"></span>
        <span id="topHealthBadge">Sistema Online</span>
      </span>
      <span class="host-badge-capsule" id="topDomainBadge">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
        <span>Domínio: -</span>
      </span>
      ${safeCfEmail ? `<span class="engine-status-pill" style="color:var(--accent-text);border-color:rgba(0,240,255,0.35);background:var(--accent-soft);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:2px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> Zero Trust: ${safeCfEmail}</span>` : ""}
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <span id="sidebarSubtitle" style="display:none;">Agent-First Micro-PaaS</span>
      <button class="secondary" onclick="toggleLang()" id="langBtn">🇧🇷 PT-BR</button>
      <button class="secondary" onclick="toggleTheme()" id="themeBtn">🌙 Escuro</button>
      <button class="secondary" onclick="loadAll()" id="btnRefresh">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:2px;"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
        <span>Atualizar</span>
      </button>
      <button class="danger" onclick="logout()" id="btnLogout">Sair</button>
    </div>
  </header>

  <!-- Horizontal Subnav Tabs with Counters -->
  <nav class="console-subnav" id="subnavTabs">
    <button class="nav-tab nav-btn" onclick="switchTab('home', this)" id="navHome">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
      <span class="nav-label">Início</span>
    </button>
    <button class="nav-tab nav-btn active" onclick="switchTab('overview', this)" id="navOverview">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
      <span class="nav-label">Aplicações</span>
      <span class="nav-counter" id="tabCountApps">0</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('databases', this)" id="navDatabases">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>
      <span class="nav-label">Bancos de Dados</span>
      <span class="nav-counter" id="tabCountDbs">0</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('vault', this)" id="navVault">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
      <span class="nav-label">Cofre &amp; Chaves</span>
      <span class="nav-counter" id="tabCountVault">0</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('agents', this)" id="navAgents">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
      <span class="nav-label">MCP &amp; IA</span>
      <span class="nav-counter" id="tabCountAgents">15</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('mirror', this)" id="navMirror">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"></polyline><path d="M3 11V9a4 4 0 0 1 4-4h14"></path><polyline points="7 23 3 19 7 15"></polyline><path d="M21 13v2a4 4 0 0 1-4 4H3"></path></svg>
      <span class="nav-label">Segundo Servidor</span>
      <span class="nav-counter" id="tabCountMirror">0</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('pool', this)" id="navPool">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
      <span class="nav-label">Ajudantes</span>
      <span class="nav-counter" id="tabCountPool">0</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('doctor', this)" id="navDoctor">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
      <span class="nav-label">Diagnóstico</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('email', this)" id="navEmail">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
      <span class="nav-label">E-mail</span>
    </button>
    <button class="nav-tab nav-btn" onclick="switchTab('updates', this)" id="navUpdates">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
      <span class="nav-label">Atualizações</span>
    </button>
  </nav>

  <!-- Two-Column Workspace Container -->
  <div class="console-container">
    <div class="console-main">
      <!-- TAB: HOME / SETUP -->
      <div class="tab-pane" id="tab-home">
        <div class="card">
          <div class="card-header">
            <h2 id="homeTitle">🏠 Início</h2>
            <p class="card-desc" data-i18n="homeDesc"></p>
          </div>
          <div class="grid-2" id="homeTiles"></div>
        </div>
        <div class="card">
          <div class="card-header">
            <h2 data-i18n="stepsTitle"></h2>
            <p class="card-desc" data-i18n="stepsDesc"></p>
          </div>
          <div id="homeSteps"></div>
        </div>
        <div class="card">
          <div class="card-header">
            <h2 id="setupTitle">🧭 Primeira configuração: o que você precisa?</h2>
            <p class="card-desc" id="setupDesc">Configure só as integrações que pretende usar. O PaaSMCP funciona localmente sem tokens de terceiros; os valores secretos são guardados no Cofre.</p>
          </div>
          <div class="grid-2">
            <div class="arch-box">
              <h3 id="setupGithubTitle">🐙 GitHub — opcional</h3>
              <p id="setupGithubDesc">Para repositório privado, use uma Deploy Key SSH somente leitura. Copie a chave pública no quadro do webhook, no fim da tela Apps, e adicione em Settings → Deploy keys. Para registrar automaticamente a chave ou clonar via HTTPS, salve <code>GITHUB_TOKEN</code> no escopo <code>system</code>. Um fine-grained token precisa de acesso apenas ao repositório e <em>Administration: read and write</em>; a chave criada continua somente leitura.</p>
              <p><a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noreferrer" id="setupGithubLink">Criar fine-grained token ↗</a> · <a href="https://docs.github.com/en/rest/deploy-keys/deploy-keys#create-a-deploy-key" target="_blank" rel="noreferrer" id="setupGithubDocsLink">Permissões da API ↗</a></p>
            </div>
            <div class="arch-box">
              <h3 id="setupCloudTitle">☁️ Cloudflare — opcional para publicar</h3>
              <p id="setupCloudDesc">Para Tunnel + DNS: token com Account → Cloudflare Tunnel: Edit e Zone → DNS: Edit, restrito à conta e zona necessárias. Para proteção Zero Trust, inclua também Account → Access: Apps and Policies: Edit. Configure Account ID, Tunnel ID, domínio e emails permitidos via <code>paasmcp config</code> ou <code>paas_configure</code>, e salve <code>CF_API_TOKEN</code> no escopo <code>system</code>.</p>
              <p><a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noreferrer" id="setupCloudLink">Criar API token ↗</a> · <a href="https://developers.cloudflare.com/fundamentals/api/get-started/create-token/" target="_blank" rel="noreferrer" id="setupCloudDocsLink">Guia de tokens ↗</a></p>
            </div>
            <div class="arch-box">
              <h3 id="setupLocalTitle">🔐 Acesso e deploy local</h3>
              <p id="setupLocalDesc">O token do painel é criado automaticamente: consulte com <code>paasmcp dashboard token</code>. Para repositório público, privado por SSH ou pasta local, não é necessário token GitHub se adicionar a chave SSH pública ao repositório. Tailscale é alternativa privada e não requer Cloudflare.</p>
            </div>
            <div class="arch-box">
              <h3 id="setupAppTitle">🧩 Segredos e sugestões por aplicação</h3>
              <p id="setupAppDesc">Salve chaves da aplicação no escopo com o slug dela (por exemplo <code>STRIPE_SECRET_KEY</code> ou <code>API_KEY</code>), nunca em <code>system</code>. Se precisar, marque PostgreSQL/Redis no deploy. Depois confira Logs e rode Doctor; exponha como Público só serviços sem login próprio. Use Zero Trust ou Tailscale para ferramentas administrativas.</p>
            </div>
          </div>
          <p class="card-desc" id="setupWebhookNote">Auto-deploy por webhook é opcional: cadastre no GitHub a URL mostrada no fim da tela Apps, evento Push e o secret mostrado pelo painel. Não cole tokens no chat; insira-os no Cofre.</p>
        </div>
      </div>

      <!-- TAB 2: OVERVIEW, APPS, DEPLOY & EXPOSE -->
      <div class="tab-pane active" id="tab-overview">
        <div class="card" style="margin-bottom:20px;">
          <div class="card-header" style="margin-bottom:14px;">
            <h2>
              <span id="appsTitle">📦 Aplicações Hospedadas &amp; Métricas</span>
              <span class="badge" id="appsBadgeCount">0 apps</span>
            </h2>
            <p class="card-desc" id="appsDesc">Containers isolados em <code>127.0.0.1:4000-4998</code> com suporte a Rollback em 1s, limites de CPU/RAM e Docker Compose multi-serviço.</p>
          </div>
          <div class="console-search-bar">
            <input class="console-search-input" id="appSearchInput" placeholder="Buscar aplicações por nome, stack ou porta..." oninput="filterApps(this.value)" />
            <button class="secondary" onclick="fillDeployPreset('saas', document.getElementById('presetSaas')); const depEl = document.getElementById('depApp'); if (depEl) { depEl.scrollIntoView({behavior:'smooth'}); depEl.focus(); }" style="padding:6px 12px;font-size:12.5px;">+ Novo Deploy</button>
          </div>
          <div class="apps-card-list" id="appsTable">
            <div style="padding: 24px; text-align: center; color: var(--muted);">...</div>
          </div>
        </div>

          <div class="row">
            <div class="card">
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
                  <label class="field-label" id="lblDepApp">Slug da Aplicação</label>
                  <input id="depApp" placeholder="ex: meu-saas" />
                </div>
                <div>
                  <label class="field-label" id="lblDepRepo">Repositório GitHub ou Caminho</label>
                  <input id="depRepo" placeholder="ex: seu-usuario/meu-repo" />
                </div>
                <div>
                  <label class="field-label" id="lblDepBranch">Branch Git</label>
                  <input id="depBranch" placeholder="main" value="main" />
                </div>
              </div>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblDepMem">Limite de RAM (Opcional)</label>
                  <input id="depMem" placeholder="ex: 512m ou 1g" />
                </div>
                <div>
                  <label class="field-label" id="lblDepCpu">Limite de vCPUs (Opcional)</label>
                  <input id="depCpu" placeholder="ex: 0.5 ou 1.0" />
                </div>
                <div>
                  <label class="field-label" data-i18n="lblDepHealth"></label>
                  <input id="depHealth" placeholder="/" />
                </div>
              </div>
              <div style="display:flex; gap:18px; align-items:center; margin-bottom:14px; font-size:12.5px; flex-wrap:wrap;">
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depPg" style="width:auto;" />
                  <span id="lblDepPg">Provisionar PostgreSQL 16 (injeta <code>DATABASE_URL</code>)</span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depRedis" style="width:auto;" />
                  <span id="lblDepRedis">Provisionar Redis 7 (injeta <code>REDIS_URL</code>)</span>
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
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
                  <input type="checkbox" id="depNoHealth" style="width:auto;" />
                  <span data-i18n="lblDepNoHealth"></span>
                </label>
              </div>
              <button onclick="deployNewApp()" id="btnDeploy">🚀 Fazer Build & Deploy</button>
            </div>

            <div class="card">
              <div class="card-header">
                <h2 id="exposeTitle">🌐 Expor Aplicação (Cloudflare Tunnel / Zero Trust / Tailscale)</h2>
                <p class="card-desc" id="exposeDesc">Configura rota no Cloudflare Tunnel + DNS CNAME proxied + política Zero Trust sem abrir nenhuma porta no roteador.</p>
              </div>
              <div class="examples-bar">
                <span id="lblQuickFillExpose">⚡ Modos:</span>
                <button class="chip" onclick="fillExposeMode('public')" id="chipModePublic">🌍 Público (HTTPS Aberto)</button>
                <button class="chip" onclick="fillExposeMode('zero-trust')" id="chipModeZT">🛡️ Zero Trust (OTP por E-mail)</button>
                <button class="chip" onclick="fillExposeMode('tailscale')" id="chipModeTS">🔒 Tailscale (VPN Privada)</button>
              </div>
              <div class="form-grid">
                <div>
                  <label class="field-label" id="lblExpApp">Aplicação</label>
                  <input id="expApp" list="hostedAppsList" placeholder="ex: meu-saas" />
                  <datalist id="hostedAppsList"></datalist>
                </div>
                <div>
                  <label class="field-label" id="lblExpMode">Modo de Segurança</label>
                  <select id="expMode">
                    <option value="public" id="optPublic">Cloudflare Público (HTTPS aberto)</option>
                    <option value="zero-trust" id="optZT">Cloudflare Zero Trust (Login PIN por E-mail)</option>
                    <option value="tailscale" id="optTS">Tailscale Serve (Privado na Tailnet)</option>
                  </select>
                </div>
                <div>
                  <label class="field-label" id="lblExpSub">Subdomínio</label>
                  <input id="expSub" placeholder="ex: app" />
                </div>
              </div>
              <button onclick="exposeApp()" id="btnExpose">🔗 Publicar Endereço</button>
            </div>
          </div>

          <div class="card" id="scaleCard">
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
              <h3 data-i18n="scaleDiaryTitle" style="margin-top:18px;"></h3>
              <p class="card-desc" data-i18n="scaleDiaryDesc"></p>
              <div id="scaleDiary"></div>
              <div class="form-grid" style="grid-template-columns:minmax(0,320px);margin-top:8px;">
                <div><label class="field-label" for="scaleLang" data-i18n="lblScaleLang"></label>
                  <select id="scaleLang" onchange="saveScaleLang()"><option value="pt">Português</option><option value="en">English</option></select></div>
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <h2 id="whTitle">⚡ Auto-Deploy via GitHub Webhook & Deploy Key SSH</h2>
              <p class="card-desc" id="whDesc">Receba <code>git push</code> do GitHub com validação de assinatura <code>X-Hub-Signature-256</code> em tempo constante para reconstruir seus apps automaticamente.</p>
            </div>
            <div style="margin-bottom:14px;">
              <span class="field-label" id="lblWhUrl">Payload URL do Webhook (adicione no GitHub → Settings → Webhooks):</span>
              <code id="webhookUrlBox" style="display:block;padding:8px 10px;user-select:all;">/api/webhooks/github</code>
            </div>
            <div style="margin-bottom:16px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">
                <span class="field-label" id="lblWhSecret" style="margin:0;">Webhook Secret (HMAC-SHA256):</span>
                <button class="chip" onclick="revealWebhookSecret()" id="btnRevealWhSecret">👁️ Revelar / Copiar Secret</button>
              </div>
              <code id="webhookSecretBox" style="display:block;padding:8px 10px;">••••••••••••</code>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span class="field-label" id="lblSshKey" style="margin:0;">Chave SSH Pública de Deploy (Ed25519):</span>
              <button class="chip" onclick="copySshKey()" id="btnCopySsh">📋 Copiar Chave SSH</button>
            </div>
            <pre id="sshKeyBox" style="margin-top:6px;user-select:all;"></pre>
          </div>
        </div>

        <!-- TAB 2: ENCRYPTED VAULT -->
        <div class="tab-pane" id="tab-vault">
          <div class="card">
            <div class="card-header">
              <h2 id="vaultTitle">🔐 Cofre Criptografado de Variáveis (AES-256-GCM Vault)</h2>
              <p class="card-desc" id="vaultDesc">Cada escopo é criptografado em disco com IV aleatório de 96 bits e tag de autenticação GCM. Valores nunca são exibidos em texto aberto após salvos.</p>
            </div>
            <div class="examples-bar">
              <span id="lblVaultScopes">⚡ Escopos:</span>
              <button class="chip" id="chipSystemScope" onclick="setVaultScope('system')">⚙️ system (Global Tokens)</button>
              <span id="dynamicScopeChips"></span>
            </div>
            <div class="form-grid">
              <div>
                <label class="field-label" id="lblSecScope">Escopo (system ou slug do app)</label>
                <input id="secScope" placeholder="system" value="system" onchange="loadSecrets()" />
              </div>
              <div>
                <label class="field-label" id="lblSecKey">Chave (A-Z, 0-9, _)</label>
                <input id="secKey" placeholder="ex: STRIPE_SECRET_KEY" />
              </div>
              <div>
                <label class="field-label" id="lblSecVal">Valor Secreto</label>
                <input id="secVal" type="password" placeholder="••••••••••••" />
              </div>
            </div>
            <div class="actions" style="margin-bottom:16px;">
              <button onclick="saveSecret()" id="btnSaveSecret">💾 Criptografar & Salvar</button>
              <button class="secondary" onclick="loadSecrets()" id="btnLoadSecrets">🔍 Recarregar Escopo</button>
            </div>
            <div id="secretsList"></div>
          </div>
        </div>

        <!-- TAB 3: DATABASES & ENCRYPTED BACKUPS -->
        <div class="tab-pane" id="tab-databases">
          <div class="card">
            <div class="card-header">
              <h2 data-i18n="offsiteTitle"></h2>
              <p class="card-desc" data-i18n="offsiteDesc"></p>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button onclick="syncOffsiteNow()" id="btnSyncOffsite" data-i18n="btnSyncOffsite"></button>
            </div>
            <details style="margin-top:10px;font-size:12.5px;color:var(--muted);"><summary data-i18n="detailsTech"></summary><p data-i18n="offsiteTech"></p></details>
          </div>
          <div class="card">
            <div class="card-header">
              <h2 data-i18n="storageTitle"></h2>
              <p class="card-desc" data-i18n="storageDesc"></p>
            </div>
            <div id="storageList" style="margin-bottom:10px;"></div>
            <label class="field-label" for="stoApp" data-i18n="lblAppName"></label>
            <input id="stoApp" placeholder="ex: meu-saas" />
            <div style="margin-top:10px;"><button onclick="provisionStorageUi()" data-i18n="btnStorage"></button></div>
          </div>
          <div class="row">
            <div class="card">
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
                  <label class="field-label" id="lblDbEngine">Engine</label>
                  <select id="dbEngine">
                    <option value="postgres" id="optDbPg">PostgreSQL 16 (Isolado por DB + Role)</option>
                    <option value="redis" id="optDbRedis">Redis 7 (DB Lógico Isolado)</option>
                  </select>
                </div>
              </div>
              <button onclick="createDb()" id="btnCreateDb" style="margin-bottom:16px;">+ Provisionar Banco</button>
              <div id="dbList"></div>
            </div>

            <div class="card">
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
                  <label class="field-label" id="lblBakEngine">Engine</label>
                  <select id="bakEngine">
                    <option value="postgres" id="optBakPg">PostgreSQL 16 (pg_dump)</option>
                    <option value="redis" id="optBakRedis">Redis 7 (RDB)</option>
                    <option value="volume">Docker volumes</option>
                  </select>
                </div>
              </div>
              <button onclick="createBackup()" id="btnCreateBackup" style="margin-bottom:16px;">📸 Criar Snapshot Criptografado</button>
              <div id="backupsList"></div>
            </div>
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
          <div class="card">
            <div class="card-header">
              <h2 data-i18n="mirrorTitle"></h2>
              <p class="card-desc" data-i18n="mirrorDesc"></p>
            </div>
            <div id="mirrorStatusBox"></div>
          </div>
          <div class="card" id="pairCard">
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
          <div class="grid-2">
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
          <div class="card">
            <div class="card-header"><h2 data-i18n="autoTitle"></h2><p class="card-desc" data-i18n="autoDesc"></p></div>
            <div id="arbStatusBox" style="margin-bottom:6px;"></div>
            <p class="card-desc" data-i18n="autoBefore"></p>

            <h3 data-i18n="autoStep1" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep1Desc"></p>

            <h3 data-i18n="autoStep2" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep2Desc"></p>
            <pre style="user-select:all;">sudo paasmcp arbiter key</pre>

            <h3 data-i18n="autoStep3" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep3Desc"></p>
            <pre id="arbInstallCmd" style="user-select:all;white-space:pre-wrap;word-break:break-all;"></pre>
            <button class="secondary" onclick="copyText(document.getElementById('arbInstallCmd').textContent)" data-i18n="aiCopy"></button>
            <p class="card-desc" data-i18n="autoStep3Check" style="margin-top:10px;"></p>
            <pre style="user-select:all;">curl http://$(tailscale ip -4):4097/health</pre>
            <p class="card-desc" data-i18n="autoStep3Shared" style="margin-top:10px;"></p>
            <pre style="user-select:all;white-space:pre-wrap;word-break:break-all;" id="arbAddKeyCmd"></pre>

            <h3 data-i18n="autoStep4" style="margin-top:16px;"></h3>
            <p class="card-desc" data-i18n="autoStep4Desc" style="margin-bottom:10px;"></p>
            <label class="field-label" for="mArbiter" data-i18n="lblArbiter"></label>
            <input id="mArbiter" placeholder="http://100.64.0.9:4097" />
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
              <button class="secondary" onclick="arbiterTest()" id="btnArbTest" data-i18n="btnArbTest"></button>
              <button onclick="arbiterSave()" data-i18n="btnArbSave"></button>
            </div>
            <div id="arbTestBox" style="margin-top:10px;"></div>

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
          <div class="card" id="activeCard">
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
          <div class="card">
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
          <div class="card">
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
          <div class="card">
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
          <div class="card">
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
          <div class="card">
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
            <div class="arch-grid" style="margin-top:16px;">
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
              <span id="logsTitle">📜 Logs do Container</span>
              <button class="secondary" id="btnCloseLogs" onclick="document.getElementById('logsCard').style.display='none'">Fechar</button>
            </h2>
          </div>
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
        setupTitle: "🧭 Primeira configuração: o que você precisa?",
        setupDesc: "Configure só as integrações que pretende usar. O PaaSMCP funciona localmente sem tokens de terceiros; os valores secretos são guardados no Cofre.",
        setupGithubTitle: "🐙 GitHub — opcional",
        setupGithubDesc: "Para repositório privado, use uma Deploy Key SSH somente leitura. Copie a chave pública no quadro do webhook, no fim da tela Apps, e adicione em Settings → Deploy keys. Para registrar automaticamente a chave ou clonar via HTTPS, salve <code>GITHUB_TOKEN</code> no escopo <code>system</code>. Um fine-grained token precisa de acesso apenas ao repositório e <em>Administration: read and write</em>; a chave criada continua somente leitura.",
        setupGithubLink: "Criar fine-grained token ↗",
        setupGithubDocsLink: "Permissões da API ↗",
        setupCloudTitle: "☁️ Cloudflare — opcional para publicar",
        setupCloudDesc: "Para Tunnel + DNS: token com Account → Cloudflare Tunnel: Edit e Zone → DNS: Edit, restrito à conta e zona necessárias. Para proteção Zero Trust, inclua também Account → Access: Apps and Policies: Edit. Configure Account ID, Tunnel ID, domínio e emails permitidos via <code>paasmcp config</code> ou <code>paas_configure</code>, e salve <code>CF_API_TOKEN</code> no escopo <code>system</code>.",
        setupCloudLink: "Criar API token ↗",
        setupCloudDocsLink: "Guia de tokens ↗",
        setupLocalTitle: "🔐 Acesso e deploy local",
        setupLocalDesc: "O token do painel é criado automaticamente: consulte com <code>paasmcp dashboard token</code>. Para repositório público, privado por SSH ou pasta local, não é necessário token GitHub se adicionar a chave SSH pública ao repositório. Tailscale é alternativa privada e não requer Cloudflare.",
        setupAppTitle: "🧩 Segredos e sugestões por aplicação",
        setupAppDesc: "Salve chaves da aplicação no escopo com o slug dela (por exemplo <code>STRIPE_SECRET_KEY</code> ou <code>API_KEY</code>), nunca em <code>system</code>. Se precisar, marque PostgreSQL/Redis no deploy. Depois confira Logs e rode Doctor; exponha como Público só serviços sem login próprio. Use Zero Trust ou Tailscale para ferramentas administrativas.",
        setupWebhookNote: "Auto-deploy por webhook é opcional: cadastre no GitHub a URL mostrada no fim da tela Apps, evento Push e o secret mostrado pelo painel. Não cole tokens no chat; insira-os no Cofre.",
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
        lblQuickFillDeploy: "⚡ Presets:",
        lblDepApp: "Slug da Aplicação",
        lblDepRepo: "Repositório GitHub ou Caminho",
        lblDepBranch: "Branch Git",
        lblDepMem: "Limite de RAM (Opcional)",
        lblDepCpu: "Limite de vCPUs (Opcional)",
        lblDepPg: "Provisionar PostgreSQL 16 (injeta <code>DATABASE_URL</code>)",
        lblDepRedis: "Provisionar Redis 7 (injeta <code>REDIS_URL</code>)",
        btnDeploy: "🚀 Fazer Build & Deploy",
        exposeTitle: "🌐 Expor Aplicação (Cloudflare Tunnel / Zero Trust / Tailscale)",
        exposeDesc: "Configura rota no Cloudflare Tunnel + DNS CNAME proxied + política Zero Trust sem abrir nenhuma porta no roteador.",
        lblQuickFillExpose: "⚡ Modos:",
        chipModePublic: "🌍 Público (HTTPS Aberto)",
        chipModeZT: "🛡️ Zero Trust (OTP por E-mail)",
        chipModeTS: "🔒 Tailscale (VPN Privada)",
        lblExpApp: "Aplicação",
        lblExpMode: "Modo de Segurança",
        optPublic: "Cloudflare Público (HTTPS aberto)",
        optZT: "Cloudflare Zero Trust (Login PIN por E-mail)",
        optTS: "Tailscale Serve (Privado na Tailnet)",
        lblExpSub: "Subdomínio",
        btnExpose: "🔗 Publicar Endereço",
        vaultTitle: "🔐 Cofre Criptografado de Variáveis (AES-256-GCM Vault)",
        vaultDesc: "Cada escopo é criptografado em disco com IV aleatório de 96 bits e tag de autenticação GCM. Valores nunca são exibidos em texto aberto após salvos.",
        lblVaultScopes: "⚡ Escopos:",
        lblSecScope: "Escopo (system ou slug do app)",
        lblSecKey: "Chave (A-Z, 0-9, _)",
        lblSecVal: "Valor Secreto",
        btnSaveSecret: "💾 Criptografar & Salvar",
        btnLoadSecrets: "🔍 Recarregar Escopo",
        dbTitle: "🗄️ Provisionar Banco Multi-Tenant Isolado",
        dbDesc: "Cria banco, role exclusiva e injeta <code>DATABASE_URL</code> / <code>REDIS_URL</code> diretamente no Cofre do app.",
        lblDbApp: "Aplicação",
        lblDbEngine: "Engine",
        optDbPg: "PostgreSQL 16 (Isolado por DB + Role)",
        optDbRedis: "Redis 7 (DB Lógico Isolado)",
        btnCreateDb: "+ Provisionar Banco",
        backupsTitle: "🛡️ Snapshots & Restore Criptografados (AES-256-GCM)",
        backupsDesc: "Gera <code>pg_dump</code> ou snapshot Redis, criptografa com a chave mestra do Vault e verifica integridade SHA-256 antes do restore.",
        lblBakApp: "App para Backup",
        lblBakEngine: "Engine",
        optBakPg: "PostgreSQL 16 (pg_dump)",
        optBakRedis: "Redis 7 (RDB)",
        btnCreateBackup: "📸 Criar Snapshot Criptografado",
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
        lblWhUrl: "Payload URL do Webhook (adicione no GitHub → Settings → Webhooks):",
        lblWhSecret: "Webhook Secret (HMAC-SHA256):",
        btnRevealWhSecret: "👁️ Revelar / Copiar Secret",
        lblSshKey: "Chave SSH Pública de Deploy (Ed25519):",
        btnCopySsh: "📋 Copiar Chave SSH",
        doctorTitle: "🩺 PaaSMCP Doctor — Diagnóstico Automático de Containers",
        doctorDesc: "Verifica <code>OOMKilled</code> (falta de RAM), loops de reinicialização, códigos de saída e saúde de todos os serviços.",
        btnRunDoctor: "🔍 Executar Diagnóstico Agora",
        agentsTitle: "🤖 Como Conectar seu Agente de IA (Clientes MCP Compatíveis)",
        agentsDesc: "O PaaSMCP expõe <strong>15 ferramentas MCP nativas</strong> via stdio JSON-RPC. Copie a configuração abaixo para que sua IA opere todo o servidor por você:",
        logsTitle: "📜 Logs do Container",
        btnCloseLogs: "Fechar",
        statHost: "Servidor Host",
        statDisk: "Disco:",
        statMem: "Memória Livre / Total",
        statIdle: "0 MB Idle Daemon",
        statAppsDbs: "Apps & Bancos Isolados",
        statSnapshots: "Snapshots Criptografados",
        statSecurityFed: "Segurança & Federação",
        presetSaas: "SaaS Next.js + PG (512MB)",
        presetCompose: "Multi-Service Compose + PG + Redis",
        presetSpa: "SPA / Site Estático",
        presetDjango: "Django + PG",
        presetFastapi: "FastAPI + PG",
        presetNode: "API Node / Express",
        presetGo: "API Go",
        presetDotnet: "C# / ASP.NET + PG",
        presetHint_dotnet: "C#: precisa de um <code>.csproj</code> na raiz (ou um projeto web em <code>src/&lt;nome&gt;</code>). O painel roda <code>dotnet publish</code> com a versão do <code>TargetFramework</code> e o app ouve a porta 8080. O banco chega em <code>DATABASE_URL</code>.",
        presetDockerfile: "Dockerfile próprio (Rails, Laravel…)",
        presetHint_saas: "Next.js: precisa de <code>package.json</code> com os scripts <code>build</code> e <code>start</code>. Roda na porta 3000 e o banco chega em <code>DATABASE_URL</code>.",
        presetHint_django: "Django: precisa de <code>manage.py</code>, <code>requirements.txt</code> e da pasta do projeto com <code>wsgi.py</code>. Roda com gunicorn na porta 8000. Coloque o domínio em <code>ALLOWED_HOSTS</code> e leia o banco de <code>DATABASE_URL</code> (ex.: dj-database-url).",
        presetHint_fastapi: "FastAPI: precisa de <code>requirements.txt</code> com <code>fastapi</code> e <code>uvicorn</code>, e do objeto <code>app</code> em <code>main.py</code> (ou <code>app.py</code>). Roda na porta 8000.",
        presetHint_node: "Node: precisa de <code>package.json</code>. Usa <code>npm start</code> (ou o arquivo de <code>main</code>). O app deve ouvir a porta de <code>process.env.PORT</code> (3000).",
        presetHint_go: "Go: precisa de <code>go.mod</code>; o <code>main</code> pode ficar na raiz ou em <code>cmd/&lt;nome&gt;</code>. O app deve ouvir a porta da variável <code>PORT</code> (8080).",
        presetHint_compose: "Usa o <code>docker-compose.yml</code> do repositório. O serviço <code>web</code>, <code>app</code> ou <code>api</code> (ou o primeiro) recebe o tráfego. Opções inseguras como <code>privileged</code> são removidas.",
        presetHint_spa: "Vite, React ou Astro sem script <code>start</code>: o painel faz o build e serve os arquivos com nginx. Um <code>index.html</code> na raiz também funciona.",
        presetHint_dockerfile: "Para Rails, Laravel, Java ou qualquer outra stack: deixe um <code>Dockerfile</code> na raiz do repositório. A porta vem do <code>EXPOSE</code>.",
        chipSystemScope: "⚙️ system (Tokens Globais)",
        followOn: "🔁 Atualiza sozinho",
        followOff: "🔁 Atualizar sozinho",
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
        emptyDbs: "Nenhum banco provisionado ainda.",
        emptyBackups: "Nenhum snapshot criptografado criado ainda.",
        emptyPeers: "Nenhum servidor secundário pareado ainda.",
        emptySecrets: "Nenhuma variável salva neste escopo.",
        emptyDoctor: "Nenhum container registrado para diagnóstico.",
        actionExpose: "🌐 Expor",
        actionEnv: "🔐 ENV",
        actionLogs: "📜 Logs",
        actionRestart: "🔄 Restart",
        actionRollback: "⏪ Rollback",
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
        toastSecretSaved: "✅ Segredo criptografado no Vault!",
        toastDbCreated: "✅ Banco isolado provisionado!",
        toastBackupSaved: "📸 Backup criptografado salvo: ",
        toastDbRestored: "✅ Banco restaurado com sucesso",
        toastExposed: "🌐 Publicado em: ",
        toastDeploying: "⏳ Fazendo Build & Deploy...",
        toastDeployDone: "🚀 Deploy concluído: ",
        toastBundleGen: "📦 Bundle criptografado gerado",
        toastHandshakeDone: "🤝 Handshake concluído com o nó primário!",
        copiedToast: "✅ Copiado para a área de transferência!",
        btnRestoreDump: "⏪ Restaurar Dump",
        btnTestRestore: "🧪 Testar",
        offsiteLabel: "fora do servidor",
        btnRemoveSecret: "Remover",
        sizeLabel: "Tamanho:",
        stoppedStatus: "Parado",
        onDemandStatus: "Sob demanda",
        depPhase_detected: "🔔 Nova versão no repositório",
        depPhase_fetching: "⬇️ Baixando o código",
        depPhase_building: "🔨 Montando a imagem",
        depPhase_checking: "🩺 Testando a nova versão",
        depPhase_switching: "🔁 Trocando de versão",
        depPhase_live: "🟢 No ar",
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
        setupTitle: "🧭 First-time setup: what do you need?",
        setupDesc: "Configure only the integrations you plan to use. PaaSMCP works locally without third-party tokens; secret values are stored in the Vault.",
        setupGithubTitle: "🐙 GitHub — optional",
        setupGithubDesc: "For a private repository, use a read-only SSH Deploy Key. Copy the public key from the webhook box at the end of the Apps screen and add it under Settings → Deploy keys. To register it automatically or clone over HTTPS, save <code>GITHUB_TOKEN</code> in the <code>system</code> scope. A fine-grained token needs access only to the target repository and <em>Administration: read and write</em>; the created key remains read-only.",
        setupGithubLink: "Create fine-grained token ↗",
        setupGithubDocsLink: "API permissions ↗",
        setupCloudTitle: "☁️ Cloudflare — optional for publishing",
        setupCloudDesc: "For Tunnel + DNS: create a token with Account → Cloudflare Tunnel: Edit and Zone → DNS: Edit, scoped to the required account and zone. For Zero Trust protection, also add Account → Access: Apps and Policies: Edit. Configure Account ID, Tunnel ID, domain, and allowed emails with <code>paasmcp config</code> or <code>paas_configure</code>, and save <code>CF_API_TOKEN</code> in <code>system</code> scope.",
        setupCloudLink: "Create API token ↗",
        setupCloudDocsLink: "Token guide ↗",
        setupLocalTitle: "🔐 Dashboard access and local deploy",
        setupLocalDesc: "The dashboard token is generated automatically: retrieve it with <code>paasmcp dashboard token</code>. Public repositories, SSH access to private repositories, and local folders do not require a GitHub token if you add the public SSH key to the repository. Tailscale is a private alternative that does not require Cloudflare.",
        setupAppTitle: "🧩 App secrets and recommendations",
        setupAppDesc: "Save application keys in the scope named after its slug (for example <code>STRIPE_SECRET_KEY</code> or <code>API_KEY</code>), never in <code>system</code>. Select PostgreSQL/Redis during deployment if needed. Then check Logs and run Doctor; expose as Public only services with their own login. Use Zero Trust or Tailscale for admin tools.",
        setupWebhookNote: "Webhook auto-deploy is optional: add the URL shown at the end of the Apps screen to GitHub, select Push events, and use the secret shown by the dashboard. Do not paste tokens into chat; enter them in the Vault.",
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
        lblQuickFillDeploy: "⚡ Presets:",
        lblDepApp: "Application Slug",
        lblDepRepo: "GitHub Repo or Path",
        lblDepBranch: "Git Branch",
        lblDepMem: "Memory Limit (Optional)",
        lblDepCpu: "vCPU Limit (Optional)",
        lblDepPg: "Provision PostgreSQL 16 (injects <code>DATABASE_URL</code>)",
        lblDepRedis: "Provision Redis 7 (injects <code>REDIS_URL</code>)",
        btnDeploy: "🚀 Build & Deploy",
        exposeTitle: "🌐 Expose Application (Cloudflare Tunnel / Zero Trust / Tailscale)",
        exposeDesc: "Configures Cloudflare Tunnel routing + proxied DNS CNAME + Zero Trust policy without opening router ports.",
        lblQuickFillExpose: "⚡ Modes:",
        chipModePublic: "🌍 Public (Open HTTPS)",
        chipModeZT: "🛡️ Zero Trust (Email OTP)",
        chipModeTS: "🔒 Tailscale (Private VPN)",
        lblExpApp: "Application",
        lblExpMode: "Security Mode",
        optPublic: "Cloudflare Public (Open HTTPS)",
        optZT: "Cloudflare Zero Trust (Email PIN Login)",
        optTS: "Tailscale Serve (Private on Tailnet)",
        lblExpSub: "Subdomain",
        btnExpose: "🔗 Expose Address",
        vaultTitle: "🔐 Encrypted Secret Vault (AES-256-GCM Vault)",
        vaultDesc: "Each scope is encrypted on disk with random 96-bit IV and GCM auth tag. Values are never exposed in plaintext after save.",
        lblVaultScopes: "⚡ Scopes:",
        lblSecScope: "Scope (system or app slug)",
        lblSecKey: "Key (A-Z, 0-9, _)",
        lblSecVal: "Secret Value",
        btnSaveSecret: "💾 Encrypt & Save",
        btnLoadSecrets: "🔍 Reload Scope",
        dbTitle: "🗄️ Provision Isolated Multi-Tenant Database",
        dbDesc: "Creates database, exclusive role, and injects <code>DATABASE_URL</code> / <code>REDIS_URL</code> directly into app Vault.",
        lblDbApp: "Application",
        lblDbEngine: "Engine",
        optDbPg: "PostgreSQL 16 (Isolated by DB + Role)",
        optDbRedis: "Redis 7 (Isolated Logical DB)",
        btnCreateDb: "+ Provision Database",
        backupsTitle: "🛡️ Encrypted Snapshots & Restore (AES-256-GCM)",
        backupsDesc: "Generates <code>pg_dump</code> or Redis snapshot, encrypts with Vault master key, and verifies SHA-256 integrity prior to restore.",
        lblBakApp: "App for Backup",
        lblBakEngine: "Engine",
        optBakPg: "PostgreSQL 16 (pg_dump)",
        optBakRedis: "Redis 7 (RDB)",
        btnCreateBackup: "📸 Create Encrypted Snapshot",
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
        lblWhUrl: "Webhook Payload URL (add in GitHub → Settings → Webhooks):",
        lblWhSecret: "Webhook Secret (HMAC-SHA256):",
        btnRevealWhSecret: "👁️ Reveal / Copy Secret",
        lblSshKey: "Public SSH Deploy Key (Ed25519):",
        btnCopySsh: "📋 Copy SSH Key",
        doctorTitle: "🩺 PaaSMCP Doctor — Automated Container Diagnostics",
        doctorDesc: "Checks for <code>OOMKilled</code> (low RAM), restart loops, exit codes, and health of all services.",
        btnRunDoctor: "🔍 Run Diagnostics Now",
        agentsTitle: "🤖 How to Connect your AI Agent (MCP Compatible Clients)",
        agentsDesc: "PaaSMCP exposes <strong>15 native MCP tools</strong> via stdio JSON-RPC. Copy the config below so your AI agent can manage the entire server for you:",
        logsTitle: "📜 Container Logs",
        btnCloseLogs: "Close",
        statHost: "Host Server",
        statDisk: "Disk:",
        statMem: "Free / Total Memory",
        statIdle: "0 MB Idle Daemon",
        statAppsDbs: "Isolated Apps & DBs",
        statSnapshots: "Encrypted Snapshots",
        statSecurityFed: "Security & Federation",
        presetSaas: "SaaS Next.js + PG (512MB)",
        presetCompose: "Multi-Service Compose + PG + Redis",
        presetSpa: "SPA / Static Site",
        presetDjango: "Django + PG",
        presetFastapi: "FastAPI + PG",
        presetNode: "Node / Express API",
        presetGo: "Go API",
        presetDotnet: "C# / ASP.NET + PG",
        presetHint_dotnet: "C#: needs a <code>.csproj</code> at the root (or one web project in <code>src/&lt;name&gt;</code>). The dashboard runs <code>dotnet publish</code> with the <code>TargetFramework</code> version and the app listens on port 8080. The database arrives in <code>DATABASE_URL</code>.",
        presetDockerfile: "Own Dockerfile (Rails, Laravel…)",
        presetHint_saas: "Next.js: needs a <code>package.json</code> with <code>build</code> and <code>start</code> scripts. Runs on port 3000 and the database arrives in <code>DATABASE_URL</code>.",
        presetHint_django: "Django: needs <code>manage.py</code>, <code>requirements.txt</code> and the project folder with <code>wsgi.py</code>. Runs with gunicorn on port 8000. Put the domain in <code>ALLOWED_HOSTS</code> and read the database from <code>DATABASE_URL</code> (e.g. dj-database-url).",
        presetHint_fastapi: "FastAPI: needs a <code>requirements.txt</code> with <code>fastapi</code> and <code>uvicorn</code>, and the <code>app</code> object in <code>main.py</code> (or <code>app.py</code>). Runs on port 8000.",
        presetHint_node: "Node: needs a <code>package.json</code>. Uses <code>npm start</code> (or the <code>main</code> file). The app must listen on <code>process.env.PORT</code> (3000).",
        presetHint_go: "Go: needs <code>go.mod</code>; <code>main</code> can live at the root or in <code>cmd/&lt;name&gt;</code>. The app must listen on the <code>PORT</code> variable (8080).",
        presetHint_compose: "Uses the repository's <code>docker-compose.yml</code>. The <code>web</code>, <code>app</code> or <code>api</code> service (or the first one) gets the traffic. Unsafe options such as <code>privileged</code> are stripped.",
        presetHint_spa: "Vite, React or Astro without a <code>start</code> script: the dashboard builds it and serves the files with nginx. A root <code>index.html</code> works too.",
        presetHint_dockerfile: "For Rails, Laravel, Java or any other stack: put a <code>Dockerfile</code> at the repository root. The port comes from <code>EXPOSE</code>.",
        chipSystemScope: "⚙️ system (Global Tokens)",
        followOn: "🔁 Auto-updates",
        followOff: "🔁 Auto-update",
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
        emptyDbs: "No databases provisioned yet.",
        emptyBackups: "No encrypted snapshots created yet.",
        emptyPeers: "No secondary servers paired yet.",
        emptySecrets: "No variables stored in this scope.",
        emptyDoctor: "No containers registered for diagnostics.",
        actionExpose: "🌐 Expose",
        actionEnv: "🔐 ENV",
        actionLogs: "📜 Logs",
        actionRestart: "🔄 Restart",
        actionRollback: "⏪ Rollback",
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
        toastSecretSaved: "✅ Secret encrypted in Vault!",
        toastDbCreated: "✅ Isolated database provisioned!",
        toastBackupSaved: "📸 Encrypted backup saved: ",
        toastDbRestored: "✅ Database restored successfully",
        toastExposed: "🌐 Published at: ",
        toastDeploying: "⏳ Building & Deploying...",
        toastDeployDone: "🚀 Deploy completed: ",
        toastBundleGen: "📦 Encrypted bundle generated",
        toastHandshakeDone: "🤝 Handshake completed with primary node!",
        copiedToast: "✅ Copied to clipboard!",
        btnRestoreDump: "⏪ Restore Dump",
        btnTestRestore: "🧪 Test",
        offsiteLabel: "off-site",
        btnRemoveSecret: "Remove",
        sizeLabel: "Size:",
        stoppedStatus: "Stopped",
        onDemandStatus: "On demand",
        depPhase_detected: "🔔 New version in the repository",
        depPhase_fetching: "⬇️ Fetching the code",
        depPhase_building: "🔨 Building the image",
        depPhase_checking: "🩺 Testing the new version",
        depPhase_switching: "🔁 Switching versions",
        depPhase_live: "🟢 Live",
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
          "navDatabases": "Bancos de Dados",
          "navVault": "Cofre & Chaves",
          "navEmail": "E-mail",
          "navMirror": "Segundo Servidor",
          "navUpdates": "Atualizações",
          "navDoctor": "Diagnóstico",
          "navAgents": "MCP & IA",
          "navPool": "Ajudantes",
          "homeTitle": "Início",
          "setupTitle": "🧭 Integrações opcionais",
          "appsTitle": "📦 Seus apps",
          "appsDesc": "Cada app roda isolado no servidor. Daqui você vê o uso de memória, abre os logs, volta para a versão anterior ou para o app. Quando chega um commit novo, a linha do app mostra a nova versão sendo montada e testada; a versão atual continua no ar até a nova passar no teste.",
          "deployTitle": "➕ Publicar um app",
          "deployDesc": "Informe o repositório do GitHub (ou uma pasta do servidor). O painel descobre a linguagem e monta tudo sozinho. As senhas do app ficam em Senhas e chaves.",
          "exposeTitle": "🌐 Deixar um app acessível",
          "exposeDesc": "Escolha quem pode abrir: qualquer pessoa na internet, só e-mails autorizados ou só a sua rede privada (Tailscale). Nenhuma porta do roteador é aberta.",
          "vaultTitle": "🔐 Senhas e chaves dos apps",
          "vaultDesc": "Guarde aqui as senhas e chaves que seus apps usam (ex.: chave do Stripe). Tudo fica cifrado no disco e não aparece de novo por inteiro depois de salvo. Use o nome do app como escopo; <code>system</code> é só para as chaves do próprio painel.",
          "dbTitle": "🗄️ Criar um banco de dados",
          "dbDesc": "Cada app ganha o seu próprio banco, separado dos outros. O endereço de conexão (<code>DATABASE_URL</code> ou <code>REDIS_URL</code>) entra sozinho nas senhas do app.",
          "backupsTitle": "🛡️ Cópias de segurança",
          "backupsDesc": "Cópias cifradas dos bancos e dos arquivos dos apps. Use “Testar” para conferir que a cópia abre antes de precisar dela.",
          "fedTitle": "🔗 Conectar outro servidor",
          "fedDesc": "Primeiro passo para ter um segundo servidor: os dois trocam uma chave de confiança. Depois use os quadros abaixo para a cópia ao vivo dos dados.",
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
          "stepsTitle": "🧭 Primeiros passos",
          "stepsDesc": "Faça na ordem. Cada passo diz o que é e por que vale a pena.",
          "step1Title": "Publicar o primeiro app",
          "step1Desc": "Cole o endereço do código e o painel monta o resto.",
          "step2Title": "Guardar cópias fora do servidor",
          "step2Desc": "Se o servidor quebrar ou for roubado, seus dados continuam salvos em outro lugar.",
          "step3Title": "Configurar o envio de e-mails",
          "step3Desc": "Para os apps mandarem “esqueci a senha” e avisos. Leva 5 minutos com uma conta gratuita.",
          "step4Title": "Ligar um segundo servidor",
          "step4Desc": "Ele guarda uma cópia ao vivo de tudo e pode assumir se este cair.",
          "step5Title": "Conectar sua IA",
          "step5Desc": "Peça em português: “publica meu app”, “faz uma cópia agora”.",
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
          "tileEmail": "E-mail",
          "tileEmailNote": "Os apps ainda não enviam e-mail",
          "detailsTech": "Detalhes técnicos",
          "offsiteTitle": "☁️ Cópias fora do servidor",
          "offsiteDesc": "Toda noite o servidor faz as cópias e manda para um serviço de armazenamento externo. As cópias locais só são apagadas depois de chegarem lá.",
          "offsiteTech": "Qualquer serviço compatível com S3 (Backblaze B2, Cloudflare R2, Wasabi ou o segundo servidor). Configure BACKUP_S3_ENDPOINT, BACKUP_S3_BUCKET, BACKUP_S3_ACCESS_KEY_ID e BACKUP_S3_SECRET_ACCESS_KEY no escopo system de Senhas e chaves. Horário automático: paasmcp backup install-timer.",
          "btnSyncOffsite": "☁️ Enviar cópias agora",
          "offsiteDone": "Cópias enviadas:",
          "offsiteFailed": "falharam:",
          "storageTitle": "🗂️ Arquivos dos apps",
          "storageDesc": "Espaço para fotos, PDFs e uploads. Cada app ganha o seu, com chave própria; as bibliotecas comuns (boto3, AWS SDK) funcionam sem mudar código.",
          "storageNone": "Nenhum app com espaço de arquivos ainda.",
          "btnStorage": "+ Criar espaço de arquivos",
          "storageDone": "Espaço criado. Publique o app de novo para ele usar.",
          "lblAppName": "Nome do app",
          "lblDepPoll": "Atualizar sozinho quando eu mudar o código (confere a cada 2 min)",
          "lblDepStorage": "Criar espaço para arquivos",
          "lblDepEmail": "Deixar o app enviar e-mails",
          "lblDepHealth": "Endereço de teste antes de trocar (Opcional)",
          "lblDepNoHealth": "Não é um site (pular o teste antes de trocar)",
          "deployHealthFailed": "A nova versão não passou no teste e NÃO foi colocada no ar. A versão anterior continua funcionando. Veja o erro do app abaixo:",
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
          "mirrorDesc": "Os dois servidores guardam uma cópia ao vivo um do outro. Se um cair, o outro pode assumir os apps dele com os dados até o último segundo. Antes, conecte os dois no quadro “Conectar outro servidor”, logo abaixo.",
          "mirrorNone": "Nenhuma cópia configurada ainda. Use os dois quadros abaixo: um servidor oferece, o outro recebe.",
          "aaTitle": "⚖️ App nos dois servidores",
          "aaDesc": "O app roda aqui e no outro servidor ao mesmo tempo, e os dois recebem visitas. Os dados continuam gravados num banco só, o deste servidor: o outro grava nele pela Tailscale. Se este servidor cair, a troca automática acima faz o outro seguir sozinho.",
          "hostReadyNote": "Antes de testar, abra o Diagnóstico: ele avisa se este servidor está sem DNS de reserva, se o Watchtower pode reiniciar os contêineres do PaaSMCP no meio do teste ou se as redes do Docker estão chegando perto da sua rede de casa.",
          "aaNone": "Nenhum app rodando nos dois servidores ainda.",
          "aaOrigin": "criado aqui, roda nos dois",
          "aaCopy": "vem de {peer}, roda aqui também",
          "aaRunning": "versão aqui",
          "aaWanted": "versão pedida",
          "aaStep1": "1. Antes: cópia e vigia",
          "aaStep1Desc": "Este servidor precisa mandar cópia para o outro (quadro “Oferecer cópia” acima, com o IP do Tailscale), e o vigia precisa rodar no outro servidor (passo 6 da troca automática). É o vigia que mantém o app do outro servidor na mesma versão deste, em até 15 segundos.",
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
          "aaP_noMirror": "Nenhum servidor recebe cópia deste ainda. Configure a cópia primeiro, nos quadros acima.",
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
          "mirrorPromotedDesc": "Os apps dele estão rodando aqui. Quando ele voltar, siga a devolução abaixo.",
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
          "autoTitle": "Troca automática",
          "autoDesc": "Se o outro servidor sumir por mais de 1 minuto, este assume os apps dele sozinho. Para isso precisa de um juiz: um terceiro aparelho que dá o voto de desempate. Sem juiz, se só a conexão entre os dois cair, cada um acharia que o outro morreu e os dois gravariam dados diferentes.",
          "autoBefore": "Antes de começar: a cópia já precisa estar funcionando (aparece “Cópia de …” no topo desta página) e os três aparelhos precisam estar na mesma rede Tailscale. Faça os passos abaixo uma vez, nesta ordem.",
          "autoStep1": "1. Escolha o aparelho do juiz",
          "autoStep1Desc": "Qualquer aparelho ligado 24 horas que não seja nenhum dos dois servidores: um Raspberry Pi, uma VPS barata ou um PC velho. De preferência em outro lugar ou outra internet. Ele precisa de Node.js 20 ou mais novo e do Tailscale ligado na mesma conta. Não precisa de Docker e quase não usa memória.",
          "autoStep2": "2. Pegue a chave do juiz (neste servidor)",
          "autoStep2Desc": "No terminal deste servidor, rode o comando abaixo e copie a linha que aparecer (64 letras e números). Os dois servidores dão a mesma chave, porque ela vem do pareamento. Ela só serve para o juiz: não abre senhas, apps nem dados.",
          "autoStep3": "3. Instale e ligue o juiz (no terceiro aparelho)",
          "autoStep3Desc": "No terminal do aparelho do juiz, rode os comandos abaixo, trocando os dois trechos entre < >. O juiz passa a rodar sozinho, volta depois de reiniciar e atende só no endereço Tailscale do aparelho, porta 4097. No fim ele mostra o endereço para usar no passo 4.",
          "autoStep3Check": "Para conferir no próprio aparelho do juiz, rode o comando abaixo. Se responder {&quot;ok&quot;:true}, o juiz está no ar.",
          "autoStep3Shared": "Se esse aparelho já é juiz de outro par de servidores, não instale de novo: rode só o comando abaixo. Cada par fica separado, com a própria chave.",
          "autoRepoPlaceholder": "<mesmo repositório que você usou nos servidores>",
          "autoKeyPlaceholder": "<chave do passo 2>",
          "autoStep4": "4. Informe o endereço do juiz (neste servidor e no outro)",
          "autoStep4Desc": "É http:// + o IP do Tailscale do aparelho do juiz + :4097, por exemplo http://100.64.0.9:4097. O IP aparece no app do Tailscale ou com “tailscale ip -4” no aparelho do juiz. Clique em Testar: tem que aparecer “O juiz respondeu”. Depois Salvar. Repita este passo no painel do outro servidor, com o mesmo endereço.",
          "btnArbTest": "Testar",
          "btnArbSave": "Salvar",
          "autoStep5": "5. Escolha qual servidor este pode substituir",
          "autoStep5Desc": "É o servidor cujos apps este vai assumir se ele cair. A lista mostra só os servidores dos quais este já guarda uma cópia. Ao ligar, o painel pede para digitar o nome para confirmar. Se a cópia é nos dois sentidos e você quer que qualquer um assuma o outro, faça este passo também no outro servidor.",
          "lblAutoPeer": "Servidor que este pode substituir",
          "autoNoCopy": "Nenhuma cópia recebida ainda (use “Receber cópia” acima)",
          "autoNoPeer": "Escolha o servidor na lista. Se ela estiver vazia, este servidor ainda não guarda cópia de nenhum outro.",
          "autoStep6": "6. Ligue o vigia (nos dois servidores)",
          "autoStep6Desc": "O vigia conversa com o juiz a cada 15 segundos. É ele que avisa o juiz que o servidor está vivo, troca sozinho quando precisa e bloqueia o servidor que volta depois de ter sido substituído. Rode o comando abaixo no terminal de cada um dos dois servidores.",
          "autoStep7": "7. Confira se está funcionando",
          "autoStep7Desc": "O quadro no topo deste cartão mostra o que o juiz está ouvindo. Está pronto quando tudo fica verde: o juiz respondeu, ouviu este servidor e o outro há menos de 1 minuto, o vigia está rodando aqui e a troca está ligada. Se o outro servidor não aparece ou aparece com tempo alto, falta o passo 4 ou 6 nele.",
          "btnArbRefresh": "Verificar de novo",
          "arbNotSet": "Juiz ainda não informado (passo 4).",
          "arbOk": "O juiz respondeu e aceitou a chave",
          "arbThisServer": "este servidor",
          "arbHeard": "O juiz ouviu {who} há {s} s",
          "arbHeardOld": "mais de 1 minuto: o vigia está ligado nele?",
          "arbPeerUnknown": "O juiz nunca ouviu {who}. Faça os passos 4 e 6 no painel e no terminal de {who}. Enquanto isso, se a cópia parar, este servidor assume.",
          "arbWatchOn": "Vigia rodando neste servidor",
          "arbWatchOff": "Vigia desligado neste servidor (passo 6)",
          "arbAutoOn": "Troca automática ligada para: {who}",
          "arbAutoOff": "Troca automática desligada neste servidor (passo 5)",
          "arbAutoTag": "troca ligada",
          "arbReady": "✅ Troca automática pronta",
          "arbNotReady": "Ainda falta algo:",
          "arbErr_badUrl": "Endereço inválido. Use http://<IP do Tailscale do juiz>:4097",
          "arbErr_badKey": "O juiz respondeu, mas recusou a chave. Reinstale o juiz com a chave do passo 2.",
          "arbErr_clock": "O juiz respondeu, mas o relógio dele está mais de 1 minuto diferente. Ligue o horário automático nos aparelhos.",
          "arbErr_notPaired": "Este servidor ainda não foi pareado com o outro: faça isso no quadro “Conectar outro servidor”, no topo da tela Segundo servidor.",
          "arbErr_notArbiter": "Algo respondeu nesse endereço, mas não é o juiz. Confira a porta (padrão 4097).",
          "arbErr_unreachable": "O juiz não respondeu. Confira se ele está ligado (passo 3), se o IP é o do Tailscale dele e se a porta é 4097.",
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
          "navVault": "Vault & Secrets",
          "navEmail": "Email",
          "navMirror": "Second Server",
          "navUpdates": "Updates",
          "navDoctor": "Diagnostics",
          "navAgents": "MCP & AI",
          "navPool": "Helpers",
          "homeTitle": "Home",
          "setupTitle": "🧭 Optional integrations",
          "appsTitle": "📦 Your apps",
          "appsDesc": "Each app runs isolated on the server. From here you see memory use, open logs, go back to the previous version or stop the app. When a new commit arrives, the app's row shows the new version being built and tested; the current version stays live until the new one passes the test.",
          "deployTitle": "➕ Publish an app",
          "deployDesc": "Enter the GitHub repository (or a folder on the server). The dashboard detects the language and builds everything. App passwords live in Passwords & keys.",
          "exposeTitle": "🌐 Make an app reachable",
          "exposeDesc": "Choose who can open it: anyone on the internet, only allowed emails, or only your private network (Tailscale). No router port is opened.",
          "vaultTitle": "🔐 App passwords & keys",
          "vaultDesc": "Store the passwords and keys your apps use (e.g. a Stripe key). Everything is encrypted on disk and never shown in full again after saving. Use the app name as scope; <code>system</code> is only for the dashboard's own keys.",
          "dbTitle": "🗄️ Create a database",
          "dbDesc": "Each app gets its own database, separate from the others. The connection address (<code>DATABASE_URL</code> or <code>REDIS_URL</code>) goes into the app's passwords automatically.",
          "backupsTitle": "🛡️ Backups",
          "backupsDesc": "Encrypted copies of app databases and files. Use “Test” to check a backup opens before you need it.",
          "fedTitle": "🔗 Connect another server",
          "fedDesc": "First step to a second server: both exchange a trust key. Then use the boxes below for the live copy of the data.",
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
          "stepsTitle": "🧭 First steps",
          "stepsDesc": "Do them in order. Each step says what it is and why it is worth it.",
          "step1Title": "Publish your first app",
          "step1Desc": "Paste the code address and the dashboard does the rest.",
          "step2Title": "Keep backups off the server",
          "step2Desc": "If the server breaks or is stolen, your data is still safe elsewhere.",
          "step3Title": "Set up email sending",
          "step3Desc": "So apps can send “forgot password” and notices. Takes 5 minutes with a free account.",
          "step4Title": "Add a second server",
          "step4Desc": "It keeps a live copy of everything and can take over if this one goes down.",
          "step5Title": "Connect your AI",
          "step5Desc": "Ask in plain words: “publish my app”, “back up now”.",
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
          "tileEmail": "Email",
          "tileEmailNote": "Apps cannot send email yet",
          "detailsTech": "Technical details",
          "offsiteTitle": "☁️ Backups off the server",
          "offsiteDesc": "Every night the server makes backups and sends them to external storage. Local copies are only deleted after they arrive there.",
          "offsiteTech": "Any S3-compatible service (Backblaze B2, Cloudflare R2, Wasabi or the second server). Set BACKUP_S3_ENDPOINT, BACKUP_S3_BUCKET, BACKUP_S3_ACCESS_KEY_ID and BACKUP_S3_SECRET_ACCESS_KEY in the system scope of Passwords & keys. Nightly schedule: paasmcp backup install-timer.",
          "btnSyncOffsite": "☁️ Send backups now",
          "offsiteDone": "Backups sent:",
          "offsiteFailed": "failed:",
          "storageTitle": "🗂️ App files",
          "storageDesc": "Space for photos, PDFs and uploads. Each app gets its own, with its own key; common libraries (boto3, AWS SDK) work without code changes.",
          "storageNone": "No app has file space yet.",
          "btnStorage": "+ Create file space",
          "storageDone": "Space created. Publish the app again so it uses it.",
          "lblAppName": "App name",
          "lblDepPoll": "Update by itself when I change the code (checks every 2 min)",
          "lblDepStorage": "Create file space",
          "lblDepEmail": "Let the app send email",
          "lblDepHealth": "Test address before switching (Optional)",
          "lblDepNoHealth": "Not a website (skip the test before switching)",
          "deployHealthFailed": "The new version failed its test and was NOT put live. The previous version is still running. The app's error is below:",
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
          "mirrorDesc": "Both servers keep a live copy of each other. If one goes down, the other can take over its apps with data up to the last second. First connect both in the “Connect another server” box just below.",
          "mirrorNone": "No copy set up yet. Use the two boxes below: one server offers, the other receives.",
          "aaTitle": "⚖️ App on both servers",
          "aaDesc": "The app runs here and on the other server at the same time, and both take visits. Data is still written to one database, this server's: the other one writes to it over Tailscale. If this server goes down, the automatic failover above keeps the other one going alone.",
          "hostReadyNote": "Before testing, open Diagnostics: it warns if this server has no fallback DNS, if Watchtower may restart PaaSMCP's containers in the middle of the test, or if Docker's networks are getting close to your home network.",
          "aaNone": "No app runs on both servers yet.",
          "aaOrigin": "created here, runs on both",
          "aaCopy": "comes from {peer}, also runs here",
          "aaRunning": "version here",
          "aaWanted": "version asked",
          "aaStep1": "1. First: copy and watchdog",
          "aaStep1Desc": "This server must send a copy to the other one (“Offer a copy” above, with the Tailscale IP), and the watchdog must run on the other server (step 6 of automatic failover). The watchdog keeps the other server's app on this server's version within 15 seconds.",
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
          "mirrorPromotedDesc": "Its apps run here. When it comes back, follow the hand-back steps below.",
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
          "autoTitle": "Automatic takeover",
          "autoDesc": "If the other server disappears for more than 1 minute, this one takes over its apps. That needs an arbiter: a third device that casts the deciding vote. Without it, if only the link between the two breaks, each would think the other died and both would write different data.",
          "autoBefore": "Before you start: the copy must already work (“Copy of …” shows at the top of this page) and all three devices must be on the same Tailscale network. Do the steps below once, in this order.",
          "autoStep1": "1. Pick the arbiter device",
          "autoStep1Desc": "Any device that stays on 24/7 and is neither of the two servers: a Raspberry Pi, a cheap VPS or an old PC. Ideally somewhere else or on another internet link. It needs Node.js 20 or newer and Tailscale on the same account. No Docker, and it barely uses memory.",
          "autoStep2": "2. Get the arbiter key (on this server)",
          "autoStep2Desc": "In this server's terminal, run the command below and copy the line it prints (64 letters and digits). Both servers print the same key, because it comes from the pairing. It only works for the arbiter: it opens no passwords, apps or data.",
          "autoStep3": "3. Install and start the arbiter (on the third device)",
          "autoStep3Desc": "In the arbiter device's terminal, run the commands below, replacing both parts between < >. The arbiter then runs on its own, comes back after a reboot and only answers on the device's Tailscale address, port 4097. At the end it prints the address to use in step 4.",
          "autoStep3Check": "To check on the arbiter device itself, run the command below. If it answers {&quot;ok&quot;:true}, the arbiter is up.",
          "autoStep3Shared": "If this device is already the arbiter for another pair of servers, don't install it again: just run the command below. Each pair stays separate, with its own key.",
          "autoRepoPlaceholder": "<same repository you used on the servers>",
          "autoKeyPlaceholder": "<key from step 2>",
          "autoStep4": "4. Enter the arbiter address (on this server and the other)",
          "autoStep4Desc": "It is http:// + the arbiter device's Tailscale IP + :4097, for example http://100.64.0.9:4097. The IP shows in the Tailscale app or with “tailscale ip -4” on the arbiter. Click Test: it must say “The arbiter answered”. Then Save. Repeat this step on the other server's dashboard, with the same address.",
          "btnArbTest": "Test",
          "btnArbSave": "Save",
          "autoStep5": "5. Choose which server this one may replace",
          "autoStep5Desc": "The server whose apps this one takes over if it goes down. The list only shows servers this one already holds a copy of. Turning it on asks you to type the name to confirm. If the copy goes both ways and either should replace the other, do this step on the other server too.",
          "lblAutoPeer": "Server this one may replace",
          "autoNoCopy": "No copy received yet (use “Receive a copy” above)",
          "autoNoPeer": "Pick the server in the list. If it is empty, this server holds no copy of another one yet.",
          "autoStep6": "6. Turn on the watchdog (on both servers)",
          "autoStep6Desc": "The watchdog talks to the arbiter every 15 seconds. It tells the arbiter the server is alive, takes over when needed and blocks a server that comes back after being replaced. Run the command below in the terminal of each of the two servers.",
          "autoStep7": "7. Check that it works",
          "autoStep7Desc": "The box at the top of this card shows what the arbiter hears. It is ready when everything is green: the arbiter answered, heard this server and the other one less than 1 minute ago, the watchdog runs here and the takeover is on. If the other server is missing or shows a long time, step 4 or 6 is missing there.",
          "btnArbRefresh": "Check again",
          "arbNotSet": "No arbiter entered yet (step 4).",
          "arbOk": "The arbiter answered and accepted the key",
          "arbThisServer": "this server",
          "arbHeard": "The arbiter heard {who} {s} s ago",
          "arbHeardOld": "over 1 minute: is the watchdog on there?",
          "arbPeerUnknown": "The arbiter never heard {who}. Do steps 4 and 6 on {who}'s dashboard and terminal. Meanwhile, if the copy stops, this server takes over.",
          "arbWatchOn": "Watchdog running on this server",
          "arbWatchOff": "Watchdog off on this server (step 6)",
          "arbAutoOn": "Automatic takeover on for: {who}",
          "arbAutoOff": "Automatic takeover off on this server (step 5)",
          "arbAutoTag": "takeover on",
          "arbReady": "✅ Automatic takeover ready",
          "arbNotReady": "Something is still missing:",
          "arbErr_badUrl": "Invalid address. Use http://<arbiter Tailscale IP>:4097",
          "arbErr_badKey": "The arbiter answered but refused the key. Reinstall it with the key from step 2.",
          "arbErr_clock": "The arbiter answered but its clock is more than 1 minute off. Turn on automatic time on the devices.",
          "arbErr_notPaired": "This server is not paired with the other one yet: do it in the “Connect another server” box at the top of the Second server screen.",
          "arbErr_notArbiter": "Something answered at that address, but it is not the arbiter. Check the port (default 4097).",
          "arbErr_unreachable": "The arbiter did not answer. Check that it is on (step 3), that the IP is its Tailscale IP and that the port is 4097.",
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
          "navPool": "🖥️ Ajudantes",
          "aaP_pool": "O app usa PCs ajudantes (cópias ou escala automática): use “Parar tudo” na escala dele primeiro. Por enquanto, um app usa ajudantes ou os dois servidores, não as duas coisas.",
          "poolTitle": "🖥️ PCs ajudantes",
          "poolDesc": "Seus próprios computadores podem rodar cópias extras dos apps deste servidor. Este servidor continua dono de tudo: guarda as senhas, monta a imagem, recebe as visitas e as divide entre a cópia daqui e as dos ajudantes. Num ajudante sem cópias, nenhum programa do PaaSMCP fica ligado.",
          "btnPoolCheck": "🔄 Verificar agora",
          "poolNone": "Nenhum PC ajudante ainda. Siga os passos abaixo para adicionar o primeiro.",
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
          "poolAppsDesc": "O número de cópias de cada app se escolhe na tela Apps, no quadro de uso e escala, à mão ou pela escala automática.",
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
          "navPool": "🖥️ Helpers",
          "aaP_pool": "The app uses helper PCs (copies or automatic scaling): use “Stop everything” in its scaling first. For now an app uses either helpers or both servers, not both.",
          "poolTitle": "🖥️ Helper PCs",
          "poolDesc": "Your own computers can run extra copies of this server's apps. This server stays in charge of everything: it keeps the passwords, builds the image, receives the visits and splits them between its own copy and the helpers'. A helper with no copies runs no PaaSMCP program at all.",
          "btnPoolCheck": "🔄 Check now",
          "poolNone": "No helper PC yet. Follow the steps below to add the first one.",
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
          "poolAppsDesc": "Each app's number of copies is set on the Apps screen, in the usage and scaling card, by hand or by automatic scaling.",
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

    function t(key) {
      const dict = I18N[currentLang] || I18N.pt;
      return dict[key] !== undefined ? dict[key] : (I18N.pt[key] !== undefined ? I18N.pt[key] : key);
    }

    const I18N_KEYS = [
      'setupTitle', 'setupDesc', 'setupGithubTitle', 'setupGithubDesc', 'setupGithubLink', 'setupGithubDocsLink',
      'setupCloudTitle', 'setupCloudDesc', 'setupCloudLink', 'setupCloudDocsLink', 'setupLocalTitle', 'setupLocalDesc',
      'setupAppTitle', 'setupAppDesc', 'setupWebhookNote',
      'sidebarSubtitle', 'navHome', 'navEmail', 'navMirror', 'navPool', 'navUpdates', 'homeTitle', 'navOverview', 'navVault', 'navDatabases', 'navDoctor', 'navAgents',
      'topHealthBadge', 'btnRefresh', 'btnLogout',
      'appsTitle', 'appsDesc', 'thApp', 'thStack', 'thMetrics', 'thPort', 'thDomains', 'thActions',
      'deployTitle', 'deployDesc', 'lblQuickFillDeploy', 'lblDepApp', 'lblDepRepo', 'lblDepBranch', 'lblDepMem', 'lblDepCpu', 'lblDepPg', 'lblDepRedis', 'btnDeploy',
      'exposeTitle', 'exposeDesc', 'lblQuickFillExpose', 'chipModePublic', 'chipModeZT', 'chipModeTS', 'lblExpApp', 'lblExpMode', 'optPublic', 'optZT', 'optTS', 'lblExpSub', 'btnExpose',
      'vaultTitle', 'vaultDesc', 'lblVaultScopes', 'lblSecScope', 'lblSecKey', 'lblSecVal', 'btnSaveSecret', 'btnLoadSecrets',
      'dbTitle', 'dbDesc', 'lblDbApp', 'lblDbEngine', 'optDbPg', 'optDbRedis', 'btnCreateDb',
      'backupsTitle', 'backupsDesc', 'lblBakApp', 'lblBakEngine', 'optBakPg', 'optBakRedis', 'btnCreateBackup',
      'fedTitle', 'fedDesc', 'lblFedUrl', 'lblFedMode', 'optFedActive', 'optFedWarm', 'btnGenInvite', 'btnExportSync', 'lblJoinPeer', 'btnJoinPeer',
      'whTitle', 'whDesc', 'lblWhUrl', 'lblWhSecret', 'btnRevealWhSecret', 'lblSshKey', 'btnCopySsh',
      'doctorTitle', 'doctorDesc', 'btnRunDoctor',
      'presetSaas', 'presetDjango', 'presetFastapi', 'presetNode', 'presetGo', 'presetDotnet', 'presetCompose', 'presetSpa', 'presetDockerfile', 'chipSystemScope',
      'promptEx1Title', 'promptEx1Desc', 'promptEx2Title', 'promptEx2Desc', 'promptEx3Title', 'promptEx3Desc',
      'agentsTitle', 'agentsDesc', 'logsTitle', 'btnCloseLogs',
    ];

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

    function switchTab(tabName, btnEl) {
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      const pane = document.getElementById('tab-' + tabName);
      if (pane) pane.classList.add('active');
      if (btnEl) btnEl.classList.add('active');
      try { localStorage.setItem('paasmcp_active_tab', tabName); } catch {}
      if (tabName === 'doctor') runDoctor();
      if (tabName === 'email') loadEmail();
      if (tabName === 'agents') { renderAi(); loadAiTokens(); }
      if (tabName === 'mirror') loadMirror();
      if (tabName === 'updates' && !updatesLoaded) loadUpdates();
      if (tabName === 'databases') loadStorage();
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
      document.getElementById('themeBtn').textContent = currentTheme === 'dark' ? (isPt ? '☀️ Claro' : '☀️ Light') : (isPt ? '🌙 Escuro' : '🌙 Dark');
      document.getElementById('langBtn').textContent = isPt ? '🇧🇷 PT-BR' : '🇺🇸 EN';
      const btnLogout = document.getElementById('btnLogout');
      if (btnLogout) btnLogout.textContent = isPt ? 'Sair' : 'Log out';
      const refreshBtn = document.getElementById('btnRefresh');
      if (refreshBtn) {
        refreshBtn.innerHTML = \`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:2px;"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg> <span>\${isPt ? 'Atualizar' : 'Refresh'}</span>\`;
      }
      document.getElementById('webhookUrlBox').textContent = window.location.origin + '/api/webhooks/github';
      const fedUrlEl = document.getElementById('fedUrl');
      if (fedUrlEl && !fedUrlEl.value) fedUrlEl.value = window.location.origin;

      document.querySelectorAll('[data-i18n]').forEach(el => { el.innerHTML = t(el.getAttribute('data-i18n')); });
      renderHome();
      renderAi();
      renderArbiterInstall();
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

      // Restore active tab
      const savedTab = localStorage.getItem('paasmcp_active_tab') || 'overview';
      const targetBtn = document.getElementById('nav' + savedTab.charAt(0).toUpperCase() + savedTab.slice(1));
      if (targetBtn && !targetBtn.classList.contains('active')) switchTab(savedTab, targetBtn);


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
    }

    function setVaultScope(scope) {
      document.getElementById('secScope').value = scope;
      loadSecrets();
      const vaultBtn = document.getElementById('navVault');
      switchTab('vault', vaultBtn);
    }

    function selectAppForExpose(appName) {
      document.getElementById('expApp').value = appName;
      document.getElementById('expSub').value = appName.replace(/^paasmcp-/, '');
      document.getElementById('expApp').scrollIntoView({ behavior: 'smooth', block: 'center' });
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

    function renderStatusData(s) {
      const isPt = currentLang === 'pt';
      const domain = getBaseDomain();
      document.getElementById('topDomainBadge').innerHTML = \`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg> <span>\${isPt ? 'Domínio' : 'Domain'}: <strong>\${esc(domain)}</strong></span>\`;
      const role = s.federation?.role || 'standalone';
      const peersCount = Object.keys(s.federation?.peers || {}).length;
      const roleLabel = role === 'standalone' ? (isPt ? 'autônomo' : 'standalone') : role;
      const peersLabel = isPt ? (peersCount === 1 ? '1 par' : peersCount + ' pares') : (peersCount === 1 ? '1 peer' : peersCount + ' peers');
      document.getElementById('nodeRoleFooter').textContent = (isPt ? 'Nó: ' : 'Node: ') + roleLabel + ' (' + peersLabel + ')';

      const elHostname = document.getElementById('topHostname');
      if (elHostname) elHostname.textContent = s.hostname || '-';

      const elHealth = document.getElementById('topHealthBadge');
      if (elHealth) elHealth.textContent = isPt ? 'Sistema Online' : 'System Online';

      // Parse disk info
      let diskTotal = '-';
      let diskUsed = '-';
      let diskPercent = 0;
      if (s.rootDisk && typeof s.rootDisk === 'string') {
        const parts = s.rootDisk.trim().split(/\s+/);
        if (parts.length >= 5) {
          diskTotal = parts[1] || '-';
          diskUsed = parts[2] || '-';
          diskPercent = parseInt((parts[4] || '0').replace('%', ''), 10) || 0;
        }
      }

      // Memory calculations
      const totalMem = s.totalMemGb || 1;
      const freeMem = s.freeMemGb || 0;
      const usedMem = Math.max(0, +(totalMem - freeMem).toFixed(1));
      const ramPercent = Math.min(100, Math.max(0, Math.round((usedMem / totalMem) * 100)));

      // Update counters in subnav tabs
      const elTabApps = document.getElementById('tabCountApps');
      if (elTabApps) elTabApps.textContent = Object.keys(s.apps || {}).length;

      const elTabDbs = document.getElementById('tabCountDbs');
      if (elTabDbs) elTabDbs.textContent = Object.keys(s.databases || {}).length;

      const elTabVault = document.getElementById('tabCountVault');
      if (elTabVault) elTabVault.textContent = (s.systemSecretsConfigured || []).length;

      const elTabMirror = document.getElementById('tabCountMirror');
      if (elTabMirror) elTabMirror.textContent = peersCount;

      const elTabPool = document.getElementById('tabCountPool');
      if (elTabPool) elTabPool.textContent = Object.keys(s.pool || {}).length;

      const roleBadge = role === 'standalone' ? (isPt ? 'AUTÔNOMO' : 'STANDALONE') : role.toUpperCase();
      const tailscaleVal = s.tailscaleDomain || (s.federation?.peers ? (isPt ? 'Rede Ativa' : 'Tailnet Active') : '127.0.0.1');
      const dockerVal = isPt ? 'Ativo (27.x)' : 'Live (27.x)';
      const daemonOverheadVal = isPt ? '0 MB Ocioso' : '0 MB Idle';
      const backupsCount = s.backupsCount || 0;
      const backupsUnit = isPt ? (backupsCount === 1 ? 'cópia' : 'cópias') : (backupsCount === 1 ? 'backup' : 'backups');

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
            <span>\${isPt ? 'Papel no Cluster' : 'Cluster Role'}</span>
            <span class="badge" style="font-size:10px;padding:2px 7px;">\${esc(roleBadge)}</span>
          </div>
        </div>

        <div class="telemetry-card">
          <div class="telemetry-title">
            <span>\${isPt ? 'Uso de Recursos' : 'Resource Usage'}</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
          </div>
          <div class="telemetry-item" style="border-bottom:none;padding-bottom:2px;">
            <span>RAM (\${usedMem} / \${s.totalMemGb} GB)</span>
            <span class="telemetry-val">\${ramPercent}%</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill \${ramPercent > 85 ? 'danger' : ramPercent > 70 ? 'warning' : ''}" style="width: \${ramPercent}%;"></div>
          </div>

          <div class="telemetry-item" style="border-bottom:none;padding-bottom:2px;">
            <span>\${isPt ? 'Disco' : 'Disk'} (\${diskTotal === '-' ? '-' : diskUsed + ' / ' + diskTotal})</span>
            <span class="telemetry-val">\${diskPercent}%</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill \${diskPercent > 85 ? 'danger' : diskPercent > 70 ? 'warning' : ''}" style="width: \${diskPercent}%;"></div>
          </div>

          <div class="telemetry-item" style="margin-top:6px;">
            <span>CPUs</span>
            <span class="telemetry-val">\${esc(s.cpus)} vCPUs</span>
          </div>
          <div class="telemetry-item">
            <span>\${isPt ? 'Sobrecarga do Daemon' : 'Daemon Overhead'}</span>
            <span class="telemetry-val" style="color:var(--success);font-weight:600;">\${daemonOverheadVal}</span>
          </div>
          <div class="telemetry-item">
            <span>\${isPt ? 'Instantâneos' : 'Snapshots'}</span>
            <span class="telemetry-val">\${esc(backupsCount)} \${backupsUnit}</span>
          </div>
        </div>
      \`;

      document.getElementById('sshKeyBox').textContent = s.sshPublicKey || '';
      document.getElementById('webhookSecretBox').textContent = s.webhookSecretMasked || '••••••••';

      const apps = Object.values(s.apps || {});
      const metricsMap = s.containerMetrics || {};
      document.getElementById('appsBadgeCount').textContent = apps.length + ' apps';

      document.getElementById('hostedAppsList').innerHTML = apps.map(a => \`<option value="\${esc(a.name)}"></option>\`).join('');
      document.getElementById('dynamicScopeChips').innerHTML = apps.map(a => \`<button class="chip" onclick="setVaultScope('\${esc(a.name)}')">📦 \${esc(a.name)}</button>\`).join(' ');

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
          const appLink = mainDomain ? mainDomain.url : \`http://127.0.0.1:\${a.localPort}\`;

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
            ? \`<span>(Limits: \${esc(a.memoryLimit || '-')} / \${esc(a.cpuLimit || '-')} CPU)</span>\`
            : '';
          const cp = s.controlPlane || {};
          const followBtn = a.runtimeType === 'paasmcp-control-plane'
            ? \`<button class="secondary" style="\${cp.enabled ? 'border-color:var(--success, #16a34a);' : ''}" onclick="toggleFollow(\${cp.enabled ? 'false' : 'true'})" title="\${esc(cp.enabled ? t('followOnTitle').replace('{branch}', cp.branch || 'main') : t('followOffTitle'))}">\${esc(cp.enabled ? t('followOn') : t('followOff'))}</button>\`
            : '';
          const followErr = a.runtimeType === 'paasmcp-control-plane' && cp.enabled && cp.lastError
            ? \`<div style="font-size:11px;color:var(--danger, #dc2626);margin-top:2px;">\${esc(t('followFailed').replace('{step}', cp.lastError.step).replace('{commit}', String(cp.lastError.commit).slice(0, 7)))}</div>\`
            : '';
          const rollbackBtn = a.previousImageTag
            ? \`<button class="secondary" onclick="appAction('\${esc(a.name)}','rollback')" title="Reverter para imagem anterior em 1s">\${esc(t('actionRollback'))}</button>\`
            : '';

          const domainPills = (a.domains || []).map(dom => \`
            <span class="app-badge-pill">
              <a href="\${esc(dom.url)}" target="_blank" rel="noopener noreferrer">🌐 \${esc(dom.url)}</a>
              <span class="badge" style="padding:1px 5px;font-size:9.5px;">\${esc(dom.mode)}</span>
            </span>
          \`).join('') || \`<span class="app-badge-pill">🔒 127.0.0.1:\${esc(a.localPort)}</span>\`;

          const dbPills = (a.databases || []).map(db => \`
            <span class="app-badge-pill" style="font-size:11px;">🗄️ \${esc(db)}</span>
          \`).join('');

          return \`
            <div class="app-entry-row">
              <div class="app-row-top">
                <div class="app-row-main-identity">
                  <a href="\${esc(appLink)}" target="_blank" rel="noopener noreferrer" class="app-row-name-link">
                    <span class="status-dot \${dotClass}"></span>
                    <span>\${esc(a.name)}</span>
                  </a>
                  <span class="app-badge-pill \${statusBadgeClass}">● \${esc(statusText)}</span>
                  \${domainPills}
                  \${dbPills}
                </div>
                <div class="app-actions-group">
                  <button class="secondary" onclick="selectAppForExpose('\${esc(a.name)}')">\${esc(t('actionExpose'))}</button>
                  <button class="secondary" onclick="setVaultScope('\${esc(a.name)}')">\${esc(t('actionEnv'))}</button>
                  <button class="secondary" onclick="appAction('\${esc(a.name)}','logs')">\${esc(t('actionLogs'))}</button>
                  <button class="secondary" onclick="appAction('\${esc(a.name)}','restart')">\${esc(t('actionRestart'))}</button>
                  \${rollbackBtn}
                  \${followBtn}
                  \${a.trashedAt
                    ? \`<span style="font-size:11px;color:var(--muted);">\${esc(t('trashedStatus') + a.trashedAt.slice(0, 10))}</span>
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
                <span>Porta: <code>\${esc(a.localPort)}</code></span>
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
        ? dbs.map(d => \`<div style="margin-bottom:6px;padding:8px 10px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12.5px;">🗄️ <strong>\${esc(d.name)}</strong> (\${esc(d.engine)}) → DB: <code>\${esc(d.dbName)}</code> | User: <code>\${esc(d.dbUser)}</code></div>\`).join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('emptyDbs')) + '</span>';

      const backups = s.backups || [];
      document.getElementById('backupsList').innerHTML = backups.length
        ? backups.map(b => \`
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;padding:8px 10px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12px;gap:8px;flex-wrap:wrap;">
            <div>
              🔒 <strong>\${esc(b.id)}</strong> (\${esc(b.engine)})<br/>
              <span style="color:var(--muted);">\${esc(t('sizeLabel'))} \${esc(b.sizeBytes)} bytes · SHA256: <code>\${esc((b.sha256 || '').slice(0, 12))}...</code>\${b.offsiteKey ? ' · ☁️ ' + esc(t('offsiteLabel')) : ''}</span>
            </div>
            <span>
              <button class="secondary" style="padding:4px 9px;font-size:11px;" onclick="testBackup('\${esc(b.id)}')">\${esc(t('btnTestRestore'))}</button>
              <button class="secondary" style="padding:4px 9px;font-size:11px;" onclick="restoreBackup('\${esc(b.id)}')">\${esc(t('btnRestoreDump'))}</button>
            </span>
          </div>
        \`).join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('emptyBackups')) + '</span>';

      const peers = Object.values(s.federation?.peers || {});
      document.getElementById('fedPeersList').innerHTML = peers.length
        ? peers.map(p => \`
          <div style="padding:8px 10px;margin-bottom:6px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12.5px;">
            🤝 <strong>\${esc(p.name)}</strong> (<code>\${esc(p.nodeId)}</code>) — <span class="badge success">\${esc(p.mode)}</span><br/>
            <span style="color:var(--muted);font-size:11.5px;">Endpoint: \${esc(p.endpointUrl)} · Key: <code>\${esc(p.publicKeyFingerprint)}</code></span>
          </div>
        \`).join('')
        : '<span style="color:var(--muted);font-size:12.5px;">' + esc(t('emptyPeers')) + '</span>';
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
    function goTab(name) { switchTab(name, document.getElementById('nav' + name.charAt(0).toUpperCase() + name.slice(1))); }
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
      const m = s.mirror || {};
      const hasMirror = Object.keys(m.replicas || {}).length + Object.keys(m.offers || {}).length > 0;
      const tile = (title, value, note) => '<div class="arch-box"><h3>' + esc(title) + '</h3><p style="font-size:18px;font-weight:700;color:var(--text);margin:4px 0;">' + esc(value) + '</p><p>' + esc(note) + '</p></div>';
      tiles.innerHTML =
        tile(t('tileApps'), String(apps.length), apps.length ? t('tileAppsNote') : t('tileAppsNone')) +
        tile(t('tileBackup'), last ? new Date(last.createdAt).toLocaleString() : t('never'), last ? (last.offsiteAt ? t('tileBackupOff') : t('tileBackupLocal')) : t('tileBackupNone')) +
        tile(t('tileMirror'), m.fenced ? t('mirrorFenced') : hasMirror ? t('tileMirrorOn') : t('tileMirrorOff'), t('tileMirrorNote')) +
        tile(t('tileEmail'), emailRelay ? emailRelay.host : t('notConfigured'), emailRelay ? emailRelay.fromDomain : t('tileEmailNote'));
      const steps = [
        ['step1', apps.length > 0, 'overview', false],
        ['step2', offsiteOn, 'databases', false],
        ['step3', Boolean(emailRelay), 'email', false],
        ['step4', hasMirror, 'mirror', true],
        ['step5', false, 'agents', true],
      ];
      document.getElementById('homeSteps').innerHTML = steps.map((st, i) => card(
        '<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;">' +
        '<div><strong>' + (i + 1) + '. ' + esc(t(st[0] + 'Title')) + '</strong>' + (st[3] ? ' <span style="color:var(--muted)">(' + esc(t('optional')) + ')</span>' : '') +
        '<div style="color:var(--muted);margin-top:4px;">' + esc(t(st[0] + 'Desc')) + '</div></div>' +
        (st[1] ? badge('success', t('done')) : '<button class="secondary" onclick="goTab(&#39;' + st[2] + '&#39;)">' + esc(t('openStep')) + '</button>') +
        '</div>')).join('');
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
      if (!res.ok) return;
      const m = await res.json();
      let html = '';
      if (m.fenced) html += card(badge('danger', t('mirrorFenced')) + '<div style="margin-top:6px;">' + esc(t('mirrorFencedDesc')) + '</div>');
      html += card('<strong>' + esc(t('mirrorAuto')) + ':</strong> ' + ((m.auto || []).length ? badge('success', (m.auto || []).join(', ')) : badge('', t('off'))) +
        ' · <strong>' + esc(t('mirrorArbiter')) + ':</strong> ' + (m.arbiterUrl ? esc(m.arbiterUrl) : esc(t('notConfigured'))));
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
      renderArbiterInstall();
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
    function renderArbiterInstall() {
      document.getElementById('arbInstallCmd').textContent =
        'git clone ' + t('autoRepoPlaceholder') + ' paasmcp\\n' +
        'cd paasmcp && npm install && npm run build\\n' +
        'sudo node dist/cli.js arbiter install-service --key ' + t('autoKeyPlaceholder');
      document.getElementById('arbAddKeyCmd').textContent =
        'cd paasmcp && sudo node dist/cli.js arbiter add-key ' + t('autoKeyPlaceholder');
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
      const res = await fetch('/api/mirror/arbiter');
      const c = await res.json().catch(() => ({}));
      if (!res.ok) { box.innerHTML = card(badge('danger', c.error || 'error')); return; }
      box.innerHTML = renderArbiterCheck(c);
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
    async function syncOffsiteNow() {
      const btn = document.getElementById('btnSyncOffsite');
      btn.disabled = true;
      try {
        const r = await postJson('/api/backups/sync', {});
        if (r) showToast(t('offsiteDone') + ' ' + r.uploaded.length + (r.failed.length ? ' · ' + t('offsiteFailed') + ' ' + r.failed.length : ''));
      } finally { btn.disabled = false; }
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
      document.getElementById('scaleLang').value = d.language;
      const a = d.apps.find(x => x.app === d.app);
      const body = document.getElementById('scaleBody');
      if (!a) {
        document.getElementById('scaleNow').innerHTML = '<p class="card-desc">' + esc(t('scaleNoApps')) + '</p>';
        document.getElementById('scaleCharts').innerHTML = '';
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
      applyPreferences();
    }

    async function loadSecrets() {
      const scope = document.getElementById('secScope').value.trim() || 'system';
      const res = await fetch('/api/secrets?scope=' + encodeURIComponent(scope));
      if (!res.ok) return;
      const data = await res.json();
      const entries = Object.entries(data.secrets || {});
      document.getElementById('secretsList').innerHTML = entries.length
        ? entries.map(([k, v]) => \`<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:6px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:12.5px;"><span>🔑 <strong>\${esc(k)}</strong> = <code>\${esc(v)}</code></span><button class="danger" style="padding:3px 9px;font-size:11px" onclick="delSecret('\${esc(scope)}','\${esc(k)}')">\${esc(t('btnRemoveSecret'))}</button></div>\`).join('')
        : '<div style="color:var(--muted);font-size:12.5px">' + esc(t('emptySecrets')) + '</div>';
    }

    async function saveSecret() {
      const scope = document.getElementById('secScope').value.trim() || 'system';
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
      loadSecrets();
    }

    async function delSecret(scope, key) {
      await fetch('/api/secrets', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope, key })
      });
      loadSecrets();
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
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      showToast(t('toastDbCreated'));
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
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      showToast((data.ok ? '✅ ' : '⚠️ ') + data.detail);
    }

    async function restoreBackup(backupId) {
      const res = await fetch('/api/backups/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backupId })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      showToast('✅ Banco restaurado com sucesso (' + data.restoredBytes + ' bytes)!');
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
          ? \`<div style="font-size:11.5px;color:var(--muted);margin-bottom:10px;">\${esc(t('lastCheck'))} <strong>\${esc(checkedTime)}</strong> · \${esc(t('overallStatus'))} <span class="badge \${data.overallHealth === 'healthy' ? 'success' : data.overallHealth === 'warning' ? 'warning' : 'danger'}">\${esc((data.overallHealth || 'healthy').toUpperCase())}</span></div>\` +
            items.map(d => \`
            <div style="padding:12px 14px;margin-bottom:8px;border-radius:10px;background:var(--bg-subtle);border:1px solid var(--border);">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
                <strong>\${esc(d.target === 'server' ? t('doctorServer') : d.target)}</strong>
                <div style="display:flex;gap:6px;align-items:center;">
                  <span class="badge \${d.severity === 'healthy' ? 'success' : d.severity === 'warning' ? 'warning' : 'danger'}">\${esc(d.severity.toUpperCase())}</span>
                  \${d.severity !== 'healthy' && d.target !== 'server' ? \`<button class="secondary" style="padding:3px 9px;font-size:11px;" onclick="appAction('\${esc(d.target)}','restart')">\${esc(t('btnRestartContainer'))}</button>\` : ''}
                </div>
              </div>
              <div style="font-size:13px;margin-top:6px;">\${esc(d.summary)}</div>
              \${d.recommendation ? \`<div style="font-size:12px;color:var(--accent-text);margin-top:4px;">💡 \${esc(d.recommendation)}</div>\` : ''}
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
      try {
        setTimeout(pollDeploys, 800);
        const res = await fetch('/api/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ appName, repoSource, branch, withPostgres, withRedis, memoryLimit, cpuLimit, healthcheckPath, skipHealthcheck })
        });
        const data = await res.json();
        if (!res.ok) alert((/HealthcheckFailedError/.test(data.error) ? t('deployHealthFailed') + '\\n\\n' : 'Error: ') + data.error);
        else {
          if (document.getElementById('depPoll').checked) await postJson('/api/poll', { appName, on: true });
          showToast(t('toastDeployDone') + appName);
          loadAll();
        }
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
      const data = await res.json();
      if (!res.ok) return alert('Error: ' + data.error);
      showToast(t('toastExposed') + data.url);
      loadAll();
    }

    async function toggleFollow(on) {
      const data = await postJson('/api/poll', { appName: 'paasmcp-dashboard', on });
      if (!data) return;
      showToast(on ? t('followOn') : t('followOff'));
      loadAll();
    }

    async function appAction(appName, action) {
      const res = await fetch('/api/lifecycle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName, action })
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error);
      if (action === 'logs') {
        const card = document.getElementById('logsCard');
        card.style.display = 'block';
        document.getElementById('logsBox').textContent = data.output || '(empty logs)';
        card.scrollIntoView({ behavior: 'smooth' });
      } else {
        showToast('✅ ' + data.output);
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
const DASHBOARD_DOCKERFILE = `FROM node:22.11.0-alpine3.20
RUN apk add --no-cache docker-cli docker-cli-compose git openssh-client
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
      - /var/run/docker.sock:/var/run/docker.sock
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
