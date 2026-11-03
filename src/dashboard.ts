import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DOCKER_NETWORK, PAAS_DATA_DIR, loadState, sanitizeSlug, saveState, withStateLock } from "./config.js";
import {
  authorizeHuman,
  ConfirmationRequiredError,
  decideApproval,
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

function isAuthenticated(req: http.IncomingMessage, expectedToken: string): boolean {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const provided = authHeader.slice("Bearer ".length).trim();
    if (timingSafeCompare(provided, expectedToken)) return true;
  }
  const cookies = parseCookies(req.headers.cookie);
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
        if (typeof body.token === "string" && timingSafeCompare(body.token.trim(), expectedToken)) {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Set-Cookie": `paasmcp_token=${encodeURIComponent(
              expectedToken
            )}; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800`,
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
        "Set-Cookie": "paasmcp_token=; HttpOnly; Path=/; Max-Age=0",
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
        res.end(renderDashboardHtml(authed, cfEmail));
      }
      return;
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
          const status = getSystemStatusSummary(true);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(status));
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
          const engine = (body.engine as "postgres" | "redis") || "postgres";
          const backup = backupDatabase(appName, engine);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(backup));
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
          const result = deployApp({
            trusted,
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
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ output }));
          return true;
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

function renderDashboardHtml(authed: boolean, cfEmail?: string): string {
  const safeCfEmail = cfEmail ? escapeHtmlServer(cfEmail) : "";
  const sharedCss = `
    :root, [data-theme="dark"] {
      --bg: #090a0f;
      --bg-elevated: #0e1017;
      --bg-subtle: #141722;
      --card: #11131c;
      --card-hover: #181b28;
      --border: rgba(255, 255, 255, 0.08);
      --border-strong: rgba(255, 255, 255, 0.15);
      --text: #f3f4f6;
      --muted: #8e95a9;
      --input-bg: #07080c;
      --accent: #6366f1;
      --accent-hover: #4f46e5;
      --accent-soft: rgba(99, 102, 241, 0.14);
      --accent-text: #a5b4fc;
      --success: #10b981;
      --success-soft: rgba(16, 185, 129, 0.14);
      --warning: #f59e0b;
      --warning-soft: rgba(245, 158, 11, 0.14);
      --danger: #ef4444;
      --danger-soft: rgba(239, 68, 68, 0.14);
      --code-bg: #07080c;
      --code-text: #c7d2fe;
      --shadow: 0 16px 40px rgba(0, 0, 0, 0.45);
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
      --input-bg: #f8fafc;
      --accent: #4f46e5;
      --accent-hover: #4338ca;
      --accent-soft: rgba(79, 70, 229, 0.09);
      --accent-text: #4338ca;
      --success: #059669;
      --success-soft: rgba(5, 150, 105, 0.12);
      --warning: #d97706;
      --warning-soft: rgba(217, 119, 6, 0.12);
      --danger: #dc2626;
      --danger-soft: rgba(220, 38, 38, 0.1);
      --code-bg: #f1f5f9;
      --code-text: #312e81;
      --shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
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
      color: #ffffff;
      font-weight: 600;
      font-size: 12.5px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.14s ease;
      white-space: nowrap;
    }
    button:hover { background: var(--accent-hover); }
    button:disabled { opacity: 0.55; cursor: not-allowed; }
    button.secondary {
      background: var(--bg-subtle);
      border-color: var(--border);
      color: var(--text);
    }
    button.secondary:hover { background: var(--card-hover); border-color: var(--border-strong); }
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
    button.chip:hover { background: var(--accent); color: #fff; }
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
    <h1>🚀 PaaSMCP</h1>
    <p id="loginDesc"></p>
    ${safeCfEmail ? `<div style="margin-bottom:16px;"><span class="badge success">✓ Cloudflare Zero Trust: ${safeCfEmail}</span></div>` : ""}
    <input type="password" id="token" placeholder="Token..." autofocus style="margin-bottom: 14px;" />
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
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.getElementById('themeBtn').textContent = currentTheme === 'dark' ? '☀️ Light' : '🌙 Dark';
      document.getElementById('langBtn').textContent = currentLang === 'pt' ? '🇧🇷 PT-BR' : '🇺🇸 EN';
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
      const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
      if (res.ok) location.reload();
      else document.getElementById('err').style.display = 'block';
    }
    document.getElementById('token').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
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
    .app-shell {
      display: grid;
      grid-template-columns: 250px 1fr;
      min-height: 100vh;
    }
    @media (max-width: 960px) {
      .app-shell { grid-template-columns: 1fr; }
      .sidebar { border-right: none; border-bottom: 1px solid var(--border); padding: 14px 16px; }
    }
    .sidebar {
      background: var(--bg-elevated);
      border-right: 1px solid var(--border);
      padding: 20px 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 20px;
    }
    .brand-box {
      padding: 4px 10px 14px;
      border-bottom: 1px solid var(--border);
    }
    .brand-title {
      font-size: 17px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: space-between;
      letter-spacing: -0.02em;
    }
    .brand-sub {
      font-size: 11.5px;
      color: var(--muted);
      margin-top: 4px;
    }
    .nav-list {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-top: 12px;
    }
    .nav-btn {
      background: transparent;
      color: var(--muted);
      border: 1px solid transparent;
      justify-content: flex-start;
      padding: 9px 12px;
      font-size: 13px;
      font-weight: 500;
      border-radius: 8px;
      width: 100%;
    }
    .nav-btn:hover {
      background: var(--bg-subtle);
      color: var(--text);
    }
    .nav-btn.active {
      background: var(--accent-soft);
      color: var(--accent-text);
      border-color: rgba(99, 102, 241, 0.28);
      font-weight: 600;
    }
    .sidebar-footer {
      padding: 12px 10px 4px;
      border-top: 1px solid var(--border);
      font-size: 11.5px;
      color: var(--muted);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .main-area {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .topbar {
      background: var(--bg-elevated);
      border-bottom: 1px solid var(--border);
      padding: 12px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .topbar-left {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .content-wrap {
      padding: 24px 28px;
      max-width: 1360px;
      width: 100%;
      margin: 0 auto;
    }
    .grid-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }
    .stat-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }
    .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
    .stat-value { font-size: 20px; font-weight: 700; margin-top: 6px; letter-spacing: -0.02em; }
    .stat-meta { color: var(--muted); font-size: 11.5px; margin-top: 4px; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px 22px;
      margin-bottom: 20px;
      box-shadow: var(--shadow);
    }
    .card-header { margin-bottom: 14px; }
    .card-header h2 {
      margin: 0 0 4px;
      font-size: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }
    .card-desc { margin: 0; font-size: 12.5px; color: var(--muted); line-height: 1.5; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 980px) { .row { grid-template-columns: 1fr; } }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }
    .field-label {
      display: block;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--muted);
      margin-bottom: 5px;
    }
    .examples-bar {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
      margin-bottom: 12px;
      padding: 8px 10px;
      border-radius: 8px;
      background: var(--bg-subtle);
      border: 1px dashed var(--border);
      font-size: 11.5px;
      color: var(--muted);
    }
    table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    th, td { text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
    .actions { display: flex; gap: 5px; flex-wrap: wrap; align-items: center; }
    .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--success); margin-right: 7px; }
    .status-dot.stopped { background: var(--danger); }
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
  <div class="app-shell">
    <!-- Sidebar Navigation -->
    <aside class="sidebar">
      <div>
        <div class="brand-box">
          <div class="brand-title">
            <span>🚀 PaaSMCP</span>
            <span class="badge" style="font-size:10px;padding:2px 7px;">v1.1</span>
          </div>
          <div class="brand-sub" id="sidebarSubtitle">Agent-First Micro-PaaS</div>
        </div>
        <nav class="nav-list">
          <button class="nav-btn active" onclick="switchTab('overview', this)" id="navOverview">📦 Aplicações & Deploy</button>
          <button class="nav-btn" onclick="switchTab('vault', this)" id="navVault">🔐 Cofre AES-256-GCM</button>
          <button class="nav-btn" onclick="switchTab('databases', this)" id="navDatabases">🗄️ Bancos & Backups</button>
          <button class="nav-btn" onclick="switchTab('federation', this)" id="navFederation">🌐 Multi-Server HA & Webhook</button>
          <button class="nav-btn" onclick="switchTab('doctor', this)" id="navDoctor">🩺 Doctor & Diagnóstico</button>
          <button class="nav-btn" onclick="switchTab('agents', this)" id="navAgents">🤖 Studio IA (MCP) & Guia</button>
        </nav>
      </div>
      <div class="sidebar-footer">
        <div>🔒 <strong>Loopback-First</strong> (127.0.0.1)</div>
        <div>⚡ <strong>0 MB</strong> Idle Daemon Overhead</div>
        <div id="nodeRoleFooter">Node: standalone</div>
      </div>
    </aside>

    <!-- Main Workspace Area -->
    <div class="main-area">
      <header class="topbar">
        <div class="topbar-left">
          <span class="badge success" id="topHealthBadge">● System Online</span>
          <span class="badge" id="topDomainBadge">Domain: -</span>
          ${safeCfEmail ? `<span class="badge success">🛡️ Zero Trust: ${safeCfEmail}</span>` : ""}
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <button class="secondary" onclick="toggleLang()" id="langBtn">🇧🇷 PT-BR</button>
          <button class="secondary" onclick="toggleTheme()" id="themeBtn">☀️ Light</button>
          <button class="secondary" onclick="loadAll()" id="btnRefresh">🔄 Atualizar</button>
          <button class="danger" onclick="logout()" id="btnLogout">Sair</button>
        </div>
      </header>

      <div class="content-wrap">
        <!-- Global Hardware & Cluster Summary -->
        <div class="grid-stats" id="statsGrid"></div>

        <!-- TAB 1: OVERVIEW, APPS, DEPLOY & EXPOSE -->
        <div class="tab-pane active" id="tab-overview">
          <div class="card" id="approvalsCard" style="display:none;">
            <div class="card-header">
              <h2 id="approvalsTitle">✋ Confirmações pendentes</h2>
              <p class="card-desc" id="approvalsDesc">Ações arriscadas pedidas por um agente de IA esperam você aqui. O agente não consegue aprovar sozinho.</p>
            </div>
            <div id="approvalsList"></div>
          </div>
          <div class="card">
            <div class="card-header">
              <h2 id="setupTitle">🧭 Primeira configuração: o que você precisa?</h2>
              <p class="card-desc" id="setupDesc">Configure só as integrações que pretende usar. O PaaSMCP funciona localmente sem tokens de terceiros; os valores secretos são guardados no Cofre.</p>
            </div>
            <div class="grid-2">
              <div class="arch-box">
                <h3 id="setupGithubTitle">🐙 GitHub — opcional</h3>
                <p id="setupGithubDesc">Para repositório privado, use uma Deploy Key SSH somente leitura. Copie a chave pública na seção Webhook abaixo e adicione em Settings → Deploy keys. Para registrar automaticamente a chave ou clonar via HTTPS, salve <code>GITHUB_TOKEN</code> no escopo <code>system</code>. Um fine-grained token precisa de acesso apenas ao repositório e <em>Administration: read and write</em>; a chave criada continua somente leitura.</p>
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
            <p class="card-desc" id="setupWebhookNote">Auto-deploy por webhook é opcional: cadastre a URL mostrada na aba Webhook no GitHub, evento Push e o secret mostrado pelo painel. Não cole tokens no chat; insira-os no Cofre.</p>
          </div>
          <div class="card">
            <div class="card-header">
              <h2>
                <span id="appsTitle">📦 Aplicações Hospedadas & Métricas em Tempo Real</span>
                <span class="badge" id="appsBadgeCount">0 apps</span>
              </h2>
              <p class="card-desc" id="appsDesc">Containers isolados em <code>127.0.0.1:4000-4998</code> com suporte a Rollback em 1s, limites de CPU/RAM e Docker Compose multi-serviço.</p>
            </div>
            <div style="overflow-x:auto;">
              <table>
                <thead>
                  <tr>
                    <th id="thApp">Aplicação</th>
                    <th id="thStack">Stack / Commit</th>
                    <th id="thMetrics">CPU / RAM (Live)</th>
                    <th id="thPort">Porta / DBs</th>
                    <th id="thDomains">Domínios HTTPS</th>
                    <th id="thActions">Ações Rápidas</th>
                  </tr>
                </thead>
                <tbody id="appsTable">
                  <tr><td colspan="6">...</td></tr>
                </tbody>
              </table>
            </div>
            <div class="guide-box">
              <div class="guide-box-title">
                <span id="guideAppsTitle">💡 Funções de Gestão & Ciclo de Vida</span>
              </div>
              <div class="guide-grid">
                <div class="guide-item">
                  <strong id="guideAppsRollbackTitle">⏪ Rollback em 1s</strong>
                  <span id="guideAppsRollbackDesc">Restaura o container para a imagem anterior instantaneamente caso o novo deploy falhe ou contenha bugs.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideAppsLimitsTitle">⚡ Limites de Memória & CPU</strong>
                  <span id="guideAppsLimitsDesc">Isolamento cgroups do kernel Linux que impede que um app consuma toda a RAM do host ou trave outros containers.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideAppsActionsTitle">🛠️ Ações Rápidas (ENV, Logs, Restart)</strong>
                  <span id="guideAppsActionsDesc">Edite segredos no cofre sem re-build, consulte logs em tempo real e reinicie containers sem downtime desnecessário.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideAppsLoopbackTitle">🔒 Isolamento Loopback</strong>
                  <span id="guideAppsLoopbackDesc">Containers escutam exclusivamente em 127.0.0.1:4000-4998, sem portas expostas no firewall ou roteador.</span>
                </div>
              </div>
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
                <button class="chip" id="presetSaas" onclick="fillDeployExample('meu-saas', 'seu-usuario/meu-saas', 'main', true, false, '512m', '1.0')">SaaS Next.js + PG (512MB)</button>
                <button class="chip" id="presetCompose" onclick="fillDeployExample('api-worker', 'seu-usuario/api-compose', 'main', true, true, '1g', '2.0')">Multi-Service Compose + PG + Redis</button>
                <button class="chip" id="presetSpa" onclick="fillDeployExample('landing', 'seu-usuario/landing', 'main', false, false, '256m', '0.5')">SPA / Site Estático</button>
              </div>
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
              <div class="guide-box">
                <div class="guide-box-title">
                  <span id="guideExposeTitle">🛡️ Como funcionam os Modos de Publicação</span>
                </div>
                <div class="guide-grid">
                  <div class="guide-item">
                    <strong id="guideExposePublicTitle">🌐 Público (Cloudflare Tunnel)</strong>
                    <span id="guideExposePublicDesc">Túnel QUIC criptografado com DNS CNAME proxied e certificado SSL automático sem abrir portas.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideExposeZTTitle">🛡️ Zero Trust (PIN por E-mail)</strong>
                    <span id="guideExposeZTDesc">Protege o app exigindo código OTP no e-mail antes do acesso. Recomendado para painéis e bancos.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideExposeTailscaleTitle">🔒 Tailscale (VPN Privada)</strong>
                    <span id="guideExposeTailscaleDesc">Expõe o serviço de forma privada diretamente na sua Tailnet WireGuard, sem acesso público.</span>
                  </div>
                </div>
              </div>
            </div>
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
            <div class="guide-box">
              <div class="guide-box-title">
                <span id="guideVaultTitle">🔐 Arquitetura de Segurança do Cofre (AES-256-GCM)</span>
              </div>
              <div class="guide-grid">
                <div class="guide-item">
                  <strong id="guideVaultScopesTitle">📁 Escopos Isolados</strong>
                  <span id="guideVaultScopesDesc">O escopo <code>system</code> guarda tokens de nuvem. Cada aplicação possui seu próprio escopo isolado.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideVaultGcmTitle">🛡️ Criptografia AES-256-GCM</strong>
                  <span id="guideVaultGcmDesc">Dados cifrados em repouso com IV aleatório de 96 bits e autenticação GCM contra adulterações.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideVaultInjectionTitle">⚡ Injeção Segura</strong>
                  <span id="guideVaultInjectionDesc">Variáveis são descriptografadas em memória na partida do container, sem nunca vazarem no código ou git.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideVaultMasterKeyTitle">🔑 Chave Mestra 0600</strong>
                  <span id="guideVaultMasterKeyDesc">Guardada em arquivo local com permissões restritas (0600), acessível apenas pelo daemon do PaaS.</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 3: DATABASES & ENCRYPTED BACKUPS -->
        <div class="tab-pane" id="tab-databases">
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
              <div class="guide-box">
                <div class="guide-box-title">
                  <span id="guideDbTitle">🗄️ Como funciona o Banco Multi-Tenant</span>
                </div>
                <div class="guide-grid">
                  <div class="guide-item">
                    <strong id="guideDbIsolationTitle">🐘 PostgreSQL 16 & Redis 7</strong>
                    <span id="guideDbIsolationDesc">Cada app recebe um banco lógico e usuário exclusivo com senha forte, isolado dos demais.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideDbInjectionTitle">🔗 DATABASE_URL Automática</strong>
                    <span id="guideDbInjectionDesc">A URL de conexão é salva no Cofre do app e injetada no container sem configuração manual.</span>
                  </div>
                </div>
              </div>
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
                  </select>
                </div>
              </div>
              <button onclick="createBackup()" id="btnCreateBackup" style="margin-bottom:16px;">📸 Criar Snapshot Criptografado</button>
              <div id="backupsList"></div>
              <div class="guide-box">
                <div class="guide-box-title">
                  <span id="guideBackupTitle">🛡️ Como funcionam os Snapshots & Restore</span>
                </div>
                <div class="guide-grid">
                  <div class="guide-item">
                    <strong id="guideBackupDumpTitle">📸 Dumps Consistentes</strong>
                    <span id="guideBackupDumpDesc">Executa <code>pg_dump</code> transacional ou RDB em tempo de execução sem interromper os serviços.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideBackupCryptoTitle">🔐 Criptografia em Repouso</strong>
                    <span id="guideBackupCryptoDesc">O dump é criptografado com chave AES-256-GCM antes de ser gravado no diretório de backups.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideBackupIntegrityTitle">🛡️ Checksum SHA-256</strong>
                    <span id="guideBackupIntegrityDesc">Todo snapshot calcula um hash SHA-256 que é estritamente verificado antes de qualquer restauração.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideBackupRestoreTitle">⏪ Restore 1-Click</strong>
                    <span id="guideBackupRestoreDesc">Restaura o banco instantaneamente para recuperação de desastres ou testes de migração.</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 4: MULTI-SERVER HA FEDERATION & GITHUB WEBHOOKS -->
        <div class="tab-pane" id="tab-federation">
          <div class="row">
            <div class="card">
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
              <div class="guide-box">
                <div class="guide-box-title">
                  <span id="guideFedTitle">🌐 Redundância e Alta Disponibilidade</span>
                </div>
                <div class="guide-grid">
                  <div class="guide-item">
                    <strong id="guideFedTokenTitle">🤝 Handshake HMAC-SHA256</strong>
                    <span id="guideFedTokenDesc">Pareia nós com token assinado e expiração de 15 minutos, impedindo conexões não autorizadas.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideFedActiveTitle">⚡ Active-Active (Cloudflare)</strong>
                    <span id="guideFedActiveDesc">Múltiplos servidores atendem no mesmo túnel com balanceamento de carga e failover automático.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideFedWarmTitle">📦 Warm Standby & Sync</strong>
                    <span id="guideFedWarmDesc">Exportação e importação de pacotes cifrados com segredos e apps para recuperação remota.</span>
                  </div>
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
              <div class="guide-box">
                <div class="guide-box-title">
                  <span id="guideWhTitle">⚡ Automação com GitHub Webhooks</span>
                </div>
                <div class="guide-grid">
                  <div class="guide-item">
                    <strong id="guideWhSigTitle">🔒 Validação HMAC-SHA256</strong>
                    <span id="guideWhSigDesc">Compara a assinatura do GitHub em tempo constante (evitando timing attacks) antes de acionar rebuilds.</span>
                  </div>
                  <div class="guide-item">
                    <strong id="guideWhSshTitle">🔑 Deploy Key Ed25519</strong>
                    <span id="guideWhSshDesc">Chave SSH somente leitura para clonar repositórios privados sem expor senhas ou tokens globais.</span>
                  </div>
                </div>
              </div>
            </div>
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
            <div class="guide-box">
              <div class="guide-box-title">
                <span id="guideDoctorTitle">🩺 Como o Doctor protege o cluster</span>
              </div>
              <div class="guide-grid">
                <div class="guide-item">
                  <strong id="guideDoctorOomTitle">🚨 Detecção de OOMKilled</strong>
                  <span id="guideDoctorOomDesc">Identifica containers mortos pelo kernel por estouro de RAM e sugere novos limites de memória.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideDoctorLoopTitle">🔄 Detecção de Crash Loops</strong>
                  <span id="guideDoctorLoopDesc">Alerta quando containers falham repetidamente e diagnostica códigos de saída anormais.</span>
                </div>
                <div class="guide-item">
                  <strong id="guideDoctorFixTitle">🛠️ Ações Corretivas 1-Click</strong>
                  <span id="guideDoctorFixDesc">Botão de reinicialização direta para reanimar containers com problemas sem sair do painel.</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 6: AI AGENT STUDIO & ARCHITECTURE -->
        <div class="tab-pane" id="tab-agents">
          <div class="card">
            <div class="card-header">
              <h2 id="agentsTitle">🤖 Como Conectar seu Agente de IA (Clientes MCP Compatíveis)</h2>
              <p class="card-desc" id="agentsDesc">O PaaSMCP expõe <strong>15 ferramentas MCP nativas</strong> via stdio JSON-RPC. Copie a configuração abaixo para que sua IA opere todo o servidor por você:</p>
            </div>
            <pre id="mcpConfigBox" style="user-select:all;">{
  "mcpServers": {
    "paasmcp": {
      "command": "paasmcp-mcp"
    }
  }
}</pre>
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

          <div class="card">
            <div class="card-header">
              <h2 id="archTitle">🏛️ Arquitetura & Modelo de Segurança (Por dentro do PaaSMCP)</h2>
              <p class="card-desc" id="archDesc">Projetado para máxima segurança e zero desperdício de recursos:</p>
            </div>
            <div class="arch-grid">
              <div class="arch-box">
                <h3 id="archPillar1Title">1. Isolamento Loopback (127.0.0.1)</h3>
                <p id="archPillar1Desc">Nenhuma porta de aplicação ou banco de dados é exposta em <code>0.0.0.0</code>. O tráfego externo entra exclusivamente via túnel outbound QUIC (Cloudflare Tunnel) ou Tailscale.</p>
              </div>
              <div class="arch-box">
                <h3 id="archPillar2Title">2. Cofre & Backups AES-256-GCM</h3>
                <p id="archPillar2Desc">Variáveis de ambiente e dumps de banco (<code>pg_dump</code>) são criptografados em repouso com chave mestra <code>0600</code> e mascarados nas respostas do MCP.</p>
              </div>
              <div class="arch-box">
                <h3 id="archPillar3Title">3. Sanitização de Docker Compose</h3>
                <p id="archPillar3Desc">Repositórios multi-serviço têm seus arquivos Compose auditados automaticamente, removendo <code>privileged: true</code>, <code>network_mode: host</code> e mounts inseguros.</p>
              </div>
              <div class="arch-box">
                <h3 id="archPillar4Title">4. Redundância Multi-Servidor</h3>
                <p id="archPillar4Desc">Dois servidores podem parear via handshake HMAC-SHA256 e operar em <strong>Active-Active</strong> no mesmo Cloudflare Tunnel ou em <strong>Warm Standby</strong>.</p>
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
    </div>
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
        setupGithubDesc: "Para repositório privado, use uma Deploy Key SSH somente leitura. Copie a chave pública na seção Webhook abaixo e adicione em Settings → Deploy keys. Para registrar automaticamente a chave ou clonar via HTTPS, salve <code>GITHUB_TOKEN</code> no escopo <code>system</code>. Um fine-grained token precisa de acesso apenas ao repositório e <em>Administration: read and write</em>; a chave criada continua somente leitura.",
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
        setupWebhookNote: "Auto-deploy por webhook é opcional: cadastre a URL mostrada na aba Webhook no GitHub, evento Push e o secret mostrado pelo painel. Não cole tokens no chat; insira-os no Cofre.",
        sidebarSubtitle: "Agent-First Micro-PaaS",
        navOverview: "📦 Aplicações & Deploy",
        navVault: "🔐 Cofre AES-256-GCM",
        navDatabases: "🗄️ Bancos & Backups",
        navFederation: "🌐 Multi-Server HA & Webhook",
        navDoctor: "🩺 Doctor & Diagnóstico",
        navAgents: "🤖 Studio IA (MCP) & Guia",
        topHealthBadge: "● System Online",
        btnRefresh: "🔄 Atualizar",
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
        archTitle: "🏛️ Arquitetura & Modelo de Segurança (Por dentro do PaaSMCP)",
        archDesc: "Projetado para máxima segurança e zero desperdício de recursos:",
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
        chipSystemScope: "⚙️ system (Tokens Globais)",
        promptEx1Title: "💬 Deploy & Banco 1-Click",
        promptEx1Desc: "'Faça o deploy do repositório <code>usuario/meu-saas</code> com PostgreSQL, limite de 512m de RAM e publique em <code>saas.{domain}</code>'",
        promptEx2Title: "💬 Backup & Rollback",
        promptEx2Desc: "'Crie um backup criptografado do banco do app <code>meu-saas</code> antes de atualizar e faça rollback se der erro'",
        promptEx3Title: "💬 Diagnóstico & Multi-Node",
        promptEx3Desc: "'Rode o <code>paas_doctor</code> para ver se algum container sofreu OOMKill e gere um token de pareamento HA'",
        archPillar1Title: "1. Isolamento Loopback (127.0.0.1)",
        archPillar1Desc: "Nenhuma porta de aplicação ou banco de dados é exposta em <code>0.0.0.0</code>. O tráfego externo entra exclusivamente via túnel outbound QUIC (Cloudflare Tunnel) ou Tailscale.",
        archPillar2Title: "2. Cofre & Backups AES-256-GCM",
        archPillar2Desc: "Variáveis de ambiente e dumps de banco (<code>pg_dump</code>) são criptografados em repouso com chave mestra <code>0600</code> e mascarados nas respostas do MCP.",
        archPillar3Title: "3. Sanitização de Docker Compose",
        archPillar3Desc: "Repositórios multi-serviço têm seus arquivos Compose auditados automaticamente, removendo <code>privileged: true</code>, <code>network_mode: host</code> e mounts inseguros.",
        archPillar4Title: "4. Redundância Multi-Servidor",
        archPillar4Desc: "Dois servidores podem parear via handshake HMAC-SHA256 e operar em <strong>Active-Active</strong> no mesmo Cloudflare Tunnel ou em <strong>Warm Standby</strong>.",
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
        btnRemoveSecret: "Remover",
        sizeLabel: "Tamanho:",
        stoppedStatus: "Parado",
        onDemandStatus: "Sob demanda",
        guideAppsTitle: "💡 Funções de Gestão & Ciclo de Vida",
        guideAppsRollbackTitle: "⏪ Rollback em 1s",
        guideAppsRollbackDesc: "Restaura o container para a imagem anterior instantaneamente caso o novo deploy falhe ou contenha bugs.",
        guideAppsLimitsTitle: "⚡ Limites de Memória & CPU",
        guideAppsLimitsDesc: "Isolamento cgroups do kernel Linux que impede que um app consuma toda a RAM do host ou trave outros containers.",
        guideAppsActionsTitle: "🛠️ Ações Rápidas (ENV, Logs, Restart)",
        guideAppsActionsDesc: "Edite segredos no cofre sem re-build, consulte logs em tempo real e reinicie containers sem downtime desnecessário.",
        guideAppsLoopbackTitle: "🔒 Isolamento Loopback",
        guideAppsLoopbackDesc: "Containers escutam exclusivamente em 127.0.0.1:4000-4998, sem portas expostas no firewall ou roteador.",
        guideExposeTitle: "🛡️ Como funcionam os Modos de Publicação",
        guideExposePublicTitle: "🌐 Público (Cloudflare Tunnel)",
        guideExposePublicDesc: "Túnel QUIC criptografado com DNS CNAME proxied e certificado SSL automático sem abrir portas.",
        guideExposeZTTitle: "🛡️ Zero Trust (PIN por E-mail)",
        guideExposeZTDesc: "Protege o app exigindo código OTP no e-mail antes do acesso. Recomendado para painéis e bancos.",
        guideExposeTailscaleTitle: "🔒 Tailscale (VPN Privada)",
        guideExposeTailscaleDesc: "Expõe o serviço de forma privada diretamente na sua Tailnet WireGuard, sem acesso público.",
        guideVaultTitle: "🔐 Arquitetura de Segurança do Cofre (AES-256-GCM)",
        guideVaultScopesTitle: "📁 Escopos Isolados",
        guideVaultScopesDesc: "O escopo <code>system</code> guarda tokens de nuvem. Cada aplicação possui seu próprio escopo exclusivo.",
        guideVaultGcmTitle: "🛡️ Criptografia AES-256-GCM",
        guideVaultGcmDesc: "Dados cifrados em repouso com IV aleatório de 96 bits e autenticação GCM contra adulterações.",
        guideVaultInjectionTitle: "⚡ Injeção Segura",
        guideVaultInjectionDesc: "Variáveis são descriptografadas em memória na partida do container, sem nunca vazarem no código ou git.",
        guideVaultMasterKeyTitle: "🔑 Chave Mestra 0600",
        guideVaultMasterKeyDesc: "Guardada em arquivo local com permissões restritas (0600), acessível apenas pelo daemon do PaaS.",
        guideDbTitle: "🗄️ Como funciona o Banco Multi-Tenant",
        guideDbIsolationTitle: "🐘 PostgreSQL 16 & Redis 7",
        guideDbIsolationDesc: "Cada app recebe um banco lógico e usuário exclusivo com senha forte, isolado dos demais.",
        guideDbInjectionTitle: "🔗 DATABASE_URL Automática",
        guideDbInjectionDesc: "A URL de conexão é salva no Cofre do app e injetada no container sem configuração manual.",
        guideBackupTitle: "🛡️ Como funcionam os Snapshots & Restore",
        guideBackupDumpTitle: "📸 Dumps Consistentes",
        guideBackupDumpDesc: "Executa <code>pg_dump</code> transacional ou RDB em tempo de execução sem interromper os serviços.",
        guideBackupCryptoTitle: "🔐 Criptografia em Repouso",
        guideBackupCryptoDesc: "O dump é criptografado com chave AES-256-GCM antes de ser gravado no diretório de backups.",
        guideBackupIntegrityTitle: "🛡️ Checksum SHA-256",
        guideBackupIntegrityDesc: "Todo snapshot calcula um hash SHA-256 que é estritamente verificado antes de qualquer restauração.",
        guideBackupRestoreTitle: "⏪ Restore 1-Click",
        guideBackupRestoreDesc: "Restaura o banco instantaneamente para recuperação de desastres ou testes de migração.",
        guideFedTitle: "🌐 Redundância e Alta Disponibilidade",
        guideFedTokenTitle: "🤝 Handshake HMAC-SHA256",
        guideFedTokenDesc: "Pareia nós com token assinado e expiração de 15 minutos, impedindo conexões não autorizadas.",
        guideFedActiveTitle: "⚡ Active-Active (Cloudflare)",
        guideFedActiveDesc: "Múltiplos servidores atendem no mesmo túnel com balanceamento de carga e failover automático.",
        guideFedWarmTitle: "📦 Warm Standby & Sync",
        guideFedWarmDesc: "Exportação e importação de pacotes cifrados com segredos e apps para recuperação remota.",
        guideWhTitle: "⚡ Automação com GitHub Webhooks",
        guideWhSigTitle: "🔒 Validação HMAC-SHA256",
        guideWhSigDesc: "Compara a assinatura do GitHub em tempo constante (evitando timing attacks) antes de acionar rebuilds.",
        guideWhSshTitle: "🔑 Deploy Key Ed25519",
        guideWhSshDesc: "Chave SSH somente leitura para clonar repositórios privados sem expor senhas ou tokens globais.",
        guideDoctorTitle: "🩺 Como o Doctor protege o cluster",
        guideDoctorOomTitle: "🚨 Detecção de OOMKilled",
        guideDoctorOomDesc: "Identifica containers mortos pelo kernel por estouro de RAM e sugere novos limites de memória.",
        guideDoctorLoopTitle: "🔄 Detecção de Crash Loops",
        guideDoctorLoopDesc: "Alerta quando containers falham repetidamente e diagnostica códigos de saída anormais.",
        guideDoctorFixTitle: "🛠️ Ações Corretivas 1-Click",
        guideDoctorFixDesc: "Botão de reinicialização direta para reanimar containers com problemas sem sair do painel."
      },
      en: {
        setupTitle: "🧭 First-time setup: what do you need?",
        setupDesc: "Configure only the integrations you plan to use. PaaSMCP works locally without third-party tokens; secret values are stored in the Vault.",
        setupGithubTitle: "🐙 GitHub — optional",
        setupGithubDesc: "For a private repository, use a read-only SSH Deploy Key. Copy the public key from the Webhook section below and add it under Settings → Deploy keys. To register it automatically or clone over HTTPS, save <code>GITHUB_TOKEN</code> in the <code>system</code> scope. A fine-grained token needs access only to the target repository and <em>Administration: read and write</em>; the created key remains read-only.",
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
        setupWebhookNote: "Webhook auto-deploy is optional: add the URL shown in the Webhook tab to GitHub, select Push events, and use the secret shown by the dashboard. Do not paste tokens into chat; enter them in the Vault.",
        sidebarSubtitle: "Agent-First Micro-PaaS",
        navOverview: "📦 Applications & Deploy",
        navVault: "🔐 AES-256-GCM Vault",
        navDatabases: "🗄️ Databases & Backups",
        navFederation: "🌐 Multi-Server HA & Webhook",
        navDoctor: "🩺 Doctor & Diagnostics",
        navAgents: "🤖 AI Studio (MCP) & Guide",
        topHealthBadge: "● System Online",
        btnRefresh: "🔄 Refresh",
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
        archTitle: "🏛️ Architecture & Security Model (Inside PaaSMCP)",
        archDesc: "Designed for maximum security and zero resource waste:",
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
        chipSystemScope: "⚙️ system (Global Tokens)",
        promptEx1Title: "💬 1-Click Deploy & Database",
        promptEx1Desc: "'Deploy repository <code>user/my-saas</code> with PostgreSQL, 512m RAM limit, and publish on <code>saas.{domain}</code>'",
        promptEx2Title: "💬 Backup & Rollback",
        promptEx2Desc: "'Create an encrypted database backup for app <code>my-saas</code> before upgrading and rollback if it fails'",
        promptEx3Title: "💬 Diagnostics & Multi-Node",
        promptEx3Desc: "'Run <code>paas_doctor</code> to check if any container suffered an OOMKill and generate an HA pairing token'",
        archPillar1Title: "1. Loopback Isolation (127.0.0.1)",
        archPillar1Desc: "No application or database ports are exposed on <code>0.0.0.0</code>. External traffic enters exclusively via outbound QUIC tunnels (Cloudflare Tunnel) or Tailscale.",
        archPillar2Title: "2. AES-256-GCM Vault & Backups",
        archPillar2Desc: "Environment variables and database dumps (<code>pg_dump</code>) are encrypted at rest with a <code>0600</code> master key and masked in MCP responses.",
        archPillar3Title: "3. Docker Compose Sanitization",
        archPillar3Desc: "Multi-service repositories have their Compose manifests audited automatically, stripping <code>privileged: true</code>, <code>network_mode: host</code>, and insecure mounts.",
        archPillar4Title: "4. Multi-Server Redundancy",
        archPillar4Desc: "Two servers can pair via HMAC-SHA256 handshake and operate in <strong>Active-Active</strong> on the same Cloudflare Tunnel or in <strong>Warm Standby</strong>.",
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
        btnRemoveSecret: "Remove",
        sizeLabel: "Size:",
        stoppedStatus: "Stopped",
        onDemandStatus: "On demand",
        guideAppsTitle: "💡 Lifecycle Management & Functions",
        guideAppsRollbackTitle: "⏪ 1-Second Rollback",
        guideAppsRollbackDesc: "Instantly restores container to the previous working build if the new deploy fails or has bugs.",
        guideAppsLimitsTitle: "⚡ Memory & CPU Limits",
        guideAppsLimitsDesc: "Linux kernel cgroups isolation preventing memory leaks from freezing the host or other apps.",
        guideAppsActionsTitle: "🛠️ Quick Actions (ENV, Logs, Restart)",
        guideAppsActionsDesc: "Edit secrets in vault without rebuilds, monitor real-time logs, and restart containers without friction.",
        guideAppsLoopbackTitle: "🔒 Loopback Isolation",
        guideAppsLoopbackDesc: "Containers listen strictly on 127.0.0.1:4000-4998, with zero exposed ports in firewall or router.",
        guideExposeTitle: "🛡️ How Publishing Modes Work",
        guideExposePublicTitle: "🌐 Public (Cloudflare Tunnel)",
        guideExposePublicDesc: "Encrypted outbound QUIC tunnel with proxied DNS CNAME and automatic SSL without open ports.",
        guideExposeZTTitle: "🛡️ Zero Trust (Email OTP PIN)",
        guideExposeZTDesc: "Protects the route requiring email verification before access. Recommended for admin tools and databases.",
        guideExposeTailscaleTitle: "🔒 Tailscale (Private VPN)",
        guideExposeTailscaleDesc: "Exposes the service privately to your WireGuard Tailnet mesh, with zero public exposure.",
        guideVaultTitle: "🔐 Vault Security Architecture (AES-256-GCM)",
        guideVaultScopesTitle: "📁 Isolated Scopes",
        guideVaultScopesDesc: "The <code>system</code> scope holds cloud tokens. Each application has its own dedicated secret scope.",
        guideVaultGcmTitle: "🛡️ AES-256-GCM Encryption",
        guideVaultGcmDesc: "Data encrypted at rest using a 96-bit random IV and GCM authentication tag against tampering.",
        guideVaultInjectionTitle: "⚡ Safe Injection",
        guideVaultInjectionDesc: "Variables are decrypted in memory when starting the container, never committed to git or logs.",
        guideVaultMasterKeyTitle: "🔑 0600 Master Key",
        guideVaultMasterKeyDesc: "Preserved in a local file with strict 0600 permissions, accessible only by the PaaS daemon.",
        guideDbTitle: "🗄️ How Isolated Multi-Tenant Databases Work",
        guideDbIsolationTitle: "🐘 PostgreSQL 16 & Redis 7",
        guideDbIsolationDesc: "Each app gets its own logical database and dedicated user with strong password, isolated from other apps.",
        guideDbInjectionTitle: "🔗 Automatic DATABASE_URL",
        guideDbInjectionDesc: "Connection string is written into the app Vault and auto-injected into containers without manual setup.",
        guideBackupTitle: "🛡️ How Snapshots & Restore Work",
        guideBackupDumpTitle: "📸 Consistent Dumps",
        guideBackupDumpDesc: "Runs transactional <code>pg_dump</code> or Redis RDB in real time without taking services down.",
        guideBackupCryptoTitle: "🔐 Encrypted at Rest",
        guideBackupCryptoDesc: "The raw dump is encrypted with an AES-256-GCM key before being saved to backup storage.",
        guideBackupIntegrityTitle: "🛡️ SHA-256 Checksum",
        guideBackupIntegrityDesc: "Every snapshot calculates a SHA-256 hash strictly re-verified before performing any restore.",
        guideBackupRestoreTitle: "⏪ 1-Click Restore",
        guideBackupRestoreDesc: "Restores database state instantly for disaster recovery or testing migrations.",
        guideFedTitle: "🌐 Redundancy & High Availability",
        guideFedTokenTitle: "🤝 HMAC-SHA256 Handshake",
        guideFedTokenDesc: "Pairs nodes with signed tokens and 15-minute expiration, blocking unauthorized cluster connections.",
        guideFedActiveTitle: "⚡ Active-Active (Cloudflare)",
        guideFedActiveDesc: "Multiple servers serve traffic on the same tunnel with automatic load balancing and failover.",
        guideFedWarmTitle: "📦 Warm Standby & Sync",
        guideFedWarmDesc: "Exports and imports encrypted bundles containing configs and vault data to keep standby nodes in sync.",
        guideWhTitle: "⚡ Automation with GitHub Webhooks",
        guideWhSigTitle: "🔒 HMAC-SHA256 Validation",
        guideWhSigDesc: "Verifies GitHub webhook payloads in constant time (preventing timing attacks) before rebuilding.",
        guideWhSshTitle: "🔑 Ed25519 Deploy Key",
        guideWhSshDesc: "Read-only SSH deploy key to pull private repositories without exposing accounts or personal tokens.",
        guideDoctorTitle: "🩺 How Doctor Protects the Cluster",
        guideDoctorOomTitle: "🚨 OOMKilled Detection",
        guideDoctorOomDesc: "Detects containers killed by the kernel due to RAM limits and suggests memory limit adjustments.",
        guideDoctorLoopTitle: "🔄 Crash Loop Detection",
        guideDoctorLoopDesc: "Alerts when containers restart repeatedly and reports abnormal process exit codes.",
        guideDoctorFixTitle: "🛠️ 1-Click Corrective Actions",
        guideDoctorFixDesc: "Provides instant restart actions to recover degraded containers directly from the dashboard."
      }
    };

    function t(key) {
      const dict = I18N[currentLang] || I18N.pt;
      return dict[key] !== undefined ? dict[key] : (I18N.pt[key] !== undefined ? I18N.pt[key] : key);
    }

    const I18N_KEYS = [
      'setupTitle', 'setupDesc', 'setupGithubTitle', 'setupGithubDesc', 'setupGithubLink', 'setupGithubDocsLink',
      'setupCloudTitle', 'setupCloudDesc', 'setupCloudLink', 'setupCloudDocsLink', 'setupLocalTitle', 'setupLocalDesc',
      'setupAppTitle', 'setupAppDesc', 'setupWebhookNote',
      'sidebarSubtitle', 'navOverview', 'navVault', 'navDatabases', 'navFederation', 'navDoctor', 'navAgents',
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
      'presetSaas', 'presetCompose', 'presetSpa', 'chipSystemScope',
      'promptEx1Title', 'promptEx1Desc', 'promptEx2Title', 'promptEx2Desc', 'promptEx3Title', 'promptEx3Desc',
      'archPillar1Title', 'archPillar1Desc', 'archPillar2Title', 'archPillar2Desc', 'archPillar3Title', 'archPillar3Desc', 'archPillar4Title', 'archPillar4Desc',
      'agentsTitle', 'agentsDesc', 'archTitle', 'archDesc', 'logsTitle', 'btnCloseLogs',
      'guideAppsTitle', 'guideAppsRollbackTitle', 'guideAppsRollbackDesc', 'guideAppsLimitsTitle', 'guideAppsLimitsDesc', 'guideAppsActionsTitle', 'guideAppsActionsDesc', 'guideAppsLoopbackTitle', 'guideAppsLoopbackDesc',
      'guideExposeTitle', 'guideExposePublicTitle', 'guideExposePublicDesc', 'guideExposeZTTitle', 'guideExposeZTDesc', 'guideExposeTailscaleTitle', 'guideExposeTailscaleDesc',
      'guideVaultTitle', 'guideVaultScopesTitle', 'guideVaultScopesDesc', 'guideVaultGcmTitle', 'guideVaultGcmDesc', 'guideVaultInjectionTitle', 'guideVaultInjectionDesc', 'guideVaultMasterKeyTitle', 'guideVaultMasterKeyDesc',
      'guideDbTitle', 'guideDbIsolationTitle', 'guideDbIsolationDesc', 'guideDbInjectionTitle', 'guideDbInjectionDesc',
      'guideBackupTitle', 'guideBackupDumpTitle', 'guideBackupDumpDesc', 'guideBackupCryptoTitle', 'guideBackupCryptoDesc', 'guideBackupIntegrityTitle', 'guideBackupIntegrityDesc', 'guideBackupRestoreTitle', 'guideBackupRestoreDesc',
      'guideFedTitle', 'guideFedTokenTitle', 'guideFedTokenDesc', 'guideFedActiveTitle', 'guideFedActiveDesc', 'guideFedWarmTitle', 'guideFedWarmDesc',
      'guideWhTitle', 'guideWhSigTitle', 'guideWhSigDesc', 'guideWhSshTitle', 'guideWhSshDesc',
      'guideDoctorTitle', 'guideDoctorOomTitle', 'guideDoctorOomDesc', 'guideDoctorLoopTitle', 'guideDoctorLoopDesc', 'guideDoctorFixTitle', 'guideDoctorFixDesc'
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
      if (tabName === 'doctor') runDoctor();
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
    }

    function applyPreferences() {
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.getElementById('themeBtn').textContent = currentTheme === 'dark' ? '☀️ Light' : '🌙 Dark';
      document.getElementById('langBtn').textContent = currentLang === 'pt' ? '🇧🇷 PT-BR' : '🇺🇸 EN';
      document.getElementById('webhookUrlBox').textContent = window.location.origin + '/api/webhooks/github';
      const fedUrlEl = document.getElementById('fedUrl');
      if (fedUrlEl && !fedUrlEl.value) fedUrlEl.value = window.location.origin;

      for (const k of I18N_KEYS) {
        const el = document.getElementById(k);
        if (el) {
          const val = t(k);
          if (val.indexOf('<') !== -1 && val.indexOf('>') !== -1) {
            el.innerHTML = val;
          } else {
            el.textContent = val;
          }
        }
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

      if (lastStatus) renderStatusData(lastStatus);
      loadSecrets();
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

    function renderStatusData(s) {
      const domain = getBaseDomain();
      document.getElementById('topDomainBadge').textContent = '🌐 ' + domain;
      const role = s.federation?.role || 'standalone';
      const peersCount = Object.keys(s.federation?.peers || {}).length;
      document.getElementById('nodeRoleFooter').textContent = 'Node: ' + role + ' (' + peersCount + ' peers)';

      document.getElementById('statsGrid').innerHTML = \`
        <div class="stat-card">
          <div class="stat-label">\${esc(t('statHost'))}</div>
          <div class="stat-value">🖥️ \${esc(s.hostname)}</div>
          <div class="stat-meta">\${esc(s.platform)} · \${esc(t('statDisk'))} \${esc(s.rootDisk)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">\${esc(t('statMem'))}</div>
          <div class="stat-value">⚡ \${esc(s.freeMemGb)} / \${esc(s.totalMemGb)} GB</div>
          <div class="stat-meta">\${esc(s.cpus)} vCPUs · \${esc(t('statIdle'))}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">\${esc(t('statAppsDbs'))}</div>
          <div class="stat-value">📦 \${esc(s.appsCount)} Apps · \${esc(s.databasesCount)} DBs</div>
          <div class="stat-meta">🛡️ \${esc(s.backupsCount || 0)} \${esc(t('statSnapshots'))}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">\${esc(t('statSecurityFed'))}</div>
          <div class="stat-value">🔒 \${esc(role.toUpperCase())}</div>
          <div class="stat-meta">SSH: <code>\${esc((s.sshKeyFingerprint || '').slice(0, 22))}...</code></div>
        </div>
      \`;

      document.getElementById('sshKeyBox').textContent = s.sshPublicKey || '';
      document.getElementById('webhookSecretBox').textContent = s.webhookSecretMasked || '••••••••';

      const apps = Object.values(s.apps || {});
      const metricsMap = s.containerMetrics || {};
      document.getElementById('appsBadgeCount').textContent = apps.length + ' apps';

      document.getElementById('hostedAppsList').innerHTML = apps.map(a => \`<option value="\${esc(a.name)}"></option>\`).join('');
      document.getElementById('dynamicScopeChips').innerHTML = apps.map(a => \`<button class="chip" onclick="setVaultScope('\${esc(a.name)}')">📦 \${esc(a.name)}</button>\`).join(' ');

      const tbody = document.getElementById('appsTable');
      if (apps.length === 0) {
        tbody.innerHTML = \`<tr><td colspan="6" style="color:var(--muted)">\${esc(t('emptyApps'))}</td></tr>\`;
      } else {
        tbody.innerHTML = apps.map(a => {
          const m = metricsMap[a.containerName];
          const metricHtml = m
            ? \`<div><code>CPU: \${esc(m.cpuPercent)}</code></div><div style="margin-top:3px;"><code>RAM: \${esc(m.memUsage)}</code></div>\`
            : \`<span style="color:var(--muted);font-size:11.5px;">\${esc(a.status === 'stopped' ? t('stoppedStatus') : t('onDemandStatus'))}</span>\`;
          const limitsHtml = (a.memoryLimit || a.cpuLimit)
            ? \`<div style="margin-top:3px;font-size:11px;color:var(--muted);">Limits: \${esc(a.memoryLimit || '-')} / \${esc(a.cpuLimit || '-')} CPU</div>\`
            : '';
          const rollbackBtn = a.previousImageTag
            ? \`<button class="secondary" style="padding:4px 9px;font-size:11.5px;" onclick="appAction('\${esc(a.name)}','rollback')" title="Reverter para imagem anterior em 1s">\${esc(t('actionRollback'))}</button>\`
            : '';

          return \`
            <tr>
              <td>
                <span class="status-dot \${a.status === 'stopped' ? 'stopped' : ''}"></span>
                <strong>\${esc(a.name)}</strong>
                \${a.lastWebhookAt ? \`<div style="font-size:10.5px;color:var(--muted);">⚡ Webhook: \${esc(a.lastWebhookAt.slice(0,19))}</div>\` : ''}
              </td>
              <td>
                <code>\${esc(a.runtimeType)}</code>
                \${a.lastCommit ? \`<div style="font-size:11px;color:var(--muted);margin-top:3px;">commit: <code>\${esc(a.lastCommit)}</code></div>\` : ''}
              </td>
              <td>\${metricHtml}\${limitsHtml}</td>
              <td>
                <div><code>127.0.0.1:\${esc(a.localPort)}</code></div>
                <div style="margin-top:3px;">\${(a.databases || []).map(d => \`<span class="badge" style="font-size:10px;padding:1px 6px;">\${esc(d)}</span>\`).join(' ') || ''}</div>
              </td>
              <td>\${(a.domains || []).map(d => \`<div style="margin-bottom:3px;"><a href="\${esc(d.url)}" target="_blank" rel="noopener noreferrer">🔗 \${esc(d.url)}</a> <span class="badge" style="padding:1px 6px;font-size:10px;">\${esc(d.mode)}</span></div>\`).join('') || '<span style="color:var(--muted)">Local only</span>'}</td>
              <td class="actions">
                <button class="secondary" style="padding:4px 9px;font-size:11.5px;" onclick="selectAppForExpose('\${esc(a.name)}')">\${esc(t('actionExpose'))}</button>
                <button class="secondary" style="padding:4px 9px;font-size:11.5px;" onclick="setVaultScope('\${esc(a.name)}')">\${esc(t('actionEnv'))}</button>
                <button class="secondary" style="padding:4px 9px;font-size:11.5px;" onclick="appAction('\${esc(a.name)}','logs')">\${esc(t('actionLogs'))}</button>
                <button class="secondary" style="padding:4px 9px;font-size:11.5px;" onclick="appAction('\${esc(a.name)}','restart')">\${esc(t('actionRestart'))}</button>
                \${rollbackBtn}
                \${a.trashedAt
                  ? \`<span style="font-size:11px;color:var(--muted);">\${esc(t('trashedStatus') + a.trashedAt.slice(0, 10))}</span>
                     <button class="secondary" style="padding:4px 9px;font-size:11.5px;" onclick="appAction('\${esc(a.name)}','restore')">\${esc(t('actionRestore'))}</button>
                     <button class="danger" style="padding:4px 9px;font-size:11.5px;" onclick="appAction('\${esc(a.name)}','purge')">\${esc(t('actionPurge'))}</button>\`
                  : \`<button class="danger" style="padding:4px 9px;font-size:11.5px;" onclick="appAction('\${esc(a.name)}','destroy')">\${esc(t('actionDelete'))}</button>\`}
              </td>
            </tr>
          \`;
        }).join('');
      }

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
              <span style="color:var(--muted);">\${esc(t('sizeLabel'))} \${esc(b.sizeBytes)} bytes · SHA256: <code>\${esc((b.sha256 || '').slice(0, 12))}...</code></span>
            </div>
            <button class="secondary" style="padding:4px 9px;font-size:11px;" onclick="restoreBackup('\${esc(b.id)}')">\${esc(t('btnRestoreDump'))}</button>
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

    async function loadAll() {
      loadApprovals();
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
                <strong>\${esc(d.target)}</strong>
                <div style="display:flex;gap:6px;align-items:center;">
                  <span class="badge \${d.severity === 'healthy' ? 'success' : d.severity === 'warning' ? 'warning' : 'danger'}">\${esc(d.severity.toUpperCase())}</span>
                  \${d.severity !== 'healthy' ? \`<button class="secondary" style="padding:3px 9px;font-size:11px;" onclick="appAction('\${esc(d.target)}','restart')">\${esc(t('btnRestartContainer'))}</button>\` : ''}
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
      if (!appName || !repoSource) return;
      const btn = document.getElementById('btnDeploy');
      btn.textContent = t('toastDeploying');
      btn.disabled = true;
      try {
        const res = await fetch('/api/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ appName, repoSource, branch, withPostgres, withRedis, memoryLimit, cpuLimit })
        });
        const data = await res.json();
        if (!res.ok) alert('Error: ' + data.error);
        else { showToast(t('toastDeployDone') + appName); loadAll(); }
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
  </script>
</body>
</html>`;
}

// Pinned base image; tools are installed once at build time, never on every start.
const DASHBOARD_DOCKERFILE = `FROM node:22.11.0-alpine3.20
RUN apk add --no-cache docker-cli docker-cli-compose git openssh-client
`;

/** Builds the dashboard image once per Dockerfile version (tag = content hash). */
function ensureDashboardImage(): string {
  const tag = `paasmcp/dashboard:${crypto.createHash("sha256").update(DASHBOARD_DOCKERFILE).digest("hex").slice(0, 12)}`;
  try {
    execFileSync("docker", ["image", "inspect", tag], { stdio: "ignore" });
  } catch {
    execFileSync("docker", ["build", "-t", tag, "-"], { input: DASHBOARD_DOCKERFILE, stdio: ["pipe", "pipe", "pipe"] });
  }
  return tag;
}

export function ensureDashboardBackgroundService(port = 4099): {
  url: string;
  localPort: number;
  containerName: string;
} {
  ensureDockerNetwork();
  getOrCreateDashboardToken();
  const dashDir = path.join(PAAS_DATA_DIR, "dashboard-service");
  fs.mkdirSync(dashDir, { recursive: true, mode: 0o700 });

  const projectRoot = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    ".."
  );

  const image = ensureDashboardImage();
  const composePath = path.join(dashDir, "compose.yaml");
  const composeContent = `services:
  dashboard:
    image: ${image}
    container_name: paasmcp-dashboard
    restart: unless-stopped
    working_dir: /app
    command: ["node", "dist/cli.js", "dashboard", "serve", "--port", "${port}", "--host", "0.0.0.0"]
    ports:
      - "127.0.0.1:${port}:${port}"
    volumes:
      - ${projectRoot}:/app:ro
      - /opt/homelab:/opt/homelab
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
    branch: "main",
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
  };
}
