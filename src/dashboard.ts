import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DOCKER_NETWORK, PAAS_DATA_DIR, loadState, saveState } from "./config.js";
import { ensureDockerNetwork, provisionDatabase } from "./database.js";
import { deployApp, manageAppLifecycle, syncHomepageDashboard } from "./deployer.js";
import { exposeApplication } from "./exposure.js";
import { getSystemStatusSummary } from "./mcp-server.js";
import {
  deleteSecretKey,
  getSecrets,
  listMaskedSecrets,
  setSecretEntries,
} from "./vault.js";

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

function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function isAuthenticated(req: http.IncomingMessage, expectedToken: string): boolean {
  const authHeader = req.headers.authorization;
  if (authHeader === `Bearer ${expectedToken}`) return true;
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.paasmcp_token === expectedToken) return true;
  return false;
}

export function startDashboardServer(port = 4099, host = "127.0.0.1"): http.Server {
  const expectedToken = getOrCreateDashboardToken();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;

    // Login endpoint
    if (pathname === "/api/login" && req.method === "POST") {
      try {
        const body = await readJsonBody(req);
        if (body.token === expectedToken) {
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

    // Protect all /api/* routes
    if (pathname.startsWith("/api/")) {
      if (!isAuthenticated(req, expectedToken)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }

      try {
        if (pathname === "/api/status" && req.method === "GET") {
          const status = getSystemStatusSummary();
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(status));
          return;
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
          return;
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
          return;
        }

        if (pathname === "/api/secrets" && req.method === "DELETE") {
          const body = await readJsonBody(req);
          const scope = String(body.scope || "system");
          const key = String(body.key || "");
          deleteSecretKey(scope, key);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              scope,
              secrets: listMaskedSecrets(scope),
            })
          );
          return;
        }

        if (pathname === "/api/db" && req.method === "POST") {
          const body = await readJsonBody(req);
          const appName = String(body.appName || "");
          const engine = (body.engine as "postgres" | "redis") || "postgres";
          const result = provisionDatabase(appName, engine);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return;
        }

        if (pathname === "/api/deploy" && req.method === "POST") {
          const body = await readJsonBody(req);
          const result = deployApp({
            appName: String(body.appName),
            repoSource: String(body.repoSource),
            branch: body.branch ? String(body.branch) : "main",
            internalPort: body.internalPort ? Number(body.internalPort) : undefined,
            withPostgres: Boolean(body.withPostgres),
            withRedis: Boolean(body.withRedis),
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return;
        }

        if (pathname === "/api/expose" && req.method === "POST") {
          const body = await readJsonBody(req);
          const result = await exposeApplication({
            appName: String(body.appName),
            mode: body.mode as "public" | "zero-trust" | "tailscale",
            subdomain: body.subdomain ? String(body.subdomain) : undefined,
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
          return;
        }

        if (pathname === "/api/lifecycle" && req.method === "POST") {
          const body = await readJsonBody(req);
          const output = manageAppLifecycle(
            String(body.appName),
            body.action as "logs" | "restart" | "stop" | "start" | "destroy",
            body.tailLines ? Number(body.tailLines) : 120
          );
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ output }));
          return;
        }
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
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

function renderDashboardHtml(authed: boolean, cfEmail?: string): string {
  const sharedCss = `
    :root, [data-theme="dark"] {
      --bg: #090d16;
      --bg-subtle: #0d1322;
      --card: #111827;
      --card-hover: #161f33;
      --border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --input-bg: #030712;
      --accent: #6366f1;
      --accent-hover: #4f46e5;
      --accent-soft: rgba(99, 102, 241, 0.14);
      --accent-text: #a5b4fc;
      --success: #10b981;
      --success-soft: rgba(16, 185, 129, 0.14);
      --danger: #ef4444;
      --danger-soft: rgba(239, 68, 68, 0.15);
      --code-bg: #030712;
      --code-text: #a5b4fc;
      --shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }
    [data-theme="light"] {
      --bg: #f8fafc;
      --bg-subtle: #f1f5f9;
      --card: #ffffff;
      --card-hover: #f8fafc;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #64748b;
      --input-bg: #f8fafc;
      --accent: #4f46e5;
      --accent-hover: #4338ca;
      --accent-soft: rgba(79, 70, 229, 0.1);
      --accent-text: #4338ca;
      --success: #059669;
      --success-soft: rgba(5, 150, 105, 0.12);
      --danger: #dc2626;
      --danger-soft: rgba(220, 38, 38, 0.1);
      --code-bg: #f1f5f9;
      --code-text: #3730a3;
      --shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
    }
    * { box-sizing: border-box; font-family: Inter, system-ui, -apple-system, sans-serif; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      transition: background 0.2s ease, color 0.2s ease;
    }
    a { color: var(--accent); text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    code, pre {
      background: var(--code-bg);
      color: var(--code-text);
      border: 1px solid var(--border);
      padding: 3px 7px;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
    }
    pre {
      padding: 14px;
      overflow-x: auto;
      max-height: 340px;
      line-height: 1.5;
      margin: 8px 0 0;
    }
    input, select {
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--input-bg);
      color: var(--text);
      font-size: 13px;
      width: 100%;
      outline: none;
      transition: border-color 0.15s ease;
    }
    input:focus, select:focus { border-color: var(--accent); }
    button {
      padding: 9px 14px;
      border-radius: 8px;
      border: 1px solid transparent;
      background: var(--accent);
      color: #ffffff;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.15s ease;
    }
    button:hover { background: var(--accent-hover); }
    button.secondary {
      background: var(--bg-subtle);
      border-color: var(--border);
      color: var(--text);
    }
    button.secondary:hover { background: var(--card-hover); border-color: var(--accent); }
    button.danger {
      background: var(--danger-soft);
      border-color: rgba(239, 68, 68, 0.35);
      color: var(--danger);
    }
    button.chip {
      padding: 5px 10px;
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
      border: 1px solid rgba(99, 102, 241, 0.3);
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
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
    .toolbar-controls {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
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
  <title>PaaSMCP — Login</title>
  <style>
    ${sharedCss}
    body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 20px; }
    .login-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: var(--shadow);
    }
    .login-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    h1 { margin: 0 0 8px; font-size: 22px; display: flex; align-items: center; gap: 10px; }
    p { margin: 0 0 20px; color: var(--muted); font-size: 14px; line-height: 1.55; }
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
      <div class="toolbar-controls">
        <button class="secondary" onclick="toggleLang()" id="langBtn" style="padding:6px 10px;font-size:12px;">🌐 PT / EN</button>
        <button class="secondary" onclick="toggleTheme()" id="themeBtn" style="padding:6px 10px;font-size:12px;">🌓</button>
      </div>
    </div>
    <h1>🚀 PaaSMCP</h1>
    <p id="loginDesc"></p>
    ${cfEmail ? `<div style="margin-bottom:16px;"><span class="badge success">✓ Cloudflare Zero Trust: ${cfEmail}</span></div>` : ""}
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
        desc: "Painel de Controle auto-hospedado para deploys, bancos PostgreSQL/Redis, cofre AES-256-GCM e túneis Cloudflare.",
        placeholder: "Cole seu DASHBOARD_TOKEN...",
        btn: "Acessar Painel de Controle",
        err: "Token inválido. Verifique e tente novamente.",
        help: "💡 Como obter seu token no terminal do servidor:"
      },
      en: {
        desc: "Self-hosted Control Plane for GitHub deployments, PostgreSQL/Redis databases, AES-256-GCM secret vault, and Cloudflare Tunnels.",
        placeholder: "Paste your DASHBOARD_TOKEN...",
        btn: "Sign In to Control Plane",
        err: "Invalid access token. Please try again.",
        help: "💡 How to retrieve your token in the server terminal:"
      }
    };
    let currentLang = localStorage.getItem('paasmcp_lang') || ((navigator.language || '').toLowerCase().startsWith('pt') ? 'pt' : 'en');
    let currentTheme = localStorage.getItem('paasmcp_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');

    function applyPrefs() {
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.documentElement.lang = currentLang === 'pt' ? 'pt-BR' : 'en';
      document.getElementById('themeBtn').textContent = currentTheme === 'dark' ? '☀️ Light' : '🌙 Dark';
      document.getElementById('langBtn').textContent = currentLang === 'pt' ? '🇧🇷 PT-BR' : '🇺🇸 EN';
      const t = I18N_LOGIN[currentLang];
      document.getElementById('loginDesc').textContent = t.desc;
      document.getElementById('token').placeholder = t.placeholder;
      document.getElementById('loginBtn').textContent = t.btn;
      document.getElementById('err').textContent = t.err;
      document.getElementById('helpTitle').textContent = t.help;
    }
    function toggleTheme() {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      localStorage.setItem('paasmcp_theme', currentTheme);
      applyPrefs();
    }
    function toggleLang() {
      currentLang = currentLang === 'pt' ? 'en' : 'pt';
      localStorage.setItem('paasmcp_lang', currentLang);
      applyPrefs();
    }
    async function doLogin() {
      const token = document.getElementById('token').value.trim();
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
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
  <title>PaaSMCP — Control Plane Dashboard</title>
  <style>
    ${sharedCss}
    body { padding: 24px 32px; max-width: 1380px; margin: 0 auto; }
    @media (max-width: 768px) { body { padding: 16px; } }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
      gap: 14px;
    }
    .brand { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 22px; letter-spacing: -0.02em; }
    .guide-banner {
      background: linear-gradient(135deg, var(--accent-soft), var(--card));
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px 24px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }
    .guide-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .guide-header h2 { margin: 0; font-size: 17px; }
    .guide-steps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-top: 16px;
    }
    .step-box {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
    }
    .step-num {
      display: inline-flex;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: var(--accent);
      color: #fff;
      font-size: 12px;
      font-weight: 700;
      align-items: center;
      justify-content: center;
      margin-right: 6px;
    }
    .step-box h3 { margin: 0 0 6px; font-size: 14px; display: flex; align-items: center; }
    .step-box p { margin: 0; font-size: 12.5px; color: var(--muted); line-height: 1.45; }
    .grid-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px 22px;
      margin-bottom: 20px;
      box-shadow: var(--shadow);
    }
    .card-header {
      margin-bottom: 14px;
    }
    .card-header h2 {
      margin: 0 0 4px;
      font-size: 16.5px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .card-desc {
      margin: 0;
      font-size: 12.5px;
      color: var(--muted);
      line-height: 1.45;
    }
    .stat-label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
    .stat-value { font-size: 22px; font-weight: 700; margin-top: 6px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 960px) { .row { grid-template-columns: 1fr; } }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
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
      font-size: 12px;
      color: var(--muted);
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.03em; }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
    .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--success); margin-right: 7px; }
    .prompt-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }
    .prompt-card {
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 10px;
    }
    .prompt-card p {
      margin: 0;
      font-size: 12.5px;
      line-height: 1.5;
      color: var(--text);
      font-style: italic;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>🚀 PaaSMCP</h1>
      <span class="badge" id="badgeSubtitle">Agent-First Micro-PaaS</span>
      ${cfEmail ? `<span class="badge success">🔒 Zero Trust: ${cfEmail}</span>` : ""}
    </div>
    <div class="toolbar-controls">
      <button class="secondary" onclick="toggleGuide()" id="btnToggleGuide">💡 Guia Rápido</button>
      <button class="secondary" onclick="toggleLang()" id="langBtn">🇧🇷 PT-BR</button>
      <button class="secondary" onclick="toggleTheme()" id="themeBtn">☀️ Light</button>
      <button class="secondary" onclick="loadAll()" id="btnRefresh">🔄 Atualizar</button>
      <button class="danger" onclick="logout()" id="btnLogout">Sair</button>
    </div>
  </header>

  <!-- Interactive Quick Start Guide -->
  <div class="guide-banner" id="guideBanner">
    <div class="guide-header">
      <div>
        <h2 id="guideTitle">👋 Bem-vindo ao seu Micro-PaaS Pessoal (Estilo Render / Vercel)</h2>
        <p class="card-desc" id="guideSubtitle">Publique qualquer repositório do GitHub com banco de dados isolado, variáveis criptografadas e HTTPS automático em 4 passos simples:</p>
      </div>
      <button class="secondary" onclick="toggleGuide()" style="font-size:12px;padding:6px 10px;" id="btnHideGuide">Ocultar Guia</button>
    </div>
    <div class="guide-steps">
      <div class="step-box">
        <h3><span class="step-num">1</span> <span id="step1Title">Variáveis & Segredos</span></h3>
        <p id="step1Desc">Salve chaves de API (OpenAI, Stripe, etc.) no Cofre AES-256-GCM usando o nome do seu app como escopo antes ou depois do deploy.</p>
      </div>
      <div class="step-box">
        <h3><span class="step-num">2</span> <span id="step2Title">Build & Deploy do GitHub</span></h3>
        <p id="step2Desc">Informe seu repositório <code>owner/repo</code>. Se não houver Dockerfile, o PaaSMCP gera um automaticamente (Node, Next, Python, Go, SPA).</p>
      </div>
      <div class="step-box">
        <h3><span class="step-num">3</span> <span id="step3Title">Banco de Dados 1-Click</span></h3>
        <p id="step3Desc">Marque PostgreSQL ou Redis no deploy (ou crie depois). A variável <code>DATABASE_URL</code> é injetada automaticamente no container.</p>
      </div>
      <div class="step-box">
        <h3><span class="step-num">4</span> <span id="step4Title">Domínio HTTPS Seguro</span></h3>
        <p id="step4Desc">Exponha na internet em <code>subdominio.{domain}</code> (Público ou protegido com login PIN por e-mail no Cloudflare Zero Trust).</p>
      </div>
    </div>
  </div>

  <!-- Stats -->
  <div class="grid-stats" id="statsGrid"></div>

  <!-- Hosted Applications Table -->
  <div class="card">
    <div class="card-header">
      <h2>
        <span id="appsTitle">📦 Aplicações Hospedadas</span>
        <span class="badge" id="appsBadgeCount">0 apps</span>
      </h2>
      <p class="card-desc" id="appsDesc">Todos os containers rodam isolados em <code>127.0.0.1:4000-4999</code> e conectados à rede <code>homelab-network</code>.</p>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th id="thApp">Aplicação</th>
            <th id="thStack">Stack Detectada</th>
            <th id="thPort">Porta Local</th>
            <th id="thDb">Bancos Vinculados</th>
            <th id="thDomains">Domínios / Endereços</th>
            <th id="thActions">Ações Rápidas</th>
          </tr>
        </thead>
        <tbody id="appsTable">
          <tr><td colspan="6">...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Deploy & Expose Row -->
  <div class="row">
    <div class="card">
      <div class="card-header">
        <h2 id="deployTitle">➕ Novo Deploy (GitHub ou Diretório Local)</h2>
        <p class="card-desc" id="deployDesc">Clona o repositório via SSH/Token, detecta a linguagem, constrói a imagem Docker e inicia o serviço.</p>
      </div>
      <div class="examples-bar">
        <span id="lblQuickFillDeploy">⚡ Preencher exemplo:</span>
        <button class="chip" onclick="fillDeployExample('meu-saas', 'seu-usuario/meu-saas', 'main', true, false)">SaaS Node/Next + Postgres</button>
        <button class="chip" onclick="fillDeployExample('api-python', 'seu-usuario/api-fastapi', 'main', true, true)">API Python + PG + Redis</button>
        <button class="chip" onclick="fillDeployExample('landing-page', 'seu-usuario/landing', 'main', false, false)">Site Estático / SPA</button>
      </div>
      <div class="form-grid">
        <div>
          <label class="field-label" id="lblDepApp">Identificador do App (slug)</label>
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
      <div style="display:flex; gap:18px; align-items:center; margin-bottom:14px; font-size:13px; flex-wrap:wrap;">
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
          <input type="checkbox" id="depPg" style="width:auto;" />
          <span id="lblDepPg">Provisionar PostgreSQL 16 (+ injetar <code>DATABASE_URL</code>)</span>
        </label>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
          <input type="checkbox" id="depRedis" style="width:auto;" />
          <span id="lblDepRedis">Provisionar Redis 7 (+ injetar <code>REDIS_URL</code>)</span>
        </label>
      </div>
      <button onclick="deployNewApp()" id="btnDeploy">🚀 Fazer Build & Deploy</button>
    </div>

    <div class="card">
      <div class="card-header">
        <h2 id="exposeTitle">🌐 Expor Aplicação na Internet ou Tailnet</h2>
        <p class="card-desc" id="exposeDesc">Cria automaticamente a rota no Cloudflare Tunnel + registro DNS CNAME sem abrir portas no seu roteador.</p>
      </div>
      <div class="examples-bar">
        <span id="lblQuickFillExpose">⚡ Modos de exposição:</span>
        <button class="chip" onclick="fillExposeMode('public')" id="chipModePublic">🌍 Público (Qualquer pessoa acessa)</button>
        <button class="chip" onclick="fillExposeMode('zero-trust')" id="chipModeZT">🛡️ Zero Trust (Pede PIN no seu e-mail)</button>
        <button class="chip" onclick="fillExposeMode('tailscale')" id="chipModeTS">🔒 Tailscale (Só sua VPN)</button>
      </div>
      <div class="form-grid">
        <div>
          <label class="field-label" id="lblExpApp">Aplicação já hospedada</label>
          <input id="expApp" list="hostedAppsList" placeholder="ex: meu-saas" />
          <datalist id="hostedAppsList"></datalist>
        </div>
        <div>
          <label class="field-label" id="lblExpMode">Modo de Segurança</label>
          <select id="expMode">
            <option value="public" id="optPublic">Cloudflare Público (HTTPS aberto)</option>
            <option value="zero-trust" id="optZT">Cloudflare Zero Trust (Login OTP por E-mail)</option>
            <option value="tailscale" id="optTS">Tailscale Serve (Privado na sua Tailnet)</option>
          </select>
        </div>
        <div>
          <label class="field-label" id="lblExpSub">Subdomínio desejado</label>
          <input id="expSub" placeholder="ex: app (vira app.seudominio.com)" />
        </div>
      </div>
      <button onclick="exposeApp()" id="btnExpose">🔗 Publicar Endereço</button>
    </div>
  </div>

  <!-- Vault & Databases Row -->
  <div class="row">
    <div class="card">
      <div class="card-header">
        <h2 id="vaultTitle">🔐 Cofre de Variáveis (AES-256-GCM Vault)</h2>
        <p class="card-desc" id="vaultDesc">Criptografia autenticada em disco. Use o escopo <code>system</code> para tokens globais ou o <strong>nome do app</strong> para variáveis daquele container.</p>
      </div>
      <div class="examples-bar">
        <span id="lblQuickScope">⚡ Escopos rápidos:</span>
        <button class="chip" onclick="setVaultScope('system')">⚙️ system (Global)</button>
        <span id="dynamicScopeChips"></span>
      </div>
      <div class="form-grid">
        <div>
          <label class="field-label" id="lblSecScope">Escopo (system ou slug do app)</label>
          <input id="secScope" placeholder="system" value="system" onchange="loadSecrets()" />
        </div>
        <div>
          <label class="field-label" id="lblSecKey">Nome da Variável (ENV)</label>
          <input id="secKey" placeholder="ex: OPENAI_API_KEY" />
        </div>
        <div>
          <label class="field-label" id="lblSecVal">Valor Secreto</label>
          <input id="secVal" type="password" placeholder="••••••••••••" />
        </div>
      </div>
      <div class="actions" style="margin-bottom:14px;">
        <button onclick="saveSecret()" id="btnSaveSecret">💾 Criptografar & Salvar</button>
        <button class="secondary" onclick="loadSecrets()" id="btnLoadSecrets">🔍 Recarregar Escopo</button>
      </div>
      <div id="secretsList"></div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2 id="dbTitle">🗄️ Bancos de Dados & Chave SSH GitHub</h2>
        <p class="card-desc" id="dbDesc">Provisiona bancos e credenciais exclusivas por aplicação e exibe sua Deploy Key para repositórios privados.</p>
      </div>
      <div class="form-grid">
        <div>
          <label class="field-label" id="lblDbApp">Vincular banco ao App</label>
          <input id="dbApp" list="hostedAppsList" placeholder="ex: meu-saas" />
        </div>
        <div>
          <label class="field-label" id="lblDbEngine">Motor do Banco</label>
          <select id="dbEngine">
            <option value="postgres">PostgreSQL 16 (Cria DB + User + DATABASE_URL)</option>
            <option value="redis">Redis 7 (Aloca DB lógico + REDIS_URL)</option>
          </select>
        </div>
      </div>
      <button onclick="createDb()" style="margin-bottom:18px;" id="btnCreateDb">+ Provisionar Banco Isolado</button>
      <div id="dbList" style="margin-bottom:18px; font-size:13px;"></div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span class="stat-label" id="lblSshKey">Chave SSH Pública de Deploy (GitHub Deploy Key):</span>
        <button class="chip" onclick="copySshKey()" id="btnCopySsh">📋 Copiar Chave SSH</button>
      </div>
      <pre id="sshKeyBox" style="margin-top:6px; user-select:all;"></pre>
    </div>
  </div>

  <!-- AI Agent Prompts & CLI Examples Card -->
  <div class="card">
    <div class="card-header">
      <h2 id="examplesTitle">🤖 Exemplos de Uso com Agentes de IA (MCP) & Terminal</h2>
      <p class="card-desc" id="examplesDesc">Como o PaaSMCP possui servidor MCP nativo, você pode pedir em linguagem natural no T3 Code / Claude / Cursor ou usar a CLI:</p>
    </div>
    <div class="prompt-grid">
      <div class="prompt-card">
        <div>
          <span class="badge" style="margin-bottom:8px;">💬 Prompt — Deploy Completo</span>
          <p id="prompt1Text">"Faça o deploy do meu repositório seu-usuario/meu-app na branch main com um banco PostgreSQL e publique em meuapp.{domain}"</p>
        </div>
        <button class="secondary" style="font-size:12px;padding:6px 10px;" onclick="copyText(document.getElementById('prompt1Text').textContent)">📋 Copiar Prompt</button>
      </div>
      <div class="prompt-card">
        <div>
          <span class="badge" style="margin-bottom:8px;">💬 Prompt — App Privado Zero Trust</span>
          <p id="prompt2Text">"Suba o repositório seu-usuario/painel-admin e exponha em admin.{domain} protegido com login por e-mail no Cloudflare Zero Trust"</p>
        </div>
        <button class="secondary" style="font-size:12px;padding:6px 10px;" onclick="copyText(document.getElementById('prompt2Text').textContent)">📋 Copiar Prompt</button>
      </div>
      <div class="prompt-card">
        <div>
          <span class="badge" style="margin-bottom:8px;">💻 Equivalente no Terminal (CLI)</span>
          <code style="display:block;padding:8px;margin-top:4px;white-space:pre-wrap;" id="cliExampleBox">paasmcp deploy meu-app seu-usuario/meu-app --postgres
paasmcp expose meu-app public meuapp</code>
        </div>
        <button class="secondary" style="font-size:12px;padding:6px 10px;" onclick="copyText(document.getElementById('cliExampleBox').textContent)">📋 Copiar Comandos</button>
      </div>
    </div>
  </div>

  <!-- Container Logs Viewer -->
  <div class="card" id="logsCard" style="display:none;">
    <div class="card-header">
      <h2>
        <span id="logsTitle">📜 Logs do Container</span>
        <button class="secondary" onclick="document.getElementById('logsCard').style.display='none'" id="btnCloseLogs">Fechar</button>
      </h2>
    </div>
    <pre id="logsBox"></pre>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    const I18N = {
      pt: {
        badgeSubtitle: "Micro-PaaS para Agentes & Humanos",
        btnToggleGuide: "💡 Guia Rápido",
        btnHideGuide: "Ocultar Guia",
        btnRefresh: "🔄 Atualizar",
        btnLogout: "Sair",
        guideTitle: "👋 Bem-vindo ao seu Micro-PaaS Pessoal (Estilo Render / Vercel)",
        guideSubtitle: "Publique qualquer repositório do GitHub com banco de dados isolado, variáveis criptografadas e HTTPS automático em 4 passos simples:",
        step1Title: "Variáveis & Segredos",
        step1Desc: "Salve chaves de API (OpenAI, Stripe, etc.) no Cofre AES-256-GCM usando o nome do seu app como escopo antes ou depois do deploy.",
        step2Title: "Build & Deploy do GitHub",
        step2Desc: "Informe seu repositório <code>owner/repo</code>. Se não houver Dockerfile, o PaaSMCP gera um automaticamente (Node, Next, Python, Go, SPA).",
        step3Title: "Banco de Dados 1-Click",
        step3Desc: "Marque PostgreSQL ou Redis no deploy (ou crie depois). A variável <code>DATABASE_URL</code> é injetada automaticamente no container.",
        step4Title: "Domínio HTTPS Seguro",
        step4Desc: "Exponha na internet em <code>subdominio.{domain}</code> (Público ou protegido com login PIN por e-mail no Cloudflare Zero Trust).",
        statServer: "Servidor Host",
        statMem: "Memória Livre / Total",
        statApps: "Aplicações & Bancos",
        statBaseDomain: "Domínio Base Cloudflare",
        appsTitle: "📦 Aplicações Hospedadas",
        appsDesc: "Todos os containers rodam isolados em 127.0.0.1:4000-4999 e conectados à rede homelab-network.",
        thApp: "Aplicação",
        thStack: "Stack Detectada",
        thPort: "Porta Local",
        thDb: "Bancos Vinculados",
        thDomains: "Domínios / Endereços",
        thActions: "Ações Rápidas",
        emptyApps: "Nenhuma aplicação hospedada ainda. Clique em um dos exemplos abaixo para preencher e testar!",
        deployTitle: "➕ Novo Deploy (GitHub ou Diretório Local)",
        deployDesc: "Clona o repositório via SSH/Token, detecta a linguagem, constrói a imagem Docker e inicia o serviço.",
        lblQuickFillDeploy: "⚡ Preencher exemplo:",
        lblDepApp: "Identificador do App (slug)",
        lblDepRepo: "Repositório GitHub ou Caminho",
        lblDepBranch: "Branch Git",
        lblDepPg: "Provisionar PostgreSQL 16 (+ injetar DATABASE_URL)",
        lblDepRedis: "Provisionar Redis 7 (+ injetar REDIS_URL)",
        btnDeploy: "🚀 Fazer Build & Deploy",
        btnDeploying: "⏳ Fazendo Build & Deploy...",
        exposeTitle: "🌐 Expor Aplicação na Internet ou Tailnet",
        exposeDesc: "Cria automaticamente a rota no Cloudflare Tunnel + registro DNS CNAME sem abrir portas no seu roteador.",
        lblQuickFillExpose: "⚡ Modos de exposição:",
        chipModePublic: "🌍 Público (Aberto)",
        chipModeZT: "🛡️ Zero Trust (PIN por E-mail)",
        chipModeTS: "🔒 Tailscale (VPN Privada)",
        lblExpApp: "Aplicação já hospedada",
        lblExpMode: "Modo de Segurança",
        optPublic: "Cloudflare Público (HTTPS aberto para todos)",
        optZT: "Cloudflare Zero Trust (Exige PIN no seu e-mail)",
        optTS: "Tailscale Serve (Privado apenas na sua Tailnet)",
        lblExpSub: "Subdomínio desejado",
        btnExpose: "🔗 Publicar Endereço",
        vaultTitle: "🔐 Cofre de Variáveis (AES-256-GCM Vault)",
        vaultDesc: "Criptografia autenticada em disco. Use o escopo 'system' para tokens globais ou o nome do app para variáveis daquele container.",
        lblQuickScope: "⚡ Esculha um escopo:",
        lblSecScope: "Escopo (system ou slug do app)",
        lblSecKey: "Nome da Variável (ENV)",
        lblSecVal: "Valor Secreto",
        btnSaveSecret: "💾 Criptografar & Salvar",
        btnLoadSecrets: "🔍 Recarregar Escopo",
        emptySecrets: "Nenhuma variável salva neste escopo.",
        btnRemoveSecret: "Remover",
        dbTitle: "🗄️ Bancos de Dados & Chave SSH GitHub",
        dbDesc: "Provisiona bancos e credenciais exclusivas por aplicação e exibe sua Deploy Key para repositórios privados.",
        lblDbApp: "Vincular banco ao App",
        lblDbEngine: "Motor do Banco",
        btnCreateDb: "+ Provisionar Banco Isolado",
        emptyDbs: "Nenhum banco de dados provisionado ainda.",
        lblSshKey: "Chave SSH Pública de Deploy (GitHub Deploy Key):",
        btnCopySsh: "📋 Copiar Chave SSH",
        examplesTitle: "🤖 Exemplos de Uso com Agentes de IA (MCP) & Terminal",
        examplesDesc: "Como o PaaSMCP possui servidor MCP nativo, você pode pedir em linguagem natural no T3 Code / Claude / Cursor ou usar a CLI:",
        prompt1Text: "\x27Faça o deploy do meu repositório seu-usuario/meu-app na branch main com um banco PostgreSQL e publique em meuapp.{domain}\x27",
        prompt2Text: "\x27Suba o repositório seu-usuario/painel-admin e exponha em admin.{domain} protegido com login por e-mail no Cloudflare Zero Trust\x27",
        logsTitle: "📜 Logs do Container",
        btnCloseLogs: "Fechar",
        btnDestroy: "Excluir",
        confirmDestroy: "Tem certeza que deseja destruir o container e os arquivos de ",
        toastCopied: "✅ Copiado para a área de transferência!",
        toastSaved: "✅ Segredo criptografado com sucesso!",
        toastExposed: "🌐 Endereço publicado: "
      },
      en: {
        badgeSubtitle: "Agent-First & Human-Friendly Micro-PaaS",
        btnToggleGuide: "💡 Quick Guide",
        btnHideGuide: "Hide Guide",
        btnRefresh: "🔄 Refresh",
        btnLogout: "Sign Out",
        guideTitle: "👋 Welcome to your Self-Hosted Micro-PaaS (Render / Vercel Style)",
        guideSubtitle: "Deploy any GitHub repository with isolated databases, encrypted secrets, and automatic HTTPS in 4 simple steps:",
        step1Title: "Environment Secrets",
        step1Desc: "Store API keys (OpenAI, Stripe, etc.) in the AES-256-GCM Vault using your app name as the scope before or after deployment.",
        step2Title: "GitHub Build & Deploy",
        step2Desc: "Enter your <code>owner/repo</code>. If no Dockerfile exists, PaaSMCP auto-generates one for Node.js, Next.js, Python, Go, or static SPAs.",
        step3Title: "1-Click Databases",
        step3Desc: "Check PostgreSQL or Redis when deploying (or provision later). <code>DATABASE_URL</code> is automatically injected into the container.",
        step4Title: "Secure HTTPS Domains",
        step4Desc: "Expose to the internet on <code>subdomain.{domain}</code> (Public HTTPS or protected by Cloudflare Zero Trust Email OTP).",
        statServer: "Host Server",
        statMem: "Free / Total Memory",
        statApps: "Active Apps & Databases",
        statBaseDomain: "Cloudflare Base Domain",
        appsTitle: "📦 Hosted Applications",
        appsDesc: "All containers run isolated on 127.0.0.1:4000-4999 and connect to the homelab-network bridge.",
        thApp: "Application",
        thStack: "Detected Stack",
        thPort: "Local Port",
        thDb: "Linked Databases",
        thDomains: "Domains / Routes",
        thActions: "Quick Actions",
        emptyApps: "No applications deployed yet. Click one of the example chips below to test!",
        deployTitle: "➕ New Deployment (GitHub or Local Path)",
        deployDesc: "Clones the repository via SSH/Token, detects the runtime stack, builds the Docker image, and starts the container.",
        lblQuickFillDeploy: "⚡ Quick fill example:",
        lblDepApp: "App Identifier (slug)",
        lblDepRepo: "GitHub Repo (owner/repo) or Path",
        lblDepBranch: "Git Branch",
        lblDepPg: "Provision PostgreSQL 16 (+ inject DATABASE_URL)",
        lblDepRedis: "Provision Redis 7 (+ inject REDIS_URL)",
        btnDeploy: "🚀 Build & Deploy",
        btnDeploying: "⏳ Building & Deploying...",
        exposeTitle: "🌐 Expose Application (Cloudflare Tunnel / Tailscale)",
        exposeDesc: "Automatically configures Cloudflare Tunnel ingress + proxied DNS CNAME without opening router ports.",
        lblQuickFillExpose: "⚡ Exposure presets:",
        chipModePublic: "🌍 Public (Open HTTPS)",
        chipModeZT: "🛡️ Zero Trust (Email OTP PIN)",
        chipModeTS: "🔒 Tailscale (Private VPN)",
        lblExpApp: "Hosted Application",
        lblExpMode: "Security Mode",
        optPublic: "Cloudflare Public (Open HTTPS to everyone)",
        optZT: "Cloudflare Zero Trust (Requires Email OTP login)",
        optTS: "Tailscale Serve (Private to your Tailnet)",
        lblExpSub: "Desired Subdomain",
        btnExpose: "🔗 Publish Domain",
        vaultTitle: "🔐 Encrypted Environment Vault (AES-256-GCM)",
        vaultDesc: "Authenticated encryption at rest. Use 'system' scope for platform tokens or your app slug for container variables.",
        lblQuickScope: "⚡ Quick scopes:",
        lblSecScope: "Scope (system or app slug)",
        lblSecKey: "Variable Name (ENV)",
        lblSecVal: "Secret Value",
        btnSaveSecret: "💾 Encrypt & Save",
        btnLoadSecrets: "🔍 Reload Scope",
        emptySecrets: "No encrypted variables stored in this scope.",
        btnRemoveSecret: "Delete",
        dbTitle: "🗄️ Databases & GitHub SSH Deploy Key",
        dbDesc: "Provisions isolated databases & credentials per app and displays your SSH public key for private GitHub repos.",
        lblDbApp: "Bind Database to App",
        lblDbEngine: "Database Engine",
        btnCreateDb: "+ Provision Isolated Database",
        emptyDbs: "No databases provisioned yet.",
        lblSshKey: "Public SSH Deploy Key (GitHub Deploy Key):",
        btnCopySsh: "📋 Copy SSH Key",
        examplesTitle: "🤖 AI Agent (MCP) Prompts & CLI Examples",
        examplesDesc: "Since PaaSMCP includes a native MCP server, you can ask your AI agent in natural language or run CLI commands:",
        prompt1Text: "\x27Deploy my repository seu-usuario/my-app on branch main with a PostgreSQL database and expose it on myapp.{domain}\x27",
        prompt2Text: "\x27Deploy seu-usuario/admin-panel and expose it on admin.{domain} protected by Cloudflare Zero Trust email login\x27",
        logsTitle: "📜 Container Logs",
        btnCloseLogs: "Close",
        btnDestroy: "Destroy",
        confirmDestroy: "Are you sure you want to destroy the container and files for ",
        toastCopied: "✅ Copied to clipboard!",
        toastSaved: "✅ Secret encrypted and saved!",
        toastExposed: "🌐 Published at: "
      }
    };

    let currentLang = localStorage.getItem('paasmcp_lang') || ((navigator.language || '').toLowerCase().startsWith('pt') ? 'pt' : 'en');
    let currentTheme = localStorage.getItem('paasmcp_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    let lastStatus = null;

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
    function t(key) {
      const raw = (I18N[currentLang] && I18N[currentLang][key]) || I18N.pt[key] || key;
      return String(raw).replace(/\{domain\}/g, getBaseDomain());
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
      showToast(t('toastCopied'));
    }

    function copySshKey() {
      copyText(document.getElementById('sshKeyBox').textContent);
    }

    function applyPreferences() {
      document.documentElement.setAttribute('data-theme', currentTheme);
      document.documentElement.lang = currentLang === 'pt' ? 'pt-BR' : 'en';
      document.getElementById('themeBtn').textContent = currentTheme === 'dark' ? '☀️ Light' : '🌙 Dark';
      document.getElementById('langBtn').textContent = currentLang === 'pt' ? '🇧🇷 PT-BR' : '🇺🇸 EN';

      const ids = [
        'badgeSubtitle','btnToggleGuide','btnHideGuide','btnRefresh','btnLogout',
        'guideTitle','guideSubtitle','step1Title','step1Desc','step2Title','step2Desc',
        'step3Title','step3Desc','step4Title','step4Desc','appsTitle','appsDesc',
        'thApp','thStack','thPort','thDb','thDomains','thActions','deployTitle','deployDesc',
        'lblQuickFillDeploy','lblDepApp','lblDepRepo','lblDepBranch','lblDepPg','lblDepRedis',
        'btnDeploy','exposeTitle','exposeDesc','lblQuickFillExpose','chipModePublic','chipModeZT',
        'chipModeTS','lblExpApp','lblExpMode','optPublic','optZT','optTS','lblExpSub','btnExpose',
        'vaultTitle','vaultDesc','lblQuickScope','lblSecScope','lblSecKey','lblSecVal',
        'btnSaveSecret','btnLoadSecrets','dbTitle','dbDesc','lblDbApp','lblDbEngine',
        'btnCreateDb','lblSshKey','btnCopySsh','examplesTitle','examplesDesc',
        'prompt1Text','prompt2Text','logsTitle','btnCloseLogs'
      ];
      for (const id of ids) {
        const el = document.getElementById(id);
        if (el) { if (id.startsWith("step") && id.endsWith("Desc")) el.innerHTML = t(id); else el.textContent = t(id); }
      }

      const guideHidden = localStorage.getItem('paasmcp_hide_guide') === '1';
      document.getElementById('guideBanner').style.display = guideHidden ? 'none' : 'block';

      const expSubEl = document.getElementById("expSub");
      if (expSubEl) expSubEl.placeholder = currentLang === "pt" ? "ex: app (vira app." + getBaseDomain() + ")" : "e.g. app (becomes app." + getBaseDomain() + ")";
      if (lastStatus) renderStatusData(lastStatus);
      loadSecrets();
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

    function toggleGuide() {
      const banner = document.getElementById('guideBanner');
      const isHidden = banner.style.display === 'none';
      banner.style.display = isHidden ? 'block' : 'none';
      localStorage.setItem('paasmcp_hide_guide', isHidden ? '0' : '1');
    }

    function fillDeployExample(app, repo, branch, pg, redis) {
      document.getElementById('depApp').value = app;
      document.getElementById('depRepo').value = repo;
      document.getElementById('depBranch').value = branch;
      document.getElementById('depPg').checked = Boolean(pg);
      document.getElementById('depRedis').checked = Boolean(redis);
    }

    function fillExposeMode(mode) {
      document.getElementById('expMode').value = mode;
    }

    function setVaultScope(scope) {
      document.getElementById('secScope').value = scope;
      loadSecrets();
    }

    function selectAppForExpose(appName) {
      document.getElementById('expApp').value = appName;
      document.getElementById('expSub').value = appName.replace(/^paasmcp-/, '');
      document.getElementById('expApp').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function renderStatusData(s) {
      document.getElementById('statsGrid').innerHTML = \`
        <div class="card" style="margin:0"><div class="stat-label">\${t('statServer')}</div><div class="stat-value">🖥️ \${s.hostname}</div><div style="color:var(--muted);font-size:12px;margin-top:4px">\${s.platform}</div></div>
        <div class="card" style="margin:0"><div class="stat-label">\${t('statMem')}</div><div class="stat-value">⚡ \${s.freeMemGb} GB / \${s.totalMemGb} GB</div><div style="color:var(--muted);font-size:12px;margin-top:4px">\${s.cpus} vCPUs</div></div>
        <div class="card" style="margin:0"><div class="stat-label">\${t('statApps')}</div><div class="stat-value">📦 \${s.appsCount} Apps · \${s.databasesCount} DBs</div><div style="color:var(--muted);font-size:12px;margin-top:4px">\${t('statBaseDomain')}: <strong>\${s.cloudflare?.baseDomain || '-'}</strong></div></div>
      \`;

      document.getElementById('sshKeyBox').textContent = s.sshPublicKey || '';

      const apps = Object.values(s.apps || {});
      document.getElementById('appsBadgeCount').textContent = apps.length + ' apps';

      // Populate datalist and dynamic scope chips
      document.getElementById('hostedAppsList').innerHTML = apps.map(a => \`<option value="\${a.name}"></option>\`).join('');
      document.getElementById('dynamicScopeChips').innerHTML = apps.map(a => \`<button class="chip" onclick="setVaultScope('\${a.name}')">📦 \${a.name}</button>\`).join(' ');

      const tbody = document.getElementById('appsTable');
      if (apps.length === 0) {
        tbody.innerHTML = \`<tr><td colspan="6" style="color:var(--muted)">\${t('emptyApps')}</td></tr>\`;
      } else {
        tbody.innerHTML = apps.map(a => \`
          <tr>
            <td><span class="status-dot"></span><strong>\${a.name}</strong></td>
            <td><code>\${a.runtimeType}</code></td>
            <td><code>127.0.0.1:\${a.localPort}</code></td>
            <td>\${(a.databases || []).map(d => \`<code>\${d}</code>\`).join(' ') || '<span style="color:var(--muted)">-</span>'}</td>
            <td>\${(a.domains || []).map(d => \`<div style="margin-bottom:3px;"><a href="\${d.url}" target="_blank">🔗 \${d.url}</a> <span class="badge" style="padding:1px 7px;font-size:10.5px;">\${d.mode}</span></div>\`).join('') || '<span style="color:var(--muted)">Local only</span>'}</td>
            <td class="actions">
              <button class="secondary" style="padding:5px 10px;font-size:12px;" onclick="selectAppForExpose('\${a.name}')">🌐 Expor</button>
              <button class="secondary" style="padding:5px 10px;font-size:12px;" onclick="setVaultScope('\${a.name}')">🔐 ENV</button>
              <button class="secondary" style="padding:5px 10px;font-size:12px;" onclick="appAction('\${a.name}','logs')">📜 Logs</button>
              <button class="secondary" style="padding:5px 10px;font-size:12px;" onclick="appAction('\${a.name}','restart')">🔄 Restart</button>
              <button class="danger" style="padding:5px 10px;font-size:12px;" onclick="if(confirm(t('confirmDestroy') + a.name + '?')) appAction('\${a.name}','destroy')">\${t('btnDestroy')}</button>
            </td>
          </tr>
        \`).join('');
      }

      const dbs = Object.values(s.databases || {});
      document.getElementById('dbList').innerHTML = dbs.length
        ? dbs.map(d => \`<div style="margin-bottom:6px;padding:6px 10px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);">🗄️ <strong>\${d.name}</strong> (\${d.engine}) → DB: <code>\${d.dbName}</code> | User: <code>\${d.dbUser}</code></div>\`).join('')
        : \`<span style="color:var(--muted)">\${t('emptyDbs')}</span>\`;
    }

    async function loadAll() {
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
        ? entries.map(([k, v]) => \`<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:6px;border-radius:8px;background:var(--bg-subtle);border:1px solid var(--border);font-size:13px;"><span>🔑 <strong>\${k}</strong> = <code>\${v}</code></span><button class="danger" style="padding:3px 9px;font-size:11px" onclick="delSecret('\${scope}','\${k}')">\${t('btnRemoveSecret')}</button></div>\`).join('')
        : \`<div style="color:var(--muted);font-size:13px">\${t('emptySecrets')}</div>\`;
    }

    async function saveSecret() {
      const scope = document.getElementById('secScope').value.trim() || 'system';
      const key = document.getElementById('secKey').value.trim();
      const value = document.getElementById('secVal').value;
      if (!key) return;
      await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope, key, value })
      });
      document.getElementById('secKey').value = '';
      document.getElementById('secVal').value = '';
      showToast(t('toastSaved'));
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
      loadAll();
    }

    async function deployNewApp() {
      const appName = document.getElementById('depApp').value.trim();
      const repoSource = document.getElementById('depRepo').value.trim();
      const branch = document.getElementById('depBranch').value.trim() || 'main';
      const withPostgres = document.getElementById('depPg').checked;
      const withRedis = document.getElementById('depRedis').checked;
      if (!appName || !repoSource) return;
      const btn = document.getElementById('btnDeploy');
      btn.textContent = t('btnDeploying');
      btn.disabled = true;
      try {
        const res = await fetch('/api/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ appName, repoSource, branch, withPostgres, withRedis })
        });
        const data = await res.json();
        if (!res.ok) alert('Error: ' + data.error);
        else loadAll();
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

  const composePath = path.join(dashDir, "compose.yaml");
  const composeContent = `services:
  dashboard:
    image: node:22-alpine
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
