import crypto from "node:crypto";
import http from "node:http";
import { loadState } from "./config.js";
import { provisionDatabase } from "./database.js";
import { deployApp, manageAppLifecycle } from "./deployer.js";
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
    if (pathname === "/" && req.method === "GET") {
      const authed = isAuthenticated(req, expectedToken);
      const cfEmail = req.headers["cf-access-authenticated-user-email"] as
        | string
        | undefined;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderDashboardHtml(authed, cfEmail));
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
  if (!authed) {
    return `<!DOCTYPE html>
<html lang="pt-BR" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PaaSMCP — Login Seguro</title>
  <style>
    :root { --bg: #090d16; --card: #111827; --border: #1f2937; --text: #f3f4f6; --muted: #9ca3af; --accent: #6366f1; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
    body { margin: 0; background: var(--bg); color: var(--text); display: flex; min-height: 100vh; align-items: center; justify-content: center; }
    .login-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 32px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
    h1 { margin: 0 0 8px; font-size: 22px; display: flex; align-items: center; gap: 10px; }
    p { margin: 0 0 24px; color: var(--muted); font-size: 14px; line-height: 1.5; }
    input { width: 100%; padding: 12px; border-radius: 8px; border: 1px solid var(--border); background: #030712; color: var(--text); font-size: 14px; margin-bottom: 16px; }
    button { width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--accent); color: white; font-weight: 600; cursor: pointer; font-size: 14px; }
    button:hover { opacity: 0.92; }
    .err { color: #f87171; font-size: 13px; margin-top: 12px; display: none; }
    code { background: #030712; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #a5b4fc; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>🚀 PaaSMCP Control Plane</h1>
    <p>Insira o seu <code>DASHBOARD_TOKEN</code> (disponível via <code>paasmcp dashboard token</code> ou via MCP) para acessar o painel de gerenciamento.</p>
    <form id="loginForm">
      <input type="password" id="tokenInput" placeholder="Cole o DASHBOARD_TOKEN..." required autofocus />
      <button type="submit">Entrar no Painel</button>
      <div class="err" id="errBox">Token inválido.</div>
    </form>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = document.getElementById('tokenInput').value.trim();
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      if (res.ok) location.reload();
      else document.getElementById('errBox').style.display = 'block';
    });
  </script>
</body>
</html>`;
  }

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PaaSMCP — Dashboard de Aplicações</title>
  <style>
    :root { --bg: #090d16; --card: #111827; --border: #1f2937; --text: #f3f4f6; --muted: #9ca3af; --accent: #6366f1; --success: #10b981; --danger: #ef4444; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
    body { margin: 0; background: var(--bg); color: var(--text); padding: 24px; max-width: 1280px; margin-inline: auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand h1 { margin: 0; font-size: 22px; }
    .badge { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3); padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
    .stat-label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-value { font-size: 22px; font-weight: 700; margin-top: 6px; }
    h2 { margin: 0 0 16px; font-size: 17px; display: flex; align-items: center; justify-content: space-between; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 900px) { .row { grid-template-columns: 1fr; } }
    input, select { padding: 9px 12px; border-radius: 8px; border: 1px solid var(--border); background: #030712; color: var(--text); font-size: 13px; width: 100%; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 12px; }
    button { padding: 8px 14px; border-radius: 8px; border: 1px solid transparent; background: var(--accent); color: white; font-weight: 600; font-size: 13px; cursor: pointer; }
    button.secondary { background: #1f2937; border-color: #374151; color: var(--text); }
    button.danger { background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4); color: #f87171; }
    button:hover { opacity: 0.9; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    code, pre { background: #030712; padding: 3px 7px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 12px; color: #a5b4fc; }
    pre { padding: 14px; overflow-x: auto; max-height: 320px; color: #d1d5db; }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; }
    a { color: #818cf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--success); margin-right: 6px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>🚀 PaaSMCP Dashboard</h1>
      <span class="badge">Agent-First Micro-PaaS</span>
      ${cfEmail ? `<span class="badge">Zero Trust: ${cfEmail}</span>` : ""}
    </div>
    <div class="actions">
      <button class="secondary" onclick="loadAll()">🔄 Atualizar</button>
      <button class="danger" onclick="logout()">Sair</button>
    </div>
  </header>

  <div class="grid-stats" id="statsGrid"></div>

  <div class="card">
    <h2>📦 Aplicações Hospedadas</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>App</th>
            <th>Stack</th>
            <th>Porta Local</th>
            <th>Bancos</th>
            <th>Domínios / Rotas</th>
            <th>Ações</th>
          </tr>
        </thead>
        <tbody id="appsTable">
          <tr><td colspan="6">Carregando...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="row">
    <div class="card">
      <h2>➕ Novo Deploy (GitHub ou Caminho Local)</h2>
      <div class="form-grid">
        <input id="depApp" placeholder="Nome do app (ex: meu-saas)" />
        <input id="depRepo" placeholder="GitHub owner/repo ou caminho" />
        <input id="depBranch" placeholder="Branch (padrão: main)" value="main" />
      </div>
      <div style="display:flex; gap:16px; align-items:center; margin-bottom:12px; font-size:13px;">
        <label><input type="checkbox" id="depPg" style="width:auto;" /> + PostgreSQL 16</label>
        <label><input type="checkbox" id="depRedis" style="width:auto;" /> + Redis 7</label>
      </div>
      <button onclick="deployNewApp()" id="btnDeploy">🚀 Fazer Build & Deploy</button>
    </div>

    <div class="card">
      <h2>🌐 Expor Aplicação (Cloudflare Tunnel / Tailscale)</h2>
      <div class="form-grid">
        <input id="expApp" placeholder="Nome do app (ex: meu-saas)" />
        <select id="expMode">
          <option value="public">Cloudflare Público (HTTPS aberto)</option>
          <option value="zero-trust">Cloudflare Zero Trust (Login PIN OTP)</option>
          <option value="tailscale">Tailscale Serve (Privado na Tailnet)</option>
        </select>
        <input id="expSub" placeholder="Subdomínio (opcional)" />
      </div>
      <button onclick="exposeApp()">🔗 Publicar Endereço</button>
    </div>
  </div>

  <div class="row">
    <div class="card">
      <h2>🔐 Cofre de Variáveis (AES-256-GCM Vault)</h2>
      <div class="form-grid">
        <input id="secScope" placeholder="Escopo (system ou nome-do-app)" value="system" onchange="loadSecrets()" />
        <input id="secKey" placeholder="CHAVE (ex: STRIPE_KEY)" />
        <input id="secVal" type="password" placeholder="Valor secreto..." />
      </div>
      <div class="actions" style="margin-bottom:14px;">
        <button onclick="saveSecret()">Salvar Segredo Criptografado</button>
        <button class="secondary" onclick="loadSecrets()">Listar Escopo</button>
      </div>
      <div id="secretsList"></div>
    </div>

    <div class="card">
      <h2>🗄️ Bancos de Dados & Chave SSH GitHub</h2>
      <div class="form-grid">
        <input id="dbApp" placeholder="App para criar banco (ex: meu-saas)" />
        <select id="dbEngine">
          <option value="postgres">PostgreSQL 16 Isolado</option>
          <option value="redis">Redis 7 Isolado</option>
        </select>
      </div>
      <button onclick="createDb()" style="margin-bottom:16px;">+ Provisionar Banco</button>
      <div id="dbList" style="margin-bottom:16px; font-size:13px;"></div>
      <div class="stat-label">Chave SSH Pública de Deploy (GitHub Deploy Key):</div>
      <pre id="sshKeyBox" style="margin-top:6px; user-select:all;"></pre>
    </div>
  </div>

  <div class="card" id="logsCard" style="display:none;">
    <h2>📜 Logs do Container <button class="secondary" onclick="document.getElementById('logsCard').style.display='none'">Fechar</button></h2>
    <pre id="logsBox"></pre>
  </div>

  <script>
    async function loadAll() {
      const res = await fetch('/api/status');
      if (!res.ok) return;
      const s = await res.json();

      document.getElementById('statsGrid').innerHTML = \`
        <div class="card" style="margin:0"><div class="stat-label">Servidor</div><div class="stat-value">\${s.hostname}</div><div style="color:var(--muted);font-size:12px;margin-top:4px">\${s.platform}</div></div>
        <div class="card" style="margin:0"><div class="stat-label">Memória Livre / Total</div><div class="stat-value">\${s.freeMemGb} GB / \${s.totalMemGb} GB</div><div style="color:var(--muted);font-size:12px;margin-top:4px">\${s.cpus} vCPUs</div></div>
        <div class="card" style="margin:0"><div class="stat-label">Apps / Bancos Ativos</div><div class="stat-value">\${s.appsCount} Apps · \${s.databasesCount} DBs</div><div style="color:var(--muted);font-size:12px;margin-top:4px">Domínio base: \${s.cloudflare?.baseDomain || '-'}</div></div>
      \`;

      document.getElementById('sshKeyBox').textContent = s.sshPublicKey || '';

      const apps = Object.values(s.apps || {});
      const tbody = document.getElementById('appsTable');
      if (apps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted)">Nenhuma aplicação hospedada ainda. Use o formulário abaixo ou o MCP para publicar!</td></tr>';
      } else {
        tbody.innerHTML = apps.map(a => \`
          <tr>
            <td><span class="status-dot"></span><strong>\${a.name}</strong></td>
            <td><code>\${a.runtimeType}</code></td>
            <td><code>127.0.0.1:\${a.localPort}</code></td>
            <td>\${(a.databases || []).map(d => \`<code>\${d}</code>\`).join(' ') || '-'}</td>
            <td>\${(a.domains || []).map(d => \`<div><a href="\${d.url}" target="_blank">\${d.url}</a> <small>(\${d.mode})</small></div>\`).join('') || '-'}</td>
            <td class="actions">
              <button class="secondary" onclick="appAction('\${a.name}','logs')">Logs</button>
              <button class="secondary" onclick="appAction('\${a.name}','restart')">Restart</button>
              <button class="danger" onclick="if(confirm('Destruir container de '+a.name+'?')) appAction('\${a.name}','destroy')">Excluir</button>
            </td>
          </tr>
        \`).join('');
      }

      const dbs = Object.values(s.databases || {});
      document.getElementById('dbList').innerHTML = dbs.length
        ? dbs.map(d => \`<div style="margin-bottom:4px">• <strong>\${d.name}</strong> (\${d.engine}) → <code>\${d.dbName}</code> (user: <code>\${d.dbUser}</code>)</div>\`).join('')
        : '<span style="color:var(--muted)">Nenhum banco provisionado.</span>';

      loadSecrets();
    }

    async function loadSecrets() {
      const scope = document.getElementById('secScope').value.trim() || 'system';
      const res = await fetch('/api/secrets?scope=' + encodeURIComponent(scope));
      const data = await res.json();
      const entries = Object.entries(data.secrets || {});
      document.getElementById('secretsList').innerHTML = entries.length
        ? entries.map(([k, v]) => \`<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px;"><span><strong>\${k}</strong> = <code>\${v}</code></span><button class="danger" style="padding:2px 8px;font-size:11px" onclick="delSecret('\${scope}','\${k}')">Remover</button></div>\`).join('')
        : '<div style="color:var(--muted);font-size:13px">Nenhuma variável salva neste escopo.</div>';
    }

    async function saveSecret() {
      const scope = document.getElementById('secScope').value.trim() || 'system';
      const key = document.getElementById('secKey').value.trim();
      const value = document.getElementById('secVal').value;
      if (!key) return alert('Informe o nome da variável');
      await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope, key, value })
      });
      document.getElementById('secKey').value = '';
      document.getElementById('secVal').value = '';
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
      if (!appName) return alert('Informe o nome do app');
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
      if (!appName || !repoSource) return alert('Preencha nome do app e repositório');
      const btn = document.getElementById('btnDeploy');
      btn.textContent = '⏳ Fazendo Build & Deploy...';
      btn.disabled = true;
      try {
        const res = await fetch('/api/deploy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ appName, repoSource, branch, withPostgres, withRedis })
        });
        const data = await res.json();
        if (!res.ok) alert('Erro: ' + data.error);
        else loadAll();
      } finally {
        btn.textContent = '🚀 Fazer Build & Deploy';
        btn.disabled = false;
      }
    }

    async function exposeApp() {
      const appName = document.getElementById('expApp').value.trim();
      const mode = document.getElementById('expMode').value;
      const subdomain = document.getElementById('expSub').value.trim() || undefined;
      if (!appName) return alert('Informe o nome do app');
      const res = await fetch('/api/expose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appName, mode, subdomain })
      });
      const data = await res.json();
      if (!res.ok) return alert('Erro: ' + data.error);
      alert('Publicado em: ' + data.url);
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
        document.getElementById('logsCard').style.display = 'block';
        document.getElementById('logsBox').textContent = data.output || '(sem logs)';
      } else {
        loadAll();
      }
    }

    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      location.reload();
    }

    loadAll();
  </script>
</body>
</html>`;
}

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { DOCKER_NETWORK, PAAS_DATA_DIR, saveState } from "./config.js";
import { ensureDockerNetwork } from "./database.js";
import { syncHomepageDashboard } from "./deployer.js";

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
