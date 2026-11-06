import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DOCKER_NETWORK, HOMELAB_ROOT, loadState, sanitizeSlug, updatePlatformConfig, writeFileAtomic, WATCHTOWER_OFF_COMPOSE, hostName } from "./config.js";
import { audit } from "./guard.js";
import { CLOUDFLARED_IMAGE, validTunnelToken } from "./activetunnel.js";
import { notifySummary } from "./notify.js";
import { getSecrets, setSecretEntries } from "./vault.js";

// Connections set up from the dashboard, so nobody needs the terminal or an AI to publish with a
// domain: the person pastes one Cloudflare token, the dashboard lists what that token can see
// (accounts, domains, tunnels) and saves the choice; with no tunnel yet it creates one and runs its
// connector here. GitHub gets a token check that says who the token belongs to.
//
// Tokens arrive in the request body only to be tested or saved, and are never sent back.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
const cfApi = () => (process.env.PAASMCP_CF_API_URL || "https://api.cloudflare.com/client/v4").replace(/\/+$/, "");
const ghApi = () => (process.env.PAASMCP_GITHUB_API_URL || "https://api.github.com").replace(/\/+$/, "");

export const MAIN_TUNNEL_DIR = path.join(HOMELAB_ROOT, "paasmcp-tunnel");
export const MAIN_TUNNEL_CONTAINER = "paasmcp-tunnel";

const CF_TOKEN_RE = /^[A-Za-z0-9_-]{30,200}$/;
const ACCOUNT_RE = /^[a-f0-9]{32}$/i;
const TUNNEL_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@,;<>"']{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i;
const GH_TOKEN_RE = /^[A-Za-z0-9_]{20,255}$/;

/** A mistake the person can fix, with the Portuguese text for the dashboard. */
export class ConnectionError extends Error {
  constructor(message: string, public pt: string) {
    super(message);
  }
}
const fail = (en: string, pt: string) => new ConnectionError(en, pt);

// ---- Cloudflare ----

async function cf<T>(token: string, method: string, route: string, body?: unknown): Promise<{ ok: boolean; status: number; result?: T }> {
  let res: Response;
  try {
    res = await fetch(`${cfApi()}${route}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw fail("Could not reach the Cloudflare API from this server.", "Este servidor não conseguiu falar com a Cloudflare. Confira a internet e o DNS do servidor (a tela Diagnóstico ajuda).");
  }
  const data = (await res.json().catch(() => ({}))) as { success?: boolean; result?: T };
  return { ok: res.ok && data.success !== false, status: res.status, result: data.result };
}

function pickCfToken(given: unknown): string {
  const token = typeof given === "string" && given.trim() ? given.trim() : getSecrets("system").CF_API_TOKEN || "";
  if (!token) throw fail("Paste the Cloudflare token first.", "Cole o token da Cloudflare primeiro.");
  if (!CF_TOKEN_RE.test(token)) {
    throw fail("That does not look like a Cloudflare API token.", "Isso não parece um token da Cloudflare. Copie o valor que aparece uma vez só, logo depois de criar o token (não a Global API Key).");
  }
  return token;
}

export interface CloudflareTunnelInfo {
  id: string;
  name: string;
  /** healthy, degraded, down or inactive (never connected). */
  status: string;
  /** Configured from the Cloudflare dashboard/API: the only kind PaaSMCP can add addresses to. */
  remote: boolean;
}

export interface CloudflareDiscovery {
  accounts: { id: string; name: string; tunnels: CloudflareTunnelInfo[]; tunnelsReadable: boolean; accessReadable: boolean }[];
  zones: { id: string; name: string; accountId: string }[];
  /** What is missing for the token to do everything PaaSMCP needs (English codes, the screen translates). */
  missing: string[];
}

/** Lists what a Cloudflare token can see. Changes nothing. */
export async function discoverCloudflare(givenToken?: unknown): Promise<CloudflareDiscovery> {
  const token = pickCfToken(givenToken);
  const accounts = await cf<{ id: string; name: string }[]>(token, "GET", "/accounts?per_page=50");
  if (accounts.status === 401 || accounts.status === 403 || (!accounts.ok && accounts.status === 400)) {
    throw fail("Cloudflare refused this token.", "A Cloudflare recusou este token. Ele pode ter sido apagado, ter expirado ou estar copiado pela metade.");
  }
  if (!accounts.ok) throw fail(`Cloudflare answered HTTP ${accounts.status}.`, `A Cloudflare respondeu com erro (HTTP ${accounts.status}). Tente de novo em alguns minutos.`);
  const zonesRes = await cf<{ id: string; name: string; status?: string; account?: { id: string; name?: string } }[]>(token, "GET", "/zones?per_page=50");
  const zones = (zonesRes.ok ? zonesRes.result || [] : [])
    .filter((z) => HOSTNAME_RE.test(String(z.name || "")) && (!z.status || z.status === "active"))
    .map((z) => ({ id: String(z.id), name: String(z.name), accountId: String(z.account?.id || "") }));
  // A token without "Account Settings: Read" lists no account, yet its zones name theirs and it may
  // manage that account's tunnels and Access: take the accounts from the zones then (each one is
  // still probed below, so nothing the token cannot do is offered).
  let listed = (accounts.result || []).filter((x) => ACCOUNT_RE.test(String(x.id)));
  if (!listed.length) {
    const seen = new Map<string, string>();
    for (const z of zonesRes.ok ? zonesRes.result || [] : []) {
      const id = String(z.account?.id || "");
      if (ACCOUNT_RE.test(id) && !seen.has(id)) seen.set(id, String(z.account?.name || id));
    }
    listed = [...seen].map(([id, name]) => ({ id, name }));
  }
  const out: CloudflareDiscovery["accounts"] = [];
  for (const a of listed.slice(0, 20)) {
    const t = await cf<{ id: string; name: string; status?: string; remote_config?: boolean; deleted_at?: string | null }[]>(
      token, "GET", `/accounts/${a.id}/cfd_tunnel?is_deleted=false&per_page=50`);
    const access = await cf<unknown[]>(token, "GET", `/accounts/${a.id}/access/apps?per_page=1`);
    out.push({
      id: a.id,
      name: String(a.name || a.id).slice(0, 120),
      tunnelsReadable: t.ok,
      accessReadable: access.ok,
      tunnels: (t.ok ? t.result || [] : [])
        .filter((x) => TUNNEL_RE.test(String(x.id)) && !x.deleted_at)
        .map((x) => ({ id: x.id, name: String(x.name || x.id).slice(0, 120), status: String(x.status || "inactive"), remote: x.remote_config !== false })),
    });
  }
  const missing: string[] = [];
  if (!out.length) missing.push("account");
  if (!zones.length) missing.push("zone");
  if (out.length && !out.some((a) => a.tunnelsReadable)) missing.push("tunnel");
  if (out.length && !out.some((a) => a.accessReadable)) missing.push("access");
  return { accounts: out, zones, missing };
}

export interface CloudflareChoice {
  token?: string;
  accountId: string;
  baseDomain: string;
  /** An existing tunnel, or "new" to create one here. */
  tunnelId: string;
  /** Run the tunnel's connector on this server (always for a new tunnel). */
  runHere?: boolean;
  zeroTrustEmails?: string[] | string;
}

const composeFor = () => `services:
  tunnel:
    image: ${CLOUDFLARED_IMAGE}
    container_name: ${MAIN_TUNNEL_CONTAINER}
    restart: unless-stopped
${WATCHTOWER_OFF_COMPOSE}    command: ["tunnel", "--no-autoupdate", "run"]
    # The token stays in .env (0600), not in this file.
    env_file: .env
    networks:
      - ${DOCKER_NETWORK}

networks:
  ${DOCKER_NETWORK}:
    external: true
`;

/** Writes the main tunnel's connector files and starts it (pinned cloudflared on the apps' network). */
export function ensureMainConnector(tunnelToken: string): void {
  if (!validTunnelToken(tunnelToken)) throw new Error("Unexpected tunnel token format.");
  fs.mkdirSync(MAIN_TUNNEL_DIR, { recursive: true, mode: 0o700 });
  const envFile = path.join(MAIN_TUNNEL_DIR, ".env");
  const composeFile = path.join(MAIN_TUNNEL_DIR, "compose.yaml");
  writeFileAtomic(envFile, `TUNNEL_TOKEN=${tunnelToken}\n`);
  fs.chmodSync(envFile, 0o600);
  writeFileAtomic(composeFile, composeFor());
  if (!OFFLINE()) execFileSync("docker", ["compose", "-f", composeFile, "up", "-d"], { cwd: MAIN_TUNNEL_DIR, stdio: "pipe" });
}

function mainConnectorState(): "running" | "stopped" | "absent" | "unknown" {
  if (!fs.existsSync(path.join(MAIN_TUNNEL_DIR, "compose.yaml"))) return "absent";
  if (OFFLINE()) return "unknown";
  try {
    const out = execFileSync("docker", ["inspect", "-f", "{{.State.Running}}", MAIN_TUNNEL_CONTAINER], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return out === "true" ? "running" : "stopped";
  } catch {
    return "stopped";
  }
}

function parseEmails(v: CloudflareChoice["zeroTrustEmails"]): string[] {
  const list = (Array.isArray(v) ? v : String(v || "").split(/[\s,;]+/)).map((e) => String(e).trim()).filter(Boolean);
  for (const e of list) {
    if (!EMAIL_RE.test(e)) throw fail(`Invalid email: ${e.slice(0, 80)}`, `E-mail inválido: ${e.slice(0, 80)}`);
  }
  return [...new Set(list)].slice(0, 50);
}

/**
 * Saves the Cloudflare connection. The choice is checked against what the token sees, so a typo
 * cannot point PaaSMCP at a domain or tunnel the token cannot change. `confirm` is called when
 * this replaces a working connection (guard "connect.cloudflare").
 */
export async function saveCloudflare(choice: CloudflareChoice, confirm: (params: Record<string, unknown>) => void): Promise<Record<string, unknown>> {
  const token = pickCfToken(choice.token);
  const accountId = String(choice.accountId || "").trim();
  const baseDomain = String(choice.baseDomain || "").trim().toLowerCase();
  const wanted = String(choice.tunnelId || "").trim();
  const emails = parseEmails(choice.zeroTrustEmails);
  if (!ACCOUNT_RE.test(accountId)) throw fail("Pick the account.", "Escolha a conta.");
  if (!HOSTNAME_RE.test(baseDomain)) throw fail("Pick the domain.", "Escolha o domínio.");
  if (wanted !== "new" && !TUNNEL_RE.test(wanted)) throw fail("Pick a tunnel or create a new one.", "Escolha um túnel ou crie um novo.");

  const found = await discoverCloudflare(token);
  const account = found.accounts.find((a) => a.id === accountId);
  if (!account) throw fail("This token cannot see that account.", "Este token não enxerga essa conta.");
  const zone = found.zones.find((z) => z.name === baseDomain);
  if (!zone) throw fail("This token cannot change that domain's DNS.", "Este token não pode mexer no DNS desse domínio. Na Cloudflare, edite o token e inclua esse domínio em Zone Resources.");
  if (zone.accountId && zone.accountId !== accountId) throw fail("That domain belongs to another account.", "Esse domínio é de outra conta da Cloudflare. Escolha a conta dele.");
  if (!account.tunnelsReadable) throw fail("The token lacks the Cloudflare Tunnel permission.", "Falta a permissão Cloudflare Tunnel: Edit no token.");

  // "new" reuses the tunnel this server created before (same name), so saving twice creates one tunnel.
  const newName = `paasmcp-${sanitizeSlug(hostName()) || "server"}`.slice(0, 60);
  const reuse = wanted === "new" ? account.tunnels.find((t) => t.name === newName) : undefined;
  const prev = loadState().cloudflare;
  const replacing = Boolean(prev.tunnelId && prev.baseDomain && prev.baseDomain !== "example.com") &&
    (prev.tunnelId !== (reuse?.id || wanted) || prev.baseDomain !== baseDomain || prev.accountId !== accountId);
  if (replacing) confirm({ replacing: true, previous: `${prev.baseDomain}`, target: baseDomain });

  let tunnelId = wanted;
  let tunnelName = "";
  let created = false;
  if (wanted === "new") {
    tunnelName = newName;
    if (reuse) {
      tunnelId = reuse.id;
    } else {
      const made = await cf<{ id: string }>(token, "POST", `/accounts/${accountId}/cfd_tunnel`, { name: tunnelName, config_src: "cloudflare" });
      if (!made.ok || !made.result?.id || !TUNNEL_RE.test(made.result.id)) {
        throw fail(`Cloudflare did not create the tunnel (HTTP ${made.status}).`, `A Cloudflare não criou o túnel (HTTP ${made.status}). Confira a permissão Cloudflare Tunnel: Edit.`);
      }
      tunnelId = made.result.id;
      created = true;
    }
  } else {
    const t = account.tunnels.find((x) => x.id === wanted);
    if (!t) throw fail("That tunnel is not in this account.", "Esse túnel não está nessa conta.");
    if (!t.remote) {
      throw fail("That tunnel is configured by a local file, so PaaSMCP cannot add addresses to it.",
        "Esse túnel é configurado por um arquivo no computador onde ele roda, então o PaaSMCP não consegue colocar endereços nele. Escolha “Criar um túnel novo” ou migre o túnel para o painel da Cloudflare.");
    }
    tunnelName = t.name;
  }

  const runHere = created || wanted === "new" || choice.runHere === true;
  if (runHere) {
    const tok = await cf<string>(token, "GET", `/accounts/${accountId}/cfd_tunnel/${tunnelId}/token`);
    if (!tok.ok || !validTunnelToken(tok.result)) throw fail("Cloudflare did not hand over the tunnel's token.", "A Cloudflare não entregou a chave do túnel. Confira a permissão Cloudflare Tunnel: Edit.");
    setSecretEntries("system", { MAIN_TUNNEL_TOKEN: tok.result as string });
    ensureMainConnector(tok.result as string);
  }
  if (choice.token) setSecretEntries("system", { CF_API_TOKEN: token });
  updatePlatformConfig({ accountId, tunnelId, baseDomain, ...(emails.length || choice.zeroTrustEmails !== undefined ? { zeroTrustEmails: emails } : {}) });
  audit({ event: "connect.cloudflare", accountId, tunnelId, baseDomain, created, runHere });
  return { accountId, baseDomain, tunnelId, tunnelName, created, runHere, zeroTrustEmails: emails };
}

// ---- GitHub ----

/** Checks a GitHub token (pasted or saved), saves it when pasted, and says whose it is. */
export async function checkGitHub(given?: unknown, save = true): Promise<{ login: string; name?: string; saved: boolean; kind: string }> {
  const pasted = typeof given === "string" && given.trim() ? given.trim() : "";
  const token = pasted || getSecrets("system").GITHUB_TOKEN || "";
  if (!token) throw fail("Paste the GitHub token first.", "Cole o token do GitHub primeiro.");
  if (!GH_TOKEN_RE.test(token)) throw fail("That does not look like a GitHub token.", "Isso não parece um token do GitHub (começa com github_pat_ ou ghp_).");
  let res: Response;
  try {
    res = await fetch(`${ghApi()}/user`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "paasmcp" },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw fail("Could not reach GitHub from this server.", "Este servidor não conseguiu falar com o GitHub.");
  }
  if (res.status === 401) throw fail("GitHub refused this token.", "O GitHub recusou este token. Ele pode ter expirado ou estar copiado pela metade.");
  if (!res.ok) throw fail(`GitHub answered HTTP ${res.status}.`, `O GitHub respondeu com erro (HTTP ${res.status}).`);
  const user = (await res.json().catch(() => ({}))) as { login?: string; name?: string };
  const login = String(user.login || "").slice(0, 100);
  if (!/^[A-Za-z0-9-]{1,100}$/.test(login)) throw fail("GitHub did not say whose token this is.", "O GitHub não disse de quem é o token.");
  if (pasted && save) setSecretEntries("system", { GITHUB_TOKEN: token });
  if (pasted && save) audit({ event: "connect.github", login });
  return { login, name: user.name ? String(user.name).slice(0, 100) : undefined, saved: Boolean(pasted && save) || !pasted, kind: token.startsWith("github_pat_") ? "fine-grained" : "classic" };
}

// ---- Summary for the screen ----

export function connectionsSummary(): Record<string, unknown> {
  const state = loadState();
  const sys = getSecrets("system");
  const c = state.cloudflare || ({} as typeof state.cloudflare);
  const domainSet = Boolean(c.baseDomain && c.baseDomain !== "example.com");
  return {
    cloudflare: {
      tokenSaved: Boolean(sys.CF_API_TOKEN),
      accountId: c.accountId || "",
      tunnelId: c.tunnelId || "",
      baseDomain: domainSet ? c.baseDomain : "",
      zeroTrustEmails: c.zeroTrustEmails || [],
      ready: Boolean(sys.CF_API_TOKEN && c.accountId && c.tunnelId && domainSet),
      connectorHere: mainConnectorState(),
    },
    github: { tokenSaved: Boolean(sys.GITHUB_TOKEN) },
    notify: notifySummary(),
    tailscaleDomain: state.tailscaleDomain || "",
  };
}

export interface GitHubRepo {
  fullName: string;
  private: boolean;
  defaultBranch: string;
  pushedAt: string;
  language: string;
}

/** The repositories the saved GitHub token reaches, most recently changed first (for the Publish screen). */
export async function listGitHubRepos(): Promise<GitHubRepo[]> {
  const token = getSecrets("system").GITHUB_TOKEN || "";
  if (!token) throw fail("No GitHub token saved.", "Nenhum token do GitHub salvo. Ligue em Conexões → GitHub.");
  let res: Response;
  try {
    res = await fetch(`${ghApi()}/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "paasmcp" },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw fail("Could not reach GitHub from this server.", "Este servidor não conseguiu falar com o GitHub.");
  }
  if (res.status === 401) throw fail("GitHub refused the saved token.", "O GitHub recusou o token salvo. Ele pode ter expirado: salve um novo em Conexões → GitHub.");
  if (!res.ok) throw fail(`GitHub answered HTTP ${res.status}.`, `O GitHub respondeu com erro (HTTP ${res.status}).`);
  const list = (await res.json().catch(() => [])) as { full_name?: string; private?: boolean; default_branch?: string; pushed_at?: string; language?: string | null }[];
  return (Array.isArray(list) ? list : [])
    .filter((r) => /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(r.full_name || "")))
    .map((r) => ({
      fullName: String(r.full_name),
      private: r.private === true,
      defaultBranch: /^[A-Za-z0-9._\/-]{1,100}$/.test(String(r.default_branch || "")) ? String(r.default_branch) : "main",
      pushedAt: String(r.pushed_at || ""),
      language: String(r.language || "").slice(0, 40),
    }));
}

// ---- GitHub push notices (webhooks) set up from the dashboard ----
//
// With the saved token, the dashboard creates (or fixes) the webhook on each repository its apps come
// from, so nobody copies an address and a secret into GitHub by hand. The token needs one more
// permission for this, Webhooks: Read and write; without it the screen says so and the manual steps
// stay. Only hooks pointing at this dashboard's own address are ever touched.

const HOOK_PATH = "/api/webhooks/github";
const REPO_RE = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

/** "owner/name" for an app's repository when it is on github.com, otherwise "". */
export function githubRepoOf(repoUrl: unknown): string {
  const s = String(repoUrl || "")
    .trim()
    .replace(/^https?:\/\/(www\.)?github\.com\//i, "")
    .replace(/^git@github\.com:/i, "")
    .replace(/^ssh:\/\/git@github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  return REPO_RE.test(s) && !s.split("/").some((p) => p === "." || p === "..") ? s : "";
}

/**
 * The address GitHub will call: https, a real public name (GitHub cannot reach a LAN address or
 * localhost), always ending in the dashboard's webhook path.
 */
export function webhookAddress(given: unknown): string {
  const raw = String(given || "").trim();
  let u: URL;
  try {
    u = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    throw fail("That is not a web address.", "Isso não é um endereço da internet. Use algo como https://painel.seudominio.com.");
  }
  if (u.protocol !== "https:") throw fail("The address must start with https://.", "O endereço precisa começar com https:// (o GitHub só avisa por conexão segura).");
  if (u.username || u.password) throw fail("The address must not carry a user or password.", "O endereço não pode ter usuário ou senha.");
  const host = u.hostname.toLowerCase();
  const local = /^(localhost|.*\.(local|lan|internal|home|home\.arpa|localdomain))$/.test(host);
  const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":") || host.startsWith("[");
  if (local || ip || !HOSTNAME_RE.test(host)) {
    throw fail("GitHub cannot reach this address: use the dashboard's internet name.", "O GitHub não alcança este endereço. Use o nome do painel na internet (ex.: https://painel.seudominio.com), não um IP ou nome da rede de casa.");
  }
  return `https://${host}${u.port ? `:${u.port}` : ""}${HOOK_PATH}`;
}

interface GhHook {
  id?: number;
  active?: boolean;
  events?: string[];
  config?: { url?: string; content_type?: string };
  last_response?: { code?: number | null; status?: string | null };
}

async function gh<T>(token: string, method: string, route: string, body?: unknown): Promise<{ status: number; data: T }> {
  let res: Response;
  try {
    res = await fetch(`${ghApi()}${route}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "paasmcp", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw fail("Could not reach GitHub from this server.", "Este servidor não conseguiu falar com o GitHub.");
  }
  const data = (await res.json().catch(() => ({}))) as T;
  return { status: res.status, data };
}

function savedToken(): string {
  const token = getSecrets("system").GITHUB_TOKEN || "";
  if (!token) throw fail("No GitHub token saved.", "Nenhum token do GitHub salvo. Ligue em Conexões → GitHub.");
  return token;
}

const sameHookUrl = (a: unknown, b: string) => String(a || "").replace(/\/+$/, "").toLowerCase() === b.toLowerCase();

export type HookState = "on" | "off" | "denied" | "error";
export interface RepoHook {
  repo: string;
  apps: string[];
  state: HookState;
  /** HTTP code of GitHub's last call to the dashboard (0 = could not connect), when known. */
  lastCode?: number;
}

function deniedOrError(status: number): HookState {
  if (status === 401) throw fail("GitHub refused the saved token.", "O GitHub recusou o token salvo. Ele pode ter expirado: salve um novo em Conexões → GitHub.");
  return status === 403 || status === 404 ? "denied" : "error";
}

async function findHook(token: string, repo: string, url: string): Promise<{ status: number; hook?: GhHook }> {
  const r = await gh<GhHook[]>(token, "GET", `/repos/${repo}/hooks?per_page=100`);
  if (r.status !== 200) return { status: r.status };
  const hook = (Array.isArray(r.data) ? r.data : []).find((h) => sameHookUrl(h.config?.url, url));
  return { status: 200, hook };
}

const lastCodeOf = (h?: GhHook) => (h && typeof h.last_response?.code === "number" ? h.last_response.code : undefined);

/** For each GitHub repository the apps come from: is the push notice to this dashboard set up? */
export async function listRepoHooks(apps: { name: string; repoUrl?: string }[], address: unknown): Promise<RepoHook[]> {
  const url = webhookAddress(address);
  const token = savedToken();
  const byRepo = new Map<string, string[]>();
  for (const a of apps) {
    const repo = githubRepoOf(a.repoUrl);
    if (!repo) continue;
    const key = repo.toLowerCase();
    byRepo.set(key, [...(byRepo.get(key) || []), a.name]);
  }
  const repos = [...byRepo.keys()].slice(0, 50);
  const names = new Map(apps.map((a) => [githubRepoOf(a.repoUrl).toLowerCase(), githubRepoOf(a.repoUrl)]));
  return Promise.all(
    repos.map(async (key): Promise<RepoHook> => {
      const repo = names.get(key) || key;
      const base = { repo, apps: byRepo.get(key) || [] };
      try {
        const f = await findHook(token, repo, url);
        if (f.status !== 200) return { ...base, state: deniedOrError(f.status) };
        if (!f.hook) return { ...base, state: "off" };
        const pushes = f.hook.active !== false && (f.hook.events || []).some((e) => e === "push" || e === "*");
        return { ...base, state: pushes ? "on" : "off", lastCode: lastCodeOf(f.hook) };
      } catch (err) {
        if (err instanceof ConnectionError && /refused/.test(err.message)) throw err;
        return { ...base, state: "error" };
      }
    })
  );
}

export interface HookResult {
  repo: string;
  created: boolean;
  /** "ok": GitHub reached the dashboard; "unreachable": it tried and could not; "unknown": no answer yet. */
  reach: "ok" | "unreachable" | "unknown";
  code?: number;
}

const waitMs = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Creates the push notice on one repository, or fixes the one already pointing here (new secret,
 * push event, json, active), then asks GitHub for a test call and reports whether it arrived.
 */
export async function ensureRepoHook(repoGiven: unknown, address: unknown, secret: string): Promise<HookResult> {
  const repo = githubRepoOf(repoGiven);
  if (!repo) throw fail("That is not a GitHub repository.", "Isso não é um repositório do GitHub.");
  const url = webhookAddress(address);
  const token = savedToken();
  const deniedMsg = () =>
    fail(
      `The saved token cannot manage webhooks on ${repo}.`,
      `O token salvo não pode criar o aviso em ${repo}. No GitHub, edite o token e dê a permissão Webhooks: Read and write (token clássico: admin:repo_hook), e confira se ${repo} está na lista de repositórios dele.`
    );
  const f = await findHook(token, repo, url);
  if (f.status !== 200) {
    if (deniedOrError(f.status) === "denied") throw deniedMsg();
    throw fail(`GitHub answered HTTP ${f.status}.`, `O GitHub respondeu com erro (HTTP ${f.status}).`);
  }
  const config = { url, content_type: "json", secret, insecure_ssl: "0" };
  let id: number;
  const created = !f.hook;
  const started = Date.now();
  if (f.hook && typeof f.hook.id === "number") {
    const r = await gh<GhHook>(token, "PATCH", `/repos/${repo}/hooks/${f.hook.id}`, { active: true, events: ["push"], config });
    if (r.status !== 200) {
      if (deniedOrError(r.status) === "denied") throw deniedMsg();
      throw fail(`GitHub answered HTTP ${r.status}.`, `O GitHub respondeu com erro (HTTP ${r.status}).`);
    }
    id = f.hook.id;
    await gh(token, "POST", `/repos/${repo}/hooks/${id}/pings`).catch(() => undefined);
  } else {
    const r = await gh<GhHook>(token, "POST", `/repos/${repo}/hooks`, { name: "web", active: true, events: ["push"], config });
    if (r.status !== 201 || typeof r.data.id !== "number") {
      if (r.status === 422) throw fail("GitHub would not add the webhook.", "O GitHub não aceitou o aviso (talvez o repositório já tenha 20 webhooks).");
      if (deniedOrError(r.status) === "denied") throw deniedMsg();
      throw fail(`GitHub answered HTTP ${r.status}.`, `O GitHub respondeu com erro (HTTP ${r.status}).`);
    }
    id = r.data.id; // GitHub sends its own test call (ping) right after creating it.
  }
  audit({ event: "connect.github.webhook", repo, created });

  // Wait a few seconds for the test call to land, reading GitHub's own record of it.
  const tries = OFFLINE() ? 1 : 6;
  for (let i = 0; i < tries; i++) {
    if (!OFFLINE()) await waitMs(1500);
    const d = await gh<{ event?: string; status_code?: number; delivered_at?: string }[]>(token, "GET", `/repos/${repo}/hooks/${id}/deliveries?per_page=5`).catch(() => undefined);
    const ping = d && d.status === 200 && Array.isArray(d.data)
      ? d.data.find((x) => x.event === "ping" && Date.parse(String(x.delivered_at || "")) >= started - 30_000)
      : undefined;
    if (ping && typeof ping.status_code === "number") {
      const code = ping.status_code;
      return { repo, created, reach: code >= 200 && code < 300 ? "ok" : "unreachable", code };
    }
  }
  return { repo, created, reach: "unknown" };
}
