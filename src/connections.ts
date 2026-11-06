import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DOCKER_NETWORK, HOMELAB_ROOT, loadState, sanitizeSlug, updatePlatformConfig, writeFileAtomic, WATCHTOWER_OFF_COMPOSE } from "./config.js";
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
  const zonesRes = await cf<{ id: string; name: string; status?: string; account?: { id: string } }[]>(token, "GET", "/zones?per_page=50");
  const zones = (zonesRes.ok ? zonesRes.result || [] : [])
    .filter((z) => HOSTNAME_RE.test(String(z.name || "")) && (!z.status || z.status === "active"))
    .map((z) => ({ id: String(z.id), name: String(z.name), accountId: String(z.account?.id || "") }));
  const out: CloudflareDiscovery["accounts"] = [];
  for (const a of (accounts.result || []).filter((x) => ACCOUNT_RE.test(String(x.id))).slice(0, 20)) {
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
  const newName = `paasmcp-${sanitizeSlug(os.hostname()) || "server"}`.slice(0, 60);
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
