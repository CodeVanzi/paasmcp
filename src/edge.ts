import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { liveCopyOf } from "./active.js";
import { EdgeConfig, HOMELAB_ROOT, loadState, ownOffers, PaaSState, sanitizeSlug, saveState, writeFileAtomic, WATCHTOWER_OFF_COMPOSE } from "./config.js";
import { audit } from "./guard.js";

// Self-hosted entry, the alternative to Cloudflare Tunnel: a Caddy container on a server with a
// public IP (usually the VPS) receives the site's requests, gets HTTPS certificates from Let's
// Encrypt by itself and splits the requests between this server's copy of the app and the other
// server's copy (over Tailscale). It probes each copy every 5 s and stops sending requests to one
// that does not answer. Caddy is part of the traffic path (like cloudflared); PaaSMCP itself keeps
// running only when called.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
export const EDGE_DIR = path.join(HOMELAB_ROOT, "paasmcp-edge");
export const EDGE_CONTAINER = "paasmcp-edge";
export const CADDY_IMAGE = "caddy:2.8.4-alpine";
const ADMIN_SOCKET = "unix//data/admin.sock";
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@{}"]+@[^\s@{}"]+\.[^\s@{}"]+$/;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

export function validateHostname(h: string): string {
  const clean = String(h || "").trim().toLowerCase().replace(/\.$/, "");
  if (!HOSTNAME_RE.test(clean)) throw new Error(`Invalid hostname '${h}'. Use a full domain such as shop.example.com.`);
  return clean;
}

export interface EdgeBackend {
  address: string;
  /** "here" or the other server's name. */
  where: string;
}

/** Where the edge sends a site's requests: this server's copy, plus the other server's copy for active-active apps. */
export function edgeBackends(state: PaaSState, appName: string): EdgeBackend[] {
  const app = state.apps[appName];
  if (!app) return [];
  const out: EdgeBackend[] = [{ address: `127.0.0.1:${app.localPort}`, where: "here" }];
  if (app.pool?.enabled && !app.originNodeId) {
    // Copies on helper PCs (pool.ts), reached over Tailscale. Paused helpers leave the list.
    for (const c of app.pool.placed) {
      const h = state.pool?.helpers[c.helper];
      if (h && !h.paused && IPV4.test(h.ip)) out.push({ address: `${h.ip}:${c.port}`, where: `helper ${h.name}` });
    }
    return out;
  }
  if (!app.activeActive) return out;
  if (!app.originNodeId) {
    for (const [peer, offer] of ownOffers(state)) {
      const ip = offer.peerCidr.replace(/\/32$/, "");
      if (IPV4.test(ip)) out.push({ address: `${ip}:${app.localPort}`, where: peer });
    }
  } else {
    const rec = liveCopyOf(state, app.originNodeId);
    if (rec && IPV4.test(rec.peerHost)) out.push({ address: `${rec.peerHost}:${app.localPort}`, where: rec.peerName });
  }
  return out;
}

/** The whole Caddyfile for the sites in state.edge (pure; tested). */
export function buildCaddyfile(state: PaaSState): string {
  const edge = state.edge;
  const lines: string[] = ["{", `\tadmin ${ADMIN_SOCKET}`];
  if (edge?.email) lines.push(`\temail ${edge.email}`);
  lines.push("}", "");
  for (const [host, site] of Object.entries(edge?.sites || {}).sort(([a], [b]) => a.localeCompare(b))) {
    const app = state.apps[site.app];
    const backends = edgeBackends(state, site.app);
    lines.push(`${validateHostname(host)} {`);
    if (!app || app.trashedAt || !backends.length) {
      lines.push(`\trespond "App '${site.app}' is not deployed on this server." 503`, "}", "");
      continue;
    }
    lines.push(`\treverse_proxy ${backends.map((b) => b.address).join(" ")} {`);
    lines.push("\t\tlb_policy round_robin", "\t\tlb_try_duration 5s", "\t\tfail_duration 30s");
    if (!app.healthcheckDisabled) {
      lines.push(`\t\thealth_uri ${app.healthcheckPath || "/"}`, "\t\thealth_interval 5s", "\t\thealth_timeout 3s", "\t\thealth_status 2xx");
    }
    lines.push("\t}", "}", "");
  }
  return lines.join("\n");
}

const COMPOSE = `services:
  edge:
    image: ${CADDY_IMAGE}
    container_name: ${EDGE_CONTAINER}
    restart: unless-stopped
${WATCHTOWER_OFF_COMPOSE}    # Host network: Caddy answers on ports 80/443 and reaches the apps on 127.0.0.1 and over Tailscale.
    network_mode: host
    volumes:
      - ./conf:/etc/caddy:ro
      - ./data:/data
      - ./config:/config
`;

/** Writes the Caddyfile; true when it changed. */
function writeConfig(state: PaaSState): boolean {
  const conf = path.join(EDGE_DIR, "conf");
  fs.mkdirSync(conf, { recursive: true, mode: 0o700 });
  const file = path.join(conf, "Caddyfile");
  const next = buildCaddyfile(state);
  if (fs.existsSync(file) && fs.readFileSync(file, "utf-8") === next) return false;
  // The directory is mounted (not the file), so an atomic rename is seen by the container.
  writeFileAtomic(file, next);
  fs.chmodSync(file, 0o644);
  return true;
}

function reload(): void {
  if (OFFLINE()) return;
  try {
    execFileSync("docker", ["exec", EDGE_CONTAINER, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--address", ADMIN_SOCKET], { stdio: "pipe" });
  } catch {
    execFileSync("docker", ["restart", EDGE_CONTAINER], { stdio: "pipe" });
  }
}

function portInUse(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once("error", (err: NodeJS.ErrnoException) => resolve(err.code === "EADDRINUSE"));
    srv.listen(port, "0.0.0.0", () => srv.close(() => resolve(false)));
  });
}

function saveEdge(update: (e: EdgeConfig) => void): PaaSState {
  const state = loadState();
  state.edge = state.edge || { sites: {} };
  update(state.edge);
  saveState(state);
  return state;
}

/** Starts the edge on this server (guard "edge.install", strong: opens 80/443 to the internet). */
export async function installEdge(opts: { email?: string } = {}): Promise<{ dir: string; sites: string[]; next: string[] }> {
  if (opts.email !== undefined && !EMAIL_RE.test(opts.email)) throw new Error(`Invalid email '${opts.email}'.`);
  const already = loadState().edge?.installedAt;
  if (!OFFLINE() && !already) {
    for (const p of [80, 443]) {
      if (await portInUse(p)) throw new Error(`Port ${p} is already in use on this server (another web server?). Stop it first, or keep using Cloudflare Tunnel.`);
    }
  }
  const state = saveEdge((e) => {
    if (opts.email) e.email = opts.email;
    e.installedAt = e.installedAt || new Date().toISOString();
  });
  fs.mkdirSync(EDGE_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(EDGE_DIR, "compose.yaml"), COMPOSE, { mode: 0o600 });
  writeConfig(state);
  if (!OFFLINE()) execFileSync("docker", ["compose", "-f", path.join(EDGE_DIR, "compose.yaml"), "up", "-d"], { cwd: EDGE_DIR, stdio: "pipe" });
  audit({ event: "edge.install" });
  return {
    dir: EDGE_DIR,
    sites: Object.keys(state.edge?.sites || {}),
    next: [
      "Open ports 80 and 443 to the internet on this server (firewall / provider panel).",
      "Add a site: paasmcp edge add <app> <hostname>, then point the hostname's DNS (record A) at this server's public IP.",
    ],
  };
}

/** Sends `hostname` to `app` through the edge (guard "app.expose" public, confirm). */
export function addEdgeSite(appName: string, hostname: string): { hostname: string; app: string; backends: EdgeBackend[]; dns: string } {
  const slug = sanitizeSlug(appName);
  const host = validateHostname(hostname);
  const s0 = loadState();
  if (!s0.apps[slug]) throw new Error(`App '${slug}' not found.`);
  const owner = s0.edge?.sites[host];
  if (owner && owner.app !== slug) throw new Error(`'${host}' already goes to app '${owner.app}'. Remove it first.`);
  const state = saveEdge((e) => {
    e.sites[host] = { app: slug, addedAt: e.sites[host]?.addedAt || new Date().toISOString() };
  });
  if (state.edge?.installedAt && writeConfig(state)) reload();
  audit({ event: "edge.add", app: slug, hostname: host });
  return {
    hostname: host,
    app: slug,
    backends: edgeBackends(state, slug),
    dns: `Create a DNS record A for ${host} pointing at this server's public IP. With two public servers, add one A record per server (each runs its own edge).`,
  };
}

export function removeEdgeSite(hostname: string): { removed: boolean } {
  const host = validateHostname(hostname);
  let removed = false;
  const state = saveEdge((e) => {
    removed = Boolean(e.sites[host]);
    delete e.sites[host];
  });
  if (removed && state.edge?.installedAt && writeConfig(state)) reload();
  return { removed };
}

/** Stops the edge; certificates stay in its data folder for a later install. */
export function uninstallEdge(): { stopped: boolean } {
  if (!OFFLINE() && fs.existsSync(path.join(EDGE_DIR, "compose.yaml"))) {
    execFileSync("docker", ["compose", "-f", path.join(EDGE_DIR, "compose.yaml"), "down"], { cwd: EDGE_DIR, stdio: "pipe" });
  }
  saveEdge((e) => {
    delete e.installedAt;
  });
  audit({ event: "edge.uninstall" });
  return { stopped: true };
}

/** Rewrites the Caddyfile after backends change (active on/off, sync); reloads only on change. */
export function refreshEdge(): boolean {
  const state = loadState();
  if (!state.edge?.installedAt) return false;
  if (!writeConfig(state)) return false;
  reload();
  return true;
}

export interface EdgeStatus {
  installed: boolean;
  running?: boolean;
  email?: string;
  sites: { hostname: string; app: string; backends: (EdgeBackend & { healthy?: boolean; detail?: string })[] }[];
}

/** Probes each backend's health path once from here (the same check Caddy makes every 5 s). */
export async function edgeStatus(probe = !OFFLINE()): Promise<EdgeStatus> {
  const state = loadState();
  const running = OFFLINE()
    ? undefined
    : (() => {
        try {
          return execFileSync("docker", ["inspect", "--format", "{{.State.Running}}", EDGE_CONTAINER], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim() === "true";
        } catch {
          return false;
        }
      })();
  const sites = await Promise.all(
    Object.entries(state.edge?.sites || {}).map(async ([hostname, site]) => {
      const app = state.apps[site.app];
      const backends = await Promise.all(
        edgeBackends(state, site.app).map(async (b) => {
          if (!probe || !app) return b;
          try {
            const res = await fetch(`http://${b.address}${app.healthcheckPath || "/"}`, { redirect: "manual", signal: AbortSignal.timeout(3000) });
            await res.body?.cancel().catch(() => undefined);
            return { ...b, healthy: res.status >= 200 && res.status < 300, detail: `HTTP ${res.status}` };
          } catch (err) {
            const cause = (err as { cause?: { code?: string } }).cause?.code;
            return { ...b, healthy: false, detail: cause || (err instanceof Error ? err.name : String(err)) };
          }
        })
      );
      return { hostname, app: site.app, backends };
    })
  );
  return { installed: Boolean(state.edge?.installedAt), running, email: state.edge?.email, sites };
}
