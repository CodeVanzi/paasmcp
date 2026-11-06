import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DOCKER_NETWORK, HOMELAB_ROOT, loadState, ownOffers, PaaSState, sanitizeSlug, saveState, writeFileAtomic, WATCHTOWER_OFF_COMPOSE, hostName } from "./config.js";
import { audit } from "./guard.js";
import { deleteSecretKey, getSecrets, setSecretEntries } from "./vault.js";

// Cloudflare Tunnel entry for apps that run on both servers.
//
// Cloudflare splits a tunnel's requests between its connectors without looking at the hostname, so
// running the main tunnel's cloudflared on the second server would send part of the requests of the
// apps that live only here to a server that does not have them. Instead, the apps that run on both
// servers get a tunnel of their own: the origin creates it, its token travels to the other server
// inside the encrypted control channel (active.ts), and both servers run a pinned cloudflared for it.
// Only the DNS of those apps' public addresses points at it; every other app stays on the main tunnel.
//
// Cloudflare does not check the health of a tunnel's origins. `mirror watch` does it here: every
// round it probes the health path of the active apps on this server, and a copy whose apps fail two
// rounds in a row stops its connector, so all requests go to the other server; it starts it again
// after two healthy rounds. The origin keeps its connector (unless it is fenced), so the two servers
// never step out at the same time.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
export const TUNNEL_DIR = path.join(HOMELAB_ROOT, "paasmcp-tunnel-active");
export const TUNNEL_CONTAINER = "paasmcp-tunnel-active";
export const CLOUDFLARED_IMAGE = "cloudflare/cloudflared:2025.8.1";
const cfApi = () => (process.env.PAASMCP_CF_API_URL || "https://api.cloudflare.com/client/v4").replace(/\/+$/, "");
const TOKEN_RE = /^[A-Za-z0-9+/=_-]{20,4096}$/;
const ID_RE = /^[a-f0-9-]{32,36}$/i;
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
/** Rounds (of ~15 s) before a copy steps out of the tunnel, and before it comes back. */
export const ROUNDS_TO_LEAVE = 2;
export const ROUNDS_TO_RETURN = 2;

export const validTunnelToken = (t: unknown): t is string => typeof t === "string" && TOKEN_RE.test(t);

async function cf<T = unknown>(method: string, route: string, body?: unknown): Promise<T> {
  const token = getSecrets("system").CF_API_TOKEN || process.env.CF_API_TOKEN;
  if (!token) throw new Error("Missing 'CF_API_TOKEN' in the 'system' vault (the same token used to publish apps).");
  const res = await fetch(`${cfApi()}${route}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  const data = (await res.json().catch(() => ({}))) as { success?: boolean; result?: T; errors?: unknown };
  if (!res.ok || data.success === false) {
    throw new Error(`Cloudflare ${method} ${route.split("?")[0]}: HTTP ${res.status} ${JSON.stringify(data.errors ?? "").slice(0, 300)}`);
  }
  return data.result as T;
}

export interface TunnelRoute {
  hostname: string;
  app: string;
  service: string;
}

/** Public addresses of the apps this server runs on both servers (pure; tested). */
export function desiredRoutes(state: PaaSState): TunnelRoute[] {
  const out: TunnelRoute[] = [];
  for (const app of Object.values(state.apps)) {
    if (!app.activeActive || app.originNodeId || app.trashedAt) continue;
    for (const d of app.domains) {
      if ((d.mode !== "public" && d.mode !== "zero-trust") || !HOSTNAME_RE.test(d.hostname)) continue;
      out.push({ hostname: d.hostname, app: app.name, service: `http://${app.containerName}:${app.internalPort}` });
    }
  }
  return out.sort((a, b) => a.hostname.localeCompare(b.hostname));
}

function cloudflareSettings(state: PaaSState) {
  const { accountId, tunnelId, baseDomain } = state.cloudflare;
  if (!accountId || !tunnelId || !baseDomain || baseDomain === "example.com") {
    throw new Error("Cloudflare Tunnel is not configured on this server (account, tunnel, domain): run 'paasmcp config' first.");
  }
  if (!ID_RE.test(tunnelId)) throw new Error("The configured tunnel id does not look like a Cloudflare tunnel id.");
  return { accountId: encodeURIComponent(accountId), mainTunnel: tunnelId, baseDomain };
}

async function zoneIdFor(baseDomain: string): Promise<string> {
  const zones = await cf<{ id: string }[]>("GET", `/zones?name=${encodeURIComponent(baseDomain)}`);
  if (!zones?.[0]?.id) throw new Error(`Could not find the Cloudflare zone for '${baseDomain}'.`);
  return zones[0].id;
}

/** Points a hostname's CNAME at a tunnel (proxied); leaves it alone when it already does. */
async function pointDns(zoneId: string, hostname: string, tunnelId: string): Promise<boolean> {
  const content = `${tunnelId}.cfargotunnel.com`;
  const z = encodeURIComponent(zoneId);
  const found = await cf<{ id: string; type: string; content: string }[]>("GET", `/zones/${z}/dns_records?name=${encodeURIComponent(hostname)}`);
  const rec = (found || []).find((r) => r.type === "CNAME") || (found || [])[0];
  const body = { type: "CNAME", name: hostname, content, proxied: true };
  if (rec?.type === "CNAME" && rec.content === content) return false;
  if (rec) await cf("PUT", `/zones/${z}/dns_records/${encodeURIComponent(rec.id)}`, body);
  else await cf("POST", `/zones/${z}/dns_records`, body);
  return true;
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/** True when the app answers on every peer's Tailscale IP (its copy there is deployed and healthy). */
async function peersServe(state: PaaSState, app: PaaSState["apps"][string], probe: (url: string) => Promise<boolean>): Promise<boolean> {
  const ips = ownOffers(state).map(([, o]) => o.peerCidr.replace(/\/32$/, "")).filter((ip) => IPV4.test(ip));
  if (!ips.length) return false;
  const healthPath = app.healthcheckDisabled ? "/" : app.healthcheckPath || "/";
  const answers = await Promise.all(ips.map((ip) => probe(`http://${ip}:${app.localPort}${healthPath}`)));
  return answers.every(Boolean);
}

async function probeUrl(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(3000), redirect: "manual" });
    return res.status >= 200 && res.status < 400;
  } catch {
    return false;
  }
}

/**
 * Origin side (after `active on/off`, and every round of `mirror watch` / `poll run`): the tunnel
 * serves the active apps' public addresses. An address joins only once the app answers on the other
 * server too (its copy may still be building), and then stays (the health watch there handles a sick
 * copy). Addresses of apps that left go back to the main tunnel, whose ingress still has them. The
 * ingress is written before any DNS moves. Nothing is sent to Cloudflare when nothing changed.
 */
export async function routeActiveTunnel(
  opts: { probe?: (url: string) => Promise<boolean>; lock?: (fn: () => void) => Promise<void> | void } = {}
): Promise<{ routed: string[]; waiting: string[]; movedBack: string[]; dnsChanged: number }> {
  const state = loadState();
  const at = state.activeTunnel;
  if (!at) return { routed: [], waiting: [], movedBack: [], dnsChanged: 0 };
  const probe = opts.probe || probeUrl;
  const routed: TunnelRoute[] = [];
  const waiting: string[] = [];
  const ready = new Map<string, boolean>();
  for (const r of desiredRoutes(state)) {
    if (!at.routes[r.hostname]) {
      if (!ready.has(r.app)) ready.set(r.app, await peersServe(state, state.apps[r.app], probe));
      if (!ready.get(r.app)) {
        waiting.push(r.hostname);
        continue;
      }
    }
    routed.push(r);
  }
  const ingress = [...routed.map((r) => ({ hostname: r.hostname, service: r.service, originRequest: {} })), { service: "http_status:404" }];
  const ingressHash = crypto.createHash("sha256").update(JSON.stringify(ingress)).digest("hex");
  const wanted = new Set(routed.map((r) => r.hostname));
  const leaving = Object.keys(at.routes).filter((h) => !wanted.has(h));
  const joining = routed.filter((r) => !at.routes[r.hostname]);
  if (ingressHash === at.ingressHash && !leaving.length && !joining.length) return { routed: [...wanted], waiting, movedBack: [], dnsChanged: 0 };

  const { accountId, mainTunnel, baseDomain } = cloudflareSettings(state);
  await cf("PUT", `/accounts/${accountId}/cfd_tunnel/${at.tunnelId}/configurations`, { config: { ingress } });
  let dnsChanged = 0;
  if (joining.length || leaving.length) {
    const zoneId = await zoneIdFor(baseDomain);
    for (const r of joining) if (await pointDns(zoneId, r.hostname, at.tunnelId)) dnsChanged++;
    for (const h of leaving) if (await pointDns(zoneId, h, mainTunnel)) dnsChanged++;
  }
  const save = () => {
    const latest = loadState();
    if (!latest.activeTunnel) return;
    latest.activeTunnel.routes = Object.fromEntries(routed.map((r) => [r.hostname, { app: r.app, at: at.routes[r.hostname]?.at || new Date().toISOString() }]));
    latest.activeTunnel.ingressHash = ingressHash;
    saveState(latest);
  };
  // The other server learns which hostnames the tunnel serves (after a failover it leaves their DNS alone).
  const { publishActiveState } = await import("./active.js");
  const saveAndPublish = () => {
    save();
    publishActiveState();
  };
  await (opts.lock ? opts.lock(saveAndPublish) : saveAndPublish());
  if (joining.length || leaving.length) audit({ event: "active.tunnel.route", joined: joining.map((r) => r.hostname), movedBack: leaving });
  return { routed: [...wanted], waiting, movedBack: leaving, dnsChanged };
}

// ---- The connector (cloudflared) on this server ----

const composeFor = () => `services:
  tunnel:
    image: ${CLOUDFLARED_IMAGE}
    container_name: ${TUNNEL_CONTAINER}
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

function containerRunning(): boolean | undefined {
  if (OFFLINE()) return undefined;
  try {
    return execFileSync("docker", ["inspect", "-f", "{{.State.Running}}", TUNNEL_CONTAINER], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim() === "true";
  } catch {
    return undefined; // no such container
  }
}

/**
 * Writes the connector's files and starts it when they changed or the container does not exist.
 * An existing container that the health watch stopped stays stopped.
 */
export function ensureConnector(token: string): { changed: boolean } {
  if (!validTunnelToken(token)) throw new Error("Unexpected tunnel token format.");
  fs.mkdirSync(TUNNEL_DIR, { recursive: true, mode: 0o700 });
  const envFile = path.join(TUNNEL_DIR, ".env");
  const composeFile = path.join(TUNNEL_DIR, "compose.yaml");
  const env = `TUNNEL_TOKEN=${token}\n`;
  const compose = composeFor();
  const changed =
    !fs.existsSync(envFile) || fs.readFileSync(envFile, "utf-8") !== env || !fs.existsSync(composeFile) || fs.readFileSync(composeFile, "utf-8") !== compose;
  if (changed) {
    writeFileAtomic(envFile, env);
    fs.chmodSync(envFile, 0o600);
    writeFileAtomic(composeFile, compose);
  }
  if (!OFFLINE() && (changed || containerRunning() === undefined)) {
    execFileSync("docker", ["compose", "-f", composeFile, "up", "-d"], { cwd: TUNNEL_DIR, stdio: "pipe" });
  }
  return { changed };
}

export function removeConnector(): void {
  const composeFile = path.join(TUNNEL_DIR, "compose.yaml");
  if (!OFFLINE()) {
    if (fs.existsSync(composeFile)) {
      try {
        execFileSync("docker", ["compose", "-f", composeFile, "down"], { cwd: TUNNEL_DIR, stdio: "pipe" });
      } catch {
        // falls through to the removal by name
      }
    }
    // Also when the container was recreated outside this compose project: the token must not keep serving.
    if (containerRunning() !== undefined) execFileSync("docker", ["rm", "-f", TUNNEL_CONTAINER], { stdio: "pipe" });
  }
  fs.rmSync(TUNNEL_DIR, { recursive: true, force: true });
}

const tokenHash = (t: string) => crypto.createHash("sha256").update(t).digest("hex").slice(0, 16);

/**
 * Peer side, from the control channel (syncActivePeers): runs the origin's connector here, or
 * removes it when the origin turned the tunnel off.
 */
export function applyPeerTunnel(fromNodeId: string, token: string | undefined, hostnames: string[] = []): "started" | "updated" | "removed" | "unchanged" {
  const state = loadState();
  const mine = state.activeTunnelCopy;
  if (!token) {
    if (!mine || mine.fromNodeId !== fromNodeId) return "unchanged";
    removeConnector();
    const s = loadState();
    delete s.activeTunnelCopy;
    saveState(s);
    audit({ event: "active.tunnel.copy.removed", from: fromNodeId });
    return "removed";
  }
  if (state.activeTunnel) throw new Error("this server runs its own tunnel for apps on both servers; turn it off here first");
  if (mine && mine.fromNodeId !== fromNodeId) throw new Error(`this server already runs the tunnel of another server (${mine.fromNodeId})`);
  const { changed } = ensureConnector(token);
  const sameHosts = JSON.stringify(mine?.hostnames || []) === JSON.stringify(hostnames);
  if (!changed && mine && sameHosts) return "unchanged";
  const s = loadState();
  s.activeTunnelCopy = { fromNodeId, tokenHash: tokenHash(token), at: changed || !mine ? new Date().toISOString() : mine.at, hostnames };
  saveState(s);
  if (!changed && mine) return "unchanged"; // only the list of hostnames moved
  audit({ event: "active.tunnel.copy", from: fromNodeId });
  return mine ? "updated" : "started";
}

// ---- Turning it on and off (origin) ----

async function waitConnected(accountId: string, tunnelId: string, waitMs: number): Promise<boolean> {
  const until = Date.now() + waitMs;
  for (;;) {
    const t = await cf<{ status?: string; connections?: unknown[] }>("GET", `/accounts/${accountId}/cfd_tunnel/${tunnelId}`);
    if ((t?.connections || []).length > 0 || t?.status === "healthy" || t?.status === "degraded") return true;
    if (Date.now() >= until) return false;
    await new Promise((r) => setTimeout(r, Math.min(2000, Math.max(50, waitMs / 10))));
  }
}

/**
 * Creates (or reuses) the tunnel for apps on both servers, runs its connector here, routes the
 * active apps to it and tells the other server (guard "active.tunnel", confirm).
 */
export async function enableActiveTunnel(opts: { waitMs?: number; probe?: (url: string) => Promise<boolean> } = {}): Promise<Record<string, unknown>> {
  const state = loadState();
  const { accountId } = cloudflareSettings(state);
  if (state.activeTunnelCopy) throw new Error("This server runs the other server's tunnel copy: turn the tunnel on on the server where the apps come from.");
  let at = state.activeTunnel;
  if (!at) {
    const name = `paasmcp-active-${sanitizeSlug(state.federation?.nodeName && state.federation.nodeName !== "primary-node" ? state.federation.nodeName : hostName())}`.slice(0, 60);
    const existing = await cf<{ id: string; name: string }[]>("GET", `/accounts/${accountId}/cfd_tunnel?name=${encodeURIComponent(name)}&is_deleted=false`);
    const tunnel = existing?.[0] || (await cf<{ id: string; name: string }>("POST", `/accounts/${accountId}/cfd_tunnel`, { name, config_src: "cloudflare" }));
    if (!tunnel?.id || !ID_RE.test(tunnel.id)) throw new Error("Cloudflare did not return a tunnel id.");
    at = { tunnelId: tunnel.id, name, createdAt: new Date().toISOString(), routes: {} };
  }
  const token = await cf<string>("GET", `/accounts/${accountId}/cfd_tunnel/${at.tunnelId}/token`);
  if (!validTunnelToken(token)) throw new Error("Cloudflare returned an unexpected tunnel token.");
  setSecretEntries("system", { ACTIVE_TUNNEL_TOKEN: token });
  const s = loadState();
  s.activeTunnel = at;
  saveState(s);
  ensureConnector(token);
  // DNS moves only once this server's connector is connected: no window where the address has no origin.
  if (!(await waitConnected(accountId, at.tunnelId, opts.waitMs ?? 60_000))) {
    throw new Error(`The tunnel '${at.name}' was created but its connector here did not connect within a minute (see 'docker logs ${TUNNEL_CONTAINER}'). No DNS was changed; run the command again.`);
  }
  const { publishActiveState } = await import("./active.js");
  // The other server gets the token first; addresses move once its copy of each app answers.
  const published = publishActiveState();
  const routed = await routeActiveTunnel({ probe: opts.probe });
  audit({ event: "active.tunnel.on", tunnel: at.tunnelId });
  return { tunnelId: at.tunnelId, name: at.name, ...routed, published: published.published };
}

/** Moves the active apps' DNS back to the main tunnel and stops the connectors (here and, through the control channel, on the other server). */
export async function disableActiveTunnel(): Promise<Record<string, unknown>> {
  const state = loadState();
  const at = state.activeTunnel;
  if (!at) return { off: true, detail: "the tunnel for apps on both servers is not on" };
  const { accountId, mainTunnel, baseDomain } = cloudflareSettings(state);
  const hosts = Object.keys(at.routes);
  if (hosts.length) {
    const zoneId = await zoneIdFor(baseDomain);
    for (const h of hosts) await pointDns(zoneId, h, mainTunnel);
  }
  await cf("PUT", `/accounts/${accountId}/cfd_tunnel/${at.tunnelId}/configurations`, { config: { ingress: [{ service: "http_status:404" }] } });
  const s = loadState();
  delete s.activeTunnel;
  saveState(s);
  deleteSecretKey("system", "ACTIVE_TUNNEL_TOKEN");
  removeConnector();
  const { publishActiveState } = await import("./active.js");
  const published = publishActiveState();
  audit({ event: "active.tunnel.off", tunnel: at.tunnelId });
  return { off: true, movedBack: hosts, published: published.published, note: `The tunnel '${at.name}' stays in your Cloudflare account (unused); turning this on again reuses it.` };
}

// ---- Health watch (mirror watch, every round) ----

export interface TunnelWatchMemory {
  bad: number;
  good: number;
}

export type TunnelAction = "leave" | "return" | "none";

/** Pure decision (tested): a copy (or a fenced origin) leaves after ROUNDS_TO_LEAVE bad rounds; anyone returns after ROUNDS_TO_RETURN good ones. */
export function tunnelDecision(o: { running: boolean; mayLeave: boolean; mem: TunnelWatchMemory; fenced?: boolean }): TunnelAction {
  if (o.running && o.fenced) return "leave"; // another server serves this one's data: no waiting
  if (o.running && o.mayLeave && o.mem.bad >= ROUNDS_TO_LEAVE) return "leave";
  if (o.fenced) return "none";
  if (!o.running && o.mem.good >= ROUNDS_TO_RETURN) return "return";
  return "none";
}

const watchMemory: TunnelWatchMemory = { bad: 0, good: 0 };

const probeApp = (port: number, healthPath: string) => probeUrl(`http://127.0.0.1:${port}${healthPath}`);

export interface TunnelWatchResult {
  at: string;
  apps: { app: string; healthy: boolean }[];
  running?: boolean;
  action: TunnelAction;
  mayLeave: boolean;
}

/**
 * One round of the health watch. Runs outside the state lock (it only reads the state); it starts
 * or stops this server's connector and keeps the last result in TUNNEL_DIR/watch.json.
 */
export async function tunnelWatchTick(
  opts: {
    probe?: (port: number, healthPath: string) => Promise<boolean>;
    docker?: { running: () => boolean | undefined; stop: () => void; start: () => void };
    mem?: TunnelWatchMemory;
  } = {}
): Promise<TunnelWatchResult | undefined> {
  if (!fs.existsSync(path.join(TUNNEL_DIR, "compose.yaml"))) return undefined;
  const state = loadState();
  const apps = Object.values(state.apps).filter((a) => a.activeActive && !a.trashedAt);
  if (!apps.length) return undefined;
  const probe = opts.probe || probeApp;
  const docker = opts.docker || {
    running: containerRunning,
    stop: () => void execFileSync("docker", ["stop", TUNNEL_CONTAINER], { stdio: "pipe" }),
    start: () => void execFileSync("docker", ["start", TUNNEL_CONTAINER], { stdio: "pipe" }),
  };
  const mem = opts.mem || watchMemory;
  const results = await Promise.all(
    apps.map(async (a) => ({ app: a.name, healthy: a.healthcheckDisabled ? true : await probe(a.localPort, a.healthcheckPath || "/") }))
  );
  if (results.every((r) => r.healthy)) {
    mem.good++;
    mem.bad = 0;
  } else {
    mem.bad++;
    mem.good = 0;
  }
  const running = docker.running();
  // The origin keeps serving unless it is fenced: the two servers never step out together. A copy
  // whose origin's data moved to another server (several copies) steps out at once, like a fenced one.
  const from = state.activeTunnelCopy?.fromNodeId;
  // A copy that follows the server that took the origin over runs none of the origin's apps either.
  const copyBehind = Boolean(from) && Object.values(state.mirror?.replicas || {}).some((r) => r.peerNodeId === from && !r.handedBackAt && (r.supersededBy || (r.servedByNodeId && !r.promotedAt)));
  const stepOut = Boolean(state.mirror?.fenced) || copyBehind;
  const mayLeave = !state.activeTunnel || stepOut;
  const action = running === undefined ? "none" : tunnelDecision({ running, mayLeave, mem, fenced: stepOut });
  if (action === "leave") docker.stop();
  if (action === "return") docker.start();
  if (action !== "none") audit({ event: action === "leave" ? "active.tunnel.leave" : "active.tunnel.return", unhealthy: results.filter((r) => !r.healthy).map((r) => r.app) });
  const out: TunnelWatchResult = { at: new Date().toISOString(), apps: results, running: action === "leave" ? false : action === "return" ? true : running, action, mayLeave };
  try {
    writeFileAtomic(path.join(TUNNEL_DIR, "watch.json"), JSON.stringify(out));
  } catch {
    // status only
  }
  return out;
}

export function activeTunnelStatus(state = loadState()): Record<string, unknown> {
  let watch: TunnelWatchResult | undefined;
  try {
    watch = JSON.parse(fs.readFileSync(path.join(TUNNEL_DIR, "watch.json"), "utf-8"));
  } catch {
    watch = undefined;
  }
  const configured = Boolean(state.cloudflare.accountId && state.cloudflare.tunnelId);
  const hasConnector = fs.existsSync(path.join(TUNNEL_DIR, "compose.yaml"));
  const running = hasConnector ? containerRunning() : undefined;
  return {
    configured,
    on: Boolean(state.activeTunnel),
    copyOf: state.activeTunnelCopy?.fromNodeId,
    tunnelId: state.activeTunnel?.tunnelId,
    name: state.activeTunnel?.name,
    hostnames: Object.keys(state.activeTunnel?.routes || {}),
    connector: !hasConnector ? "none" : running === true ? "running" : running === false ? "stopped" : OFFLINE() ? "unknown" : "absent",
    watch,
  };
}
