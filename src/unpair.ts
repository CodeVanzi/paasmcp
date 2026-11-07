import crypto from "node:crypto";
import { AppRecord, loadState, PaaSState, saveState } from "./config.js";
import { audit } from "./guard.js";
import { deleteSecretKey, getSecrets, setSecretEntries } from "./vault.js";

// Disconnecting ("unpairing") another computer from this server, from one place in the dashboard
// (Connections → PCs). What ties a server to another one is spread over several records: the
// pairing (`node invite/join`), the mirror's copy each way, automatic takeover, apps on both servers
// and the judge. `pairedServers` groups them per server and says, for each, what a disconnect would
// do (effects) and what has to be done first (blockers); `unpairServer` does it.
//
// Nothing is deleted that may be the only copy of some data: copies are set aside on disk, and a
// disconnect is refused while this server serves the other one's data (or the other serves this
// one's). The other server still knows this pair's key until it disconnects too; when no paired
// server is left, the key changes, so it cannot talk to this server any more.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";
/** The name `node invite` gives every server by default: it never identifies one. */
const GENERIC = "primary-node";

export class UnpairError extends Error {
  constructor(message: string, public pt: string) {
    super(message);
  }
}

export type UnpairBlocker =
  | { code: "fenced" }
  | { code: "dataHere" }
  | { code: "failback" }
  | { code: "activeOrigin"; apps: string[] }
  | { code: "activeTunnel" };

export type UnpairEffect =
  | { code: "stopSending" }
  | { code: "revokeBackups" }
  | { code: "dropCopy" }
  | { code: "autoOff" }
  | { code: "stopCopies"; apps: string[] }
  | { code: "tunnelCopy" }
  | { code: "backupsTarget" }
  | { code: "forget" }
  | { code: "rotateKey" }
  | { code: "judgeDropped" }
  | { code: "keyKept"; others: string[] }
  | { code: "importedKept"; apps: string[] }
  | { code: "otherSide" };

export interface PairedServer {
  /** Stable id for the API: "id:<node id>" or "name:<name>". */
  key: string;
  name: string;
  nodeIds: string[];
  /** Keys into state.federation.peers, state.mirror.offers and state.mirror.replicas. */
  federation: string[];
  offers: string[];
  replicas: string[];
  /** Short state for the list: what links the two servers now. */
  links: ("paired" | "sending" | "receiving" | "auto" | "servingHere" | "behind")[];
  blockers: UnpairBlocker[];
  effects: UnpairEffect[];
}

interface Group {
  names: string[];
  nodeIds: Set<string>;
  hosts: Set<string>;
  federation: string[];
  offers: string[];
  replicas: string[];
}

function groupsOf(state: PaaSState): Group[] {
  const groups: Group[] = [];
  const byId = (id: string | undefined) => (id ? groups.find((g) => g.nodeIds.has(id)) : undefined);
  const byName = (name: string) => (name && name !== GENERIC ? groups.find((g) => g.names.includes(name)) : undefined);
  const byHost = (host: string | undefined) => (host ? groups.find((g) => g.hosts.has(host)) : undefined);
  const endpointHost = (endpoint: string | undefined): string | undefined => {
    if (!endpoint) return undefined;
    try {
      return new URL(endpoint).hostname;
    } catch {
      return undefined;
    }
  };
  const cidrHost = (cidr: string | undefined): string | undefined => {
    const host = cidr?.split("/", 1)[0];
    return host?.replace(/^\[|\]$/g, "");
  };
  const make = () => {
    const g: Group = { names: [], nodeIds: new Set(), hosts: new Set(), federation: [], offers: [], replicas: [] };
    groups.push(g);
    return g;
  };
  const named = (g: Group, name: string | undefined, first = false) => {
    if (!name || g.names.includes(name)) return;
    first ? g.names.unshift(name) : g.names.push(name);
  };
  // The copies carry the server's own name (its hostname); the pairing often only the generic one.
  for (const [k, r] of Object.entries(state.mirror?.replicas || {})) {
    const g = byId(r.peerNodeId) || byName(r.peerName) || make();
    if (r.peerNodeId) g.nodeIds.add(r.peerNodeId);
    if (r.peerHost) g.hosts.add(r.peerHost);
    named(g, r.peerName, true);
    g.replicas.push(k);
  }
  for (const [k, p] of Object.entries(state.federation?.peers || {})) {
    const host = endpointHost(p.endpointUrl);
    const g = byId(p.nodeId) || byName(p.name) || make();
    if (p.nodeId) g.nodeIds.add(p.nodeId);
    if (host) g.hosts.add(host);
    named(g, p.name);
    g.federation.push(k);
  }
  // Offers are keyed by the name a person typed for the peer (no node id).
  for (const [k, o] of Object.entries(state.mirror?.offers || {})) {
    const name = o.peer || k;
    const g = byName(name) || byHost(cidrHost(o.peerCidr)) || make();
    const host = cidrHost(o.peerCidr);
    if (host) g.hosts.add(host);
    named(g, name, !g.names.length || g.names[0] === GENERIC);
    g.offers.push(k);
  }
  return groups;
}

const displayName = (g: Group) => g.names.find((n) => n !== GENERIC) || g.names[0] || "?";
const keyOf = (g: Group) => (g.nodeIds.size ? `id:${[...g.nodeIds].sort()[0]}` : `name:${displayName(g)}`);

function ownActiveApps(state: PaaSState): string[] {
  return Object.values(state.apps).filter((a) => a.activeActive && !a.originNodeId && !a.trashedAt).map((a) => a.name);
}

/** Host of this server's off-site backup destination when it is another PaaSMCP's Garage. */
function backupsGoTo(): string | undefined {
  const sys = getSecrets("system");
  if (sys.BACKUP_S3_PROVIDER !== "paasmcp" || !sys.BACKUP_S3_ENDPOINT) return undefined;
  try {
    return new URL(sys.BACKUP_S3_ENDPOINT).hostname;
  } catch {
    return undefined;
  }
}

function describe(state: PaaSState, g: Group, all: Group[]): PairedServer {
  const m = state.mirror;
  const replicas = g.replicas.map((k) => m!.replicas[k]);
  const ids = g.nodeIds;
  const links: PairedServer["links"] = [];
  if (g.federation.length) links.push("paired");
  if (g.offers.length) links.push("sending");
  if (replicas.some((r) => !r.promotedAt && !r.supersededBy)) links.push("receiving");
  if (replicas.some((r) => r.promotedAt && !r.handedBackAt && !r.supersededBy)) links.push("servingHere");
  if (replicas.some((r) => r.supersededBy)) links.push("behind");
  if (g.replicas.some((k) => (m?.auto || []).includes(k))) links.push("auto");

  const blockers: UnpairBlocker[] = [];
  if (m?.fenced && ids.has(m.fenced.byNodeId)) blockers.push({ code: "fenced" });
  if (replicas.some((r) => r.promotedAt && !r.handedBackAt && !r.supersededBy)) blockers.push({ code: "dataHere" });
  if (replicas.some((r) => r.failback || r.container === "paasmcp-postgres")) blockers.push({ code: "failback" });
  if (g.offers.length) {
    const apps = ownActiveApps(state);
    if (apps.length) blockers.push({ code: "activeOrigin", apps });
    if (state.activeTunnel) blockers.push({ code: "activeTunnel" });
  }

  const effects: UnpairEffect[] = [];
  if (g.offers.length) effects.push({ code: "stopSending" });
  if (g.offers.some((k) => !m!.offers[k].dataOf)) effects.push({ code: "revokeBackups" });
  if (g.replicas.length) effects.push({ code: "dropCopy" });
  if (links.includes("auto")) effects.push({ code: "autoOff" });
  const imported = Object.values(state.apps).filter((a) => a.originNodeId && ids.has(a.originNodeId) && !a.trashedAt);
  const copies = imported.filter((a) => a.activeActive).map((a) => a.name);
  if (copies.length) effects.push({ code: "stopCopies", apps: copies });
  if (state.activeTunnelCopy && ids.has(state.activeTunnelCopy.fromNodeId)) effects.push({ code: "tunnelCopy" });
  const target = backupsGoTo();
  if (target && replicas.some((r) => r.peerHost === target)) effects.push({ code: "backupsTarget" });
  if (g.federation.length) effects.push({ code: "forget" });
  const others = all.filter((o) => o !== g).map(displayName);
  if (others.length) effects.push({ code: "keyKept", others });
  else {
    effects.push({ code: "rotateKey" });
    if (m?.arbiterUrl) effects.push({ code: "judgeDropped" });
  }
  if (imported.length) effects.push({ code: "importedKept", apps: imported.map((a) => a.name) });
  effects.push({ code: "otherSide" });

  return { key: keyOf(g), name: displayName(g), nodeIds: [...ids], federation: g.federation, offers: g.offers, replicas: g.replicas, links, blockers, effects };
}

/** Every server this one is paired with, one entry per server, with what a disconnect would do. */
export function pairedServers(state = loadState()): PairedServer[] {
  const groups = groupsOf(state);
  return groups.map((g) => describe(state, g, groups));
}

const BLOCKER_TEXT: Record<UnpairBlocker["code"], [string, string]> = {
  fenced: [
    "That server serves this server's data since a takeover: disconnecting now would leave your apps stopped here. Get the data back first (Second server → Give apps back).",
    "Aquele servidor está servindo os dados deste desde uma troca: desconectar agora deixaria seus apps parados aqui. Traga os dados de volta antes (Segundo servidor → Devolver apps).",
  ],
  dataHere: [
    "This server serves that server's data since it took over: hand it back first (Second server → Live copy → Hand the apps back), or keep it.",
    "Este servidor está servindo os dados daquele desde que assumiu: devolva antes (Segundo servidor → Cópia ao vivo → Devolver os apps), ou continue com ele.",
  ],
  failback: [
    "This server's own database is following that server to get its data back: let the hand-back finish first.",
    "O banco deste servidor está seguindo aquele para receber os dados de volta: deixe a devolução terminar antes.",
  ],
  activeOrigin: [
    "Some apps of this server also run there: switch them to “Run here only” first (Second server → App on both).",
    "Alguns apps deste servidor também rodam lá: passe-os para “Rodar só aqui” antes (Segundo servidor → App nos dois).",
  ],
  activeTunnel: [
    "The tunnel for apps on both servers is on: turn it off first (Second server → App on both).",
    "O túnel dos apps nos dois servidores está ligado: desligue antes (Segundo servidor → App nos dois).",
  ],
};

function patchApps(names: string[], patch: (a: AppRecord) => void): void {
  const s = loadState();
  for (const n of names) if (s.apps[n]) patch(s.apps[n]);
  saveState(s);
}

export interface UnpairResult {
  name: string;
  done: UnpairEffect["code"][];
  errors: string[];
  movedAside: string[];
  /** The server still shows up as paired (something could not be undone): try again. */
  stillPaired: boolean;
}

/**
 * Disconnects this server from one paired server (`key` from `pairedServers`). The caller checks the
 * guard ("pc.unpair", strong) and holds the state lock. Steps that fail are reported, not hidden.
 */
export async function unpairServer(key: string, opts: { by?: string } = {}): Promise<UnpairResult> {
  const before = pairedServers();
  const target = before.find((p) => p.key === key);
  if (!target) throw new UnpairError(`This server is not paired with '${key}'.`, `Este servidor não está pareado com '${key}'.`);
  if (target.blockers.length) {
    const [en, pt] = BLOCKER_TEXT[target.blockers[0].code];
    throw new UnpairError(en, pt);
  }
  const done: UnpairEffect["code"][] = [];
  const errors: string[] = [];
  const movedAside: string[] = [];
  const ids = new Set(target.nodeIds);
  const err = (what: string, e: unknown) => errors.push(`${what}: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);

  // 1. Copies of its apps that run here (apps on both servers) stop, as when the origin turns that off.
  const copies = Object.values(loadState().apps).filter((a) => a.originNodeId && ids.has(a.originNodeId) && a.activeActive && !a.trashedAt).map((a) => a.name);
  if (copies.length) {
    const { manageAppLifecycle } = await import("./deployer.js");
    for (const app of copies) {
      try {
        if (!OFFLINE()) manageAppLifecycle(app, "stop");
      } catch (e) {
        err(app, e);
      }
    }
    patchApps(copies, (a) => {
      a.activeActive = undefined;
      a.activeSync = undefined;
      a.status = "stopped";
    });
    done.push("stopCopies");
  }
  const tunnelFrom = loadState().activeTunnelCopy?.fromNodeId;
  if (tunnelFrom && ids.has(tunnelFrom)) {
    try {
      const { applyPeerTunnel } = await import("./activetunnel.js");
      applyPeerTunnel(tunnelFrom, undefined);
      done.push("tunnelCopy");
    } catch (e) {
      err("tunnel", e);
    }
  }

  // 2. The mirror, both ways.
  const { dropCopy, dropOffers } = await import("./mirror.js");
  if (target.offers.length) {
    const r = await dropOffers(target.offers);
    errors.push(...r.errors);
    if (r.dropped.length) done.push("stopSending");
  }
  const peerHosts = target.replicas.map((k) => loadState().mirror?.replicas[k]?.peerHost).filter(Boolean);
  for (const k of target.replicas) {
    try {
      const r = dropCopy(k);
      if (r.movedAside) movedAside.push(r.movedAside);
      if (!done.includes("dropCopy")) done.push("dropCopy");
    } catch (e) {
      err(k, e);
    }
  }
  const backupsHost = backupsGoTo();
  if (backupsHost && peerHosts.includes(backupsHost)) {
    for (const k of ["BACKUP_S3_PROVIDER", "BACKUP_S3_ENDPOINT", "BACKUP_S3_BUCKET", "BACKUP_S3_ACCESS_KEY_ID", "BACKUP_S3_SECRET_ACCESS_KEY", "BACKUP_S3_REGION"]) deleteSecretKey("system", k);
    done.push("backupsTarget");
  }

  // 3. The pairing itself.
  if (target.federation.length) {
    const s = loadState();
    for (const k of target.federation) delete s.federation?.peers[k];
    if (s.federation && !Object.keys(s.federation.peers).length) s.federation.role = "standalone";
    saveState(s);
    done.push("forget");
  }

  // 4. Nobody left: a new key, so the server that was disconnected cannot talk to this one any more.
  const after = pairedServers();
  const stillPaired = after.some((p) => p.key === key);
  if (!after.length) {
    setSecretEntries("system", { FEDERATION_CLUSTER_KEY: crypto.randomBytes(32).toString("hex") });
    done.push("rotateKey");
    const s = loadState();
    if (s.mirror?.arbiterUrl) {
      delete s.mirror.arbiterUrl;
      s.mirror.auto = [];
      saveState(s);
      done.push("judgeDropped");
    }
  }
  audit({ event: "pc.unpair", by: opts.by, server: target.name, nodeIds: target.nodeIds, done, errors: errors.length, stillPaired });
  return { name: target.name, done, errors, movedAside, stillPaired };
}

/** The judge this server uses, and the servers that probably use it too (this pair). */
export function judgeInUse(state = loadState()): { url: string; auto: string[]; partners: string[] } | undefined {
  const url = state.mirror?.arbiterUrl;
  if (!url) return undefined;
  return { url, auto: state.mirror?.auto || [], partners: pairedServers(state).map((p) => p.name) };
}

/**
 * This server stops using its judge: automatic takeover turns off here. The caller checks the guard
 * ("judge.unpair"). The judge itself keeps the pair's key; the other server must do the same.
 */
export function unpairJudge(opts: { by?: string } = {}): { url: string; autoWas: string[] } {
  const s = loadState();
  const url = s.mirror?.arbiterUrl;
  if (!s.mirror || !url) throw new UnpairError("This server uses no judge.", "Este servidor não usa juiz.");
  const autoWas = s.mirror.auto || [];
  delete s.mirror.arbiterUrl;
  s.mirror.auto = [];
  saveState(s);
  audit({ event: "judge.unpair", by: opts.by, url, autoWas });
  return { url, autoWas };
}
