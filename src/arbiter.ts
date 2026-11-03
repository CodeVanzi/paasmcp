import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { PAAS_DATA_DIR, writeFileAtomic } from "./config.js";
import { getSecrets, timingSafeCompare } from "./vault.js";

// The arbiter is the third vote for automatic failover: a server may take over its peer's data only
// when the arbiter, too, has stopped hearing from that peer. It runs anywhere small (Raspberry, VPS)
// with `paasmcp arbiter serve`, and knows only a key derived from the cluster key (it cannot read
// mirror tokens or vault bundles).

export const DEAD_AFTER_MS = 60_000;
const MAX_CLOCK_SKEW_MS = 60_000;

export interface ArbiterState {
  nodes: Record<string, { lastSeen: number; epoch: number }>;
  /** Who serves the data that originally belongs to each node, and since which epoch. */
  owners: Record<string, { owner: string; epoch: number }>;
}

export function deriveArbiterKey(clusterKeyHex = getSecrets("system").FEDERATION_CLUSTER_KEY): string {
  if (!clusterKeyHex) throw new Error("No cluster key: pair the servers first.");
  return crypto.createHmac("sha256", Buffer.from(clusterKeyHex, "hex")).update("paasmcp-arbiter-v1").digest("hex");
}

const sign = (key: string, body: string) => crypto.createHmac("sha256", key).update(body).digest("hex");

type Op = "heartbeat" | "claim" | "handover";

export function arbiterDecide(state: ArbiterState, req: { op: Op; node: string; epoch: number; dataOf?: string; to?: string }, now: number) {
  const seen = state.nodes[req.node];
  state.nodes[req.node] = { lastSeen: now, epoch: Math.max(req.epoch, seen?.epoch || 0) };
  if (req.op === "claim" && req.dataOf) {
    const target = state.nodes[req.dataOf];
    const current = state.owners[req.dataOf] || { owner: req.dataOf, epoch: 0 };
    const targetDead = !target || now - target.lastSeen > DEAD_AFTER_MS;
    // The owner must look dead to the arbiter too (not just to the claimer), and epochs only go up.
    const ownerDead = current.owner === req.dataOf ? targetDead : !state.nodes[current.owner] || now - state.nodes[current.owner].lastSeen > DEAD_AFTER_MS;
    const granted = current.owner !== req.node && ownerDead && req.epoch > current.epoch;
    if (granted) state.owners[req.dataOf] = { owner: req.node, epoch: req.epoch };
    return { granted, owner: state.owners[req.dataOf] || current, state };
  }
  if (req.op === "handover" && req.dataOf && req.to) {
    const current = state.owners[req.dataOf];
    const granted = !!current && current.owner === req.node && req.epoch > current.epoch;
    if (granted) state.owners[req.dataOf] = { owner: req.to, epoch: req.epoch };
    return { granted, owner: state.owners[req.dataOf], state };
  }
  return { granted: true, state };
}

export function startArbiterServer(opts: { port: number; host: string; key: string; stateFile?: string }): http.Server {
  const file = opts.stateFile || path.join(PAAS_DATA_DIR, "arbiter.json");
  const load = (): ArbiterState => (fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf-8")) : { nodes: {}, owners: {} });
  const server = http.createServer((req, res) => {
    if (req.method !== "POST" || req.url !== "/arbiter") return res.writeHead(404).end();
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 10_000) req.destroy();
    });
    req.on("end", () => {
      const reply = (code: number, o: unknown) => res.writeHead(code, { "Content-Type": "application/json" }).end(JSON.stringify(o));
      if (!timingSafeCompare(sign(opts.key, body), String(req.headers["x-paasmcp-signature"] || ""))) return reply(401, { error: "bad signature" });
      let msg: { op: Op; node: string; epoch: number; ts: number; dataOf?: string; to?: string };
      try {
        msg = JSON.parse(body);
      } catch {
        return reply(400, { error: "bad json" });
      }
      const now = Date.now();
      if (Math.abs(now - msg.ts) > MAX_CLOCK_SKEW_MS) return reply(400, { error: "clock skew or replay" });
      const state = load();
      const out = arbiterDecide(state, msg, now);
      writeFileAtomic(file, JSON.stringify(state, null, 2));
      reply(200, { granted: out.granted, owner: out.owner, owners: state.owners, nodes: state.nodes, now });
    });
  });
  server.listen(opts.port, opts.host);
  return server;
}

export async function askArbiter(
  url: string,
  msg: { op: Op; node: string; epoch: number; dataOf?: string; to?: string }
): Promise<{ granted: boolean; owner?: { owner: string; epoch: number }; owners: ArbiterState["owners"]; nodes: ArbiterState["nodes"]; now: number }> {
  const body = JSON.stringify({ ...msg, ts: Date.now() });
  const res = await fetch(`${url.replace(/\/+$/, "")}/arbiter`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Paasmcp-Signature": sign(deriveArbiterKey(), body) },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Arbiter answered HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json() as never;
}
