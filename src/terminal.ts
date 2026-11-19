import http from "node:http";
import crypto from "node:crypto";
import type { Duplex } from "node:stream";
import type { WebSocket } from "ws";
import { loadState, saveState, sanitizeSlug } from "./config.js";
import { audit } from "./guard.js";

/**
 * A terminal in the dashboard (off by default; the owner turns it on with a strong confirmation).
 * It talks to Docker's API directly, which allocates the terminal (TTY) itself: no native module here.
 * - "server": a short-lived privileged container enters the host's namespaces (nsenter -t 1) and runs a login
 *   shell as root. That is no more than the dashboard can already do (it holds the Docker socket).
 * - an app: `docker exec` of a shell in that app's container.
 * Only a person logged in to the dashboard opens it (never a token, never MCP). Sessions close after
 * 15 minutes without typing, and when the terminal is turned off. Opening and closing are audited;
 * what is typed is not. A shell's last 2 MB of output stay in memory while it runs (so a page can come back
 * to it) and are never written to disk.
 */

const DOCKER_SOCK = () => process.env.PAASMCP_DOCKER_SOCK || "/var/run/docker.sock";
export const TERMINAL_IDLE_MS = () => Number(process.env.PAASMCP_TERMINAL_IDLE_MS) || 15 * 60_000;
const MAX_SESSIONS = 4;
// The host's first process; labs whose sandbox hides PID 1 point it at another process of theirs.
const hostPid = () => (/^[1-9][0-9]{0,9}$/.test(process.env.PAASMCP_TERMINAL_HOST_PID || "") ? String(process.env.PAASMCP_TERMINAL_HOST_PID) : "1");
const SHELL = "cd ~ 2>/dev/null; if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi";

export function terminalEnabled(): boolean {
  return loadState().terminal?.enabled === true;
}

export function setTerminalEnabled(on: boolean, by: string): void {
  const state = loadState();
  state.terminal = { enabled: on, updatedAt: new Date().toISOString(), by };
  saveState(state);
  audit({ event: on ? "terminal.enabled" : "terminal.disabled", by });
  if (!on) for (const s of [...sessions.values()]) s.close("turned off");
}

/** "server", or the slug of an app here that has a container. */
export function terminalTarget(raw: string): { kind: "server" } | { kind: "app"; app: string; container: string } {
  if (raw === "server") return { kind: "server" };
  const app = sanitizeSlug(raw);
  const container = loadState().apps[app]?.containerName;
  if (!container || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(container)) throw new Error(`App '${app}' has no container here.`);
  return { kind: "app", app, container };
}

function dockerApi(method: string, apiPath: string, body?: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request(
      { socketPath: DOCKER_SOCK(), method, path: apiPath, headers: data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {} },
      (res) => {
        let text = "";
        res.on("data", (c) => { text += c; });
        res.on("end", () => {
          let json: any = {};
          try { json = text ? JSON.parse(text) : {}; } catch { json = { message: text }; }
          if ((res.statusCode || 500) >= 400) reject(new Error(`Docker: ${json.message || res.statusCode}`));
          else resolve({ status: res.statusCode || 200, json });
        });
      }
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

/** POST that Docker answers by turning the connection into the raw terminal stream (TTY: no multiplexing). */
function dockerHijack(apiPath: string, body?: unknown): Promise<Duplex> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body ?? {});
    const req = http.request({
      socketPath: DOCKER_SOCK(),
      method: "POST",
      path: apiPath,
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data), Connection: "Upgrade", Upgrade: "tcp" },
    });
    req.on("upgrade", (_res, socket, head) => {
      if (head.length) socket.unshift(head);
      resolve(socket);
    });
    req.on("response", (res) => {
      let text = "";
      res.on("data", (c) => { text += c; });
      res.on("end", () => reject(new Error(`Docker: ${text.trim() || res.statusCode}`)));
    });
    req.on("error", reject);
    req.end(data);
  });
}

interface Pty {
  stream: Duplex;
  resize: (cols: number, rows: number) => void;
  stop: () => void;
}

async function openServerShell(image: string): Promise<Pty> {
  const name = `paasmcp-terminal-${crypto.randomBytes(4).toString("hex")}`;
  const { json } = await dockerApi("POST", `/containers/create?name=${name}`, {
    Image: image,
    // -S/-G: root with no extra groups (the helper image's groups have other meanings, or none, on the host).
    Cmd: ["nsenter", "-t", hostPid(), "-m", "-u", "-i", "-n", "-p", "-S", "0", "-G", "0", "--", "/bin/sh", "-c", SHELL],
    Env: ["TERM=xterm-256color", "HOME=/root"],
    Tty: true,
    OpenStdin: true,
    StdinOnce: true,
    AttachStdin: true,
    AttachStdout: true,
    AttachStderr: true,
    Labels: { "paasmcp.terminal": "1", "com.centurylinklabs.watchtower.enable": "false" },
    HostConfig: { Privileged: true, PidMode: "host", NetworkMode: "none", AutoRemove: true },
  });
  const id = String(json.Id);
  try {
    const stream = await dockerHijack(`/containers/${id}/attach?stream=1&stdin=1&stdout=1&stderr=1`);
    await dockerApi("POST", `/containers/${id}/start`);
    return {
      stream,
      resize: (c, r) => { dockerApi("POST", `/containers/${id}/resize?h=${r}&w=${c}`).catch(() => {}); },
      stop: () => { stream.destroy(); dockerApi("DELETE", `/containers/${id}?force=1`).catch(() => {}); },
    };
  } catch (err) {
    dockerApi("DELETE", `/containers/${id}?force=1`).catch(() => {});
    throw err;
  }
}

async function openAppShell(container: string): Promise<Pty> {
  const { json } = await dockerApi("POST", `/containers/${encodeURIComponent(container)}/exec`, {
    AttachStdin: true,
    AttachStdout: true,
    AttachStderr: true,
    Tty: true,
    Env: ["TERM=xterm-256color"],
    Cmd: ["sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi"],
  });
  const id = String(json.Id);
  const stream = await dockerHijack(`/exec/${id}/start`, { Detach: false, Tty: true });
  return {
    stream,
    resize: (c, r) => { dockerApi("POST", `/exec/${id}/resize?h=${r}&w=${c}`).catch(() => {}); },
    stop: () => { stream.write("exit\r"); stream.destroy(); },
  };
}

const HISTORY_BYTES = 2 * 1024 * 1024;
// What the shell asked the terminal (where is the cursor? what are you?): replayed, it would get a fresh answer
// typed at the prompt. Bytes as latin1 so nothing else changes.
const QUERIES = /\x1b\[[0-9;?>=]*[cn]|\x1b\][0-9]+;\?(?:\x07|\x1b\\)/g;

interface Session {
  id: string;
  target: string;
  by: string;
  startedAt: string;
  history: Buffer[];
  historyBytes: number;
  ws?: WebSocket;
  onMessage: (raw: unknown) => void;
  close: (reason: string) => void;
}
const sessions = new Map<string, Session>();

/** Open shells (attached to a page or waiting for it to come back). */
export function terminalSessions(): { id: string; target: string; attached: boolean; startedAt: string }[] {
  return [...sessions.values()].map((s) => ({ id: s.id, target: s.target, attached: !!s.ws, startedAt: s.startedAt }));
}

function note(ws: WebSocket | undefined, text: string): void {
  try { ws?.send(Buffer.from(`\r\n\x1b[33m[${text}]\x1b[0m\r\n`)); } catch { /* gone */ }
}

/**
 * Joins a browser WebSocket to a shell. The shell lives here, not in the page: closing the tab or losing the
 * network only detaches it, and opening it again (same `sessionId`) shows what it printed meanwhile.
 * It ends with `exit`, the page's Close (`{t:"close"}`), 15 minutes without typing, or turning the terminal off.
 * Browser → server: JSON {t:"in",d} (typed text), {t:"resize",c,r} or {t:"close"}.
 * Server → browser: the terminal's bytes (binary frames) and {t:"session",id,resumed} (text).
 */
export async function attachTerminal(
  ws: WebSocket,
  target: ReturnType<typeof terminalTarget>,
  opts: { image: string; by: string; sessionId?: string }
): Promise<void> {
  const label = target.kind === "server" ? "server" : target.app;
  const existing = opts.sessionId ? sessions.get(opts.sessionId) : undefined;
  if (existing && existing.target === label && existing.by === opts.by) return join(existing, ws, true);
  if (sessions.size >= MAX_SESSIONS) {
    ws.close(4429, "Too many terminals open");
    return;
  }
  const started = Date.now();
  let pty: Pty | undefined;
  let closed = false;
  let idle: NodeJS.Timeout | undefined;
  const session: Session = {
    id: crypto.randomBytes(12).toString("hex"),
    target: label,
    by: opts.by,
    startedAt: new Date(started).toISOString(),
    history: [],
    historyBytes: 0,
    onMessage: () => {},
    close: (reason: string) => {
      if (closed) return;
      closed = true;
      clearTimeout(idle);
      sessions.delete(session.id);
      pty?.stop();
      if (reason === "idle") note(session.ws, "closed after 15 minutes without typing");
      if (reason === "turned off") note(session.ws, "the terminal was turned off");
      session.ws?.close(1000, reason.slice(0, 100));
      audit({ event: "terminal.close", target: label, reason, seconds: Math.round((Date.now() - started) / 1000), by: opts.by });
    },
  };
  sessions.set(session.id, session);
  const touch = () => {
    clearTimeout(idle);
    idle = setTimeout(() => session.close("idle"), TERMINAL_IDLE_MS());
  };
  touch();
  let size: [number, number] | undefined;
  const onMessage = (raw: unknown) => {
    let msg: { t?: string; d?: unknown; c?: unknown; r?: unknown };
    try { msg = JSON.parse(String(raw)); } catch { return; }
    if (msg.t === "in" && typeof msg.d === "string" && msg.d.length <= 64 * 1024) {
      touch();
      pty?.stream.write(msg.d);
    } else if (msg.t === "resize") {
      const c = Number(msg.c), r = Number(msg.r);
      if (Number.isInteger(c) && Number.isInteger(r) && c > 0 && r > 0 && c <= 1000 && r <= 500) {
        size = [c, r];
        pty?.resize(c, r);
      }
    } else if (msg.t === "close") session.close("closed");
  };
  session.onMessage = onMessage;
  session.ws = ws;
  ws.on("message", onMessage);
  // Until the shell is open, a page that goes away ends it (nothing to come back to yet).
  const early = () => { if (!pty) session.close("closed"); };
  ws.on("close", early);
  try {
    pty = target.kind === "server" ? await openServerShell(opts.image) : await openAppShell(target.container);
  } catch (err) {
    note(session.ws, err instanceof Error ? err.message : String(err));
    session.close("failed");
    return;
  }
  if (closed) { pty.stop(); return; }
  audit({ event: "terminal.open", target: label, by: opts.by });
  pty.stream.on("data", (d: Buffer) => {
    session.history.push(d);
    session.historyBytes += d.length;
    while (session.historyBytes > HISTORY_BYTES && session.history.length > 1) session.historyBytes -= session.history.shift()!.length;
    if (session.ws && session.ws.readyState === session.ws.OPEN) session.ws.send(d);
  });
  for (const ev of ["end", "close", "error"]) pty.stream.on(ev, () => session.close("ended"));
  if (size) pty.resize(size[0], size[1]);
  ws.off("close", early);
  join(session, ws, false);
}

function join(session: Session, ws: WebSocket, resumed: boolean): void {
  const onMessage = session.onMessage;
  const old = session.ws;
  if (old && old !== ws) {
    old.off("message", onMessage);
    note(old, "opened in another tab");
    old.close(4409, "Opened elsewhere");
  }
  session.ws = ws;
  if (resumed) {
    ws.on("message", onMessage);
    const replay = Buffer.concat(session.history).toString("latin1").replace(QUERIES, "");
    if (replay) ws.send(Buffer.from(replay, "latin1"));
  }
  ws.send(JSON.stringify({ t: "session", id: session.id, resumed }));
  // The page went away (tab closed, network lost): the shell keeps running until it comes back or goes idle.
  ws.on("close", () => {
    if (session.ws !== ws) return;
    ws.off("message", onMessage);
    session.ws = undefined;
  });
  ws.on("error", () => { /* followed by close */ });
}

export const openTerminalCount = () => sessions.size;
