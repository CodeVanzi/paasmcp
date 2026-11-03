import { execFileSync } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ForbiddenActionError } from "./guard.js";
import { createMcpServer } from "./mcp-server.js";
import { verifyToken } from "./tokens.js";

/**
 * MCP over Streamable HTTP for any MCP client (Claude, ChatGPT/Gemini desktop clients, Cursor,
 * local models...), authenticated with personal tokens (`paasmcp token create`).
 * It only listens on loopback or on the Tailscale address: on the open internet a bearer token
 * alone is not enough (an OAuth login would be needed first).
 */

const TAILSCALE_V4 = { base: "100.64.0.0", bits: 10 };

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

export function isAllowedMcpBindHost(host: string): boolean {
  if (host === "127.0.0.1" || host === "::1" || host === "localhost") return true;
  if (net.isIPv4(host)) {
    const mask = (~0 << (32 - TAILSCALE_V4.bits)) >>> 0;
    return (ipv4ToInt(host) & mask) === (ipv4ToInt(TAILSCALE_V4.base) & mask);
  }
  return net.isIPv6(host) && host.toLowerCase().startsWith("fd7a:115c:a1e0:");
}

function resolveBindHost(host: string): string {
  if (host !== "tailscale") return host;
  return execFileSync("tailscale", ["ip", "-4"], { encoding: "utf-8" }).trim().split("\n")[0];
}

const failedAuth = new Map<string, { count: number; until: number }>();

function tooManyFailures(ip: string): boolean {
  const entry = failedAuth.get(ip);
  return Boolean(entry && entry.count >= 10 && entry.until > Date.now());
}

function noteFailure(ip: string): void {
  const entry = failedAuth.get(ip);
  const fresh = !entry || entry.until < Date.now();
  failedAuth.set(ip, { count: fresh ? 1 : entry.count + 1, until: Date.now() + 5 * 60 * 1000 });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

export function startMcpHttpServer(port = 4098, requestedHost = "127.0.0.1"): http.Server {
  const host = resolveBindHost(requestedHost);
  if (!isAllowedMcpBindHost(host)) {
    throw new ForbiddenActionError(
      `MCP over HTTP only listens on loopback or on the Tailscale address (got '${host}'). Publish it through Tailscale (tailscale serve), never directly on the internet.`
    );
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    const ip = req.socket.remoteAddress || "unknown";
    const url = new URL(req.url || "/", "http://localhost");
    if (url.pathname !== "/mcp") return sendJson(res, 404, { error: "Not found. The MCP endpoint is /mcp." });
    if (req.method !== "POST") {
      // Stateless server: no SSE stream to resume and no session to delete.
      return sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
    }
    if (tooManyFailures(ip)) return sendJson(res, 429, { error: "Too many failed attempts. Try again in 5 minutes." });

    const auth = String(req.headers.authorization || "");
    const record = auth.startsWith("Bearer ") ? verifyToken(auth.slice(7)) : null;
    if (!record) {
      noteFailure(ip);
      return sendJson(
        res,
        401,
        { error: "Missing or invalid token. Create one on the server with `paasmcp token create <name>`." },
        { "WWW-Authenticate": 'Bearer realm="paasmcp"' }
      );
    }

    let raw = "";
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 2_000_000) return sendJson(res, 413, { error: "Payload too large" });
    }
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return sendJson(res, 400, { error: "Invalid JSON" });
    }

    const mcp = createMcpServer(record.level);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });
    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      if (!res.headersSent) sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  server.listen(port, host);
  return server;
}
