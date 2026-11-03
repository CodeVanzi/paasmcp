import net from "node:net";
import tls from "node:tls";
import { sanitizeSlug } from "./config.js";
import { getSecrets, setSecretEntries } from "./vault.js";

// Mail from a home server does not arrive (port 25 blocked, residential IPs on blocklists), so apps send
// through one relay (Brevo, SES, Mailgun, Resend, Postmark...) configured once in the system vault.

export interface RelayConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  fromDomain: string;
  apiKey?: string;
}

export function setEmailRelay(cfg: RelayConfig): void {
  if (!/^[a-zA-Z0-9.-]+$/.test(cfg.host)) throw new Error(`Invalid SMTP host '${cfg.host}'.`);
  if (!Number.isInteger(cfg.port) || cfg.port < 1 || cfg.port > 65535) throw new Error(`Invalid SMTP port '${cfg.port}'.`);
  if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cfg.fromDomain)) throw new Error(`Invalid sender domain '${cfg.fromDomain}'.`);
  setSecretEntries("system", {
    EMAIL_SMTP_HOST: cfg.host,
    EMAIL_SMTP_PORT: String(cfg.port),
    EMAIL_SMTP_USER: cfg.user,
    EMAIL_SMTP_PASSWORD: cfg.password,
    EMAIL_FROM_DOMAIN: cfg.fromDomain,
    ...(cfg.apiKey ? { EMAIL_API_KEY: cfg.apiKey } : {}),
  });
}

export function getEmailRelay(): RelayConfig | null {
  const s = getSecrets("system");
  if (!s.EMAIL_SMTP_HOST || !s.EMAIL_SMTP_PASSWORD) return null;
  return {
    host: s.EMAIL_SMTP_HOST,
    port: Number(s.EMAIL_SMTP_PORT || 587),
    user: s.EMAIL_SMTP_USER || "",
    password: s.EMAIL_SMTP_PASSWORD,
    fromDomain: s.EMAIL_FROM_DOMAIN || "",
    apiKey: s.EMAIL_API_KEY || undefined,
  };
}

function requireRelay(): RelayConfig {
  const r = getEmailRelay();
  if (!r) throw new Error("No email relay configured. Run 'paasmcp email set --host <smtp host> --port 587 --user <login> --from-domain <your domain>' (password asked, never in the command line).");
  return r;
}

/** Puts the relay settings into an app's vault under the names common frameworks read. */
export function provisionEmail(appName: string, fromName?: string): { appName: string; from: string; injectedKeys: string[] } {
  const slug = sanitizeSlug(appName);
  const r = requireRelay();
  const address = `${slug}@${r.fromDomain}`;
  const from = fromName ? `${fromName.replace(/[<>"\r\n]/g, "")} <${address}>` : address;
  const secure = r.port === 465 ? "ssl" : "starttls";
  const enc = encodeURIComponent;
  const env: Record<string, string> = {
    SMTP_HOST: r.host,
    SMTP_PORT: String(r.port),
    SMTP_USER: r.user,
    SMTP_PASSWORD: r.password,
    SMTP_SECURE: secure,
    EMAIL_FROM: from,
    DEFAULT_FROM_EMAIL: from,
    // dj-email-url / many Node libs
    EMAIL_URL: `${r.port === 465 ? "smtps" : "submission"}://${enc(r.user)}:${enc(r.password)}@${r.host}:${r.port}`,
  };
  // Brevo HTTP API: for hosts that block SMTP (e.g. some free PaaS plans).
  if (r.apiKey) env.BREVO_API_KEY = r.apiKey;
  setSecretEntries(slug, env);
  return { appName: slug, from, injectedKeys: Object.keys(env) };
}

// ---------------------------------------------------------------------------
// Minimal SMTP client (no dependency) for `paasmcp email test`.
// ---------------------------------------------------------------------------

export async function sendTestEmail(to: string, opts: { relay?: RelayConfig; allowPlaintextForLocalTest?: boolean } = {}): Promise<{ accepted: string; log: string[] }> {
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(to)) throw new Error(`Invalid recipient '${to}'.`);
  const r = opts.relay || requireRelay();
  const from = `paasmcp@${r.fromDomain}`;
  const log: string[] = [];
  let socket: net.Socket = r.port === 465 ? tls.connect({ host: r.host, port: r.port, servername: r.host }) : net.connect({ host: r.host, port: r.port });
  socket.setTimeout(20_000, () => socket.destroy(new Error("SMTP timeout")));
  let buffer = "";
  let pending: { resolve: (reply: string) => void; reject: (e: Error) => void } | null = null;
  let failure: Error | null = null;
  const fail = (e: Error) => {
    failure = failure || e;
    pending?.reject(failure);
    pending = null;
  };
  const attach = (s: net.Socket) => {
    s.on("data", (d) => {
      buffer += d.toString("utf-8");
      // A reply is complete when its last line has "NNN " (space, not dash) after the code.
      if (pending && /(^|\r\n)\d{3} [^\r\n]*\r\n$/.test(buffer)) {
        const reply = buffer;
        buffer = "";
        const p = pending;
        pending = null;
        p.resolve(reply);
      }
    });
    s.on("error", fail);
    s.on("close", () => fail(new Error("SMTP connection closed")));
  };
  attach(socket);
  const read = () =>
    new Promise<string>((resolve, reject) => {
      if (/(^|\r\n)\d{3} [^\r\n]*\r\n$/.test(buffer)) {
        const reply = buffer;
        buffer = "";
        return resolve(reply);
      }
      if (failure) return reject(failure);
      pending = { resolve, reject };
    });
  const expect = async (code: string, cmd?: string, shown?: string) => {
    if (cmd) socket.write(cmd + "\r\n");
    const reply = await read();
    log.push(`${shown ?? cmd ?? "(greeting)"} -> ${reply.trim().split("\r\n").pop()}`);
    if (!reply.split("\r\n").filter(Boolean).pop()!.startsWith(code)) throw new Error(`SMTP: expected ${code}, got: ${reply.trim()}`);
    return reply;
  };

  try {
    await expect("220");
    let ehlo = await expect("250", "EHLO paasmcp.local");
    if (r.port !== 465) {
      if (/STARTTLS/i.test(ehlo)) {
        await expect("220", "STARTTLS");
        socket.removeAllListeners("data");
        socket.removeAllListeners("close");
        socket.removeAllListeners("error");
        socket = tls.connect({ socket, servername: r.host });
        attach(socket);
        await new Promise<void>((res, rej) => {
          socket.once("secureConnect", () => res());
          socket.once("error", rej);
        });
        ehlo = await expect("250", "EHLO paasmcp.local");
      } else if (!opts.allowPlaintextForLocalTest) {
        // Never send the relay password over an unencrypted connection.
        throw new Error("The relay does not offer STARTTLS on this port; refusing to send the password in clear. Use port 465 or 587.");
      }
    }
    if (r.user) {
      const plain = Buffer.from(`\0${r.user}\0${r.password}`).toString("base64");
      await expect("235", `AUTH PLAIN ${plain}`, "AUTH PLAIN ****");
    }
    await expect("250", `MAIL FROM:<${from}>`);
    await expect("250", `RCPT TO:<${to}>`);
    await expect("354", "DATA");
    const msg = [
      `From: PaaSMCP <${from}>`,
      `To: <${to}>`,
      "Subject: PaaSMCP email test",
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@${r.fromDomain}>`,
      "Content-Type: text/plain; charset=utf-8",
      "",
      "If you can read this, apps on your server can send email through the relay.",
      ".",
    ].join("\r\n");
    const accepted = await expect("250", msg, "(message)");
    socket.write("QUIT\r\n");
    return { accepted: accepted.trim(), log };
  } finally {
    socket.end();
  }
}
