import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PAAS_DATA_DIR, ensureDirectories, writeFileAtomic } from "./config.js";

/**
 * Risk policy for every action that can hurt the server or its data.
 *
 * - No risk: runs right away.
 * - "confirm": a person must confirm (dashboard button, CLI prompt or `--yes`).
 * - "strong": a person must type the subject name (dashboard prompt or CLI `--confirm-name`).
 * - Forbidden: no safe way to do it; always refused.
 *
 * AI agents never confirm by themselves: an MCP call that needs confirmation creates a pending
 * request that a person approves in the dashboard or with `paasmcp approve <id>`, then the agent
 * repeats the call with `approvalId`.
 */

export type RiskLevel = "confirm" | "strong";

export interface Risk {
  action: string;
  subject: string;
  level: RiskLevel;
  warning: { en: string; pt: string };
  params: Record<string, unknown>;
}

export class ForbiddenActionError extends Error {}

export class ConfirmationRequiredError extends Error {
  constructor(public risk: Risk, public approvalId?: string) {
    super(
      approvalId
        ? `Confirmation required (${risk.level}): ${risk.warning.en} Ask a person to approve request ${approvalId} in the dashboard (Approvals) or run \`paasmcp approve ${approvalId}\` on the server, then repeat this call with approvalId="${approvalId}".`
        : `Confirmation required (${risk.level}): ${risk.warning.en}`
    );
  }
}

export const DASHBOARD_APP_NAME = "paasmcp-dashboard";
export const APPROVAL_TTL_MS = 10 * 60 * 1000;
const APPROVALS_PATH = path.join(PAAS_DATA_DIR, "approvals.json");
const AUDIT_LOG_PATH = path.join(PAAS_DATA_DIR, "audit.log");

function risk(
  action: string,
  subject: string,
  level: RiskLevel,
  en: string,
  pt: string,
  params: Record<string, unknown>
): Risk {
  return { action, subject, level, warning: { en, pt }, params };
}

/** Classifies an action. Returns null when it is free, throws ForbiddenActionError when it is never allowed. */
export function assessRisk(action: string, params: Record<string, unknown>): Risk | null {
  const subject = String(params.appName || params.scope || params.backupId || params.peer || action);
  switch (action) {
    case "app.destroy":
      return risk(action, subject, "confirm",
        `App '${subject}' goes offline and moves to the trash for 30 days (database and volumes are kept; it can be restored).`,
        `O app '${subject}' sai do ar e vai para a lixeira por 30 dias (banco e volumes ficam guardados; dá para restaurar).`,
        params);
    case "app.purge":
      return risk(action, subject, "strong",
        `Permanently deletes app '${subject}': containers, volumes, images and files. This cannot be undone.`,
        `Apaga de vez o app '${subject}': containers, volumes, imagens e arquivos. Não dá para desfazer.`,
        params);
    case "app.trust":
      return risk(action, subject, "strong",
        `Marks app '${subject}' as trusted: its docker-compose.yml keeps privileged mode, host network, capabilities, devices and host folders (including /var/run/docker.sock). A trusted app can take full control of this server.`,
        `Marca o app '${subject}' como confiável: o docker-compose.yml dele mantém modo privilegiado, rede do servidor, capabilities, dispositivos e pastas do servidor (inclusive /var/run/docker.sock). Um app confiável pode controlar o servidor inteiro.`,
        params);
    case "app.expose": {
      const mode = String(params.mode);
      if (subject === DASHBOARD_APP_NAME) {
        if (mode === "public") {
          throw new ForbiddenActionError(
            "The dashboard controls the whole server (it holds the Docker socket) and cannot be published on the open internet protected only by a token. Use mode 'zero-trust' (Cloudflare Access login) or 'tailscale'."
          );
        }
        return risk(action, subject, "confirm",
          `The dashboard controls the whole server. It will be reachable through ${mode === "tailscale" ? "your Tailnet" : "Cloudflare Zero Trust (email login)"}.`,
          `O painel controla o servidor inteiro. Ele ficará acessível ${mode === "tailscale" ? "pela sua Tailnet" : "pelo Cloudflare Zero Trust (login por e-mail)"}.`,
          params);
      }
      if (mode === "public") {
        return risk(action, subject, "confirm",
          `App '${subject}' will be open to anyone on the internet. Only do this for apps with their own login or public content.`,
          `O app '${subject}' ficará aberto para qualquer pessoa na internet. Faça isso só com apps que têm login próprio ou conteúdo público.`,
          params);
      }
      return null;
    }
    case "db.restore":
      return risk(action, subject, "confirm",
        `The current database will be replaced by backup '${subject}'. A backup of the current state is taken first.`,
        `O banco atual será substituído pelo backup '${subject}'. Antes, é feito um backup do estado atual.`,
        params);
    case "secret.delete":
      return risk(action, subject, "confirm",
        `Removes ${String(params.keyName)} from '${subject}'. The app may stop working; the previous value is kept in the vault's deleted archive.`,
        `Remove ${String(params.keyName)} de '${subject}'. O app pode parar; o valor anterior fica guardado no arquivo de apagados do cofre.`,
        params);
    case "federation.join":
      return risk(action, subject, "confirm",
        "Pairs this server with another one. The other server will be able to send configuration and secrets to this one.",
        "Pareia este servidor com outro. O outro servidor poderá enviar configuração e segredos para este.",
        params);
    case "federation.import":
      return risk(action, subject, "confirm",
        "Replaces this server's app registry and vault with the received bundle.",
        "Substitui o registro de apps e o cofre deste servidor pelo pacote recebido.",
        params);
    default:
      return null;
  }
}

export interface ApprovalRecord {
  id: string;
  action: string;
  subject: string;
  level: RiskLevel;
  warning: { en: string; pt: string };
  paramsHash: string;
  status: "pending" | "approved" | "rejected" | "used";
  createdAt: string;
  expiresAt: string;
  decidedAt?: string;
  decidedBy?: string;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`)
    .join(",")}}`;
}

function hashRisk(r: Risk): string {
  return crypto.createHash("sha256").update(`${r.action}\n${stableStringify(r.params)}`).digest("hex");
}

function loadApprovals(): Record<string, ApprovalRecord> {
  if (!fs.existsSync(APPROVALS_PATH)) return {};
  return JSON.parse(fs.readFileSync(APPROVALS_PATH, "utf-8")) as Record<string, ApprovalRecord>;
}

function saveApprovals(all: Record<string, ApprovalRecord>): void {
  ensureDirectories();
  // Keep the file small: drop finished requests older than 7 days.
  const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
  for (const [id, rec] of Object.entries(all)) {
    if (rec.status !== "pending" && Date.parse(rec.createdAt) < cutoff) delete all[id];
  }
  writeFileAtomic(APPROVALS_PATH, JSON.stringify(all, null, 2));
}

export function audit(event: Record<string, unknown>): void {
  ensureDirectories();
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify({ at: new Date().toISOString(), ...event }) + "\n", {
    mode: 0o600,
  });
}

function isExpired(rec: ApprovalRecord): boolean {
  return Date.parse(rec.expiresAt) < Date.now();
}

export function requestApproval(r: Risk, requestedBy = "agent"): ApprovalRecord {
  const all = loadApprovals();
  const paramsHash = hashRisk(r);
  const existing = Object.values(all).find(
    (a) => a.status === "pending" && a.paramsHash === paramsHash && !isExpired(a)
  );
  if (existing) return existing;
  const now = Date.now();
  const rec: ApprovalRecord = {
    id: `c-${crypto.randomBytes(3).toString("hex").toUpperCase()}`,
    action: r.action,
    subject: r.subject,
    level: r.level,
    warning: r.warning,
    paramsHash,
    status: "pending",
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + APPROVAL_TTL_MS).toISOString(),
  };
  all[rec.id] = rec;
  saveApprovals(all);
  audit({ event: "approval.requested", id: rec.id, action: r.action, subject: r.subject, by: requestedBy });
  return rec;
}

export function listApprovals(onlyPending = false): ApprovalRecord[] {
  return Object.values(loadApprovals())
    .map((a) => (a.status === "pending" && isExpired(a) ? { ...a, status: "rejected" as const } : a))
    .filter((a) => !onlyPending || a.status === "pending")
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** Only for people (dashboard or CLI on the server). Strong requests need the subject name typed. */
export function decideApproval(
  id: string,
  approve: boolean,
  decidedBy: string,
  confirmName?: string
): ApprovalRecord {
  const all = loadApprovals();
  const rec = all[id];
  if (!rec) throw new Error(`Approval request '${id}' not found.`);
  if (rec.status !== "pending") throw new Error(`Approval request '${id}' is already ${rec.status}.`);
  if (isExpired(rec)) throw new Error(`Approval request '${id}' expired. Ask the agent to try again.`);
  if (approve && rec.level === "strong" && confirmName !== rec.subject) {
    throw new Error(`This is a strong confirmation: type the name '${rec.subject}' to approve.`);
  }
  rec.status = approve ? "approved" : "rejected";
  rec.decidedAt = new Date().toISOString();
  rec.decidedBy = decidedBy;
  saveApprovals(all);
  audit({ event: approve ? "approval.approved" : "approval.rejected", id, action: rec.action, subject: rec.subject, by: decidedBy });
  return rec;
}

/** Uses an approved request once, only for the exact same action and parameters. */
export function consumeApproval(id: string, r: Risk): boolean {
  const all = loadApprovals();
  const rec = all[id];
  if (!rec || rec.status !== "approved" || isExpired(rec) || rec.paramsHash !== hashRisk(r)) return false;
  rec.status = "used";
  saveApprovals(all);
  audit({ event: "approval.used", id, action: rec.action, subject: rec.subject });
  return true;
}

/** Gate for AI agents (MCP). Throws ConfirmationRequiredError with a pending request id. */
export function authorizeAgent(action: string, params: Record<string, unknown>, approvalId?: string): void {
  const r = assessRisk(action, params);
  if (!r) return;
  if (approvalId && consumeApproval(approvalId, r)) return;
  const rec = requestApproval(r);
  throw new ConfirmationRequiredError(r, rec.id);
}

/** Gate for people (dashboard, CLI). Throws ConfirmationRequiredError until they confirm. */
export function authorizeHuman(
  action: string,
  params: Record<string, unknown>,
  opts: { confirmed?: boolean; confirmName?: string; by: string }
): void {
  const r = assessRisk(action, params);
  if (!r) return;
  if (!opts.confirmed || (r.level === "strong" && opts.confirmName !== r.subject)) {
    throw new ConfirmationRequiredError(r);
  }
  audit({ event: "action.confirmed", action, subject: r.subject, by: opts.by });
}
