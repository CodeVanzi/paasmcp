import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PAAS_DATA_DIR, ensureDirectories, loadState, writeFileAtomic } from "./config.js";
import { isDashboardTwoFactorEnabled } from "./totp.js";

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
    case "mirror.promote":
      return risk(action, subject, "strong",
        `This server takes over the apps of '${subject}' using its copy of the database. If '${subject}' is still running, both sides would accept changes (split brain): make sure it is really down or cut off. Changes made on '${subject}' after the last replicated moment stay only there.`,
        `Este servidor assume os apps de '${subject}' com a cópia do banco que tem aqui. Se '${subject}' ainda estiver ligado, os dois lados aceitariam alterações (cérebro dividido): confirme que ele caiu de verdade ou está isolado. O que foi gravado em '${subject}' depois do último momento copiado fica só lá.`,
        params);
    case "mirror.auto":
      if (!params.arbiterUrl && !loadState().mirror?.arbiterUrl) {
        throw new ForbiddenActionError(
          "Automatic failover needs an arbiter (paasmcp arbiter serve on a third device). Without one, a network split would make both servers take the data (split brain). Use manual 'mirror promote' instead."
        );
      }
      return risk(action, subject, "strong",
        `This server will take over '${subject}' on its own when both this server and the arbiter lose it for over a minute and its copy stops streaming. Changes made on '${subject}' in its last seconds may stay only there.`,
        `Este servidor vai assumir '${subject}' sozinho quando ele e o árbitro perderem contato com '${subject}' por mais de um minuto e a cópia parar de receber. O que '${subject}' gravou nos últimos segundos pode ficar só lá.`,
        params);
    case "mirror.rejoin":
      return risk(action, "rejoin", "confirm",
        "This server's database is stopped, moved aside (kept on disk, not deleted) and replaced by a read-only copy of the server that took over. Its apps stay stopped until you hand back.",
        "O banco deste servidor é parado, movido para o lado (fica guardado no disco, não é apagado) e trocado por uma cópia só de leitura do servidor que assumiu. Os apps daqui ficam parados até a devolução.",
        params);
    case "mirror.retire":
      return risk(action, subject, "confirm",
        `This server stops following '${subject}' for good: the copies of its apps here stop and its copy of the database stays on disk, read-only. Do this on every server that did NOT take over '${subject}'. A new offer rebuilds the copy later.`,
        `Este servidor deixa de seguir '${subject}' de vez: as cópias dos apps dele param aqui e a cópia do banco fica guardada no disco, só leitura. Faça isso em cada servidor que NÃO assumiu '${subject}'. Uma nova oferta refaz a cópia depois.`,
        params);
    case "mirror.handback":
      return risk(action, subject, "confirm",
        `The apps of '${subject}' stop here and the data goes back to '${subject}' once its copy has every change. Then run 'paasmcp mirror promote' there.`,
        `Os apps de '${subject}' param aqui e os dados voltam para '${subject}' assim que a cópia dele tiver tudo. Depois rode 'paasmcp mirror promote' lá.`,
        params);
    case "app.active":
      return risk(action, subject, "confirm",
        `App '${subject}' will also run on the other server and both will take requests. The other server receives its settings and secrets, reaches this server's database, Redis and S3 over Tailscale, and the app's port is published on this server's Tailscale IP.`,
        `O app '${subject}' vai rodar também no outro servidor, e os dois vão receber requisições. O outro servidor recebe as configurações e os segredos do app, acessa o banco, o Redis e o S3 daqui pela Tailscale, e a porta do app passa a ser publicada no IP Tailscale deste servidor.`,
        params);
    case "active.tunnel":
      return risk(action, "tunnel", "confirm",
        "Creates a second Cloudflare Tunnel used only by the apps that run on both servers, runs it on this server and on the other one, and moves the DNS of those apps' public addresses to it (each one once its copy on the other server answers). Apps that run only here stay on the current tunnel. The other server receives the tunnel's token through the encrypted control channel.",
        "Cria um segundo túnel da Cloudflare, usado só pelos apps que rodam nos dois servidores, roda esse túnel aqui e no outro servidor e muda o DNS dos endereços públicos desses apps para ele (cada um quando a cópia no outro servidor responder). Os apps que rodam só aqui continuam no túnel atual. O outro servidor recebe o token do túnel pelo canal cifrado.",
        params);
    case "edge.install":
      return risk(action, "edge", "strong",
        "Starts a web server (Caddy) on ports 80 and 443 of this server, open to the internet. It only serves the sites you add with 'edge add', and gets their HTTPS certificates from Let's Encrypt.",
        "Liga um servidor web (Caddy) nas portas 80 e 443 deste servidor, aberto para a internet. Ele só atende os sites que você adicionar com 'edge add' e pega os certificados HTTPS no Let's Encrypt.",
        params);
    case "scale.test":
      return risk(action, subject, "confirm",
        `Sends up to ${Number(params.maxConcurrency) || 32} parallel GET requests to app '${subject}' on ${String(params.path || "/")} for up to a few minutes, to find how much one copy handles. Visitors may find the app slower meanwhile. Use a path that only reads (it is called thousands of times).`,
        `Manda até ${Number(params.maxConcurrency) || 32} requisições GET ao mesmo tempo para o app '${subject}' em ${String(params.path || "/")} por até alguns minutos, para descobrir quanto uma cópia aguenta. Quem visitar o app nesse meio tempo pode achá-lo mais lento. Use um caminho que só lê (ele é chamado milhares de vezes).`,
        params);
    case "pool.invite": {
      const helper = String(params.helper);
      return risk(action, helper, "confirm",
        `Creates a one-use invite for the PC '${helper}'. Whoever runs it on a PC within 15 minutes lets this server give that PC orders: run copies of the apps you choose there, with their variables (secrets included). The first time, this server's Postgres, Redis and S3 are also published on its Tailscale IP (a few seconds of restart), so those copies can reach them.`,
        `Cria um convite de uso único para o PC '${helper}'. Quem rodar o convite num PC nos próximos 15 minutos deixa este servidor dar ordens a ele: rodar lá cópias dos apps que você escolher, com as variáveis deles (inclusive senhas). Na primeira vez, o Postgres, o Redis e o S3 deste servidor também passam a ser publicados no IP Tailscale dele (alguns segundos de reinício), para essas cópias alcançarem.`,
        params);
    }
    case "pool.remove": {
      const helper = String(params.helper);
      return risk(action, helper, "confirm",
        `The PC '${helper}' leaves the pool: its copies leave the balancer, get 30 s to finish the visits in progress and stop, and this server's key is removed from it. Copies move to other helpers when there is room.`,
        `O PC '${helper}' sai do pool: as cópias dele saem do balanceador, têm 30 s para terminar as visitas em curso e param, e a chave deste servidor é apagada de lá. As cópias vão para outros ajudantes quando houver espaço.`,
        params);
    }
    case "app.pool": {
      // Free while the app already uses helpers and stays within its scale rule's maximum (decided in
      // the plan: moving inside limits a person set is free; the first time and going past them is not).
      const copies = Number(params.copies);
      const max = Number(params.max);
      if (!(copies > 1) || (!params.enabling && copies <= max)) return null;
      if (!params.enabling) {
        return risk(action, subject, "confirm",
          `App '${subject}' goes to ${copies} copies, above the maximum of ${max} in its scale rule.`,
          `O app '${subject}' vai para ${copies} cópias, acima do máximo de ${max} da regra de escala dele.`,
          params);
      }
      return risk(action, subject, "confirm",
        `App '${subject}' will run ${copies} copies: this server's and ${copies - 1} on helper PCs. Each helper receives the app's image and variables (secrets included, kept only in memory there), its copies reach this server's database, Redis and S3 over Tailscale, and the app's visits go through a small balancer on this server.`,
        `O app '${subject}' vai rodar ${copies} cópias: a deste servidor e ${copies - 1} em PCs ajudantes. Cada ajudante recebe a imagem e as variáveis do app (inclusive senhas, guardadas só na memória dele), as cópias acessam o banco, o Redis e o S3 daqui pela Tailscale, e as visitas do app passam por um pequeno balanceador neste servidor.`,
        params);
    }
    case "pool.join": {
      const origin = String(params.origin);
      return risk(action, origin, "confirm",
        `This PC will take orders from the server '${origin}' (${String(params.originIp)}): a user 'paasmcp-worker' is created in the docker group, and that server's key can run app copies here (up to ${String(params.cpus)} CPUs and ${String(params.memMb)} MB), and nothing else: no terminal, no files. Undo with 'sudo paasmcp pool leave'.`,
        `Este PC vai receber ordens do servidor '${origin}' (${String(params.originIp)}): é criado um usuário 'paasmcp-worker' no grupo docker, e a chave daquele servidor pode rodar cópias de apps aqui (até ${String(params.cpus)} CPUs e ${String(params.memMb)} MB), e nada mais: sem terminal, sem arquivos. Para desfazer: 'sudo paasmcp pool leave'.`,
        params);
    }
    case "pool.leave":
      return risk(action, "pool", "confirm",
        "The app copies running on this PC stop, their images are removed, and the user 'paasmcp-worker' with the server's key is deleted. Remove the PC on the server too ('paasmcp pool remove <name>').",
        "As cópias de apps que rodam neste PC param, as imagens delas são apagadas e o usuário 'paasmcp-worker' com a chave do servidor é removido. Remova o PC no servidor também ('paasmcp pool remove <nome>').",
        params);
    case "update.apply":
      return risk(action, String(params.component), "confirm",
        `${String(params.component)} restarts on ${String(params.image)} (a few seconds of downtime for every app that uses it). Databases are backed up first; if it does not come back healthy in 60 s, the previous version is restored.`,
        `${String(params.component)} reinicia em ${String(params.image)} (alguns segundos fora do ar para os apps que usam). Os bancos têm backup antes; se não voltar saudável em 60 s, a versão anterior é restaurada.`,
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
          if (!isDashboardTwoFactorEnabled()) {
            throw new ForbiddenActionError(
              "The dashboard controls the whole server (it holds the Docker socket) and cannot be published on the open internet protected only by a token. Enable two-factor login first (`paasmcp dashboard 2fa enable`), or use mode 'zero-trust' (Cloudflare Access login) or 'tailscale'."
            );
          }
          return risk(action, subject, "strong",
            "The dashboard controls the whole server and will be reachable by anyone on the internet, protected by token + two-factor code. Zero Trust or Tailscale remain safer.",
            "O painel controla o servidor inteiro e ficará acessível a qualquer pessoa na internet, protegido por token + código de dois fatores. Zero Trust ou Tailscale continuam mais seguros.",
            params);
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
        `The current data (database or volume) will be replaced by backup '${subject}'. A backup of the current state is taken first.`,
        `Os dados atuais (banco ou volume) serão substituídos pelo backup '${subject}'. Antes, é feito um backup do estado atual.`,
        params);
    case "secret.delete":
      return risk(action, subject, "confirm",
        `Removes ${String(params.keyName)} from '${subject}'. The app may stop working; the previous value is kept in the vault's deleted archive.`,
        `Remove ${String(params.keyName)} de '${subject}'. O app pode parar; o valor anterior fica guardado no arquivo de apagados do cofre.`,
        params);
    case "dashboard.2fa-off":
      if (loadState().apps[DASHBOARD_APP_NAME]?.domains.some((d) => d.mode === "public")) {
        throw new ForbiddenActionError(
          "The dashboard is published on the open internet; two-factor login cannot be turned off while it is. Unpublish it first."
        );
      }
      return risk(action, "dashboard", "confirm",
        "Turns off two-factor login: the dashboard token alone will be enough again. If the dashboard is public, unpublish it first.",
        "Desliga o login com dois fatores: o token do painel volta a bastar sozinho. Se o painel estiver público, tire-o do ar antes.",
        params);
    case "federation.invite":
      return risk(action, subject, "confirm",
        "Creates a join token that carries the cluster key. Whoever holds it in the next 15 minutes can pair a server with this one.",
        "Cria um token de pareamento que leva a chave do cluster. Quem tiver o token nos próximos 15 minutos consegue parear um servidor com este.",
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
