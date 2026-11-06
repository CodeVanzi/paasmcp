import { audit } from "./guard.js";
import { deleteSecretKey, getSecrets, setSecretEntries } from "./vault.js";

// Notices to the person when nobody is looking at the screen: a deploy that failed (or, if they ask,
// one that went live on its own after a git push), and an app that stopped on its own (appwatch.ts). One address, kept in the system vault, that is
// either a Discord or Slack webhook or an ntfy topic (free phone app), or any URL that takes a POST.

export type NotifyKind = "discord" | "slack" | "ntfy";
export type NotifyLang = "pt" | "en";

/** Who started a deploy; the dashboard person is watching, so no notice is needed for them. */
const AUTOMATIC = new Set(["webhook", "poll", "active", "mirror"]);

export class NotifyError extends Error {
  constructor(message: string, readonly pt: string) {
    super(message);
    this.name = "NotifyError";
  }
}

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

export function notifyKind(url: string): NotifyKind {
  const u = new URL(url);
  if (/(^|\.)discord(app)?\.com$/.test(u.hostname) && u.pathname.startsWith("/api/webhooks/")) return "discord";
  if (u.hostname === "hooks.slack.com") return "slack";
  return "ntfy";
}

export function validateNotifyUrl(raw: string): string {
  const url = raw.trim();
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new NotifyError("Invalid notification URL.", "Endereço inválido. Cole o endereço completo, começando com https://.");
  }
  const loopback = /^(127\.\d+\.\d+\.\d+|localhost)$/.test(u.hostname);
  if (u.protocol !== "https:" && !(OFFLINE() && loopback && u.protocol === "http:")) {
    throw new NotifyError("The notification URL must use https://.", "O endereço precisa começar com https://.");
  }
  if (u.username || u.password) {
    throw new NotifyError("The notification URL must not carry a user or password.", "O endereço não pode ter usuário e senha.");
  }
  if (url.length > 500) throw new NotifyError("The notification URL is too long.", "O endereço é longo demais.");
  return u.toString();
}

/** What the screen may show: never the address itself (a Discord/Slack webhook URL is a secret). */
export function notifySummary(): { configured: boolean; kind?: NotifyKind; host?: string; onSuccess: boolean; lang: NotifyLang } {
  const s = getSecrets("system");
  const lang: NotifyLang = s.NOTIFY_LANG === "en" ? "en" : "pt";
  if (!s.NOTIFY_URL) return { configured: false, onSuccess: false, lang };
  let host = "";
  let kind: NotifyKind = "ntfy";
  try {
    host = new URL(s.NOTIFY_URL).hostname;
    kind = notifyKind(s.NOTIFY_URL);
  } catch {
    // stored before validation existed; shown as unknown
  }
  return { configured: true, kind, host, onSuccess: s.NOTIFY_ON_SUCCESS === "1", lang };
}

async function post(url: string, title: string, text: string): Promise<void> {
  const kind = notifyKind(url);
  const body =
    kind === "discord"
      ? JSON.stringify({ content: `**${title}**\n${text}`.slice(0, 1900) })
      : kind === "slack"
        ? JSON.stringify({ text: `*${title}*\n${text}`.slice(0, 3000) })
        : `${text}`.slice(0, 3000);
  const headers: Record<string, string> =
    kind === "ntfy"
      ? // ntfy reads the title from a header; other services ignore it. Header values must be plain ASCII.
        { "Content-Type": "text/plain; charset=utf-8", Title: title.normalize("NFD").replace(/[^\x20-\x7e]/g, "") }
      : { "Content-Type": "application/json" };
  const res = await fetch(url, { method: "POST", headers, body, redirect: "error", signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

/** Tests the address with a real notice, then saves it. Nothing is saved if the test fails. */
export async function saveNotify(input: { url: string; onSuccess?: boolean; lang?: string }): Promise<ReturnType<typeof notifySummary>> {
  const url = validateNotifyUrl(input.url);
  const lang: NotifyLang = input.lang === "en" ? "en" : "pt";
  try {
    await post(
      url,
      "PaaSMCP",
      lang === "pt" ? "Teste: os avisos do PaaSMCP chegam aqui." : "Test: PaaSMCP notices arrive here."
    );
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new NotifyError(`The test notice did not go through (${why}).`, `O aviso de teste não chegou (${why}). Confira o endereço.`);
  }
  setSecretEntries("system", { NOTIFY_URL: url, NOTIFY_ON_SUCCESS: input.onSuccess ? "1" : "0", NOTIFY_LANG: lang });
  audit({ event: "notify.set", kind: notifyKind(url) });
  return notifySummary();
}

export function clearNotify(): void {
  for (const k of ["NOTIFY_URL", "NOTIFY_ON_SUCCESS", "NOTIFY_LANG"]) deleteSecretKey("system", k);
  audit({ event: "notify.clear" });
}

export interface DeployNotice {
  app: string;
  trigger: string;
  ok: boolean;
  commit?: string;
  error?: string;
}

/** The notice text for one finished deploy, or undefined when none is due. Pure, for tests. */
export function deployNoticeText(n: DeployNotice, settings: { onSuccess: boolean; lang: NotifyLang }): { title: string; text: string } | undefined {
  if (n.trigger === "dashboard") return undefined;
  if (n.ok && !(settings.onSuccess && AUTOMATIC.has(n.trigger))) return undefined;
  const c = n.commit ? ` (${n.commit.slice(0, 7)})` : "";
  if (settings.lang === "en") {
    return n.ok
      ? { title: `${n.app} is live`, text: `✅ ${n.app}${c} was published and is live.` }
      : { title: `${n.app}: publish failed`, text: `❌ Publishing ${n.app}${c} failed: ${n.error || "unknown error"}\nThe previous version is still running. Details on the dashboard.` };
  }
  return n.ok
    ? { title: `${n.app} no ar`, text: `✅ ${n.app}${c} foi publicado e está no ar.` }
    : { title: `${n.app}: falha ao publicar`, text: `❌ A publicação de ${n.app}${c} falhou: ${n.error || "erro desconhecido"}\nA versão anterior continua no ar. Detalhes no painel.` };
}

/** Sends one notice when notices are set up. Never throws: a notice must not break what triggered it. */
export async function sendNotice(build: (lang: NotifyLang) => { title: string; text: string } | undefined, event: string, app: string): Promise<void> {
  try {
    const s = getSecrets("system");
    if (!s.NOTIFY_URL) return;
    const msg = build(s.NOTIFY_LANG === "en" ? "en" : "pt");
    if (!msg) return;
    await post(s.NOTIFY_URL, msg.title, msg.text);
  } catch (err) {
    audit({ event: "notify.failed", about: event, app, error: err instanceof Error ? err.message : String(err) });
  }
}

/** The notice for a finished deploy, if one is due. */
export async function notifyDeploy(n: DeployNotice): Promise<void> {
  const onSuccess = (() => {
    try {
      return getSecrets("system").NOTIFY_ON_SUCCESS === "1";
    } catch {
      return false;
    }
  })();
  await sendNotice((lang) => deployNoticeText(n, { onSuccess, lang }), n.ok ? "deploy.live" : "deploy.failed", n.app);
}
