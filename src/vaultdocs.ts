/**
 * Built-in explanations for the keys PaaSMCP itself creates in the vault. The dashboard shows one when
 * nobody wrote a description for that key, and anyone can replace it with their own text.
 * System keys only match in the "system" scope, app keys only in an app's scope, so a variable an app
 * happens to name GITHUB_TOKEN never gets the dashboard's explanation.
 * Kept out of vault.ts on purpose: the judge (judge.ts) ships vault.js alone to other PCs.
 */
import { sanitizeSlug } from "./config.js";
import { getSecretMeta, getSecrets, maskSecretValue, type SecretMeta } from "./vault.js";

type Doc = { pt: string; en: string };

const SYSTEM_KEYS: Record<string, Doc> = {
  DASHBOARD_TOKEN: {
    pt: "Senha de entrada do painel. Quem tem este valor entra no painel; troque se ele vazar.",
    en: "The dashboard's sign-in password. Whoever has it can open the dashboard; change it if it leaks.",
  },
  DASHBOARD_TOTP_SECRET: {
    pt: "Semente do código de 6 dígitos (verificação em duas etapas) do painel. Fica no app autenticador do celular.",
    en: "Seed for the dashboard's 6-digit code (two-step verification). It lives in the phone's authenticator app.",
  },
  GITHUB_TOKEN: {
    pt: "Token do GitHub que o painel usa para listar seus repositórios, baixar o código e ligar o webhook. Criado em Conexões → GitHub.",
    en: "GitHub token the dashboard uses to list your repositories, fetch code and turn on the webhook. Set under Connections → GitHub.",
  },
  CF_API_TOKEN: {
    pt: "Token da Cloudflare que cria os endereços (DNS) e os túneis dos apps. Criado em Conexões → Domínio.",
    en: "Cloudflare token that creates the apps' addresses (DNS) and tunnels. Set under Connections → Domain.",
  },
  MAIN_TUNNEL_TOKEN: {
    pt: "Chave do túnel da Cloudflare que roda neste servidor e leva os visitantes até os apps.",
    en: "Key of the Cloudflare tunnel running on this server, which brings visitors to the apps.",
  },
  ACTIVE_TUNNEL_TOKEN: {
    pt: "Chave do túnel extra usado quando dois servidores atendem o mesmo app ao mesmo tempo.",
    en: "Key of the extra tunnel used when two servers serve the same app at once.",
  },
  WEBHOOK_SECRET: {
    pt: "Assinatura que confere se o aviso de “código novo” veio mesmo do GitHub, para publicar sozinho a cada push.",
    en: "Signature that checks a “new code” notice really came from GitHub, to publish on every push.",
  },
  POOL_INVITE_KEY: {
    pt: "Assina os convites que deixam outros PCs entrarem como ajudantes deste servidor.",
    en: "Signs the invites that let other PCs join as this server's helpers.",
  },
  FEDERATION_CLUSTER_KEY: {
    pt: "Chave compartilhada com o servidor pareado: cifra e assina o que os dois trocam. Precisa ser igual nos dois.",
    en: "Key shared with the paired server: encrypts and signs what the two exchange. Must match on both.",
  },
  POSTGRES_ROOT_PASSWORD: {
    pt: "Senha de administrador do Postgres compartilhado. Cada app recebe o próprio usuário; esta só o PaaSMCP usa.",
    en: "Administrator password of the shared Postgres. Each app gets its own user; only PaaSMCP uses this one.",
  },
  REDIS_ROOT_PASSWORD: {
    pt: "Senha do Redis compartilhado pelos apps.",
    en: "Password of the Redis the apps share.",
  },
  MIRROR_REPLICATOR_PASSWORD: {
    pt: "Senha do usuário que copia o banco Postgres para o servidor espelho (cópia ao vivo).",
    en: "Password of the user that copies the Postgres database to the mirror server (live copy).",
  },
  GARAGE_RPC_SECRET: {
    pt: "Segredo interno do Garage, o guardador de arquivos (S3) deste servidor. Não precisa mexer.",
    en: "Internal secret of Garage, this server's file store (S3). No need to touch it.",
  },
  GARAGE_ADMIN_TOKEN: {
    pt: "Token de administração do Garage: o PaaSMCP o usa para criar pastas (buckets) e chaves de arquivos.",
    en: "Garage admin token: PaaSMCP uses it to create buckets and file keys.",
  },
  BACKUP_S3_PROVIDER: {
    pt: "Serviço onde ficam as cópias fora do servidor (Backblaze, R2, outro PaaSMCP...).",
    en: "Service holding the off-server backups (Backblaze, R2, another PaaSMCP...).",
  },
  BACKUP_S3_ENDPOINT: {
    pt: "Endereço do serviço das cópias fora do servidor.",
    en: "Address of the off-server backup service.",
  },
  BACKUP_S3_BUCKET: {
    pt: "Pasta (bucket) que recebe as cópias fora do servidor.",
    en: "Bucket that receives the off-server backups.",
  },
  BACKUP_S3_ACCESS_KEY_ID: {
    pt: "Identificação da chave de acesso às cópias fora do servidor.",
    en: "Access key id for the off-server backups.",
  },
  BACKUP_S3_SECRET_ACCESS_KEY: {
    pt: "Parte secreta da chave de acesso às cópias fora do servidor.",
    en: "Secret part of the access key for the off-server backups.",
  },
  BACKUP_S3_REGION: {
    pt: "Região do serviço das cópias fora do servidor.",
    en: "Region of the off-server backup service.",
  },
  BACKUP_S3_PREFIX: {
    pt: "Subpasta, dentro do bucket, onde as cópias ficam.",
    en: "Folder inside the bucket where backups go.",
  },
  BACKUP_S3_TESTED_AT: {
    pt: "Quando o destino das cópias foi testado com sucesso pela última vez. Não é segredo.",
    en: "When the backup destination last passed a test. Not a secret.",
  },
  NOTIFY_URL: {
    pt: "Endereço que recebe os avisos do servidor (Telegram, Discord, ntfy...).",
    en: "Address that receives the server's alerts (Telegram, Discord, ntfy...).",
  },
  NOTIFY_ON_SUCCESS: {
    pt: "1 para avisar também quando dá certo, 0 só quando algo falha.",
    en: "1 to also notify on success, 0 only on failures.",
  },
  NOTIFY_LANG: {
    pt: "Idioma dos avisos (pt ou en).",
    en: "Language of the alerts (pt or en).",
  },
  EMAIL_SMTP_HOST: {
    pt: "Servidor de envio de e-mail (SMTP) que os apps usam.",
    en: "Email sending server (SMTP) the apps use.",
  },
  EMAIL_SMTP_PORT: { pt: "Porta do servidor de e-mail.", en: "Email server port." },
  EMAIL_SMTP_USER: { pt: "Usuário do servidor de e-mail.", en: "Email server user." },
  EMAIL_SMTP_PASSWORD: { pt: "Senha do servidor de e-mail.", en: "Email server password." },
  EMAIL_FROM_DOMAIN: {
    pt: "Domínio dos remetentes: cada app envia como app@este-domínio.",
    en: "Senders' domain: each app sends as app@this-domain.",
  },
  EMAIL_API_KEY: {
    pt: "Chave da API HTTP de e-mail (Brevo), para hospedagens que bloqueiam SMTP.",
    en: "Email HTTP API key (Brevo), for hosts that block SMTP.",
  },
};

const APP_KEYS: Record<string, Doc> = {
  DATABASE_URL: {
    pt: "Endereço completo do banco Postgres do app (usuário e senha inclusos). Criado pelo PaaSMCP.",
    en: "Full address of the app's Postgres database (user and password included). Made by PaaSMCP.",
  },
  POSTGRES_URL: {
    pt: "O mesmo endereço do banco, com o nome que algumas bibliotecas procuram.",
    en: "The same database address, under the name some libraries look for.",
  },
  LOCAL_DATABASE_URL: {
    pt: "Endereço do banco para usar no próprio servidor (fora do contêiner), por exemplo para migrações.",
    en: "Database address to use on the server itself (outside the container), e.g. for migrations.",
  },
  REDIS_URL: {
    pt: "Endereço do Redis do app (senha inclusa). Criado pelo PaaSMCP.",
    en: "Address of the app's Redis (password included). Made by PaaSMCP.",
  },
  LOCAL_REDIS_URL: {
    pt: "Endereço do Redis para usar no próprio servidor, fora do contêiner.",
    en: "Redis address to use on the server itself, outside the container.",
  },
  S3_ENDPOINT: { pt: "Endereço do guardador de arquivos (S3) do app.", en: "Address of the app's file store (S3)." },
  S3_BUCKET: { pt: "Pasta (bucket) de arquivos do app.", en: "The app's file bucket." },
  S3_ACCESS_KEY_ID: { pt: "Identificação da chave de arquivos do app.", en: "The app's file access key id." },
  S3_SECRET_ACCESS_KEY: { pt: "Parte secreta da chave de arquivos do app.", en: "Secret part of the app's file key." },
  S3_REGION: { pt: "Região do guardador de arquivos.", en: "File store region." },
  AWS_ENDPOINT_URL_S3: {
    pt: "Mesmo endereço de arquivos, com o nome que as bibliotecas da AWS leem sozinhas.",
    en: "The same file address, under the name AWS libraries read on their own.",
  },
  AWS_ACCESS_KEY_ID: {
    pt: "Mesma chave de arquivos, com o nome que as bibliotecas da AWS leem sozinhas.",
    en: "The same file key, under the name AWS libraries read on their own.",
  },
  AWS_SECRET_ACCESS_KEY: {
    pt: "Parte secreta da mesma chave de arquivos, no nome das bibliotecas da AWS.",
    en: "Secret part of the same file key, under the AWS libraries' name.",
  },
  AWS_REGION: { pt: "Região, no nome das bibliotecas da AWS.", en: "Region, under the AWS libraries' name." },
  SMTP_HOST: { pt: "Servidor de e-mail que o app usa para enviar.", en: "Email server the app sends through." },
  SMTP_PORT: { pt: "Porta do servidor de e-mail.", en: "Email server port." },
  SMTP_USER: { pt: "Usuário do servidor de e-mail.", en: "Email server user." },
  SMTP_PASSWORD: { pt: "Senha do servidor de e-mail.", en: "Email server password." },
  SMTP_SECURE: { pt: "true quando a conexão de e-mail já começa cifrada (porta 465).", en: "true when the email connection starts encrypted (port 465)." },
  EMAIL_FROM: { pt: "Remetente dos e-mails do app.", en: "Sender of the app's emails." },
  DEFAULT_FROM_EMAIL: { pt: "O mesmo remetente, no nome que o Django procura.", en: "The same sender, under the name Django looks for." },
  EMAIL_URL: { pt: "Configuração de e-mail inteira em um endereço só (senha inclusa).", en: "The whole email setup as one address (password included)." },
  BREVO_API_KEY: { pt: "Chave da API de e-mail da Brevo, para quando o SMTP está bloqueado.", en: "Brevo email API key, for when SMTP is blocked." },
};

export function suggestedSecretDescription(scope: string, key: string): Doc | undefined {
  const table = sanitizeSlug(scope) === "system" ? SYSTEM_KEYS : APP_KEYS;
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

export interface SecretDetails extends SecretMeta {
  masked: string;
  /** The built-in explanation for keys PaaSMCP itself creates, shown when nobody wrote one. */
  suggested?: { pt: string; en: string };
}

/** Masked values plus description, dates and the built-in suggestion, for screens and tools. */
export function listSecretDetails(scope: string): Record<string, SecretDetails> {
  const current = getSecrets(scope);
  const meta = getSecretMeta(scope);
  const out: Record<string, SecretDetails> = {};
  for (const [k, v] of Object.entries(current)) {
    const m = meta[k] || {};
    const suggested = suggestedSecretDescription(scope, k);
    out[k] = {
      masked: maskSecretValue(v),
      ...(m.description ? { description: m.description } : {}),
      ...(m.createdAt ? { createdAt: m.createdAt } : {}),
      ...(m.updatedAt ? { updatedAt: m.updatedAt } : {}),
      ...(suggested ? { suggested } : {}),
    };
  }
  return out;
}
