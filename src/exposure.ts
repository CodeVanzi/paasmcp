import { execFileSync } from "node:child_process";
import { appServiceUrl, loadState, sanitizeSlug, saveState } from "./config.js";
import { syncHomepageDashboard } from "./deployer.js";
import { assessRisk, audit } from "./guard.js";
import { getSecrets } from "./vault.js";

/** A problem the person can fix; `pt` is the same text in Portuguese for the dashboard. */
export class ExposeError extends Error {
  constructor(message: string, readonly pt: string) {
    super(message);
    this.name = "ExposeError";
  }
}

/** Pure (tested): turns a failed `tailscale serve` into what the person can do about it. */
export function tailscaleServeError(err: unknown, tsPort: number, localPort: number, turnOff = false): Error {
  const e = err as { code?: string; stderr?: Buffer | string; message?: string };
  const out = `${e?.stderr ? String(e.stderr) : ""} ${e?.message || ""}`;
  const byHand = turnOff ? `sudo tailscale serve --https=${tsPort} off` : `sudo tailscale serve --bg --https=${tsPort} http://127.0.0.1:${localPort}`;
  if (e?.code === "ENOENT" || /tailscaled\.sock|failed to connect to local Tailscale|is Tailscale running/i.test(out)) {
    return new ExposeError(
      `Tailscale is not reachable from here. Check that Tailscale is installed and logged in on the server ('tailscale status'), then restart the dashboard ('paasmcp dashboard'), or run on the server: ${byHand}`,
      `O Tailscale não foi encontrado daqui. Confira no servidor se ele está instalado e conectado ('tailscale status') e reinicie o painel ('paasmcp dashboard'), ou rode no servidor: ${byHand}`
    );
  }
  if (/serve.*(not enabled|disabled)|HTTPS.*(not enabled|disabled)|enable HTTPS/i.test(out)) {
    return new ExposeError(
      "Tailscale Serve needs HTTPS turned on for your tailnet: in the Tailscale admin console, open DNS and enable MagicDNS and HTTPS Certificates, then try again.",
      "O Tailscale Serve precisa do HTTPS ligado na sua tailnet: no painel do Tailscale (login.tailscale.com), abra DNS e ligue MagicDNS e HTTPS Certificates. Depois tente de novo."
    );
  }
  return err instanceof Error ? err : new Error(String(err));
}

export interface ExposeOptions {
  appName: string;
  subdomain?: string;
  mode: "public" | "zero-trust" | "tailscale";
  tailscalePort?: number;
}

function detectTailscaleDomain(configured?: string): string {
  if (configured) return configured;
  try {
    const out = execFileSync("tailscale", ["status", "--json"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const parsed = JSON.parse(out) as { Self?: { DNSName?: string } };
    if (parsed.Self?.DNSName) {
      return parsed.Self.DNSName.replace(/\.$/, "");
    }
  } catch {
    // fallback
  }
  return "localhost.ts.net";
}

export async function exposeApplication(opts: ExposeOptions): Promise<{
  url: string;
  mode: string;
  details: string;
}> {
  const slug = sanitizeSlug(opts.appName);
  assessRisk("app.expose", { appName: slug, mode: opts.mode }); // throws for forbidden exposures, whatever the caller
  const state = loadState();
  const app = state.apps[slug];
  if (!app) {
    throw new Error(`Application '${slug}' not found. Deploy it first.`);
  }

  if (opts.mode === "tailscale") {
    const tsPort = opts.tailscalePort || 8460 + (app.localPort - 4000);
    const tsDomain = detectTailscaleDomain(state.tailscaleDomain);
    try {
      execFileSync("tailscale", ["serve", "--bg", `--https=${tsPort}`, `http://127.0.0.1:${app.localPort}`], { stdio: "pipe", timeout: 60_000 });
    } catch (err) {
      throw tailscaleServeError(err, tsPort, app.localPort);
    }
    const url = `https://${tsDomain}:${tsPort}`;
    const existingIdx = app.domains.findIndex((d) => d.url === url);
    if (existingIdx === -1) {
      app.domains.push({
        hostname: `${tsDomain}:${tsPort}`,
        mode: "tailscale",
        url,
      });
    }
    saveState(state);
    syncHomepageDashboard();
    return {
      url,
      mode: "tailscale",
      details: `Exposed on Tailnet via Tailscale Serve (${url} -> 127.0.0.1:${app.localPort}).`,
    };
  }

  // Cloudflare Tunnel exposure
  const { accountId, tunnelId, baseDomain, zeroTrustEmails, zeroTrustPolicyName } =
    state.cloudflare;

  if (!accountId || !tunnelId || !baseDomain || baseDomain === "example.com") {
    throw new Error(
      "Cloudflare Tunnel parameters (accountId, tunnelId, baseDomain) are not configured. Run paas_configure or 'paasmcp config --account-id <id> --tunnel-id <id> --domain <domain>'."
    );
  }

  const subdomain = sanitizeSlug(opts.subdomain || slug);
  const fullHostname = subdomain.endsWith(baseDomain)
    ? subdomain
    : `${subdomain}.${baseDomain}`;
  // With copies on helpers, visits go through the pool balancer here (pool.ts).
  const internalServiceUrl = appServiceUrl(app);

  const sysSecrets = getSecrets("system");
  const cfToken = sysSecrets.CF_API_TOKEN || process.env.CF_API_TOKEN;
  if (!cfToken) {
    throw new Error(
      `Missing 'CF_API_TOKEN' in the 'system' vault. Store a Cloudflare API Token with 'Cloudflare Tunnel:Edit', 'DNS:Edit', and 'Access: Apps and Policies:Edit' permissions using paas_secret_set(scope="system", secrets={"CF_API_TOKEN": "..."}).`
    );
  }

  const headers = {
    Authorization: `Bearer ${cfToken}`,
    "Content-Type": "application/json",
  };

  // 1. Fetch current Cloudflare Tunnel configuration
  const getCfgRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`,
    { headers }
  );
  if (!getCfgRes.ok) {
    throw new Error(
      `Failed to read Cloudflare Tunnel config (${getCfgRes.status}): ${await getCfgRes.text()}`
    );
  }
  const cfgData = (await getCfgRes.json()) as {
    result?: {
      config?: {
        ingress?: Array<{
          hostname?: string;
          service: string;
          originRequest?: Record<string, unknown>;
        }>;
      };
    };
  };

  const currentIngress = cfgData.result?.config?.ingress || [
    { service: "http_status:404" },
  ];

  const catchAll =
    currentIngress.find((r) => !r.hostname) || { service: "http_status:404" };
  const hostRules = currentIngress.filter(
    (r) => r.hostname && r.hostname !== fullHostname
  );

  hostRules.push({
    hostname: fullHostname,
    service: internalServiceUrl,
    originRequest: {},
  });

  const updatedIngress = [...hostRules, catchAll];

  const putCfgRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`,
    {
      method: "PUT",
      headers,
      body: JSON.stringify({
        config: {
          ingress: updatedIngress,
        },
      }),
    }
  );
  if (!putCfgRes.ok) {
    throw new Error(
      `Failed to update Cloudflare Tunnel ingress (${putCfgRes.status}): ${await putCfgRes.text()}`
    );
  }

  // 2. Ensure CNAME DNS record exists in the Cloudflare Zone for baseDomain
  const zoneRes = await fetch(
    `https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(baseDomain)}`,
    { headers }
  );
  const zoneData = (await zoneRes.json()) as { result?: Array<{ id: string }> };
  const zoneId = zoneData.result?.[0]?.id;
  if (!zoneId) {
    throw new Error(`Could not find Cloudflare Zone ID for domain '${baseDomain}'.`);
  }

  const existingDnsRes = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${encodeURIComponent(fullHostname)}`,
    { headers }
  );
  const existingDnsData = (await existingDnsRes.json()) as {
    result?: Array<{ id: string }>;
  };

  // A hostname already served by the tunnel for apps on both servers stays on it (activetunnel.ts).
  const onSecond = app.activeActive && state.activeTunnel?.routes[fullHostname] ? state.activeTunnel.tunnelId : undefined;
  const cnameTarget = `${onSecond || tunnelId}.cfargotunnel.com`;
  if (existingDnsData.result && existingDnsData.result.length > 0) {
    const recordId = existingDnsData.result[0].id;
    await fetch(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${recordId}`,
      {
        method: "PUT",
        headers,
        body: JSON.stringify({
          type: "CNAME",
          name: fullHostname,
          content: cnameTarget,
          proxied: true,
        }),
      }
    );
  } else {
    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        type: "CNAME",
        name: fullHostname,
        content: cnameTarget,
        proxied: true,
      }),
    });
  }

  // 3. Optional Zero Trust Access protection
  let zeroTrustStatus = "Public access enabled (no Zero Trust gate).";
  if (opts.mode === "zero-trust") {
    const allowedEmails = zeroTrustEmails || [];
    if (allowedEmails.length === 0) {
      zeroTrustStatus =
        "Tunnel & DNS configured. Warning: No zeroTrustEmails configured in state; configure emails via paas_configure to attach an email OTP Access policy.";
    } else {
      const appsRes = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/access/apps`,
        { headers }
      );
      if (appsRes.ok) {
        const appsData = (await appsRes.json()) as {
          result?: Array<{ id: string; domain: string }>;
        };
        const alreadyExists = appsData.result?.some((a) => a.domain === fullHostname);
        if (!alreadyExists) {
          const createAppRes = await fetch(
            `https://api.cloudflare.com/client/v4/accounts/${accountId}/access/apps`,
            {
              method: "POST",
              headers,
              body: JSON.stringify({
                name: `PaaSMCP - ${slug}`,
                domain: fullHostname,
                type: "self_hosted",
                session_duration: "24h",
                policies: [
                  {
                    name: zeroTrustPolicyName || "PaaSMCP Zero Trust",
                    decision: "allow",
                    include: allowedEmails.map((email) => ({
                      email: { email },
                    })),
                  },
                ],
              }),
            }
          );
          if (createAppRes.ok) {
            zeroTrustStatus = `Protected with Cloudflare Zero Trust Access (OTP policy for ${allowedEmails.join(", ")}).`;
          } else {
            zeroTrustStatus = `Tunnel & DNS configured; Zero Trust app creation returned ${createAppRes.status}.`;
          }
        } else {
          zeroTrustStatus =
            "Cloudflare Zero Trust Access application already active for this domain.";
        }
      }
    }
  }

  const publicUrl = `https://${fullHostname}`;
  const filteredDomains = app.domains.filter((d) => d.hostname !== fullHostname);
  filteredDomains.unshift({
    hostname: fullHostname,
    mode: opts.mode,
    url: publicUrl,
  });
  app.domains = filteredDomains;
  saveState(state);
  syncHomepageDashboard();

  // An app that runs on both servers moves to their tunnel once its copy there answers (activetunnel.ts).
  let tunnelNote = "";
  if (app.activeActive && state.activeTunnel) {
    const { routeActiveTunnel } = await import("./activetunnel.js");
    const r = await routeActiveTunnel().catch((err: unknown) => ({ error: err instanceof Error ? err.message : String(err) }));
    tunnelNote = "error" in r ? ` Tunnel for apps on both servers: ${r.error}` : r.routed.includes(fullHostname) ? " Served by both servers (their tunnel)." : " Moves to the tunnel of both servers once the other server's copy answers.";
  }

  return {
    url: publicUrl,
    mode: opts.mode,
    details: `Cloudflare Tunnel route ${publicUrl} -> ${internalServiceUrl} configured with proxied CNAME DNS. ${zeroTrustStatus}${tunnelNote}`,
  };
}

// ---- Taking an address off the air (dashboard: Make reachable → Published addresses) ----

const cfApi = () => (process.env.PAASMCP_CF_API_URL || "https://api.cloudflare.com/client/v4").replace(/\/+$/, "");

/**
 * Removes one of an app's addresses: its tunnel route, its DNS record (only a CNAME that points to a
 * Cloudflare tunnel, so nothing else of the person's is touched) and the email gate PaaSMCP created
 * for it; with Tailscale, the `tailscale serve` entry. Only addresses saved on the app can be removed.
 */
export async function removeAppAddress(appName: string, hostname: string): Promise<{ removed: string; notes: string[] }> {
  const slug = sanitizeSlug(appName);
  const state = loadState();
  const app = state.apps[slug];
  if (!app) throw new Error(`Application '${slug}' not found.`);
  const entry = app.domains.find((d) => d.hostname === hostname);
  if (!entry) {
    throw new ExposeError(`'${hostname}' is not an address of ${slug}.`, `'${hostname}' não é um endereço de ${slug}.`);
  }
  const notes: string[] = [];

  if (entry.mode === "tailscale") {
    const port = Number(hostname.split(":").pop());
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`No port in '${hostname}'.`);
    try {
      execFileSync("tailscale", ["serve", `--https=${port}`, "off"], { stdio: "pipe", timeout: 60_000 });
    } catch (err) {
      const e = err as { stderr?: Buffer | string };
      // Already gone (removed by hand): the saved address goes too.
      if (!/not found|no serve config|nothing to remove|handler does not exist/i.test(String(e?.stderr || ""))) {
        throw tailscaleServeError(err, port, app.localPort, true);
      }
      notes.push("Tailscale had no entry for it any more.");
    }
  } else if (entry.mode === "public" || entry.mode === "zero-trust") {
    const { accountId, tunnelId, baseDomain } = state.cloudflare;
    const token = getSecrets("system").CF_API_TOKEN || process.env.CF_API_TOKEN;
    if (!accountId || !tunnelId || !baseDomain || !token) {
      throw new ExposeError(
        "Cloudflare is not connected, so the address cannot be removed from here (Connections → Domain).",
        "O Cloudflare não está conectado, então o endereço não pode ser tirado daqui (Conexões → Domínio)."
      );
    }
    const cf = async <T>(method: string, route: string, body?: unknown): Promise<T> => {
      let res: Response;
      try {
        res = await fetch(`${cfApi()}${route}`, {
          method,
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(20_000),
        });
      } catch (err) {
        throw new ExposeError(
          `Could not reach Cloudflare (${err instanceof Error ? err.message : String(err)}). The address stays listed; try again in a moment.`,
          "Não deu para falar com o Cloudflare agora (a internet do servidor caiu?). O endereço continua na lista; tente de novo daqui a pouco."
        );
      }
      const data = (await res.json().catch(() => ({}))) as { result?: T };
      if (!res.ok) throw new Error(`Cloudflare ${method} ${route.split("?")[0]}: HTTP ${res.status}`);
      return data.result as T;
    };

    // An app on both servers: forget the address first, so their tunnel hands it back to the main one.
    if (state.activeTunnel?.routes[hostname]) {
      app.domains = app.domains.filter((d) => d.hostname !== hostname);
      saveState(state);
      try {
        const { routeActiveTunnel } = await import("./activetunnel.js");
        await routeActiveTunnel();
      } catch (err) {
        const back = loadState();
        if (back.apps[slug] && !back.apps[slug].domains.some((d) => d.hostname === hostname)) {
          back.apps[slug].domains.push(entry);
          saveState(back);
        }
        throw err;
      }
    }

    type Ingress = { hostname?: string; service: string; [k: string]: unknown };
    const cfg = await cf<{ config?: { ingress?: Ingress[]; [k: string]: unknown } }>("GET", `/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`);
    const config = cfg?.config || {};
    const ingress = config.ingress || [];
    if (ingress.some((r) => r.hostname === hostname)) {
      const kept = ingress.filter((r) => r.hostname !== hostname);
      if (!kept.some((r) => !r.hostname)) kept.push({ service: "http_status:404" });
      await cf("PUT", `/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`, { config: { ...config, ingress: kept } });
    }

    const zones = await cf<Array<{ id: string }>>("GET", `/zones?name=${encodeURIComponent(baseDomain)}`);
    const zoneId = zones?.[0]?.id;
    if (zoneId) {
      const records = await cf<Array<{ id: string; type: string; content: string }>>("GET", `/zones/${zoneId}/dns_records?name=${encodeURIComponent(hostname)}`);
      for (const r of records || []) {
        if (r.type === "CNAME" && /\.cfargotunnel\.com$/i.test(r.content)) await cf("DELETE", `/zones/${zoneId}/dns_records/${encodeURIComponent(r.id)}`);
        else notes.push(`DNS record ${r.type} ${hostname} was not created by PaaSMCP and was left alone.`);
      }
    }

    try {
      const accessApps = await cf<Array<{ id: string; domain: string; name: string }>>("GET", `/accounts/${accountId}/access/apps`);
      for (const a of accessApps || []) {
        if (a.domain === hostname && /^PaaSMCP\b/.test(a.name)) await cf("DELETE", `/accounts/${accountId}/access/apps/${encodeURIComponent(a.id)}`);
      }
    } catch {
      if (entry.mode === "zero-trust") notes.push("The email gate could not be checked (token without Access permission); remove it in Cloudflare Zero Trust → Access if it is still listed.");
    }
  }

  const latest = loadState();
  const a = latest.apps[slug];
  if (a && a.domains.some((d) => d.hostname === hostname)) {
    a.domains = a.domains.filter((d) => d.hostname !== hostname);
    saveState(latest);
  }
  syncHomepageDashboard();
  audit({ event: "app.unexpose", app: slug, hostname, mode: entry.mode });
  return { removed: entry.url, notes };
}
