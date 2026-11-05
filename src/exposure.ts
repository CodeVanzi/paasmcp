import { execFileSync } from "node:child_process";
import { appServiceUrl, loadState, sanitizeSlug, saveState } from "./config.js";
import { syncHomepageDashboard } from "./deployer.js";
import { assessRisk } from "./guard.js";
import { getSecrets } from "./vault.js";

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
    execFileSync(
      "tailscale",
      [
        "serve",
        "--bg",
        `--https=${tsPort}`,
        `http://127.0.0.1:${app.localPort}`,
      ],
      { stdio: "pipe" }
    );
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
