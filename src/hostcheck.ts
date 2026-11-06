// Server checks for `paasmcp doctor` (no app): things in the host around PaaSMCP that break it
// without any PaaSMCP bug. Found on a real homelab: a DNS server running as a container on the same
// host (when it does not come back, the host cannot resolve names and Cloudflare Tunnel, image pulls
// and builds stop), Watchtower restarting PaaSMCP's containers on its own, and Docker running out of
// its 172.17-172.31 networks and moving to 192.168.x.0/20, which can cover the home LAN.
//
// Read-only: nothing here changes the host. Environment values of other containers are never read.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { DOCKER_NETWORK, loadState, WATCHTOWER_OFF_LABEL } from "./config.js";

export interface HostDiagnostic {
  target: string;
  severity: "healthy" | "warning" | "critical";
  summary: string;
  recommendation?: string;
  details?: Record<string, unknown>;
  /** Stable id of this finding plus its values, so the dashboard can say it in the screen's language. */
  code?: string;
  vars?: Record<string, string | number>;
}

const TARGET = "server";
const DNS_PROBE_HOST = "registry-1.docker.io";

// ---------- pure helpers (tested) ----------

function ipv4ToInt(ip: string): number | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return undefined;
    n = n * 256 + Number(p);
  }
  return n;
}

/** Parses "a.b.c.d/len" into a [first, last] range of integers; undefined for IPv6 or garbage. */
export function cidrRange(cidr: string): [number, number] | undefined {
  const [ip, lenRaw] = cidr.trim().split("/");
  const base = ipv4ToInt(ip);
  const len = Number(lenRaw);
  if (base === undefined || !Number.isInteger(len) || len < 0 || len > 32) return undefined;
  const size = 2 ** (32 - len);
  const first = Math.floor(base / size) * size;
  return [first, first + size - 1];
}

export function cidrsOverlap(a: string, b: string): boolean {
  const ra = cidrRange(a);
  const rb = cidrRange(b);
  return Boolean(ra && rb && ra[0] <= rb[1] && rb[0] <= ra[1]);
}

/**
 * How many of Docker's default 172.17-172.31 /16 networks are taken. Docker picks the next free one
 * for each new network; after the 15th it takes 192.168.0.0/20, 192.168.16.0/20 and so on.
 */
export function defaultPoolUse(subnets: string[]): { used: number; total: number } {
  const taken = new Set<number>();
  for (const s of subnets) {
    const r = cidrRange(s);
    if (!r) continue;
    for (let second = 17; second <= 31; second++) {
      const block = cidrRange(`172.${second}.0.0/16`)!;
      if (r[0] <= block[1] && block[0] <= r[1]) taken.add(second);
    }
  }
  return { used: taken.size, total: 15 };
}

/** Docker subnets that cover one of the host's own networks (LAN or Tailscale). */
export function overlappingSubnets(dockerSubnets: string[], hostNets: string[]): { docker: string; host: string }[] {
  const out: { docker: string; host: string }[] = [];
  for (const d of dockerSubnets) for (const h of hostNets) if (cidrsOverlap(d, h)) out.push({ docker: d, host: h });
  return out;
}

// ---------- probes ----------

function docker(args: string[]): string | undefined {
  try {
    return execFileSync("docker", args, { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 10_000 });
  } catch {
    return undefined;
  }
}

function inContainer(): boolean {
  return fs.existsSync("/.dockerenv");
}

/** Name resolution, in a child process so a hung resolver cannot hang the doctor. */
function dnsWorks(): boolean {
  const r = spawnSync(
    process.execPath,
    ["-e", `require("node:dns").lookup(${JSON.stringify(DNS_PROBE_HOST)}, (e) => process.exit(e ? 1 : 0))`],
    { stdio: "ignore", timeout: 8000 }
  );
  return r.status === 0;
}

function checkDns(): HostDiagnostic {
  if (dnsWorks()) {
    return { target: TARGET, severity: "healthy", summary: `This server resolves names (${DNS_PROBE_HOST}).`, code: "dns_ok" };
  }
  return {
    target: TARGET,
    severity: "critical",
    summary: `This server cannot resolve names (${DNS_PROBE_HOST}). Cloudflare Tunnel, deploys, image pulls and the helper pool stop working without DNS.`,
    recommendation:
      "If the DNS server runs on this same machine (AdGuard Home, Pi-hole), check that it is up, and give the host a fallback so it never depends on it alone: in /etc/systemd/resolved.conf set FallbackDNS=1.1.1.1 9.9.9.9 and make /etc/resolv.conf point to systemd-resolved.",
    code: "dns_fail",
  };
}

interface ContainerRow {
  name: string;
  image: string;
  labelOff: boolean;
}

function listContainers(): ContainerRow[] | undefined {
  const out = docker(["ps", "--format", `{{.Names}}\t{{.Image}}\t{{.Label "com.centurylinklabs.watchtower.enable"}}`]);
  if (out === undefined) return undefined;
  return out
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [name, image, label] = line.split("\t");
      return { name, image, labelOff: label === "false" };
    });
}

function watchtowerLabelMode(name: string): boolean {
  // Only this one key is looked at; other variables (notification URLs, tokens) are never printed.
  const out = docker(["inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", name]) || "";
  if (out.split("\n").some((l) => /^WATCHTOWER_LABEL_ENABLE=(true|1)$/i.test(l.trim()))) return true;
  const cmd = docker(["inspect", "--format", "{{json .Config.Cmd}}", name]) || "";
  return /"--label-enable(=true)?"/.test(cmd);
}

function checkWatchtower(rows: ContainerRow[]): HostDiagnostic | undefined {
  const watchtowers = rows.filter((r) => /(^|\/)watchtower(:|$)/.test(r.image) || /watchtower/i.test(r.name));
  if (!watchtowers.length) return undefined;
  if (watchtowers.every((w) => watchtowerLabelMode(w.name))) {
    return {
      target: TARGET,
      severity: "healthy",
      summary: "Watchtower runs here, but only updates containers marked for it, so it leaves PaaSMCP alone.",
      code: "wt_label_mode",
    };
  }
  const state = loadState();
  const ours = new Set<string>(Object.values(state.apps).map((a) => a.containerName));
  const unlabeled = rows
    .filter((r) => (r.name.startsWith("paasmcp-") || ours.has(r.name)) && !r.labelOff)
    .map((r) => r.name);
  if (!unlabeled.length) {
    return {
      target: TARGET,
      severity: "healthy",
      summary: "Watchtower runs here and every PaaSMCP container carries the label that tells it to skip them.",
      code: "wt_all_labeled",
    };
  }
  return {
    target: TARGET,
    severity: "warning",
    summary: `Watchtower runs here and may restart ${unlabeled.length} PaaSMCP container(s) on its own: ${unlabeled.slice(0, 8).join(", ")}${unlabeled.length > 8 ? ", ..." : ""}. A surprise restart of Postgres or an app looks like an outage to the active-active watch and the scale decider.`,
    recommendation: `New PaaSMCP containers get the label ${WATCHTOWER_OFF_LABEL}; these older ones get it the next time PaaSMCP recreates them (an app on its next deploy). Until then, the simplest and safest fix: run Watchtower with WATCHTOWER_LABEL_ENABLE=true (or --label-enable) and label only the services you want it to update. Pause it while testing active-active or scaling.`,
    details: { containers: unlabeled },
    code: "wt_unlabeled",
    vars: { count: unlabeled.length, names: unlabeled.slice(0, 8).join(", ") + (unlabeled.length > 8 ? ", ..." : "") },
  };
}

function hostNetworks(): string[] {
  const nets: string[] = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (/^(docker|br-|veth|lo)/.test(name)) continue;
    for (const a of addrs || []) if (a.family === "IPv4" && !a.internal && a.cidr) nets.push(a.cidr);
  }
  return nets;
}

function checkNetworks(): HostDiagnostic | undefined {
  const ids = docker(["network", "ls", "-q"]);
  if (ids === undefined) return undefined;
  const list = ids.split("\n").filter(Boolean);
  if (!list.length) return undefined;
  const out = docker(["network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", ...list]) || "";
  const subnets = out.split(/\s+/).filter((s) => s.includes("/") && !s.includes(":"));
  const hostNets = inContainer() ? [] : [...hostNetworks(), "100.64.0.0/10"];
  const clash = overlappingSubnets(subnets, hostNets);
  if (clash.length) {
    return {
      target: TARGET,
      severity: "critical",
      summary: `A Docker network covers one of this server's own networks: ${clash.map((c) => `${c.docker} over ${c.host}`).join(", ")}. Traffic to those addresses goes into Docker instead of the LAN or Tailscale.`,
      recommendation:
        'Move Docker to a range of its own: in /etc/docker/daemon.json add "default-address-pools": [{"base": "10.200.0.0/16", "size": 24}], restart Docker in a quiet moment, then recreate the network that clashes.',
      details: { clash },
      code: "net_clash",
      vars: { clash: clash.map((c) => `${c.docker} / ${c.host}`).join(", ") },
    };
  }
  const pool = defaultPoolUse(subnets);
  if (pool.used >= pool.total - 3) {
    return {
      target: TARGET,
      severity: "warning",
      summary: `Docker has used ${pool.used} of its ${pool.total} default networks (172.17-172.31). The next ones come from 192.168.x.0/20, which can cover a home LAN such as 192.168.31.0/24.`,
      recommendation:
        'Give Docker a range of its own before that happens: in /etc/docker/daemon.json add "default-address-pools": [{"base": "10.200.0.0/16", "size": 24}] and restart Docker in a quiet moment. It only affects networks created afterwards.',
      details: { used: pool.used, total: pool.total },
      code: "net_pool",
      vars: { used: pool.used, total: pool.total },
    };
  }
  return undefined;
}

function checkTunnelNetwork(rows: ContainerRow[]): HostDiagnostic | undefined {
  const state = loadState();
  if (!state.cloudflare?.tunnelId) return undefined;
  const tunnels = rows.filter((r) => /cloudflared/.test(r.image) && r.name !== "paasmcp-tunnel-active");
  if (!tunnels.length) return undefined; // cloudflared may run as a system service: it then reaches apps another way
  const onNet = tunnels.filter((t) => {
    const nets = docker(["inspect", "--format", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", t.name]) || "";
    return nets.split(/\s+/).includes(DOCKER_NETWORK);
  });
  if (onNet.length) return undefined;
  return {
    target: TARGET,
    severity: "warning",
    summary: `The Cloudflare Tunnel container (${tunnels.map((t) => t.name).join(", ")}) is not on the '${DOCKER_NETWORK}' network. PaaSMCP sends public addresses to apps by container name on that network, so they would answer 502.`,
    recommendation: `Connect it: docker network connect ${DOCKER_NETWORK} ${tunnels[0].name} (and add the network to its compose file so it stays after a restart).`,
    code: "tunnel_net",
    vars: { names: tunnels.map((t) => t.name).join(", "), network: DOCKER_NETWORK, first: tunnels[0].name },
  };
}

/** Server checks for the doctor. Each check is best effort: a missing tool just skips it. */
export function checkHost(): HostDiagnostic[] {
  if (process.env.PAASMCP_OFFLINE_TEST === "1") return [];
  const out: HostDiagnostic[] = [checkDns()];
  const rows = listContainers();
  if (rows) {
    const w = checkWatchtower(rows);
    if (w) out.push(w);
    const t = checkTunnelNetwork(rows);
    if (t) out.push(t);
  }
  const n = checkNetworks();
  if (n) out.push(n);
  return out;
}
