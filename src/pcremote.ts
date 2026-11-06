import { ChildProcess, execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadState, sanitizeSlug, withStateLock } from "./config.js";
import { publicRepoUrl } from "./arbiter.js";
import { audit } from "./guard.js";
import { listTailscalePeers } from "./judge.js";
import { INSTALLS_FILE, InstallRecord, listTailnetPcs, readInstalls, sshBanner, sshKind } from "./pcinstall.js";
import { followedCode, originOf, readFollow } from "./selfupdate.js";

// Installing PaaSMCP on another PC of the Tailscale network, from the dashboard (Connections > PCs).
//
// One job at a time, in two halves:
//   1. connect + check: one SSH connection to the PC's Tailscale IP, by Tailscale SSH (no password; a
//      "check" rule shows a login link that the person opens) or by the PC's password typed once. The
//      connection is kept open (OpenSSH ControlMaster in a private temporary folder) and a read-only
//      script reports the system, the CPU type, free space and what is missing. Nothing changes there.
//   2. install, after the person picks the role and confirms: one root script (packages from the
//      system's apt, Node.js from the distro or the official tarball checked against a pinned SHA-256,
//      the same PaaSMCP commit as this server, `npm ci` + build), then the role: an independent server
//      (`init` + dashboard), a helper (`pool join` with an invite made here, then `pool add`) or the
//      arbiter of this server's pair (`arbiter be-judge` there + pairing by its code here).
//
// What is never kept: the password lives in this process's memory for the job only (sent to `sudo` on
// stdin, to ssh through a one-shot askpass file in a private folder that is deleted right after login);
// no key of this server is left on the PC; the connection closes at the end. The PC's identity: Tailscale
// already ties the IP to that device; when Tailscale knows its SSH host keys they are pinned, otherwise
// the key is accepted on first use and its fingerprint is shown and recorded.

const OFFLINE = () => process.env.PAASMCP_OFFLINE_TEST === "1";

/** Node.js installed when the PC has none (or < 20) and apt has no 20+: official tarball, checksum pinned. */
export const NODE_VERSION = "22.23.4";
export const NODE_SHA256: Record<string, string> = {
  x64: "1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce",
  arm64: "6287aa46b6c375d816e63ae66d024fbbfd70404825aabdfdf898a970871d2f4b",
};
/** Where the code goes on the PC (root-owned, like a system install; the CLI is linked in /usr/local/bin). */
export const REMOTE_DIR = "/opt/paasmcp";

export type InstallRole = "server" | "helper" | "arbiter";
export const ROLES: InstallRole[] = ["server", "helper", "arbiter"];
export type JobPhase = "connecting" | "ready" | "installing" | "done" | "failed" | "cancelled";
export type StepId = "connect" | "check" | "packages" | "node" | "code" | "role" | "finish";
export type StepState = "todo" | "run" | "ok" | "fail" | "skip";
/** Error codes the dashboard turns into sentences. */
export type JobError =
  | "auth" | "hostKey" | "unreachable" | "timeout" | "notSupported" | "noSudo" | "sudoPassword"
  | "busy" | "rateLimited" | "notInList" | "badInput" | "expired" | "remote" | "role" | "cancelled";

export class PcInstallError extends Error {
  constructor(public code: JobError, message: string, public pt: string) {
    super(message);
  }
}
const fail = (code: JobError, en: string, pt: string) => new PcInstallError(code, en, pt);

export interface PcFacts {
  osId: string;
  osLike: string;
  osVersion: string;
  osName: string;
  arch: string;
  user: string;
  root: boolean;
  /** How root is reached: already root, sudo without password, sudo with the password, or not at all. */
  sudo: "root" | "nopass" | "password" | "none";
  memMb: number;
  diskMb: number;
  systemd: boolean;
  git: string;
  node: string;
  npm: string;
  docker: string;
  compose: string;
  tailscale: string;
  sshd: boolean;
  /** PaaSMCP code already in REMOTE_DIR (commit), or "". */
  paasmcp: string;
}

export interface PcPlan {
  supported: boolean;
  problems: ("notDebian" | "arch" | "systemd" | "disk" | "noSudo" | "sudoNeedsPassword" | "tailscale")[];
  warnings: ("diskLow" | "memLow" | "archDiffers" | "hasPaasmcp")[];
  install: ("git" | "docker" | "compose" | "node" | "sshd")[];
  /** Roles this PC can take (arbiter only when this server has a pair). */
  roles: InstallRole[];
  nodeFrom?: "keep" | "apt-or-tarball";
}

export interface PcJob {
  id: string;
  ip: string;
  name: string;
  user: string;
  phase: JobPhase;
  via?: "tailscale" | "password";
  /** A Tailscale SSH "check" rule asks the person to log in: open this link. */
  authUrl?: string;
  hostKey?: { fingerprint: string; pinned: boolean };
  facts?: PcFacts;
  plan?: PcPlan;
  role?: InstallRole;
  steps: { id: StepId; state: StepState }[];
  log: string[];
  error?: string;
  errorPt?: string;
  errorCode?: JobError;
  result?: { role: InstallRole; commit: string; dashboard?: string; helper?: string; arbiterUrl?: string; tailscaleSshOff?: boolean };
  startedAt: string;
  readyUntil?: string;
  finishedAt?: string;
  by: string;
}

// ---------- validation ----------

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
export function validateIp(v: unknown): string {
  const s = String(v ?? "").trim();
  const m = IPV4.exec(s);
  if (!m || m.slice(1).some((x) => Number(x) > 255)) throw fail("badInput", `Invalid IP '${s.slice(0, 40)}'.`, `IP inválido '${s.slice(0, 40)}'.`);
  return s;
}
/** A Linux login name (no options, no shell characters). */
export function validateUser(v: unknown): string {
  const s = String(v ?? "").trim();
  if (!/^[a-z_][a-z0-9_.-]{0,31}$/.test(s)) throw fail("badInput", "Type the user name you log in with on that PC (lower-case letters, digits, _ . -).", "Digite o usuário com que você entra naquele PC (letras minúsculas, números, _ . -).");
  return s;
}
/** Name of the new PaaSMCP (helper name rules: what `pool` accepts). */
export function validatePcName(v: unknown): string {
  const s = sanitizeSlug(String(v ?? "")).slice(0, 32).replace(/-+$/, "");
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(s)) throw fail("badInput", "Give the PC a short name (letters, digits, dashes).", "Dê um nome curto ao PC (letras, números e traços).");
  return s;
}
export function validatePassword(v: unknown): string | undefined {
  if (v === undefined || v === null || v === "") return undefined;
  const s = String(v);
  if (s.length > 256 || /[\r\n\0]/.test(s)) throw fail("badInput", "That password cannot be used here (line breaks or too long).", "Essa senha não dá para usar aqui (tem quebra de linha ou é longa demais).");
  return s;
}

/** Single-quoted for a POSIX shell. */
export const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** Removes the password (and its shell-quoted form) from anything that goes to the log or the screen. */
export function redact(line: string, secret?: string): string {
  if (!secret) return line;
  return line.split(secret).join("•••").split(shq(secret)).join("•••");
}

// ---------- facts (what the read-only check prints) ----------

/** The read-only check, run as the login user. Prints key=value lines only. */
export const CHECK_SCRIPT = `
export LC_ALL=C
kv() { printf '%s=%s\\n' "$1" "$(printf '%s' "$2" | tr -d '\\n\\r=' | cut -c1-120)"; }
if [ -r /etc/os-release ]; then . /etc/os-release; fi
kv osId "\${ID:-}"; kv osLike "\${ID_LIKE:-}"; kv osVersion "\${VERSION_ID:-}"; kv osName "\${PRETTY_NAME:-}"
kv arch "$(uname -m)"; kv user "$(id -un)"; kv uid "$(id -u)"
kv memMb "$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null)"
d=/opt; [ -d "$d" ] || d=/
kv diskMb "$(df -Pm "$d" 2>/dev/null | awk 'NR==2{print $4}')"
[ -d /run/systemd/system ] && kv systemd 1 || kv systemd 0
kv git "$(git --version 2>/dev/null)"
kv node "$(node -v 2>/dev/null)"
kv npm "$(npm -v 2>/dev/null)"
kv docker "$(docker --version 2>/dev/null)"
kv compose "$( (docker compose version --short || sudo -n docker compose version --short) 2>/dev/null | head -1)"
kv tailscale "$(tailscale version 2>/dev/null | head -1)"
{ command -v sshd || test -x /usr/sbin/sshd; } >/dev/null 2>&1 && kv sshd 1 || kv sshd 0
kv paasmcp "$(git -C ${REMOTE_DIR} rev-parse HEAD 2>/dev/null)"
if [ "$(id -u)" = 0 ]; then kv sudo root
elif ! command -v sudo >/dev/null 2>&1; then kv sudo none
elif sudo -n true 2>/dev/null; then kv sudo nopass
else kv sudo password; fi
`;

const str = (v: string | undefined, max = 120) => String(v || "").replace(/[^\x20-\x7e]/g, "").slice(0, max);
const num = (v: string | undefined) => (/^\d{1,9}$/.test(String(v || "")) ? Number(v) : 0);

/** Parses the check's output (untrusted: only known keys, printable ASCII, capped). */
export function parseFacts(out: string): PcFacts {
  const kv: Record<string, string> = {};
  for (const line of out.split("\n").slice(0, 100)) {
    const m = /^([A-Za-z]{2,12})=(.*)$/.exec(line.trim());
    if (m) kv[m[1]] = m[2];
  }
  const sudo = ["root", "nopass", "password", "none"].includes(kv.sudo) ? (kv.sudo as PcFacts["sudo"]) : "none";
  return {
    osId: str(kv.osId, 30).toLowerCase(),
    osLike: str(kv.osLike, 60).toLowerCase(),
    osVersion: str(kv.osVersion, 20),
    osName: str(kv.osName, 80),
    arch: str(kv.arch, 20),
    user: str(kv.user, 32),
    root: kv.uid === "0",
    sudo,
    memMb: num(kv.memMb),
    diskMb: num(kv.diskMb),
    systemd: kv.systemd === "1",
    git: str(kv.git, 60),
    node: str(kv.node, 20),
    npm: str(kv.npm, 20),
    docker: str(kv.docker, 80),
    compose: str(kv.compose, 30),
    tailscale: str(kv.tailscale, 30),
    sshd: kv.sshd === "1",
    paasmcp: /^[0-9a-f]{40}$/.test(kv.paasmcp || "") ? kv.paasmcp : "",
  };
}

const nodeMajor = (v: string) => Number((/^v?(\d+)\./.exec(v) || [])[1] || 0);
/** uname -m → the names Node.js and Docker use. */
export const archOf = (m: string) => (m === "x86_64" || m === "amd64" || m === "x64" ? "x64" : m === "aarch64" || m === "arm64" ? "arm64" : "");

/** What the PC needs and whether PaaSMCP can go there; `hasPair` = this server has a mirror pair (arbiter role). */
export function planFor(f: PcFacts, opts: { hasPair: boolean; localArch?: string; havePassword: boolean }): PcPlan {
  const problems: PcPlan["problems"] = [];
  const warnings: PcPlan["warnings"] = [];
  const debianFamily = ["debian", "ubuntu"].includes(f.osId) || /\b(debian|ubuntu)\b/.test(f.osLike);
  if (!debianFamily) problems.push("notDebian");
  if (!archOf(f.arch)) problems.push("arch");
  if (!f.systemd) problems.push("systemd");
  if (f.diskMb && f.diskMb < 1536) problems.push("disk");
  else if (f.diskMb && f.diskMb < 4096) warnings.push("diskLow");
  if (f.memMb && f.memMb < 1024) warnings.push("memLow");
  if (f.sudo === "none") problems.push("noSudo");
  if (f.sudo === "password" && !opts.havePassword) problems.push("sudoNeedsPassword");
  if (!f.tailscale) problems.push("tailscale");
  const local = archOf(opts.localArch ?? os.arch());
  if (archOf(f.arch) && local && archOf(f.arch) !== local) warnings.push("archDiffers");
  if (f.paasmcp) warnings.push("hasPaasmcp");
  const install: PcPlan["install"] = [];
  if (!f.git) install.push("git");
  if (!f.docker) install.push("docker", "compose");
  else if (!f.compose) install.push("compose");
  if (nodeMajor(f.node) < 20) install.push("node");
  const roles: InstallRole[] = opts.hasPair ? ["server", "helper", "arbiter"] : ["server", "helper"];
  return { supported: problems.length === 0, problems, warnings, install, roles, nodeFrom: install.includes("node") ? "apt-or-tarball" : "keep" };
}

// ---------- the code this server runs ----------

/** Repository (https, no credentials) and commit of the code this dashboard runs. */
export function codeSource(): { repoUrl: string; ref: string; commit?: string } {
  const followed = followedCode();
  const dir = followed?.dir || path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
  let commit = followed?.commit;
  if (!commit) {
    try {
      commit = execFileSync("git", ["-c", `safe.directory=${dir}`, "-C", dir, "rev-parse", "HEAD"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      commit = undefined;
    }
  }
  const repoUrl = publicRepoUrl(readFollow()?.repoUrl || originOf(dir));
  const ok = commit && /^[0-9a-f]{40}$/.test(commit) ? commit : undefined;
  return { repoUrl, ref: ok || "main", ...(ok ? { commit: ok } : {}) };
}

// ---------- the install script (root) ----------

export interface ScriptInput {
  role: InstallRole;
  repoUrl: string;
  ref: string;
  ip: string;
  /** Helper role: the one-use invite made on this server. */
  invite?: string;
}

/** The root script. Every value is validated and single-quoted; steps are marked with "@@step <id>". */
export function installScript(i: ScriptInput): string {
  if (!ROLES.includes(i.role)) throw fail("role", "Unknown role.", "Papel desconhecido.");
  if (!/^https:\/\/[A-Za-z0-9.-]+(:\d+)?\/[A-Za-z0-9._~/-]+$/.test(i.repoUrl)) throw fail("badInput", "Bad repository URL.", "Endereço do repositório inválido.");
  if (!/^([0-9a-f]{40}|main)$/.test(i.ref)) throw fail("badInput", "Bad commit.", "Commit inválido.");
  validateIp(i.ip);
  if (i.role === "helper" && !/^[A-Za-z0-9._~:+/=-]{20,4000}$/.test(i.invite || "")) throw fail("badInput", "Bad invite.", "Convite inválido.");
  const tarball = (a: string) => `https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${a}.tar.xz`;
  return `#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
REPO=${shq(i.repoUrl)}
REF=${shq(i.ref)}
DIR=${shq(REMOTE_DIR)}
ROLE=${shq(i.role)}
IP=${shq(i.ip)}
step() { echo "@@step $1"; }
die() { echo "@@fail $1"; exit 3; }
apt_get() { apt-get -o Dpkg::Use-Pty=0 -o APT::Color=0 "$@"; }

step packages
apt_get update -q
pk="git ca-certificates curl xz-utils"
[ "$ROLE" = helper ] && pk="$pk openssh-server"
command -v docker >/dev/null 2>&1 || pk="$pk docker.io"
apt_get install -y -q --no-install-recommends $pk
if ! docker compose version >/dev/null 2>&1; then
  for p in docker-compose-v2 docker-compose-plugin docker-compose; do
    if apt-cache show "$p" >/dev/null 2>&1; then
      apt_get install -y -q --no-install-recommends "$p" || true
      docker compose version >/dev/null 2>&1 && break
    fi
  done
fi
docker compose version >/dev/null 2>&1 || die compose
systemctl enable --now docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || die docker
if [ "$ROLE" = helper ]; then systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1 || true; fi

step node
major() { node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\\1/' || true; }
if [ "$(major)" = "" ] || [ "$(major)" -lt 20 ]; then
  cand="$(apt-cache policy nodejs 2>/dev/null | awk '/Candidate:/{print $2}')"
  cmaj="$(printf '%s' "$cand" | sed -E 's/^([0-9]+:)?([0-9]+).*/\\2/')"
  if [ -n "$cand" ] && [ "$cand" != "(none)" ] && [ "\${cmaj:-0}" -ge 20 ] 2>/dev/null; then
    apt_get install -y -q --no-install-recommends nodejs npm
  else
    case "$(uname -m)" in
      x86_64|amd64) A=x64; SUM=${shq(NODE_SHA256.x64)}; URL=${shq(tarball("x64"))} ;;
      aarch64|arm64) A=arm64; SUM=${shq(NODE_SHA256.arm64)}; URL=${shq(tarball("arm64"))} ;;
      *) die arch ;;
    esac
    T="$(mktemp -d)"
    curl -fsSL --proto '=https' -o "$T/node.tar.xz" "$URL"
    echo "$SUM  $T/node.tar.xz" | sha256sum -c - >/dev/null || die nodesum
    mkdir -p /usr/local/lib/nodejs
    tar -xJf "$T/node.tar.xz" -C /usr/local/lib/nodejs
    rm -rf "$T"
    for b in node npm npx; do ln -sf "/usr/local/lib/nodejs/node-v${NODE_VERSION}-linux-$A/bin/$b" "/usr/local/bin/$b"; done
    hash -r
  fi
fi
[ "$(major)" -ge 20 ] || die node
echo "node $(node -v)"

step code
if [ -d "$DIR/.git" ]; then
  have="$(git -C "$DIR" remote get-url origin 2>/dev/null || true)"
  [ "$have" = "$REPO" ] || die otherRepo
  git -C "$DIR" fetch -q origin
else
  [ -e "$DIR" ] && die dirTaken
  git clone -q "$REPO" "$DIR"
fi
if [ "$REF" = main ]; then git -C "$DIR" -c advice.detachedHead=false checkout -q origin/main
else git -C "$DIR" cat-file -e "$REF^{commit}" 2>/dev/null || git -C "$DIR" fetch -q origin "$REF" || die commit
  git -C "$DIR" -c advice.detachedHead=false checkout -q "$REF"; fi
cd "$DIR"
npm ci --no-audit --no-fund --loglevel=error
npm run -s build
chmod +x dist/cli.js dist/mcp-server.js
ln -sf "$DIR/dist/cli.js" /usr/local/bin/paasmcp
ln -sf "$DIR/dist/mcp-server.js" /usr/local/bin/paasmcp-mcp
echo "code $(git -C "$DIR" rev-parse --short HEAD)"

step role
case "$ROLE" in
  server)
    node dist/cli.js init >/dev/null
    node dist/cli.js dashboard >/dev/null
    echo "@@dashboard http://127.0.0.1:4099"
    ;;
  helper)
    node dist/cli.js pool join ${shq(i.invite || "")} --ip "$IP" --yes >/dev/null
    echo "@@helper joined"
    ;;
  arbiter)
    echo "@@arbiter ready"
    ;;
esac
echo "@@done"
`;
}

// ---------- SSH ----------

interface Conn {
  dir: string;
  ip: string;
  user: string;
  pinned: boolean;
  password?: string;
  master?: ChildProcess;
}

function sshBase(c: Conn, logLevel = "ERROR"): string[] {
  return [
    "-F", "/dev/null",
    "-o", `ControlPath=${path.join(c.dir, "cm")}`,
    "-o", `UserKnownHostsFile=${path.join(c.dir, "known_hosts")}`,
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", `StrictHostKeyChecking=${c.pinned ? "yes" : "accept-new"}`,
    "-o", "PubkeyAuthentication=no",
    "-o", "IdentitiesOnly=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "ClearAllForwardings=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=8",
    "-o", `LogLevel=${logLevel}`,
    "-p", String(Number(process.env.PAASMCP_PC_SSH_PORT || 22)),
    "-T",
  ];
}

/** Private temporary folder for one connection (tmpfs when there is one, so the askpass file never hits disk). */
function connDir(): string {
  const base = fs.existsSync("/dev/shm") && fs.statSync("/dev/shm").isDirectory() ? "/dev/shm" : os.tmpdir();
  try {
    return fs.mkdtempSync(path.join(base, "paasmcp-pc-"));
  } catch {
    return fs.mkdtempSync(path.join(os.tmpdir(), "paasmcp-pc-"));
  }
}

const LOGIN_URL = /https:\/\/login\.tailscale\.com\/[A-Za-z0-9/_.?=&%-]{4,300}/;

/**
 * Opens the shared connection. Resolves with how it logged in; `onAuthUrl` gets a Tailscale login link
 * when a "check" rule asks for one (the person opens it; this keeps waiting up to `waitMs`).
 */
export function openConnection(c: Conn, opts: { onAuthUrl?: (u: string) => void; waitMs?: number } = {}): Promise<"tailscale" | "password"> {
  return new Promise((resolve, reject) => {
    const askpass = path.join(c.dir, "askpass");
    const pwFile = path.join(c.dir, "pw");
    const usePw = Boolean(c.password);
    if (usePw) {
      fs.writeFileSync(pwFile, c.password + "\n", { mode: 0o600 });
      fs.writeFileSync(askpass, `#!/bin/sh\ncat ${shq(pwFile)}\n`, { mode: 0o700 });
    }
    // INFO: a Tailscale SSH "check" rule sends its login link as the SSH banner, which ERROR hides.
    const args = [
      ...sshBase(c, "INFO"),
      "-o", "ControlMaster=yes",
      "-o", "ControlPersist=1800",
      "-o", usePw ? "BatchMode=no" : "BatchMode=yes",
      "-o", usePw ? "PreferredAuthentications=keyboard-interactive,password" : "PreferredAuthentications=keyboard-interactive",
      "-o", "NumberOfPasswordPrompts=1",
      "-o", usePw ? "PasswordAuthentication=yes" : "PasswordAuthentication=no",
      `${c.user}@${c.ip}`,
      "true",
    ];
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: c.dir, LANG: "C" };
    if (usePw) Object.assign(env, { SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: "force", DISPLAY: "paasmcp:0" });
    const child = spawn("ssh", args, { env, stdio: ["ignore", "pipe", "pipe"], detached: false });
    let err = "";
    let settled = false;
    const cleanupPw = () => {
      fs.rmSync(pwFile, { force: true });
      fs.rmSync(askpass, { force: true });
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      cleanupPw();
      reject(fail("timeout", "The PC did not finish the login in time.", "O PC não terminou a entrada a tempo."));
    }, opts.waitMs ?? 5 * 60 * 1000);
    const onText = (d: Buffer) => {
      err += d.toString("utf-8");
      if (err.length > 20000) err = err.slice(-20000);
      const m = LOGIN_URL.exec(err);
      if (m && opts.onAuthUrl) opts.onAuthUrl(m[0]);
    };
    child.stdout.on("data", onText);
    child.stderr.on("data", onText);
    child.on("error", (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanupPw();
      reject(fail("unreachable", `Could not run ssh here: ${e.message}`, `Não deu para rodar o ssh aqui: ${e.message}`));
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanupPw();
      if (code === 0) return resolve(usePw ? "password" : "tailscale");
      reject(sshError(err));
    });
  });
}

/** Turns ssh's complaint into one of the codes the screen explains. */
export function sshError(stderr: string): PcInstallError {
  const e = stderr.toLowerCase();
  if (/host key verification failed|remote host identification has changed|host key for .* has changed/.test(e))
    return fail("hostKey", "The PC answered with an SSH key that is not the one Tailscale knows for it. Nothing was sent.", "O PC respondeu com uma chave SSH diferente da que a Tailscale conhece dele. Nada foi enviado.");
  if (/permission denied|authentication failed|too many authentication failures|tailscale: .*denied|not allowed/.test(e))
    return fail("auth", "The PC did not accept the login (user, password or Tailscale SSH rule).", "O PC não aceitou a entrada (usuário, senha ou regra do SSH da Tailscale).");
  if (/connection timed out|operation timed out|no route to host/.test(e))
    return fail("unreachable", "The PC did not answer on the SSH port.", "O PC não respondeu na porta do SSH.");
  if (/connection refused|connection closed|connection reset/.test(e))
    return fail("unreachable", "The PC refused the SSH connection.", "O PC recusou a conexão SSH.");
  const last = stderr.trim().split("\n").pop() || "ssh failed";
  return fail("remote", last.slice(0, 200), last.slice(0, 200));
}

/** Runs a command over the open connection. stdout/stderr lines go to `onLine`; resolves with the exit code. */
export function runRemote(c: Conn, command: string, opts: { stdin?: string; onLine?: (l: string) => void; timeoutMs?: number } = {}): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const child = spawn("ssh", [...sshBase(c), "-o", "ControlMaster=no", "-o", "BatchMode=yes", `${c.user}@${c.ip}`, command], {
      env: { PATH: process.env.PATH, HOME: c.dir, LANG: "C" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    let buf = "";
    const feed = (d: Buffer) => {
      const s = d.toString("utf-8");
      out += s;
      if (out.length > 200_000) out = out.slice(-200_000);
      buf += s;
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() || "";
      for (const l of lines) opts.onLine?.(l);
    };
    child.stdout.on("data", feed);
    child.stderr.on("data", feed);
    const timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs ?? 10 * 60 * 1000);
    child.on("error", () => {
      clearTimeout(timer);
      resolve({ code: 255, out });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (buf) opts.onLine?.(buf);
      resolve({ code: code ?? 255, out });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(opts.stdin ?? "");
  });
}

function closeConnection(c: Conn | undefined): void {
  if (!c) return;
  try {
    execFileSync("ssh", [...sshBase(c), "-O", "exit", `${c.user}@${c.ip}`], { stdio: "ignore", timeout: 5000, env: { PATH: process.env.PATH, HOME: c.dir } });
  } catch {
    /* already closed */
  }
  c.password = undefined;
  fs.rmSync(c.dir, { recursive: true, force: true });
}

function hostFingerprint(c: Conn): string {
  try {
    const out = execFileSync("ssh-keygen", ["-l", "-f", path.join(c.dir, "known_hosts")], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] });
    return (/(SHA256:[A-Za-z0-9+/=]{20,60})/.exec(out) || [])[1] || "";
  } catch {
    return "";
  }
}

// ---------- the job ----------

let job: PcJob | undefined;
let conn: Conn | undefined;
let readyTimer: NodeJS.Timeout | undefined;
const failures = new Map<string, { n: number; until: number }>();
const READY_MS = 15 * 60 * 1000;
const MAX_FAILS = 3;
const BLOCK_MS = 10 * 60 * 1000;

const STEPS: StepId[] = ["connect", "check", "packages", "node", "code", "role", "finish"];

/** The current (or last) job, as the screen shows it. Never carries the password. */
export function currentPcJob(): PcJob | null {
  return job ? JSON.parse(JSON.stringify(job)) : null;
}

function logLine(l: string): void {
  if (!job) return;
  const clean = redact(l, conn?.password).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").slice(0, 300);
  if (!clean.trim()) return;
  job.log.push(`${new Date().toISOString().slice(11, 19)} ${clean}`);
  if (job.log.length > 300) job.log.splice(0, job.log.length - 300);
}
function setStep(id: StepId, state: StepState): void {
  const s = job?.steps.find((x) => x.id === id);
  if (s) s.state = state;
}
function finish(phase: "done" | "failed" | "cancelled", e?: unknown): void {
  if (!job) return;
  if (readyTimer) clearTimeout(readyTimer);
  readyTimer = undefined;
  job.phase = phase;
  job.finishedAt = new Date().toISOString();
  delete job.readyUntil;
  if (e) {
    const pe = e instanceof PcInstallError ? e : fail("remote", e instanceof Error ? e.message : String(e), e instanceof Error ? e.message : String(e));
    job.error = redact(pe.message, conn?.password);
    job.errorPt = redact(pe.pt, conn?.password);
    job.errorCode = pe.code;
    for (const s of job.steps) if (s.state === "run") s.state = "fail";
  }
  for (const s of job.steps) if (s.state === "todo") s.state = "skip";
  audit({ event: `pc.install.${phase}`, ip: job.ip, name: job.name, role: job.role, by: job.by, ...(job.errorCode ? { error: job.errorCode } : {}) });
  closeConnection(conn);
  conn = undefined;
}

function hasPair(): boolean {
  const m = loadState().mirror;
  return Boolean(m && (Object.keys(m.replicas || {}).length || Object.keys(m.offers || {}).length));
}

/**
 * Step 1: logs in to the PC and runs the read-only check. Answers at once with the job; the screen polls
 * `currentPcJob()` (phase connecting → ready, or failed).
 */
export async function startPcCheck(input: { ip: unknown; user: unknown; password?: unknown; by: string }): Promise<PcJob> {
  const ip = validateIp(input.ip);
  const user = validateUser(input.user);
  const password = validatePassword(input.password);
  if (job && (job.phase === "connecting" || job.phase === "installing")) throw fail("busy", `Wait for the current install on ${job.name} to finish.`, `Espere terminar a instalação em ${job.name}.`);
  if (job?.phase === "ready") cancelPcJob();
  const f = failures.get(ip);
  if (f && f.n >= MAX_FAILS && f.until > Date.now()) throw fail("rateLimited", "Too many failed logins on this PC. Try again in 10 minutes.", "Muitas entradas erradas nesse PC. Tente de novo daqui a 10 minutos.");

  // Only a device of the list, as the list shows it: the owner's own Linux PC, online, without PaaSMCP
  // (or one this dashboard installed, to finish or repeat it).
  const list = await listTailnetPcs({ probe: false });
  const pc = list.pcs.find((p) => p.ip === ip);
  if (!pc || !(pc.state === "installable" || (pc.state === "paasmcp" && pc.roles.length === 1 && pc.roles[0] === "installed")))
    throw fail("notInList", "This IP is not one of your Linux PCs without PaaSMCP in Connections > PCs.", "Esse IP não é um dos seus PCs Linux sem PaaSMCP em Conexões → PCs.");
  const peer = listTailscalePeers().peers.find((p) => p.ip === ip);

  const dir = connDir();
  const keys = peer?.sshHostKeys || [];
  if (keys.length) fs.writeFileSync(path.join(dir, "known_hosts"), keys.map((k) => `${ip} ${k}`).join("\n") + "\n", { mode: 0o600 });
  conn = { dir, ip, user, pinned: keys.length > 0, ...(password ? { password } : {}) };
  job = {
    id: crypto.randomBytes(4).toString("hex"),
    ip,
    name: validatePcName(pc.name),
    user,
    phase: "connecting",
    steps: STEPS.map((id) => ({ id, state: "todo" as StepState })),
    log: [],
    startedAt: new Date().toISOString(),
    by: input.by,
  };
  audit({ event: "pc.install.connect", ip, user, by: input.by, pinned: conn.pinned });
  const my = job;
  const c = conn;
  setStep("connect", "run");
  void (async () => {
    try {
      const banner = sshKind(await sshBanner(ip, Number(process.env.PAASMCP_PC_SSH_PORT || 22), 4000));
      if (banner === "closed") throw fail("unreachable", "No SSH answers on that PC.", "Nenhum SSH responde nesse PC.");
      logLine(`ssh: ${banner}${c.pinned ? " (host key from Tailscale)" : ""}`);
      await openConnection(c, { onAuthUrl: (u) => { if (job === my) my.authUrl = u; } });
      // Tailscale SSH lets the login in by itself (a password typed for sudo does not change that).
      my.via = banner === "tailscale" ? "tailscale" : "password";
      delete my.authUrl;
      my.hostKey = { fingerprint: hostFingerprint(c), pinned: c.pinned };
      failures.delete(ip);
      setStep("connect", "ok");
      setStep("check", "run");
      const r = await runRemote(c, "bash -s", { stdin: CHECK_SCRIPT, timeoutMs: 60_000 });
      if (r.code !== 0) throw fail("remote", "The check did not run on the PC.", "A conferência não rodou no PC.");
      my.facts = parseFacts(r.out);
      my.plan = planFor(my.facts, { hasPair: hasPair(), havePassword: Boolean(c.password) });
      setStep("check", my.plan.supported ? "ok" : "fail");
      if (!my.plan.supported) throw fail("notSupported", "PaaSMCP cannot be installed on this PC from here (see the check).", "Não dá para instalar o PaaSMCP nesse PC daqui (veja a conferência).");
      if (my.facts.sudo === "password") {
        // The password must also work for sudo, before anything is offered.
        const v = await runRemote(c, "sudo -S -p '' -v", { stdin: (c.password || "") + "\n", timeoutMs: 30_000 });
        if (v.code !== 0) throw fail("sudoPassword", "sudo did not accept the password on that PC.", "O sudo não aceitou a senha nesse PC.");
      }
      if (job !== my) return;
      my.phase = "ready";
      my.readyUntil = new Date(Date.now() + READY_MS).toISOString();
      readyTimer = setTimeout(() => {
        if (job === my && my.phase === "ready") finish("cancelled", fail("expired", "Nothing was installed: the 15 minutes to confirm ran out.", "Nada foi instalado: os 15 minutos para confirmar acabaram."));
      }, READY_MS);
    } catch (e) {
      if (e instanceof PcInstallError && e.code === "auth") {
        const cur = failures.get(ip);
        failures.set(ip, { n: (cur && cur.until > Date.now() ? cur.n : 0) + 1, until: Date.now() + BLOCK_MS });
      }
      if (job === my) finish("failed", e);
    }
  })();
  return currentPcJob()!;
}

export function cancelPcJob(): void {
  if (job && (job.phase === "ready" || job.phase === "connecting")) finish("cancelled");
}

/** How root runs a command on the PC (the password, when sudo wants one, goes on stdin, never in argv). */
export function asRoot(f: Pick<PcFacts, "sudo">, cmd: string, password?: string): { command: string; stdin?: string } {
  if (f.sudo === "root") return { command: cmd };
  if (f.sudo === "nopass") return { command: `sudo -n ${cmd}` };
  return { command: `sudo -S -p '' ${cmd}`, stdin: (password || "") + "\n" };
}

/** Writes a file on the PC as the login user (private), over the open connection. */
async function putFile(c: Conn, file: string, content: string): Promise<void> {
  const r = await runRemote(c, `umask 077 && cat > ${shq(file)}`, { stdin: content, timeoutMs: 30_000 });
  if (r.code !== 0) throw fail("remote", "Could not copy the install script to the PC.", "Não deu para copiar o script de instalação para o PC.");
}

export interface InstallDeps {
  createInvite: (name: string) => Promise<{ invite: string }>;
  addHelper: (name: string, ip: string) => Promise<unknown>;
  pairArbiter: (ip: string, code: string) => Promise<{ url: string }>;
}

/**
 * Step 2, after the person confirmed: installs and sets the role. Answers at once; the screen polls.
 * `turnOffTailscaleSsh`: switch Tailscale SSH off on the PC at the end (always for a helper, whose orders
 * must reach the OpenSSH forced command).
 */
export function startPcInstall(input: { jobId: unknown; role: unknown; name?: unknown; turnOffTailscaleSsh?: unknown; by: string }, deps: InstallDeps): PcJob {
  if (!job || job.id !== String(input.jobId || "") || job.phase !== "ready" || !conn || !job.facts || !job.plan)
    throw fail("expired", "This check is over. Log in to the PC again.", "Essa conferência acabou. Entre no PC de novo.");
  const role = String(input.role || "") as InstallRole;
  if (!job.plan.roles.includes(role)) throw fail("role", "That role is not available for this PC.", "Esse papel não está disponível para esse PC.");
  const name = input.name !== undefined && input.name !== "" ? validatePcName(input.name) : job.name;
  if (role === "helper" && loadState().pool?.helpers[name]) throw fail("badInput", `A helper named '${name}' already exists: pick another name.`, `Já existe um ajudante chamado '${name}': escolha outro nome.`);
  if (readyTimer) clearTimeout(readyTimer);
  readyTimer = undefined;
  const my = job;
  const c = conn;
  const facts = job.facts;
  my.phase = "installing";
  delete my.readyUntil;
  my.role = role;
  my.name = name;
  const turnOff = my.via === "tailscale" && (role === "helper" || input.turnOffTailscaleSsh === true);
  const src = codeSource();
  audit({ event: "pc.install.start", ip: my.ip, name, role, ref: src.ref, by: input.by });
  void (async () => {
    const remoteFile = `/tmp/paasmcp-install-${my.id}.sh`;
    const marks: Record<string, string> = {};
    try {
      let invite: string | undefined;
      if (role === "helper") invite = (await withStateLock(() => deps.createInvite(name))).invite;
      await putFile(c, remoteFile, installScript({ role, repoUrl: src.repoUrl, ref: src.ref, ip: my.ip, invite }));
      const rc = asRoot(facts, `bash ${shq(remoteFile)}`, c.password);
      let current: StepId | undefined;
      const r = await runRemote(c, rc.command, {
        stdin: rc.stdin,
        timeoutMs: 45 * 60 * 1000,
        onLine: (l) => {
          const m = /^@@(\w+)\s*(.*)$/.exec(l.trim());
          if (m && m[1] === "step" && STEPS.includes(m[2] as StepId)) {
            if (current) setStep(current, "ok");
            current = m[2] as StepId;
            setStep(current, "run");
            return;
          }
          if (m) {
            marks[m[1]] = m[2];
            return;
          }
          logLine(l);
        },
      });
      // The script file held the invite: gone either way.
      await runRemote(c, `rm -f ${shq(remoteFile)}`, { timeoutMs: 20_000 });
      if (r.code !== 0 || !("done" in marks)) {
        const why = marks.fail || "";
        throw fail("remote", `The install stopped on the PC${why ? ` (${why})` : ""}. See the log.`, `A instalação parou no PC${why ? ` (${why})` : ""}. Veja o registro.`);
      }
      if (current) setStep(current, "ok");
      setStep("finish", "run");
      const result: NonNullable<PcJob["result"]> = { role, commit: src.ref };
      if (role === "server") result.dashboard = marks.dashboard || "http://127.0.0.1:4099";
      if (role === "arbiter") {
        // The PC starts its arbiter and opens a pairing window; this server pairs with that code.
        const be = asRoot(facts, `node ${REMOTE_DIR}/dist/cli.js arbiter be-judge`, c.password);
        const jr = await runRemote(c, be.command, { stdin: be.stdin, timeoutMs: 5 * 60 * 1000 });
        const code = (/"code":\s*"(\d{6})"/.exec(jr.out) || [])[1];
        if (jr.code !== 0 || !code) throw fail("remote", "The PC did not start its arbiter.", "O PC não ligou o juiz.");
        result.arbiterUrl = (await withStateLock(() => deps.pairArbiter(my.ip, code))).url;
      }
      if (turnOff) {
        // Detached on the PC, so it runs after this connection (which it ends) is gone.
        const off = asRoot(facts, `sh -c ${shq("nohup sh -c 'sleep 2; tailscale set --ssh=false' >/dev/null 2>&1 &")}`, c.password);
        await runRemote(c, off.command, { stdin: off.stdin, timeoutMs: 30_000 });
        let offNow = false;
        for (let i = 0; i < 15 && !offNow; i++) {
          await new Promise((res) => setTimeout(res, 1000));
          offNow = sshKind(await sshBanner(my.ip, Number(process.env.PAASMCP_PC_SSH_PORT || 22), 2000)) !== "tailscale";
        }
        result.tailscaleSshOff = offNow;
        logLine(offNow ? "tailscale ssh: off" : "tailscale ssh: still on");
        if (role === "helper" && !offNow) throw fail("remote", "Tailscale SSH is still on there, so this server's orders would not reach the helper. Run 'sudo tailscale set --ssh=false' on the PC, then add it in Helpers.", "O SSH da Tailscale continua ligado lá, e as ordens deste servidor não chegariam ao ajudante. Rode 'sudo tailscale set --ssh=false' no PC e depois adicione-o em Ajudantes.");
      }
      if (role === "helper") {
        await withStateLock(() => deps.addHelper(name, my.ip));
        result.helper = name;
      }
      recordInstall({ name, ip: my.ip, role, commit: src.commit, at: new Date().toISOString(), by: input.by });
      my.result = result;
      setStep("finish", "ok");
      finish("done");
    } catch (e) {
      await runRemote(c, `rm -f ${shq(remoteFile)}`, { timeoutMs: 20_000 }).catch(() => undefined);
      finish("failed", e);
    }
  })();
  return currentPcJob()!;
}

function recordInstall(r: InstallRecord): void {
  const all = readInstalls().filter((x) => x.ip !== r.ip);
  all.push(r);
  fs.mkdirSync(path.dirname(INSTALLS_FILE()), { recursive: true, mode: 0o700 });
  fs.writeFileSync(INSTALLS_FILE(), JSON.stringify(all.slice(-200), null, 2), { mode: 0o600 });
}

/** For tests: forget the job and the login failures. */
export function resetPcJobs(): void {
  if (readyTimer) clearTimeout(readyTimer);
  closeConnection(conn);
  conn = undefined;
  job = undefined;
  failures.clear();
}

export const _offline = OFFLINE;
