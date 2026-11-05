import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  authorizedKeysLine,
  decodeInvite,
  defaultRouteIface,
  HELPER_TAG,
  IFACE_NAME,
  normalizeMac,
  parseEthtoolWake,
  parseMemoryMb,
  POOL_IMAGE_REPO,
  sshKeyFingerprint,
  TMPFILES_CONF,
  validateIpv4,
  WORKER_HOME,
  WOL_MARKER,
  WORKER_RUN_DIR,
  WORKER_USER,
} from "./poolproto.js";

// One-time setup of a PC as a helper (`sudo paasmcp pool join <invite>`) and its undo
// (`sudo paasmcp pool leave`). Runs on the helper, as root, and never touches PaaSMCP's own state, so a
// PC can be a helper whether or not it is also a PaaSMCP server.
//
// What join leaves behind: a system user (paasmcp-worker) in the docker group whose only SSH key is the
// origin's, accepted only from the origin's IP and only to run the worker (no terminal, no forwarding);
// a tmpfiles.d rule for its in-memory folder; its configuration (what the owner gives); and a root-owned
// copy of the worker program in /usr/local/lib/paasmcp-worker. No service.

const run = (cmd: string, args: string[]) => execFileSync(cmd, args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const ok = (cmd: string, args: string[]) => spawnSync(cmd, args, { stdio: "ignore" }).status === 0;

function requireRoot(): void {
  if (typeof process.getuid === "function" && process.getuid() !== 0) throw new Error("Run it as root (sudo), so it can create the worker user.");
}

function userIds(user: string): { uid: number; gid: number } | undefined {
  try {
    return { uid: Number(run("id", ["-u", user])), gid: Number(run("id", ["-g", user])) };
  } catch {
    return undefined;
  }
}

function tailscaleIp(): string | undefined {
  try {
    return validateIpv4(run("tailscale", ["ip", "-4"]).split("\n")[0]);
  } catch {
    return undefined;
  }
}

/** Default share: half the PC's CPUs and memory (at least 1 CPU and 512 MB). */
export function defaultGive(cpus = os.cpus().length, memMb = Math.round(os.totalmem() / 1024 / 1024)): { cpus: number; memMb: number } {
  return { cpus: Math.max(1, Math.floor(cpus / 2)), memMb: Math.max(512, Math.floor(memMb / 2 / 256) * 256) };
}

export function parseGive(opts: { cpus?: string; memory?: string }): { cpus: number; memMb: number } {
  const base = defaultGive();
  const total = { cpus: os.cpus().length, memMb: Math.round(os.totalmem() / 1024 / 1024) };
  let cpus = base.cpus;
  let memMb = base.memMb;
  if (opts.cpus !== undefined) {
    cpus = Number(opts.cpus);
    if (!Number.isFinite(cpus) || cpus <= 0 || cpus > total.cpus) throw new Error(`--cpus must be more than 0 and at most ${total.cpus} (this PC's CPUs).`);
  }
  if (opts.memory !== undefined) {
    const m = parseMemoryMb(opts.memory);
    if (!m || m < 256 || m > total.memMb) throw new Error(`--memory must be like 2g or 1536m, from 256m up to this PC's ${total.memMb} MB.`);
    memMb = m;
  }
  return { cpus: Math.round(cpus * 100) / 100, memMb };
}

export interface JoinPreview {
  name: string;
  originName: string;
  originIp: string;
  originKeyFingerprint: string;
  give: { cpus: number; memMb: number };
  ip?: string;
  warnings: string[];
}

/** Checks the invite and this PC without changing anything (what the person confirms). */
export function previewJoin(inviteText: string, opts: { cpus?: string; memory?: string; ip?: string } = {}): JoinPreview {
  const inv = decodeInvite(inviteText);
  const warnings: string[] = [];
  if (!ok("docker", ["version"])) throw new Error("Docker is not running on this PC. Install Docker first (https://docs.docker.com/engine/install/).");
  if (!ok("getent", ["group", "docker"])) throw new Error("The 'docker' group does not exist: is Docker installed the usual way?");
  if (!fs.existsSync("/usr/sbin/sshd") && !ok("sh", ["-c", "command -v sshd"])) {
    throw new Error("The OpenSSH server is not installed (Debian/Ubuntu: sudo apt install openssh-server).");
  }
  const ip = opts.ip ? validateIpv4(opts.ip) : tailscaleIp();
  if (!ip) warnings.push("Tailscale is not on (or 'tailscale ip -4' found no address). The server reaches helpers over Tailscale: install it and log in with the same account.");
  const user = userIds(WORKER_USER);
  if (user && fs.existsSync(path.join(WORKER_HOME, "worker.json"))) warnings.push("This PC is already a helper: joining again replaces the server it obeys.");
  return { name: inv.name, originName: inv.originName, originIp: inv.originIp, originKeyFingerprint: sshKeyFingerprint(inv.originKey), give: parseGive(opts), ip, warnings };
}

/** Where join installs the worker program: owned by root, readable by everyone, apart from any checkout. */
export const WORKER_LIB = "/usr/local/lib/paasmcp-worker";

/** Every folder on the way to `file` lets other users through, and the file itself is readable (and runnable). */
function reachableByOthers(file: string, exec: boolean): boolean {
  let p = path.resolve(file);
  try {
    const st = fs.statSync(p);
    if (!(st.mode & (exec ? 0o001 : 0o004))) return false;
    while (p !== path.dirname(p)) {
      p = path.dirname(p);
      if (!(fs.statSync(p).mode & 0o001)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Copies the worker (worker.js and the one module it imports) to WORKER_LIB, owned by root. The forced
 * command runs that copy, so nothing in a person's checkout or home folder can change what runs with
 * Docker access, and the worker user never needs to read the checkout.
 */
export function installWorkerFiles(): string {
  requireRoot();
  const node = fs.realpathSync(process.execPath);
  if (!reachableByOthers(node, true)) {
    throw new Error(`Node.js here (${node}) is installed only for your user, so the worker user cannot run it. Install Node.js 20 or newer for the whole system (your distribution's package or NodeSource) and run this again.`);
  }
  const dist = path.dirname(new URL(import.meta.url).pathname);
  fs.mkdirSync(WORKER_LIB, { recursive: true, mode: 0o755 });
  fs.chownSync(WORKER_LIB, 0, 0);
  fs.chmodSync(WORKER_LIB, 0o755);
  let version = "";
  try {
    version = String(JSON.parse(fs.readFileSync(path.join(dist, "..", "package.json"), "utf-8")).version || "");
  } catch {
    // unknown version
  }
  const files: Record<string, string> = {
    "worker.js": fs.readFileSync(path.join(dist, "worker.js"), "utf-8"),
    "poolproto.js": fs.readFileSync(path.join(dist, "poolproto.js"), "utf-8"),
    "package.json": JSON.stringify({ name: "paasmcp-worker", private: true, type: "module", version }, null, 2) + "\n",
  };
  for (const [name, content] of Object.entries(files)) {
    const dest = path.join(WORKER_LIB, name);
    const tmp = `${dest}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, content, { mode: 0o644 });
    fs.chownSync(tmp, 0, 0);
    fs.renameSync(tmp, dest);
  }
  return `${node} ${path.join(WORKER_LIB, "worker.js")}`;
}

/** Runs the worker's own check as the worker user (files, Docker, the in-memory folder). */
function workerSelfTest(command: string): void {
  if (!/^[A-Za-z0-9/._ +-]+$/.test(command)) throw new Error("Node.js is installed in a path with unusual characters; install it in a plain path.");
  const quoted = command.split(" ").map((p) => `'${p}'`).join(" ");
  const st = spawnSync("su", ["-s", "/bin/sh", "-c", `${quoted} --selftest`, WORKER_USER], { encoding: "utf-8" });
  if (st.status === 0) return;
  let problems: string[] = [];
  try {
    problems = JSON.parse(String(st.stdout).trim().split("\n").pop() || "{}").problems || [];
  } catch {
    problems = [String(st.stderr || st.stdout).trim().split("\n").pop() || "unknown error"];
  }
  throw new Error(`The worker user could not run its check:\n- ${problems.join("\n- ")}`);
}

/** After updating PaaSMCP on this PC: installs the new worker, keeping the server's key and settings. */
export function updateWorker(): { command: string; version: string } {
  requireRoot();
  if (!userIds(WORKER_USER) || !fs.existsSync(path.join(WORKER_HOME, "worker.json"))) throw new Error("This PC is not a helper yet ('sudo paasmcp pool join <invite>').");
  const command = installWorkerFiles();
  workerSelfTest(command);
  let version = "";
  try {
    version = JSON.parse(fs.readFileSync(path.join(WORKER_LIB, "package.json"), "utf-8")).version || "";
  } catch {
    // unknown
  }
  return { command, version };
}

export function joinPool(inviteText: string, opts: { cpus?: string; memory?: string; ip?: string } = {}): JoinPreview & { next: string[] } {
  requireRoot();
  const preview = previewJoin(inviteText, opts);
  const inv = decodeInvite(inviteText);
  const command = installWorkerFiles();
  const keyLine = authorizedKeysLine({ originIp: inv.originIp, command, publicKey: inv.originKey });

  if (!userIds(WORKER_USER)) {
    run("useradd", ["--system", "--user-group", "--create-home", "--home-dir", WORKER_HOME, "--shell", "/bin/sh", "--comment", "PaaSMCP helper (orders from the origin server only)", WORKER_USER]);
  }
  // "*": no password can ever log in, but the account is not "locked" (sshd refuses key logins of locked accounts).
  run("usermod", ["-p", "*", WORKER_USER]);
  run("usermod", ["-aG", "docker", WORKER_USER]);
  const ids = userIds(WORKER_USER)!;

  const sshDir = path.join(WORKER_HOME, ".ssh");
  fs.mkdirSync(sshDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(WORKER_HOME, 0o700);
  fs.chmodSync(sshDir, 0o700);
  fs.writeFileSync(path.join(sshDir, "authorized_keys"), keyLine + "\n", { mode: 0o600 });
  fs.writeFileSync(
    path.join(WORKER_HOME, "worker.json"),
    JSON.stringify(
      {
        v: 1,
        name: inv.name,
        originNodeId: inv.originNodeId,
        originName: inv.originName,
        originIp: inv.originIp,
        inviteId: inv.id,
        proofKey: inv.proofKey,
        give: preview.give,
        joinedAt: new Date().toISOString(),
      },
      null,
      2
    ),
    { mode: 0o600 }
  );
  for (const p of [WORKER_HOME, sshDir, path.join(sshDir, "authorized_keys"), path.join(WORKER_HOME, "worker.json")]) fs.chownSync(p, ids.uid, ids.gid);

  // The in-memory folder for app variables: recreated at every boot by systemd-tmpfiles (no service).
  fs.mkdirSync(path.dirname(TMPFILES_CONF), { recursive: true, mode: 0o755 });
  fs.writeFileSync(TMPFILES_CONF, `d ${WORKER_RUN_DIR} 0700 ${WORKER_USER} ${WORKER_USER} -\n`, { mode: 0o644 });
  if (!ok("systemd-tmpfiles", ["--create", TMPFILES_CONF])) {
    fs.mkdirSync(WORKER_RUN_DIR, { recursive: true, mode: 0o700 });
    fs.chownSync(WORKER_RUN_DIR, ids.uid, ids.gid);
    fs.chmodSync(WORKER_RUN_DIR, 0o700);
  }

  // Run the worker once as its user: it must read its files, reach Docker and find the folder in memory.
  workerSelfTest(command);

  const ip = preview.ip || "<this PC's Tailscale IP>";
  return {
    ...preview,
    next: [
      `On the server, run: paasmcp pool add ${inv.name} ${ip}   (or in the dashboard: Helpers → step 4), within the next hour.`,
      `Recommended: tag this PC in Tailscale so the access rules can fence it in: sudo tailscale up --advertise-tags=${HELPER_TAG} (the server shows the rules with 'paasmcp pool acl').`,
      "To stop being a helper: sudo node dist/cli.js pool leave (in this folder). After updating PaaSMCP here: sudo node dist/cli.js pool update-worker",
    ],
  };
}

/** Undoes join on this PC: copies stop, images and variables go, the worker user and its key are removed. */
export function leavePool(): { removedUser: boolean; stoppedCopies: number } {
  requireRoot();
  let stoppedCopies = 0;
  try {
    const ids = run("docker", ["ps", "-aq", "--filter", "label=paasmcp.pool"]).split("\n").filter(Boolean);
    stoppedCopies = ids.length;
    if (ids.length) spawnSync("docker", ["rm", "-f", ...ids], { stdio: "ignore" });
    const tags = run("docker", ["image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", `reference=${POOL_IMAGE_REPO}/*`]).split("\n").filter(Boolean);
    if (tags.length) spawnSync("docker", ["image", "rm", ...tags], { stdio: "ignore" });
  } catch {
    // Docker down: nothing of ours is running
  }
  fs.rmSync(WORKER_RUN_DIR, { recursive: true, force: true });
  fs.rmSync(TMPFILES_CONF, { force: true });
  if (fs.existsSync(WOL_UNIT) || fs.existsSync(WOL_MARKER)) undoWakeSetup();
  fs.rmSync(WORKER_LIB, { recursive: true, force: true });
  const existed = Boolean(userIds(WORKER_USER));
  if (existed) {
    spawnSync("userdel", ["-r", WORKER_USER], { stdio: "ignore" });
    // userdel refuses while an order is still running; the key must go regardless.
    fs.rmSync(WORKER_HOME, { recursive: true, force: true });
  }
  return { removedUser: existed, stoppedCopies };
}

// ---------- Wake-on-LAN on this PC (`sudo paasmcp pool wake-setup`) ----------
//
// For the server to wake this PC with a magic packet, its network card must listen for one while the PC
// sleeps. That is a setting of the card (ethtool "wol g") that many systems reset at boot, so a small
// oneshot unit sets it again at every start (nothing stays running). NetworkManager, when it manages the
// card, is told too. Waking from power off may also need the BIOS/UEFI option (Wake on LAN, Power On by
// PCI-E): that part only the owner can do.

export const WOL_UNIT = "/etc/systemd/system/paasmcp-wol.service";

function findEthtool(): string {
  for (const p of ["/usr/sbin/ethtool", "/sbin/ethtool", "/usr/bin/ethtool", "/bin/ethtool"]) if (fs.existsSync(p)) return p;
  throw new Error("ethtool is not installed. Install it (Debian/Ubuntu: sudo apt install ethtool) and run this again.");
}

export function wolUnit(ethtool: string, iface: string): string {
  if (!IFACE_NAME.test(iface) || !/^\/[A-Za-z0-9/._-]+$/.test(ethtool)) throw new Error("Unexpected interface or ethtool path.");
  return [
    "[Unit]",
    `Description=PaaSMCP helper: keep Wake-on-LAN on ${iface}`,
    "After=network.target NetworkManager.service",
    "",
    "[Service]",
    "Type=oneshot",
    `ExecStart=${ethtool} -s ${iface} wol g`,
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

/** Arms this PC's wired card for magic packets, now and at every boot. Run as root on the helper. */
export function setupWake(opts: { iface?: string } = {}): { iface: string; mac: string; before: string; notes: string[] } {
  requireRoot();
  const iface = opts.iface ?? defaultRouteIface(fs.readFileSync("/proc/net/route", "utf-8"));
  if (!iface) throw new Error("This PC has no default route, so the card to arm is unknown. Pass it: --interface <name> (see 'ip link').");
  if (!IFACE_NAME.test(iface) || !fs.existsSync(path.join("/sys/class/net", iface))) throw new Error(`No network interface named '${iface}' here (see 'ip link').`);
  if (fs.existsSync(path.join("/sys/class/net", iface, "wireless")) || fs.existsSync(path.join("/sys/class/net", iface, "phy80211"))) {
    throw new Error(`${iface} is a Wi-Fi card: Wake-on-LAN almost never works over Wi-Fi. Connect the PC by cable and run this again (or pass --interface <wired card>).`);
  }
  const ethtool = findEthtool();
  const info = parseEthtoolWake(run(ethtool, [iface]));
  if (!info.supports.includes("g")) {
    throw new Error(`The card ${iface} does not support waking by magic packet (ethtool says "Supports Wake-on: ${info.supports || "nothing"}"). This PC cannot be woken over the network.`);
  }
  run(ethtool, ["-s", iface, "wol", "g"]);
  const notes: string[] = [];
  fs.writeFileSync(WOL_UNIT, wolUnit(ethtool, iface), { mode: 0o644 });
  if (!ok("systemctl", ["daemon-reload"]) || !ok("systemctl", ["enable", "paasmcp-wol.service"])) {
    notes.push(`systemd could not enable ${WOL_UNIT}: after a reboot, run this again (or 'sudo ethtool -s ${iface} wol g').`);
  }
  // NetworkManager applies its own Wake-on-LAN setting when it brings the card up: make it the same.
  if (ok("nmcli", ["-v"])) {
    let conn = "";
    try {
      conn = run("nmcli", ["-g", "GENERAL.CONNECTION", "device", "show", iface]).split("\n")[0].trim();
    } catch {
      // not managed by NetworkManager
    }
    if (conn && conn !== "--" && !ok("nmcli", ["connection", "modify", conn, "802-3-ethernet.wake-on-lan", "magic"])) {
      notes.push(`NetworkManager could not be told to keep Wake-on-LAN on '${conn}': nmcli connection modify '${conn}' 802-3-ethernet.wake-on-lan magic`);
    }
  }
  const mac = normalizeMac(fs.readFileSync(path.join("/sys/class/net", iface, "address"), "utf-8"));
  fs.writeFileSync(WOL_MARKER, JSON.stringify({ iface, mac, at: new Date().toISOString() }) + "\n", { mode: 0o644 });
  notes.push(
    "Waking from sleep (suspend) usually works with this alone. To wake from power off, also turn on 'Wake on LAN' (or 'Power On by PCI-E') in the PC's BIOS/UEFI.",
    "On the server: paasmcp pool wake <this PC's name> on, then test with: suspend this PC and run paasmcp pool wake <name> now.",
    "A PC woken by the server still sleeps by its own power settings when idle; while it runs copies, keep its automatic suspend long enough (or off), or it will sleep with visits in progress and be woken again."
  );
  return { iface, mac, before: info.current || "?", notes };
}

/** Undoes wake-setup (also run by `pool leave`): the unit and the marker go, the card stops listening. */
export function undoWakeSetup(): { removed: boolean } {
  requireRoot();
  let iface: string | undefined;
  try {
    iface = JSON.parse(fs.readFileSync(WOL_MARKER, "utf-8")).iface;
  } catch {
    // no marker
  }
  const had = fs.existsSync(WOL_UNIT) || fs.existsSync(WOL_MARKER);
  if (fs.existsSync(WOL_UNIT)) {
    ok("systemctl", ["disable", "paasmcp-wol.service"]);
    fs.rmSync(WOL_UNIT, { force: true });
    ok("systemctl", ["daemon-reload"]);
  }
  fs.rmSync(WOL_MARKER, { force: true });
  if (iface && IFACE_NAME.test(iface)) {
    try {
      spawnSync(findEthtool(), ["-s", iface, "wol", "d"], { stdio: "ignore" });
    } catch {
      // no ethtool any more
    }
    try {
      const conn = run("nmcli", ["-g", "GENERAL.CONNECTION", "device", "show", iface]).split("\n")[0].trim();
      if (conn && conn !== "--") ok("nmcli", ["connection", "modify", conn, "802-3-ethernet.wake-on-lan", "default"]);
    } catch {
      // no NetworkManager
    }
  }
  return { removed: had };
}
