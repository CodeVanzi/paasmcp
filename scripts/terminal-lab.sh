#!/usr/bin/env bash
# Real-Docker lab for the dashboard terminal (src/terminal.ts): a server shell (nsenter into the host) and a
# shell inside an app's container, both through the dashboard's WebSocket; resize, idle close, turning it off,
# and no helper container left behind.
# Run: sudo env PATH=$PATH scripts/terminal-lab.sh   (needs Docker; pulls node:22.11.0-alpine3.20)
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build --silent

ROOT="$(mktemp -d)"
export PAASMCP_ROOT="$ROOT" PAASMCP_DASHBOARD_POLL=0 PAASMCP_TERMINAL_IDLE_MS=4000
APP=paasmcp-lab-term-app
cleanup() { docker rm -f "$APP" >/dev/null 2>&1 || true; [ -n "${PAASMCP_TERMINAL_HOST_PID:-}" ] && kill "$PAASMCP_TERMINAL_HOST_PID" 2>/dev/null; rm -rf "$ROOT"; }
trap cleanup EXIT

docker image inspect node:22.11.0-alpine3.20 >/dev/null 2>&1 || docker pull -q node:22.11.0-alpine3.20 >/dev/null
docker run -d --name "$APP" node:22.11.0-alpine3.20 sleep 600 >/dev/null
# Some sandboxes (like cloud dev containers) hide PID 1's namespaces even from root: then the "server" is a
# process of ours, which still checks the whole path (privileged helper, nsenter, host shell, TTY, cleanup).
if ! ls /proc/1/ns/mnt >/dev/null 2>&1 || ! readlink /proc/1/ns/mnt >/dev/null 2>&1; then
  sleep 600 & export PAASMCP_TERMINAL_HOST_PID=$!
  echo "  (PID 1 is hidden here: the server shell enters process $PAASMCP_TERMINAL_HOST_PID instead)"
fi
# The dashboard image is node-alpine plus tools; its busybox nsenter is what the server shell needs.
TAG="$(node -e 'import("./dist/dashboard.js").then((d) => console.log(d.dashboardImageTag()))')"
docker image inspect "$TAG" >/dev/null 2>&1 || docker tag node:22.11.0-alpine3.20 "$TAG"

node --input-type=module - "$APP" <<'JS'
const app = process.argv[2];
const config = await import("./dist/config.js");
const dashboard = await import("./dist/dashboard.js");
const totp = await import("./dist/totp.js");
const { WebSocket } = await import("ws");
const { execFileSync } = await import("node:child_process");
const st = config.loadState();
st.apps["term-app"] = { name: "term-app", containerName: app, localPort: 4999, createdAt: new Date().toISOString() };
config.saveState(st);
const ok = (m) => console.log(`  ✓ ${m}`);
const fail = (m) => { console.log(`  ✗ ${m}`); process.exit(1); };

const srv = dashboard.startDashboardServer(0, "127.0.0.1");
await new Promise((r) => srv.once("listening", r));
const port = srv.address().port;
const base = `http://127.0.0.1:${port}`;
const secret = totp.getDashboardTotpSecret();
const login = await fetch(`${base}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: dashboard.getOrCreateDashboardToken(), ...(secret ? { code: totp.totpCode(secret) } : {}) }) });
const cookie = (login.headers.get("set-cookie") || "").split(";")[0];
const post = (u, b) => fetch(`${base}${u}`, { method: "POST", headers: { cookie, "Content-Type": "application/json" }, body: JSON.stringify(b) });
await post("/api/terminal", { on: true, confirmed: true, confirmName: "terminal" });

function open(target) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/api/terminal?target=${target}`, { headers: { cookie, origin: base } });
  const s = { ws, out: "", closed: false };
  // Answer "where is the cursor?" like a real terminal (xterm.js) does; busybox sh waits for it.
  ws.on("message", (d) => { const t = d.toString(); s.out += t; if (t.includes("\x1b[6n")) ws.send(JSON.stringify({ t: "in", d: "\x1b[1;1R" })); });
  ws.on("close", () => { s.closed = true; });
  s.send = (d) => ws.send(JSON.stringify({ t: "in", d }));
  s.until = async (re, ms = 20000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { if (re.test(s.out)) return; await new Promise((r) => setTimeout(r, 100)); }
    fail(`timed out waiting for ${re} in: ${JSON.stringify(s.out.slice(-400))}`);
  };
  return new Promise((resolve) => ws.on("open", () => resolve(s)));
}

console.log("1. Server shell: root on the host (its hostname, its processes), resize applies");
const host = execFileSync("hostname", { encoding: "utf-8" }).trim();
const a = await open("server");
a.ws.send(JSON.stringify({ t: "resize", c: 132, r: 41 }));
await new Promise((r) => setTimeout(r, 1500));
a.send("echo ID=$(id -u) HOST=$(hostname) SIZE=$(stty size) N=$((6*7))\r");
await a.until(/ID=0 HOST=\S+ SIZE=41 132 N=42/);
if (!a.out.includes(`HOST=${host}`)) fail(`not the host: ${a.out.slice(-300)}`);
ok(`root on ${host}, 132x41`);
a.send("exit\r");
await a.until(/.*/);
for (let i = 0; i < 50 && !a.closed; i++) await new Promise((r) => setTimeout(r, 100));
if (!a.closed) fail("exit did not close the terminal");
ok("exit closes it");

console.log("2. App shell: inside the app's container");
const b = await open("term-app");
await b.until(/[#$] /);
b.send("cat /etc/os-release | grep ^ID= ; echo APPHOST=$(hostname)\r");
await b.until(/ID=alpine[\s\S]*APPHOST=\w+/);
ok("alpine container");

console.log("3. Idle: closes by itself (4 s in this lab, 15 min for real)");
await b.until(/without typing/, 10000);
for (let i = 0; i < 30 && !b.closed; i++) await new Promise((r) => setTimeout(r, 100));
if (!b.closed) fail("idle did not close");
ok("closed after idle");

console.log("4. Turning it off closes what is open");
const c = await open("server");
await new Promise((r) => setTimeout(r, 1500));
await post("/api/terminal", { on: false });
await c.until(/turned off/, 5000);
ok("closed when turned off");

console.log("5. Nothing left behind, and the audit has open/close but no typed text");
await new Promise((r) => setTimeout(r, 3000));
const left = execFileSync("docker", ["ps", "-aq", "--filter", "label=paasmcp.terminal=1"], { encoding: "utf-8" }).trim();
if (left) fail(`helper containers left: ${left}`);
const fs = await import("node:fs");
const path = await import("node:path");
const auditFile = execFileSync("sh", ["-c", `grep -rl terminal.open ${process.env.PAASMCP_ROOT} | head -1`], { encoding: "utf-8" }).trim();
const auditText = auditFile ? fs.readFileSync(auditFile, "utf-8") : "";
if (!/terminal\.open/.test(auditText) || !/terminal\.close/.test(auditText)) fail("open/close not audited");
if (auditText.includes("os-release") || auditText.includes("6*7")) fail("typed text went to the audit");
ok("no helper container, audit has open/close only");
srv.close();
console.log("All terminal lab checks passed.");
process.exit(0);
JS
