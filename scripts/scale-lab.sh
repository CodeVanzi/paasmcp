#!/bin/bash
# Real-Docker check of scale phase 1 (measure and rehearse, never act): a CPU-limited app is measured
# while idle, under a steady load and after the load stops. The numbers must match what is going on
# (CPU near the app's limit under load, more traffic, slower answers), the rehearsal must climb and
# come back down without flapping, the 24 h history must get one point per minute, and the capacity
# test must find that the app's CPU is what chokes. Isolated root and network; needs Docker and
# `npm run build`. Takes about 5 minutes.
# Usage: sudo scripts/scale-lab.sh
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-scale-lab
APP=scale-lab; SRC=$(mktemp -d); fail=0
CLI="node $REPO/dist/cli.js"
if node -e 'require("net").connect(4000,"127.0.0.1").on("connect",()=>process.exit(0)).on("error",()=>process.exit(1))'; then
  echo "127.0.0.1:4000 is in use (a real PaaSMCP app?); the lab's fresh state would allocate it. Stop it first."; exit 1
fi
cleanup() {
  [ -n "${LOAD_PID:-}" ] && kill "$LOAD_PID" 2>/dev/null
  docker compose -f "$(find "$PAASMCP_ROOT" -name compose.yaml | head -1)" down --rmi all >/dev/null 2>&1
  docker rm -f "paasmcp-$APP" "paasmcp-$APP-candidate" >/dev/null 2>&1
  docker rmi "paasmcp/$APP:previous" "paasmcp/$APP:latest" >/dev/null 2>&1
  docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
js() { node -e "const s=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log($1)"; }

# /work burns ~8 ms of CPU and sends 8 KB, so a 0.5-core limit saturates with a few parallel requests.
cat > "$SRC/app.js" <<'JS'
const body = "x".repeat(8192);
require("http").createServer((q, s) => {
  if (q.url === "/work") { const end = Date.now() + 8; let x = 0; while (Date.now() < end) x += Math.sqrt(x + 1); return s.end(body); }
  s.end("ok");
}).listen(3000);
JS
printf 'FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
cat > "$SRC/load.js" <<'JS'
const http = require("http"); const [url, ms, par] = [process.argv[2], Number(process.argv[3]), Number(process.argv[4])];
const agent = new http.Agent({ keepAlive: true, maxSockets: par }); const end = Date.now() + ms; let ok = 0, fail = 0;
const one = () => new Promise((r) => http.get(url, { agent }, (res) => { res.resume(); res.on("end", () => { ok++; r(); }); }).on("error", () => { fail++; r(); }));
(async () => { await Promise.all(Array.from({ length: par }, async () => { while (Date.now() < end) await one(); })); console.log(JSON.stringify({ ok, fail })); agent.destroy(); })();
JS

node --input-type=module -e "
  const d = await import('$REPO/dist/deployer.js');
  await d.deployApp({ appName: '$APP', repoSource: '$SRC', internalPort: 3000, cpuLimit: '0.5', healthcheckPath: '/health' });" \
  || { echo "FAIL deploy"; exit 1; }
$CLI scale rule $APP --target-cpu 60 --down-after 60 --cooldown 20 >/dev/null
tick() { $CLI scale tick --quiet >> "$SRC/ticks.log" 2>&1; }
status() { $CLI scale status $APP; }

echo "     idle for 20 s"
for i in 1 2 3 4; do tick; sleep 5; done
idle=$(status)
check "idle: measured, CPU well under the limit, health path answers" \
  "$(echo "$idle" | js 's.apps[0].measuring && s.apps[0].cpuOfLimit < 30 && s.apps[0].last.ok === true && s.apps[0].last.lat !== null ? 1 : 0')"
idleLat=$(echo "$idle" | js 's.apps[0].last.lat')
check "idle: the rehearsal stays at one copy" "$(echo "$idle" | js 's.apps[0].rehearsalCopies === 1 ? 1 : 0')"

echo "     steady load for 50 s (8 parallel requests on /work)"
node "$SRC/load.js" "http://127.0.0.1:4000/work" 50000 8 > "$SRC/load.out" & LOAD_PID=$!
sleep 3
peakCpu=0; peakLat=0; peakTx=0
for i in $(seq 1 9); do
  tick
  s=$(status)
  peakCpu=$(echo "$s" | js "Math.max($peakCpu, s.apps[0].cpuOfLimit || 0)")
  peakLat=$(echo "$s" | js "Math.max($peakLat, s.apps[0].last.lat || 0)")
  peakTx=$(echo "$s" | js "Math.max($peakTx, s.apps[0].last.tx || 0)")
  sleep 5
done
wait "$LOAD_PID"; LOAD_PID=
echo "     load: $(cat "$SRC/load.out") · peak CPU ${peakCpu}% of the limit · answer ${idleLat} ms idle, ${peakLat} ms under load · sent ${peakTx} B/s"
check "under load: CPU reaches the app's 0.5-core limit (>= 80% of it)" "$([ "$peakCpu" -ge 80 ] && echo 1 || echo 0)"
check "under load: CPU never reads far above the limit (<= 130%)" "$([ "$peakCpu" -le 130 ] && echo 1 || echo 0)"
check "under load: traffic is measured (> 100 kB/s sent)" "$(echo "$peakTx" | js 's > 100000 ? 1 : 0')"
check "under load: the health path answers slower than idle" "$(node -e "console.log($peakLat > $idleLat ? 1 : 0)")"
upCopies=$(status | js 's.apps[0].rehearsalCopies')
check "under load: the rehearsal climbed (now $upCopies copies, max 3)" "$([ "$upCopies" -ge 2 ] && [ "$upCopies" -le 3 ] && echo 1 || echo 0)"

echo "     after the load, 140 s"
for i in $(seq 1 28); do tick; sleep 5; done
check "after the load: back to one copy" "$(status | js 's.apps[0].rehearsalCopies === 1 ? 1 : 0')"
diary=$($CLI scale diary $APP --lang en)
echo "$diary" | sed 's/^/     diary: /'
kinds=$(node -e "
  const lines = require('fs').readFileSync('$PAASMCP_ROOT/paasmcp/scale/diary.ndjson', 'utf8').trim().split('\n').map(JSON.parse);
  console.log(lines.filter((e) => e.kind === 'would_up' || e.kind === 'would_down').map((e) => e.kind === 'would_up' ? 'U' : 'D').join(''))")
check "no flapping: every step up comes before every step down ($kinds)" "$(echo "$kinds" | grep -qE '^U+D+$' && echo 1 || echo 0)"
check "the diary explains it in Portuguese too" "$($CLI scale diary $APP --lang pt | grep -q 'Ensaio: subiria de 1 para 2 cópias' && echo 1 || echo 0)"

hist=$($CLI scale history $APP --bucket 1)
check "24 h history: one point per minute ($(echo "$hist" | js 's.points.length') so far)" "$(echo "$hist" | js 's.points.length >= 3 && s.points.every((p) => p.n >= 1) ? 1 : 0')"
check "measurement files are private (dir 700, files 600)" \
  "$([ "$(stat -c %a "$PAASMCP_ROOT/paasmcp/scale")" = 700 ] && [ -z "$(find "$PAASMCP_ROOT/paasmcp/scale" -type f ! -perm 600)" ] && echo 1 || echo 0)"

echo "     capacity test (3 s steps, up to 8 parallel)"
cap=$($CLI scale test $APP --path /work --step-seconds 3 --max-concurrency 8 --yes 2>"$SRC/cap.err")
sed 's/^/     /' "$SRC/cap.err"
check "capacity test: finds the rate one copy handles and that its CPU chokes ($(echo "$cap" | js 's.rps + " req/s, " + s.bottleneck'))" \
  "$(echo "$cap" | js 's.rps > 0 && s.bottleneck === "app_cpu" ? 1 : 0')"
check "capacity test: result saved on the app" "$(status | js 's.apps[0].capacity && s.apps[0].capacity.rps > 0 ? 1 : 0')"
exit $fail
