#!/bin/bash
# Real-Docker check of scale phase 4 (automatic scaling). The same two "PCs" as the pool lab (Ubuntu
# containers with Docker inside, sshd and Node, helper-a 172.31.251.11 and helper-b .12, the lab
# network's gateway .1 playing this server's Tailscale IP) join with invites. An app with a Postgres
# database (its /healthz answers 503 for its first 6 s, like an app warming up) gets automatic scaling:
# 1 to 3 copies, 20 visits/s per copy. Rounds run every few seconds by hand instead of the timer.
# Checks: the balancer counts the app's visits; a step of load adds copies one at a time on the helpers
# and they leave when the load stops, without flapping; fast waves never bring copies back and forth;
# lowering the maximum is free and raising it asks; with Postgres near its connection limit no copy is
# added (the diary says why) until it frees up; a round killed while adding a copy (this server
# "restarted") leaves no orphan on a helper after the next round; "stop everything" leaves one copy here
# and nothing on the helpers.
# Needs Docker with privileged containers, `npm run build`, ssh and ssh-keygen. Isolated root, network
# and names; refuses to run where PaaSMCP already runs. Takes about 10 minutes.
# Usage: sudo scripts/autoscale-lab.sh   (AUTOSCALE_LAB_BUILD_FLAGS="..." is passed to the helper image build)
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-autoscale-lab PAASMCP_POOL_DRAIN_SECONDS=3
NET=$PAASMCP_DOCKER_NETWORK GW=172.31.251.1 IPA=172.31.251.11 IPB=172.31.251.12
HA=paasmcp-lab-helper-a HB=paasmcp-lab-helper-b IMG=paasmcp-lab-helper:1
APP=auto-lab SRC=$(mktemp -d) fail=0
CLI="node $REPO/dist/cli.js"
for c in paasmcp-postgres paasmcp-pool-lb "paasmcp-$APP" "$HA" "$HB"; do
  if docker inspect "$c" >/dev/null 2>&1; then echo "Container '$c' already exists (a real PaaSMCP, or another lab?). Run this lab elsewhere." >&2; exit 1; fi
done
for p in 4000 5432; do
  if node -e "require('net').connect($p,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"; then
    echo "127.0.0.1:$p is in use (a real PaaSMCP?); the lab's fresh state would use it." >&2; exit 1
  fi
done
cleanup() {
  echo; echo "=== cleanup"
  rm -f "$SRC/ticking"
  for p in ${LOAD_PID:-} ${TICKER_PID:-} ${TICK_PID:-}; do kill "$p" 2>/dev/null; done
  docker rm -fv "$HA" "$HB" >/dev/null 2>&1
  docker rm -f paasmcp-pool-lb "paasmcp-$APP" "paasmcp-$APP-candidate" paasmcp-postgres >/dev/null 2>&1
  docker rmi "paasmcp/$APP:previous" "paasmcp/$APP:latest" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
step() { echo; echo "=== $*"; }
js() { node -e "const s=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log($1)"; }
STATE="$PAASMCP_ROOT/paasmcp/state.json"

step "Helper image (Docker-in-Docker with sshd and Node)"
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  mkdir -p "$SRC/img"
  cat > "$SRC/img/Dockerfile" <<'DF'
# A plain Ubuntu PC with Docker, the OpenSSH server and Node.js 20 (Docker inside uses the dind helper).
FROM node:20-bookworm-slim AS node
FROM docker:27-dind AS dind
FROM ubuntu:24.04
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=dind /usr/local/bin/dind /usr/local/bin/dind
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io openssh-server openssh-client iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >> /etc/ssh/sshd_config \
 && printf '#!/bin/sh\nmkdir -p /run/sshd && /usr/sbin/sshd\nexec dind dockerd --host=unix:///var/run/docker.sock --group docker\n' > /start.sh && chmod +x /start.sh
VOLUME /var/lib/docker
ENTRYPOINT ["/start.sh"]
DF
  # shellcheck disable=SC2086
  docker build ${AUTOSCALE_LAB_BUILD_FLAGS:-} -t "$IMG" "$SRC/img" >/dev/null || { echo "FAIL building the helper image"; exit 1; }
fi
docker network create --subnet 172.31.251.0/24 --gateway "$GW" "$NET" >/dev/null || exit 1
for h in "$HA:$IPA" "$HB:$IPB"; do
  docker run -d --privileged --name "${h%%:*}" --hostname "${h%%:*}" --network "$NET" --ip "${h##*:}" \
    --tmpfs /run:rw,mode=755 -v "$REPO:/opt/paasmcp:ro" "$IMG" >/dev/null || exit 1
done
for h in "$HA" "$HB"; do
  for _ in $(seq 60); do docker exec "$h" docker info >/dev/null 2>&1 && break; sleep 1; done
done
for pair in "helper-a:$HA:$IPA" "helper-b:$HB:$IPB"; do
  IFS=: read -r name ctr ip <<<"$pair"
  out=$($CLI pool invite "$name" --advertise "$GW" --yes 2>&1) || { echo "$out"; echo "FAIL invite $name"; exit 1; }
  inv=$(echo "$out" | grep -o "paasmcp-pool://[A-Za-z0-9_-]*" | head -1)
  docker exec "$ctr" node /opt/paasmcp/dist/cli.js pool join "$inv" --cpus 1 --memory 512m --ip "$ip" --yes >"$SRC/join-$name.log" 2>&1 \
    || { cat "$SRC/join-$name.log"; echo "FAIL join $name"; exit 1; }
  $CLI pool add "$name" "$ip" >"$SRC/add-$name.json" 2>&1 || { cat "$SRC/add-$name.json"; echo "FAIL add $name"; exit 1; }
done
ok "two helper PCs joined"

step "An app with Postgres, deployed here"
cat > "$SRC/app.js" <<'JS'
// Answers with its host name; /healthz says 503 for the first 6 s, like an app that warms up.
const started = Date.now();
require("http").createServer((q, r) => {
  if (q.url === "/healthz") return r.writeHead(Date.now() - started < 6000 ? 503 : 200).end();
  r.setHeader("Content-Type", "application/json");
  r.end(JSON.stringify({ host: process.env.HOSTNAME, db: Boolean(process.env.DATABASE_URL) }));
}).listen(3000);
JS
printf 'FROM node:20-alpine\nWORKDIR /app\nCOPY app.js .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
node --input-type=module -e "
  const d = await import('$REPO/dist/deployer.js');
  await d.deployApp({ appName: '$APP', repoSource: '$SRC', internalPort: 3000, cpuLimit: '0.25', memoryLimit: '128m', withPostgres: true, healthcheckPath: '/healthz' });" \
  >"$SRC/deploy.log" 2>&1 || { cat "$SRC/deploy.log"; echo "FAIL deploy"; exit 1; }
PORT=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'].localPort)")
ok "deployed on 127.0.0.1:$PORT"

# Visits at a steady rate (or in waves: on for WAVE ms, off for WAVE ms), recording which copy answered.
cat > "$SRC/rate.js" <<'JS'
const http = require("http"), fs = require("fs");
const [url, rate, ms, out, wave] = [process.argv[2], Number(process.argv[3]), Number(process.argv[4]), process.argv[5], Number(process.argv[6] || 0)];
const agent = new http.Agent({ keepAlive: true, maxSockets: 64 }); const t0 = Date.now(); const log = [];
const one = () => { const s = Date.now();
  http.get(url, { agent, timeout: 5000 }, (res) => { let b = ""; res.on("data", (d) => (b += d)); res.on("end", () => {
    let host = null; try { host = JSON.parse(b).host; } catch {} log.push({ at: s - t0, ok: res.statusCode === 200, host }); }); })
    .on("error", () => log.push({ at: s - t0, ok: false, host: null })); };
const timer = setInterval(() => { if (wave && Math.floor((Date.now() - t0) / wave) % 2) return; for (let i = 0; i < rate / 10; i++) one(); }, 100);
const stop = () => { clearInterval(timer); setTimeout(() => { fs.writeFileSync(out, JSON.stringify(log)); process.exit(0); }, 1500); };
if (ms > 0) setTimeout(stop, ms);
process.on("SIGTERM", stop);
JS
# One round, as the timer runs it; one line per round in rounds.ndjson (copies, visits/s, what it did).
tick() {
  $CLI scale tick 2>>"$SRC/ticks.err" | node -e "
    let b = ''; process.stdin.on('data', (d) => (b += d)).on('end', () => {
      const i = b.search(/^\{/m); let r = {}; try { r = JSON.parse(b.slice(i)); } catch {}
      const a = (r.apps || {})['$APP'] || {};
      console.log(JSON.stringify({ at: Date.now(), copies: a.copies, rps: a.rps, step: a.step || null, event: a.event || null, skipped: r.skipped || null }));
    });" >> "$SRC/rounds.ndjson"
}
ticker() { while [ -e "$SRC/ticking" ]; do tick; sleep 3; done; }
startTicker() { touch "$SRC/ticking"; ticker & TICKER_PID=$!; }
stopTicker() { rm -f "$SRC/ticking"; wait "$TICKER_PID" 2>/dev/null; TICKER_PID=; }
copies() { node -e "const s=JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'];console.log(s.pool&&s.pool.enabled?1+s.pool.placed.length:1)"; }
# The copies the last finished round reported.
lastRound() { tail -n 1 "$SRC/rounds.ndjson" 2>/dev/null | node -e "let b='';process.stdin.on('data',d=>b+=d).on('end',()=>{try{console.log(JSON.parse(b).copies)}catch{console.log('')}})"; }
# Waits until the app runs $1 copies and the round that changed them is over (a copy that leaves is out of
# the balancer while it drains, before it stops). Up to $2 s; prints the seconds it took.
waitCopies() {
  local t0=$SECONDS
  while [ "$(copies)" != "$1" ] || [ "$(lastRound)" != "$1" ] || [ -e "$PAASMCP_ROOT/paasmcp/scale/$APP.step.json" ]; do
    [ $((SECONDS - t0)) -ge "$2" ] && { echo "timeout"; return 1; }; sleep 2
  done
  echo $((SECONDS - t0))
}
# The copies each round saw since line $1 of rounds.ndjson, without repeats ("1 2 3 2 1").
pathSince() { tail -n +"$1" "$SRC/rounds.ndjson" | node -e "const l=require('fs').readFileSync(0,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse).map(x=>x.copies).filter(x=>x!==undefined);console.log(l.filter((x,i)=>i===0||x!==l[i-1]).join(' '))"; }
rounds() { wc -l < "$SRC/rounds.ndjson" 2>/dev/null || echo 0; }
diary() { $CLI scale diary "$APP" --lang pt --limit "${1:-30}"; }
helperCopies() { for h in "$HA" "$HB"; do docker exec "$h" docker ps --filter "label=paasmcp.app=$APP" --format '{{.Label "paasmcp.copy"}}'; done | sort; }
knownCopies() { node -e "const s=JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'];console.log(((s.pool&&s.pool.placed)||[]).map(c=>c.id).sort().join('\n'))" | sed '/^$/d'; }
balancer() { node --input-type=module -e "const a = await import('$REPO/dist/autoscale.js'); console.log(JSON.stringify(await a.readBalancer()));"; }

step "Automatic scaling on: 1 to 3 copies, 20 visits/s per copy"
$CLI scale rule "$APP" --target-rps 20 --target-cpu 90 --up-rounds 2 --down-after 60 --cooldown 20 >/dev/null 2>"$SRC/rule.err" || { cat "$SRC/rule.err"; bad "rule"; }
check "turning it on without confirming is refused" "$($CLI scale auto on "$APP" --max 3 </dev/null >/dev/null 2>&1 && echo 0 || echo 1)"
$CLI scale auto on "$APP" --min 1 --max 3 --yes >"$SRC/on.json" 2>"$SRC/on.err" || { cat "$SRC/on.err"; bad "auto on"; }
LB=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" paasmcp-pool-lb 2>/dev/null)
check "on: the app is behind the pool balancer at one copy" "$([ -n "$LB" ] && [ "$(copies)" = 1 ] && curl -s --max-time 5 "http://$LB:$PORT/" | grep -q '"host"' && echo 1 || echo 0)"
check "the balancer names the app's server and keeps its metrics" \
  "$(grep -Pzo "servers :$PORT \{\n\t\tname $APP\n\t\tmetrics" "$PAASMCP_ROOT/paasmcp-pool-lb/conf/Caddyfile" >/dev/null && echo 1 || echo 0)"
b0=$(balancer)
for i in $(seq 1 40); do curl -s --max-time 5 -o /dev/null "http://$LB:$PORT/"; done
b1=$(balancer)
check "the balancer counted exactly the 40 visits sent through it" \
  "$(node -e "const a=$b0,b=$b1;console.log(a&&b&&b.requests['$APP']-(a.requests['$APP']||0)===40?1:0)")"
check "...and sees this server's copy as healthy" "$(node -e "const b=$b1;console.log(b.healthy['paasmcp-$APP:3000']===true?1:0)")"

step "A step of load (50 visits/s), then nothing"
startTicker
sleep 8
start=$(( $(rounds) + 1 ))
node "$SRC/rate.js" "http://$LB:$PORT/" 50 0 "$SRC/step.json" & LOAD_PID=$!
t=$(waitCopies 3 180) && ok "3 copies after ${t} s of load" || bad "3 copies under load (now $(copies))"
sleep 25
check "...and it stays at 3 (16.7 visits/s per copy, under the target)" "$([ "$(copies)" = 3 ] && echo 1 || echo 0)"
kill "$LOAD_PID"; wait "$LOAD_PID"; LOAD_PID=
check "visits reached the 3 copies (here and on both helpers)" \
  "$(node -e "const l=require('$SRC/step.json');const last=l.filter(x=>x.ok&&x.at>l[l.length-1].at-15000);console.log(new Set(last.map(x=>x.host)).size===3?1:0)")"
check "no visit failed while copies were added" "$(node -e "const l=require('$SRC/step.json');const f=l.filter(x=>!x.ok).length;console.log(f===0?1:0);if(f)console.error('     '+f+' of '+l.length+' failed')")"
t=$(waitCopies 1 240) && ok "back to 1 copy ${t} s after the load stopped" || bad "back to 1 copy (now $(copies))"
p=$(pathSince "$start")
check "copies followed the load one step at a time: $p" "$([ "$p" = "1 2 3 2 1" ] && echo 1 || echo 0)"
check "nothing left on the helpers" "$([ -z "$(helperCopies)" ] && echo 1 || echo 0)"
d=$(diary 40)
check "the diary says why it went up (visits per copy over the target)" "$(echo "$d" | grep -q 'Subi de 1 para 2 cópias: as visitas por cópia ficaram em' && echo 1 || echo 0)"
check "the diary says why it went down" "$(echo "$d" | grep -q 'Desci de 2 para 1 cópia: a CPU por cópia ficou abaixo de 45% e as visitas abaixo de 10/s por cópia por 1 min' && echo 1 || echo 0)"

step "Fast waves: 10 s at 50 visits/s, 10 s at nothing, for 100 s"
start=$(( $(rounds) + 1 ))
node "$SRC/rate.js" "http://$LB:$PORT/" 50 100000 "$SRC/waves.json" 10000 & LOAD_PID=$!
wait "$LOAD_PID"; LOAD_PID=
p=$(pathSince "$start")
check "copies only went up during the waves, never back and forth: $p" \
  "$(echo "$p" | node -e "const l=require('fs').readFileSync(0,'utf8').trim().split(' ').map(Number);console.log(l.every((x,i)=>i===0||x>l[i-1])?1:0)")"

step "Limits: lowering the maximum is free, raising it asks"
$CLI scale rule "$APP" --max 1 >/dev/null 2>"$SRC/max1.err" || { cat "$SRC/max1.err"; bad "lower max"; }
t=$(waitCopies 1 90) && ok "max 1: back to one copy in ${t} s" || bad "max 1 (now $(copies))"
check "the diary says it was the maximum" "$(diary 5 | grep -q 'para respeitar o máximo da regra' && echo 1 || echo 0)"
check "raising the maximum without confirming is refused" "$($CLI scale rule "$APP" --max 3 </dev/null >/dev/null 2>&1 && echo 0 || echo 1)"
$CLI scale rule "$APP" --max 3 --yes >/dev/null 2>"$SRC/max3.err" || { cat "$SRC/max3.err"; bad "raise max with --yes"; }

step "Postgres near its connection limit: no copy is added until it frees up"
docker exec -d paasmcp-postgres sh -c 'for i in $(seq 80); do psql -U paasmcp_admin -d postgres -c "select pg_sleep(50)" >/dev/null 2>&1 & done; wait'
sleep 4
db=$(node --input-type=module -e "const a = await import('$REPO/dist/autoscale.js'); console.log(JSON.stringify(await a.postgresConnections('$APP')));")
check "the decider sees the connections in use ($db)" "$(node -e "const d=$db;console.log(d&&d.used>=78&&d.limit===97?1:0)")"
node "$SRC/rate.js" "http://$LB:$PORT/" 50 0 "$SRC/db.json" & LOAD_PID=$!
sleep 25
check "under load, still 1 copy while Postgres is busy" "$([ "$(copies)" = 1 ] && echo 1 || echo 0)"
check "the diary says why" "$(diary 5 | grep -q 'Não subi para 2 cópias: o Postgres já usa' && echo 1 || echo 0)"
t=$(waitCopies 2 150) && ok "once the connections closed, a copy was added (${t} s later)" || bad "a copy after Postgres freed up (now $(copies))"

step "This server 'restarts' in the middle of adding a copy"
stopTicker
# Exactly 2 copies first (a maximum of 2 for a moment), then a third is due: 25 visits/s per copy.
$CLI scale rule "$APP" --max 2 >/dev/null 2>&1
for _ in $(seq 20); do [ "$(copies)" = 2 ] && break; tick; sleep 3; done
$CLI scale rule "$APP" --max 3 --yes >/dev/null 2>&1
check "2 copies, load still on (25 visits/s per copy, so a third is due)" "$([ "$(copies)" = 2 ] && echo 1 || echo 0)"
orphan=
for _ in $(seq 25); do
  $CLI scale tick >/dev/null 2>&1 & TICK_PID=$!
  while kill -0 "$TICK_PID" 2>/dev/null; do
    extra=$(comm -23 <(helperCopies) <(knownCopies))
    if [ -n "$extra" ]; then kill -9 "$TICK_PID"; orphan=$extra; break; fi
    sleep 0.3
  done
  wait "$TICK_PID" 2>/dev/null; TICK_PID=
  [ -n "$orphan" ] && break
  sleep 3
done
check "the round was killed while its new copy ($orphan) was warming up on a helper" "$([ -n "$orphan" ] && echo 1 || echo 0)"
check "...which left the step's file behind" "$([ -e "$PAASMCP_ROOT/paasmcp/scale/$APP.step.json" ] && echo 1 || echo 0)"
tick
check "the next round repaired it (the diary says so)" "$(diary 5 | grep -q 'Uma mudança de cópias foi interrompida no meio' && echo 1 || echo 0)"
check "no orphan on the helpers: they run exactly the copies this server knows" \
  "$([ "$(helperCopies)" = "$(knownCopies)" ] && ! helperCopies | grep -qx "$orphan" && echo 1 || echo 0)"
check "the step's file is gone and the app runs what it asked for ($(copies) copies)" \
  "$([ ! -e "$PAASMCP_ROOT/paasmcp/scale/$APP.step.json" ] && [ "$(copies)" = "$(node -e "console.log(JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'].pool.copies)")" ] && echo 1 || echo 0)"
kill "$LOAD_PID"; wait "$LOAD_PID"; LOAD_PID=

step "Stop everything"
$CLI scale off "$APP" >/dev/null 2>"$SRC/off.err" || { cat "$SRC/off.err"; bad "scale off"; }
check "one copy, here; automatic scaling off; the balancer is gone" \
  "$([ "$(copies)" = 1 ] && [ "$(node -e "const a=JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'];console.log(a.scale&&a.scale.auto?1:0)")" = 0 ] && ! docker inspect paasmcp-pool-lb >/dev/null 2>&1 && echo 1 || echo 0)"
check "nothing on the helpers" "$([ -z "$(helperCopies)" ] && echo 1 || echo 0)"
check "the app still answers here" "$(curl -s --max-time 5 "http://127.0.0.1:$PORT/" | grep -q '"host"' && echo 1 || echo 0)"
check "the diary says so" "$(diary 3 | grep -q 'Parar tudo: o app voltou a uma cópia, só neste servidor, e a escala automática foi desligada' && echo 1 || echo 0)"
echo
echo "     diary (pt):"
diary 40 | sed 's/^/     /'
echo
[ "$fail" = 0 ] && echo "All checks passed." || echo "Some checks FAILED."
exit $fail
