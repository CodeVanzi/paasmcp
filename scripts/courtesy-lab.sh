#!/bin/bash
# Real-Docker check of courteous mode (helper PCs whose owner is using them). The same two "PCs" as the
# pool lab (Ubuntu containers with Docker inside, sshd and Node, helper-a 172.31.252.11 and helper-b .12,
# the lab network's gateway .1 playing this server's Tailscale IP) join with invites. An app gets 2 copies
# by hand: one here, one on a helper. Rounds run every few seconds by hand instead of the timer, and the
# courteous check runs every 10 s (60 s on a real server), with a 30 s calm while (5 min).
# Checks: each PC reports its owner's CPU outside the copies, and a PC busy with something else is not
# counted on the other; when the "owner" burns CPU on the PC with the copy, the copy moves to the other PC
# with no visit failing, and the diary says why; that PC is free again after the calm while; in warn
# mode the copy stays and a new copy goes elsewhere; in mode off nothing is watched.
# Needs Docker with privileged containers, `npm run build`, ssh and ssh-keygen. Isolated root, network
# and names; refuses to run where PaaSMCP already runs. Takes about 6 minutes.
# Usage: sudo scripts/courtesy-lab.sh   (COURTESY_LAB_BUILD_FLAGS="..." is passed to the helper image build)
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-courtesy-lab PAASMCP_POOL_DRAIN_SECONDS=3
export PAASMCP_COURTESY_EVERY_SECONDS=10 PAASMCP_COURTESY_CALM_SECONDS=30
NET=$PAASMCP_DOCKER_NETWORK GW=172.31.252.1 IPA=172.31.252.11 IPB=172.31.252.12
HA=paasmcp-lab-helper-a HB=paasmcp-lab-helper-b IMG=paasmcp-lab-helper:1
APP=court-lab SRC=$(mktemp -d) fail=0
CLI="node $REPO/dist/cli.js"
for c in paasmcp-pool-lb "paasmcp-$APP" "$HA" "$HB"; do
  if docker inspect "$c" >/dev/null 2>&1; then echo "Container '$c' already exists (a real PaaSMCP, or another lab?). Run this lab elsewhere." >&2; exit 1; fi
done
if node -e "require('net').connect(4000,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"; then
  echo "127.0.0.1:4000 is in use (a real PaaSMCP?); the lab's fresh state would use it." >&2; exit 1
fi
cleanup() {
  echo; echo "=== cleanup"
  rm -f "$SRC/ticking"
  for p in ${LOAD_PID:-} ${TICKER_PID:-}; do kill "$p" 2>/dev/null; done
  docker rm -fv "$HA" "$HB" >/dev/null 2>&1
  docker rm -f paasmcp-pool-lb "paasmcp-$APP" "paasmcp-$APP-candidate" >/dev/null 2>&1
  docker rmi "paasmcp/$APP:previous" "paasmcp/$APP:latest" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
step() { echo; echo "=== $*"; echo "$(date +%s%3N) $*" >> "${SRC}/phases"; }
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
  docker build ${COURTESY_LAB_BUILD_FLAGS:-} -t "$IMG" "$SRC/img" >/dev/null || { echo "FAIL building the helper image"; exit 1; }
fi
docker network create --subnet 172.31.252.0/24 --gateway "$GW" "$NET" >/dev/null || exit 1
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
# The lab's "PCs" share this machine's CPUs (no quota), so 2 busy loops are 2 of its CPUs: a limit of
# 25% is crossed on any machine with up to 8 CPUs.
CORES=$(nproc)
LIMIT=25
[ "$CORES" -gt 8 ] && LIMIT=10
for h in helper-a helper-b; do $CLI pool courtesy "$h" auto --cpu "$LIMIT" >/dev/null 2>"$SRC/court.err" || { cat "$SRC/court.err"; bad "courtesy $h"; }; done
ok "courteous mode: automatic, limit $LIMIT% (this machine has $CORES CPUs)"

step "An app with 2 copies: one here, one on a helper"
cat > "$SRC/app.js" <<'JS'
require("http").createServer((q, r) => {
  if (q.url === "/healthz") return r.writeHead(200).end();
  r.setHeader("Content-Type", "application/json");
  r.end(JSON.stringify({ host: process.env.HOSTNAME }));
}).listen(3000);
JS
printf 'FROM node:20-alpine\nWORKDIR /app\nCOPY app.js .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
node --input-type=module -e "
  const d = await import('$REPO/dist/deployer.js');
  await d.deployApp({ appName: '$APP', repoSource: '$SRC', internalPort: 3000, cpuLimit: '0.25', memoryLimit: '128m', healthcheckPath: '/healthz' });" \
  >"$SRC/deploy.log" 2>&1 || { cat "$SRC/deploy.log"; echo "FAIL deploy"; exit 1; }
PORT=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'].localPort)")
$CLI scale set "$APP" 2 --yes >"$SRC/set2.json" 2>"$SRC/set2.err" || { cat "$SRC/set2.err"; bad "scale set 2"; }
LB=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" paasmcp-pool-lb 2>/dev/null)
placedOn() { node -e "const a=JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'];console.log(((a.pool&&a.pool.placed)||[]).map(c=>c.helper).sort().join(' '))"; }
FIRST=$(placedOn)
check "the copy runs on a helper ($FIRST)" "$([ "$FIRST" = helper-a ] || [ "$FIRST" = helper-b ]; echo $(( $? == 0 )))"
if [ "$FIRST" = helper-a ]; then BUSY=helper-a BUSYC=$HA OTHER=helper-b OTHERC=$HB; else BUSY=helper-b BUSYC=$HB OTHER=helper-a OTHERC=$HA; fi

# Visits at a steady rate through the balancer, recording which copy answered.
cat > "$SRC/rate.js" <<'JS'
const http = require("http"), fs = require("fs");
const [url, rate, out] = [process.argv[2], Number(process.argv[3]), process.argv[4]];
const agent = new http.Agent({ keepAlive: true, maxSockets: 64 }); const t0 = Date.now(); const log = [];
const one = () => { const s = Date.now();
  http.get(url, { agent, timeout: 5000 }, (res) => { let b = ""; res.on("data", (d) => (b += d)); res.on("end", () => {
    let host = null; try { host = JSON.parse(b).host; } catch {} log.push({ at: s - t0, ok: res.statusCode === 200, host }); }); })
    .on("error", () => log.push({ at: s - t0, ok: false, host: null })); };
const timer = setInterval(() => { for (let i = 0; i < rate / 10; i++) one(); }, 100);
process.on("SIGTERM", () => { clearInterval(timer); setTimeout(() => { fs.writeFileSync(out, JSON.stringify({ t0, log })); process.exit(0); }, 1500); });
JS
tick() { $CLI scale tick >>"$SRC/ticks.log" 2>>"$SRC/ticks.err"; }
ticker() { while [ -e "$SRC/ticking" ]; do tick; sleep 3; done; }
touch "$SRC/ticking"; ticker & TICKER_PID=$!
node "$SRC/rate.js" "http://$LB:$PORT/" 20 "$SRC/visits.json" & LOAD_PID=$!
owner() { $CLI pool status --no-probe 2>/dev/null | node -e "const s=JSON.parse(require('fs').readFileSync(0,'utf8'));const h=s.helpers.find(x=>x.name==='$1');console.log(h&&h.owner&&typeof h.owner.cpuPct==='number'?h.owner.cpuPct:'')"; }
busyOf() { node -e "const h=JSON.parse(require('fs').readFileSync('$STATE','utf8')).pool.helpers['$1'];console.log(h.ownerBusy?1:0)"; }
diary() { $CLI scale diary "$APP" --lang pt --limit "${1:-30}"; }
# Waits until the command prints what is expected, up to $3 s; prints the seconds it took.
waitFor() {
  local t0=$SECONDS
  while [ "$(eval "$1")" != "$2" ]; do [ $((SECONDS - t0)) -ge "$3" ] && { echo "timeout"; return 1; }; sleep 2; done
  echo $((SECONDS - t0))
}
# A copy start makes the first window unsure (Docker's CPU); the next ones give numbers.
for _ in $(seq 30); do a=$(owner "$BUSY"); b=$(owner "$OTHER"); [ -n "$a" ] && [ -n "$b" ] && break; sleep 2; done
check "both PCs report their owner's CPU while idle ($BUSY $a%, $OTHER $b%)" "$([ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$LIMIT" ] && [ "$b" -lt "$LIMIT" ] && echo 1 || echo 0)"
check "the worker keeps its last reading in a private file" "$(docker exec "$BUSYC" stat -c %a /var/lib/paasmcp-worker/owner.json 2>/dev/null | grep -qx 600 && echo 1 || echo 0)"

step "The owner of $BUSY starts using it (2 busy loops outside the copies)"
# Two busy loops on the PC itself, outside any copy; their pids are kept to stop them.
burn() { docker exec -d "$1" sh -c 'rm -f /root/burn.pids; for i in 1 2; do (while :; do :; done) & echo $! >> /root/burn.pids; done; wait'; }
unburn() { docker exec "$1" sh -c 'kill $(cat /root/burn.pids) 2>/dev/null; rm -f /root/burn.pids'; }
burn "$BUSYC"
t=$(waitFor placedOn "$OTHER" 120) && ok "the copy moved to $OTHER ${t} s later" || bad "the copy moved away from $BUSY (now on '$(placedOn)')"
check "$BUSY is marked busy" "$(busyOf "$BUSY")"
o=$(owner "$OTHER")
check "the other PC does not count that CPU as its owner's ($OTHER $o%)" "$([ -n "$o" ] && [ "$o" -lt "$LIMIT" ] && echo 1 || echo 0)"
check "nothing of the app left on $BUSY" "$([ -z "$(docker exec "$BUSYC" docker ps -q --filter label=paasmcp.app=$APP)" ] && echo 1 || echo 0)"
check "the diary says why, and where the copy went" "$(diary 10 | grep -q "O dono de $BUSY está usando o PC (CPU fora das cópias em .*%, limite $LIMIT%). A cópia saiu de lá depois de terminar as visitas em curso e foi para $OTHER." && echo 1 || echo 0)"
check "the status shows it" "$($CLI pool status --no-probe | node -e "const s=JSON.parse(require('fs').readFileSync(0,'utf8'));const h=s.helpers.find(x=>x.name==='$BUSY');console.log(h.state==='busy'&&h.ownerBusy&&h.ownerBusy.cpuPct>=$LIMIT?1:0)")"

step "The owner stops: $BUSY is free again after the calm while"
echo "$(date +%s%3N) unburn BUSYC" >> "$SRC/phases"
unburn "$BUSYC"
t=$(waitFor "busyOf $BUSY" 0 120) && ok "free again ${t} s later" || bad "$BUSY free again"
check "the diary says so" "$(diary 10 | grep -q "$BUSY está livre de novo (CPU do dono abaixo de .*% por 1 min). Ele volta a receber cópias." && echo 1 || echo 0)"
check "the copy stays where it went ($(placedOn))" "$([ "$(placedOn)" = "$OTHER" ] && echo 1 || echo 0)"

step "Warn mode on $OTHER: the copy stays, a new one goes elsewhere"
$CLI pool courtesy "$OTHER" warn >/dev/null 2>"$SRC/warn.err" || { cat "$SRC/warn.err"; bad "courtesy warn"; }
echo "$(date +%s%3N) burn OTHERC" >> "$SRC/phases"
burn "$OTHERC"
t=$(waitFor "busyOf $OTHER" 1 120) && ok "$OTHER marked busy ${t} s later" || bad "$OTHER marked busy"
sleep 8
check "the copy stays on $OTHER" "$([ "$(placedOn)" = "$OTHER" ] && echo 1 || echo 0)"
check "the diary warns" "$(diary 10 | grep -q "O dono de $OTHER está usando o PC (CPU fora das cópias em .*%, limite $LIMIT%). Modo com aviso: a cópia fica lá, mas nenhuma nova vai para esse PC até ele liberar." && echo 1 || echo 0)"
rm -f "$SRC/ticking"; wait "$TICKER_PID" 2>/dev/null; TICKER_PID=
echo "$(date +%s%3N) CLI scale set APP 3 --yes" >> "$SRC/phases"
$CLI scale set "$APP" 3 --yes >"$SRC/set3.json" 2>"$SRC/set3.err" || { cat "$SRC/set3.err"; bad "scale set 3"; }
check "a third copy went to $BUSY, not to the busy $OTHER ($(placedOn))" "$([ "$(placedOn)" = "helper-a helper-b" ] && echo 1 || echo 0)"
echo "$(date +%s%3N) CLI scale set APP 2 --yes" >> "$SRC/phases"
$CLI scale set "$APP" 2 --yes >/dev/null 2>&1

step "Mode off on $OTHER: its owner is no longer watched"
$CLI pool courtesy "$OTHER" off >/dev/null 2>"$SRC/off.err" || { cat "$SRC/off.err"; bad "courtesy off"; }
check "off clears the busy mark at once" "$([ "$(busyOf "$OTHER")" = 0 ] && echo 1 || echo 0)"
touch "$SRC/ticking"; ticker & TICKER_PID=$!
sleep 35
check "with the owner still busy, it stays unmarked" "$([ "$(busyOf "$OTHER")" = 0 ] && echo 1 || echo 0)"
rm -f "$SRC/ticking"; wait "$TICKER_PID" 2>/dev/null; TICKER_PID=
unburn "$OTHERC"

kill "$LOAD_PID"; wait "$LOAD_PID"; LOAD_PID=
check "no visit failed while copies moved" "$(node -e "
  const {t0,log:l}=require('$SRC/visits.json');const bad=l.filter(x=>!x.ok);console.log(l.length>1000&&bad.length===0?1:0);
  if(bad.length||l.length<=1000){console.error('     '+bad.length+' of '+l.length+' failed');
    const ph=require('fs').readFileSync('$SRC/phases','utf8').trim().split('\\n').map(x=>[Number(x.split(' ')[0]),x.slice(x.indexOf(' ')+1)]);
    for(const b of bad.slice(0,10)){const at=t0+b.at;const p=ph.filter(x=>x[0]<=at).pop();console.error('     at +'+Math.round((at-(p?p[0]:t0))/1000)+' s into: '+(p?p[1]:'?'));}}")"
check "no round failed" "$([ ! -s "$SRC/ticks.err" ] && echo 1 || { head -5 "$SRC/ticks.err" | sed 's/^/     /' >&2; echo 0; })"
echo
echo "     diary (pt):"
diary 20 | sed 's/^/     /'
echo
[ "$fail" = 0 ] && echo "All checks passed." || echo "Some checks FAILED."
exit $fail
