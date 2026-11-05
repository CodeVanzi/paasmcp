#!/bin/bash
# Real-Docker check of Wake-on-LAN (sleeping helper PCs woken over the network). The same two "PCs" as the
# pool lab (Ubuntu containers with Docker inside, sshd and Node, helper-a 172.31.253.11 and helper-b .12,
# the lab network's gateway .1 playing this server's address on the home network and its Tailscale IP)
# join with invites. A PC "sleeps" by being frozen (docker pause: it stops answering, its copies stay in
# memory, as in a suspend), and a small listener on the same network plays its network card: when a
# magic packet with helper-b's MAC arrives, it unfreezes it 5 s later.
# Checks: each PC reports its card; Wake-on-LAN is turned on from what it reported; a third copy with no
# awake room wakes helper-b and runs there once it answers; automatic scaling holds its step, wakes the PC
# and steps up when it answers, with the diary saying why; a PC holding a copy that stops answering is
# woken; a PC that never answers gets 3 tries, then is left alone until a person wakes it by hand.
# Needs Docker with privileged containers, `npm run build`, ssh and ssh-keygen. Isolated root, network
# and names; refuses to run where PaaSMCP already runs. Takes about 6 minutes.
# Usage: sudo scripts/wake-lab.sh   (WAKE_LAB_BUILD_FLAGS="..." is passed to the helper image build)
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-wake-lab PAASMCP_POOL_DRAIN_SECONDS=3
# A PC gets 20 s to answer before another packet (3 min on a real server); the decider tries its step
# again 8 s after waking one (1 min).
export PAASMCP_WAKE_WAIT_SECONDS=20 PAASMCP_WAKE_RECHECK_SECONDS=8
NET=$PAASMCP_DOCKER_NETWORK GW=172.31.253.1 IPA=172.31.253.11 IPB=172.31.253.12 IPW=172.31.253.20
HA=paasmcp-lab-helper-a HB=paasmcp-lab-helper-b IMG=paasmcp-lab-helper:1 CARD=paasmcp-lab-card
APP=wake-lab SRC=$(mktemp -d) fail=0
CLI="node $REPO/dist/cli.js"
for c in paasmcp-pool-lb "paasmcp-$APP" "$HA" "$HB" "$CARD"; do
  if docker inspect "$c" >/dev/null 2>&1; then echo "Container '$c' already exists (a real PaaSMCP, or another lab?). Run this lab elsewhere." >&2; exit 1; fi
done
if node -e "require('net').connect(4000,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"; then
  echo "127.0.0.1:4000 is in use (a real PaaSMCP?); the lab's fresh state would use it." >&2; exit 1
fi
cleanup() {
  echo; echo "=== cleanup"
  rm -f "$SRC/ticking" "$SRC/carding"
  for p in ${TICKER_PID:-} ${CARD_PID:-}; do kill "$p" 2>/dev/null; done
  docker unpause "$HA" "$HB" >/dev/null 2>&1
  docker rm -fv "$HA" "$HB" "$CARD" >/dev/null 2>&1
  docker rm -f paasmcp-pool-lb "paasmcp-$APP" "paasmcp-$APP-candidate" >/dev/null 2>&1
  docker rmi "paasmcp/$APP:previous" "paasmcp/$APP:latest" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
step() { echo; echo "=== $*"; }
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
  docker build ${WAKE_LAB_BUILD_FLAGS:-} -t "$IMG" "$SRC/img" >/dev/null || { echo "FAIL building the helper image"; exit 1; }
fi
docker network create --subnet 172.31.253.0/24 --gateway "$GW" "$NET" >/dev/null || exit 1
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
# Only this lab's own ups and downs of the "PCs" count, not their owner: courteous mode off.
for h in helper-a helper-b; do $CLI pool courtesy "$h" off >/dev/null 2>&1; done

step "Each PC reports its network card; Wake-on-LAN on for helper-b"
helperJson() { $CLI pool status ${2:-} 2>/dev/null | node -e "const s=JSON.parse(require('fs').readFileSync(0,'utf8'));const h=s.helpers.find(x=>x.name==='$1');console.log(JSON.stringify(h||{}))"; }
field() { node -e "const v=JSON.parse(process.argv[1]);const r=process.argv[2].split('.').reduce((o,k)=>o==null?o:o[k],v);console.log(r===undefined||r===null?'':typeof r==='object'?JSON.stringify(r):r)" "$1" "$2"; }
HBJ=$(helperJson helper-b)
MACB=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").MacAddress}}" "$HB")
check "helper-b reports its card: eth0, $MACB, $IPB/24, wired, not armed yet" \
  "$([ "$(field "$HBJ" lan.iface)" = eth0 ] && [ "$(field "$HBJ" lan.mac)" = "$MACB" ] && [ "$(field "$HBJ" lan.ip)" = "$IPB" ] && [ "$(field "$HBJ" lan.prefix)" = 24 ] && [ "$(field "$HBJ" lan.wired)" = true ] && [ "$(field "$HBJ" lan.armed)" = false ] && echo 1 || echo 0)"
# The lab's "card" is a virtual one: the setup on the PC must refuse it plainly, changing nothing.
setup=$(docker exec "$HB" node /opt/paasmcp/dist/cli.js pool wake-setup 2>&1); rc=$?
check "wake-setup on the PC refuses a card it cannot arm (exit $rc: $(echo "$setup" | tail -1 | cut -c1-90))" \
  "$([ $rc != 0 ] && echo "$setup" | grep -Eq "ethtool is not installed|does not support waking" && echo 1 || echo 0)"
$CLI pool wake helper-b on >"$SRC/wake-on.json" 2>"$SRC/wake-on.err" || { cat "$SRC/wake-on.err"; bad "pool wake helper-b on"; }
check "on, from what it reported: packet to 172.31.253.255:9, sent from $GW" \
  "$(node -e "const r=JSON.parse(require('fs').readFileSync('$SRC/wake-on.json','utf8'));console.log(r.wake.mac==='$MACB'&&r.wake.broadcast==='172.31.253.255'&&r.wake.port===9&&r.from==='$GW'?1:0)")"
check "it warns that the card was not prepared on the PC" "$(grep -q "pool wake-setup" "$SRC/wake-on.err" && echo 1 || echo 0)"
$CLI pool wake helper-b on --broadcast 8.8.8.255 >/dev/null 2>"$SRC/pub.err"
check "a public broadcast address is refused" "$(grep -q "home or office network" "$SRC/pub.err" && echo 1 || echo 0)"

step "An app with 2 copies: one here, one on helper-a"
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
placedOn() { node -e "const a=JSON.parse(require('fs').readFileSync('$STATE','utf8')).apps['$APP'];console.log(((a.pool&&a.pool.placed)||[]).map(c=>c.helper).sort().join(' '))"; }
$CLI scale set "$APP" 2 --yes >"$SRC/set2.json" 2>"$SRC/set2.err" || { cat "$SRC/set2.err"; bad "scale set 2"; }
check "the copy runs on helper-a ($(placedOn))" "$([ "$(placedOn)" = helper-a ] && echo 1 || echo 0)"

# The card: a listener on the lab network that sees every magic packet; for helper-b's MAC it unfreezes
# the PC 5 s later (as if it booted), unless the lab turned that off.
docker run -d --name "$CARD" --network "$NET" --ip "$IPW" node:20-alpine node -e '
  const s = require("dgram").createSocket("udp4");
  const last = {};
  s.on("message", (m, r) => {
    if (m.length !== 102 || !m.subarray(0, 6).equals(Buffer.alloc(6, 0xff))) return;
    const mac = m.subarray(6, 12).toString("hex").match(/../g).join(":");
    // The server sends each wake-up twice, 100 ms apart (UDP may lose one): count it once.
    if (Date.now() - (last[mac] || 0) < 1000) return;
    last[mac] = Date.now();
    console.log(Date.now() + " " + mac + " from " + r.address);
  });
  s.bind(9);' >/dev/null || { echo "FAIL starting the card listener"; exit 1; }
packets() { docker logs "$CARD" 2>/dev/null | grep -c " $MACB from $GW" ; }
card() {
  local seen=0 n
  while [ -e "$SRC/carding" ]; do
    n=$(packets)
    if [ "$n" -gt "$seen" ]; then
      seen=$n
      if [ ! -e "$SRC/insomnia" ]; then (sleep 5; docker unpause "$HB" >/dev/null 2>&1; echo "$(date +%s) unpaused" >> "$SRC/card.log") & fi
    fi
    sleep 1
  done
}
touch "$SRC/carding"; card & CARD_PID=$!
tick() { $CLI scale tick >>"$SRC/ticks.log" 2>>"$SRC/ticks.err"; }
ticker() { while [ -e "$SRC/ticking" ]; do tick; sleep 3; done; }
startTicks() { touch "$SRC/ticking"; ticker & TICKER_PID=$!; }
stopTicks() { rm -f "$SRC/ticking"; wait "$TICKER_PID" 2>/dev/null; TICKER_PID=; }
diary() { $CLI scale diary "$APP" --lang pt --limit "${1:-30}"; }
waitFor() {
  local t0=$SECONDS
  while [ "$(eval "$1")" != "$2" ]; do [ $((SECONDS - t0)) -ge "$3" ] && { echo "timeout"; return 1; }; sleep 2; done
  echo $((SECONDS - t0))
}
stateOf() { field "$(helperJson "$1" "${2:-}")" state; }

step "helper-b sleeps; a third copy has no awake room: it is woken and takes it"
docker pause "$HB" >/dev/null
check "helper-b shows as asleep ($(stateOf helper-b))" "$([ "$(stateOf helper-b)" = asleep ] && echo 1 || echo 0)"
check "nothing woke it just for being asleep" "$([ "$(packets)" = 0 ] && echo 1 || echo 0)"
startTicks
$CLI scale set "$APP" 3 --yes >"$SRC/set3.json" 2>"$SRC/set3.err" || { cat "$SRC/set3.err"; bad "scale set 3"; }
check "the answer says it is waking helper-b" "$(grep -q "Waking helper-b over the network" "$SRC/set3.json" && echo 1 || echo 0)"
check "the magic packet reached its card (from $GW)" "$([ "$(packets)" -ge 1 ] && echo 1 || echo 0)"
t=$(waitFor placedOn "helper-a helper-b" 90) && ok "the third copy runs on helper-b ${t} s later" || bad "third copy on helper-b (now on '$(placedOn)')"
check "the diary says it woke" "$(diary 10 | grep -q "helper-b acordou pela rede: respondeu [0-9]* s depois do primeiro pedido." && echo 1 || echo 0)"
check "one packet was enough ($(packets))" "$([ "$(packets)" = 1 ] && echo 1 || echo 0)"
stopTicks

step "Automatic scaling: the step waits while helper-b wakes, then happens"
$CLI scale set "$APP" 2 --yes >/dev/null 2>&1
check "back to 2: the newest copy (helper-b) left ($(placedOn))" "$([ "$(placedOn)" = helper-a ] && echo 1 || echo 0)"
docker pause "$HB" >/dev/null
$CLI scale auto on "$APP" --min 2 --max 3 --yes >"$SRC/auto.json" 2>"$SRC/auto.err" || { cat "$SRC/auto.err"; bad "scale auto on"; }
$CLI scale rule "$APP" --min 3 >/dev/null 2>"$SRC/rule.err" || { cat "$SRC/rule.err"; bad "scale rule --min 3"; }
before=$(packets)
startTicks
t=$(waitFor placedOn "helper-a helper-b" 120) && ok "the decider's copy runs on helper-b ${t} s later" || bad "decider's copy on helper-b (now on '$(placedOn)')"
check "the diary says it waited for helper-b to wake" "$(diary 15 | grep -q "Precisava de 3 cópias e nenhum ajudante acordado tinha espaço. Mandei acordar helper-b pela rede (Wake-on-LAN), o que leva de 30 s a 1 min. Sigo com 2 cópias e tento de novo em 1 min." && echo 1 || echo 0)"
check "...and that it stepped up there" "$(diary 15 | grep -q "Subi de 2 para 3 cópias para cumprir o mínimo da regra. A nova cópia roda em helper-b." && echo 1 || echo 0)"
check "one more packet ($before → $(packets))" "$([ "$(packets)" = $((before + 1)) ] && echo 1 || echo 0)"
stopTicks
$CLI scale auto off "$APP" >/dev/null 2>&1

step "helper-b falls asleep holding a copy: it is woken"
docker pause "$HB" >/dev/null
before=$(packets)
$CLI scale set "$APP" 3 --yes >"$SRC/keep.json" 2>"$SRC/keep.err" || { cat "$SRC/keep.err"; bad "scale set 3 (keep)"; }
check "the copy stays listed and its PC gets a packet ($before → $(packets))" "$([ "$(placedOn)" = "helper-a helper-b" ] && [ "$(packets)" = $((before + 1)) ] && echo 1 || echo 0)"
startTicks
t=$(waitFor "stateOf helper-b --no-probe" working 60) && ok "helper-b answers again with its copy ${t} s later" || bad "helper-b back (state $(stateOf helper-b --no-probe))"
check "the copy survived the sleep (same container)" "$([ "$(docker exec "$HB" docker ps -q --filter label=paasmcp.app=$APP | wc -l)" = 1 ] && echo 1 || echo 0)"
stopTicks

step "A PC that never answers: 3 tries, then left alone until a person wakes it"
touch "$SRC/insomnia"
docker pause "$HB" >/dev/null
before=$(packets)
$CLI scale set "$APP" 3 --yes >/dev/null 2>&1
startTicks
t=$(waitFor "diary 5 | grep -c 'Pedi 3 vezes para helper-b acordar pela rede'" 1 150) && ok "given up ${t} s later" || bad "given up"
check "3 packets in this series ($((  $(packets) - before )))" "$([ $(( $(packets) - before )) = 3 ] && echo 1 || echo 0)"
check "the diary says so" "$(diary 10 | grep -q "Pedi 3 vezes para helper-b acordar pela rede e ele não respondeu em [0-9]* min. Paro de tentar até ele responder de novo ou alguém usar \"Acordar agora\" na tela Ajudantes." && echo 1 || echo 0)"
sleep 25
check "no more packets after giving up ($(( $(packets) - before )))" "$([ $(( $(packets) - before )) = 3 ] && echo 1 || echo 0)"
check "the status shows it given up ($(stateOf helper-b --no-probe))" "$(field "$(helperJson helper-b --no-probe)" waking.gaveUp | grep -qx true && echo 1 || echo 0)"
rm -f "$SRC/insomnia"
$CLI pool wake helper-b now >"$SRC/now.json" 2>&1 || { cat "$SRC/now.json"; bad "pool wake now"; }
check "a person wakes it by hand: packet sent" "$([ $(( $(packets) - before )) = 4 ] && grep -q '"sent": true' "$SRC/now.json" && echo 1 || echo 0)"
t=$(waitFor "stateOf helper-b --no-probe" working 60) && ok "helper-b answers again ${t} s later" || bad "helper-b back after wake now"
stopTicks
check "the app answers through the balancer" "$(LB=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" paasmcp-pool-lb); node -e "fetch('http://$LB:$PORT/').then(r=>console.log(r.ok?1:0)).catch(()=>console.log(0))")"

step "Off: nothing is woken any more"
$CLI pool wake helper-b off >/dev/null 2>&1
docker pause "$HB" >/dev/null
before=$(packets)
$CLI scale set "$APP" 3 --yes >/dev/null 2>&1
check "helper-b not answering, no packet ($(stateOf helper-b --no-probe))" "$([ "$(packets)" = "$before" ] && [ "$(stateOf helper-b --no-probe)" = gone ] && echo 1 || echo 0)"
docker unpause "$HB" >/dev/null

check "no round failed" "$([ ! -s "$SRC/ticks.err" ] && echo 1 || { head -5 "$SRC/ticks.err" | sed 's/^/     /' >&2; echo 0; })"
echo
echo "     diary (pt):"
diary 25 | sed 's/^/     /'
echo
[ "$fail" = 0 ] && echo "All checks passed." || echo "Some checks FAILED."
exit $fail
