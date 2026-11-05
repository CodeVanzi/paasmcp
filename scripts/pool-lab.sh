#!/bin/bash
# Real-Docker check of scale phase 3 (helper pool, manual copies). Two "PCs" are Ubuntu containers
# with Docker inside, sshd and Node (helper-a 172.31.250.11, helper-b .12) on a lab network whose gateway
# (172.31.250.1) plays this server's Tailscale IP. Each PC joins with an invite, this server adds it
# over SSH, then an app that counts visits in Redis runs 3 copies: here, on helper-a and on helper-b,
# behind the pool balancer. Checks: visits reach every copy and share Redis; the variables reach the
# copies but never a helper's disk; the SSH key opens no terminal, forwards nothing and only works from
# this server; a helper "pulled from the plug" under load leaves the traffic within ~10 s; pause, a new
# deploy (copies roll to the new version), back to one copy, remove and leave.
# Needs Docker with privileged containers, `npm run build`, ssh and ssh-keygen. Isolated root, network
# and names; refuses to run where PaaSMCP already runs. Takes about 4 minutes.
# Usage: sudo scripts/pool-lab.sh   (POOL_LAB_BUILD_FLAGS="..." is passed to the helper image build)
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-pool-lab PAASMCP_POOL_DRAIN_SECONDS=3
NET=$PAASMCP_DOCKER_NETWORK GW=172.31.250.1 IPA=172.31.250.11 IPB=172.31.250.12
HA=paasmcp-lab-helper-a HB=paasmcp-lab-helper-b IMG=paasmcp-lab-helper:1
APP=pool-lab SRC=$(mktemp -d) fail=0
CLI="node $REPO/dist/cli.js"
for c in paasmcp-redis paasmcp-pool-lb "paasmcp-$APP"; do
  if docker inspect "$c" >/dev/null 2>&1; then echo "Container '$c' already exists (a real PaaSMCP?). Run this lab elsewhere." >&2; exit 1; fi
done
if node -e 'require("net").connect(4000,"127.0.0.1").on("connect",()=>process.exit(0)).on("error",()=>process.exit(1))'; then
  echo "127.0.0.1:4000 is in use (a real PaaSMCP app?); the lab's fresh state would allocate it." >&2; exit 1
fi
cleanup() {
  echo; echo "=== cleanup"
  [ -n "${LOAD_PID:-}" ] && kill "$LOAD_PID" 2>/dev/null
  docker rm -fv "$HA" "$HB" >/dev/null 2>&1
  docker rm -f paasmcp-pool-lb "paasmcp-$APP" "paasmcp-$APP-candidate" paasmcp-redis >/dev/null 2>&1
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
KEY="$PAASMCP_ROOT/paasmcp/pool/pool_ed25519"
sshw() { ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 "$@"; }

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
  docker build ${POOL_LAB_BUILD_FLAGS:-} -t "$IMG" "$SRC/img" >/dev/null || { echo "FAIL building the helper image"; exit 1; }
fi
docker network create --subnet 172.31.250.0/24 --gateway "$GW" "$NET" >/dev/null || exit 1
for h in "$HA:$IPA" "$HB:$IPB"; do
  docker run -d --privileged --name "${h%%:*}" --hostname "${h%%:*}" --network "$NET" --ip "${h##*:}" \
    --tmpfs /run:rw,mode=755 -v "$REPO:/opt/paasmcp:ro" "$IMG" >/dev/null || exit 1
done
for h in "$HA" "$HB"; do
  for _ in $(seq 60); do docker exec "$h" docker info >/dev/null 2>&1 && break; sleep 1; done
done
ok "two helper PCs up (Docker inside, sshd, no PaaSMCP running)"

step "Invite, join on each PC, add here"
for pair in "helper-a:$HA:$IPA" "helper-b:$HB:$IPB"; do
  IFS=: read -r name ctr ip <<<"$pair"
  out=$($CLI pool invite "$name" --advertise "$GW" --yes 2>&1) || { echo "$out"; bad "invite $name"; continue; }
  inv=$(echo "$out" | grep -o "paasmcp-pool://[A-Za-z0-9_-]*" | head -1)
  docker exec "$ctr" node /opt/paasmcp/dist/cli.js pool join "$inv" --cpus 1 --memory 512m --ip "$ip" --yes >"$SRC/join-$name.log" 2>&1 \
    || { cat "$SRC/join-$name.log"; bad "join $name"; continue; }
  $CLI pool add "$name" "$ip" >"$SRC/add-$name.json" 2>&1 || { cat "$SRC/add-$name.json"; bad "add $name"; continue; }
  ok "$name joined and was added ($(js 's.helper.give.cpus + " CPU, " + s.helper.give.memMb + " MB, " + s.helper.arch' < "$SRC/add-$name.json"))"
done
check "the invite cannot be used twice" "$($CLI pool add helper-a "$IPA" >/dev/null 2>&1 && echo 0 || echo 1)"
check "the worker copy is owned by root, outside the checkout" \
  "$(docker exec "$HA" stat -c '%U %a' /usr/local/lib/paasmcp-worker/worker.js | grep -qx 'root 644' && echo 1 || echo 0)"
check "the helper's key line: only from this server, only the worker, restricted" \
  "$(docker exec "$HA" cat /var/lib/paasmcp-worker/.ssh/authorized_keys | grep -q "^from=\"$GW\",command=\"/usr/local/bin/node /usr/local/lib/paasmcp-worker/worker.js\",restrict ssh-ed25519 " && echo 1 || echo 0)"
check "the invite's proof key is gone from the PC after it answered" \
  "$(docker exec "$HA" grep -c proofKey /var/lib/paasmcp-worker/worker.json | grep -qx 0 && echo 1 || echo 0)"

step "The SSH key opens no terminal, forwards nothing and works only from this server"
check "no command: refused, no shell" "$(sshw "paasmcp-worker@$IPA" </dev/null 2>&1 | grep -q 'never opens a terminal' && echo 1 || echo 0)"
check "a shell command: refused" "$(sshw "paasmcp-worker@$IPA" 'cat /etc/shadow' 2>&1 | grep -q 'Unknown order' && echo 1 || echo 0)"
tty=$(sshw -tt "paasmcp-worker@$IPA" bash </dev/null 2>&1)
check "a terminal (-t bash): refused" "$(echo "$tty" | grep -qE 'PTY allocation request failed|Unknown order' && ! echo "$tty" | grep -q '[#$] *$' && echo 1 || echo 0)"
check "port forwarding: refused" "$(sshw -W 127.0.0.1:22 "paasmcp-worker@$IPA" </dev/null >/dev/null 2>&1 && echo 0 || echo 1)"
# (/tmp is a tmpfs inside these containers, so docker cp would land under it: pipe the key instead.)
docker exec -i "$HB" sh -c 'umask 077; cat > /root/stolen' < "$KEY"
stolen=$(docker exec "$HB" ssh -i /root/stolen -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 "paasmcp-worker@$IPA" list 2>&1)
check "the same key from another machine: refused" "$(echo "$stolen" | grep -q 'Permission denied' && echo 1 || echo 0)"
check "...while the key itself is the right one (it works from this server)" "$(sshw "paasmcp-worker@$IPA" list 2>&1 | grep -q '"ok":true' && echo 1 || echo 0)"
docker exec "$HB" rm -f /root/stolen

step "An app with Redis and a secret, deployed here"
SECRET="lab-secret-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > "$SRC/app.js" <<'JS'
// Counts visits in Redis over raw RESP (no dependencies); /healthz answers 200 only while Redis does.
const http = require("http"), net = require("net"), crypto = require("crypto"), fs = require("fs");
const u = new URL(process.env.REDIS_URL);
const version = fs.readFileSync(__dirname + "/VERSION", "utf8").trim();
const enc = (a) => `*${a.length}\r\n` + a.map((x) => `$${Buffer.byteLength(String(x))}\r\n${x}\r\n`).join("");
// Sends the commands at once and resolves with one reply per command ("+PONG", ":12", bulk text).
function redis(cmds) {
  return new Promise((ok, ko) => {
    const s = net.connect(Number(u.port || 6379), u.hostname); let buf = "";
    s.setTimeout(1500, () => { s.destroy(); ko(new Error("redis timeout")); });
    s.on("error", ko);
    s.on("data", (d) => {
      buf += d; const replies = []; let i = 0;
      for (;;) {
        const e = buf.indexOf("\r\n", i); if (e < 0) break;
        const line = buf.slice(i, e);
        if (line[0] === "$" && Number(line.slice(1)) >= 0) {
          const len = Number(line.slice(1)); if (buf.length < e + 4 + len) break;
          replies.push(buf.slice(e + 2, e + 2 + len)); i = e + 4 + len;
        } else { replies.push(line); i = e + 2; }
      }
      if (replies.length < cmds.length) return;
      s.end();
      const err = replies.find((r) => typeof r === "string" && r[0] === "-");
      err ? ko(new Error(err)) : ok(replies);
    });
    s.write(cmds.map(enc).join(""));
  });
}
const auth = () => [["AUTH", decodeURIComponent(u.password)], ["SELECT", u.pathname.slice(1) || "0"]];
http.createServer(async (q, r) => {
  try {
    if (q.url === "/healthz") { const out = await redis([...auth(), ["PING"]]); return r.writeHead(out[2] === "+PONG" ? 200 : 503).end(); }
    const out = await redis([...auth(), ["INCR", "hits"]]);
    const hits = Number(out[2].slice(1));
    r.setHeader("Content-Type", "application/json");
    r.end(JSON.stringify({ host: process.env.HOSTNAME, hits, version, secret: crypto.createHash("sha256").update(process.env.LAB_SECRET || "").digest("hex").slice(0, 12) }));
  } catch (e) { r.writeHead(503).end(String(e.message)); }
}).listen(3000);
JS
echo v1 > "$SRC/VERSION"
printf 'FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
$CLI secret set "$APP" "LAB_SECRET=$SECRET" >/dev/null
deploy() { node --input-type=module -e "
  const d = await import('$REPO/dist/deployer.js');
  const r = await d.deployApp({ appName: '$APP', repoSource: '$SRC', internalPort: 3000, cpuLimit: '0.25', memoryLimit: '128m', withRedis: true, healthcheckPath: '/healthz' });
  if (r.warning) console.log(r.warning);"; }
deploy >"$SRC/deploy1.log" 2>&1 || { cat "$SRC/deploy1.log"; echo "FAIL deploy"; exit 1; }
PORT=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PAASMCP_ROOT/paasmcp/state.json','utf8')).apps['$APP'].localPort)")
check "Redis is also published on this server's helper address ($GW:6379)" "$(docker port paasmcp-redis | grep -q "$GW:6379" && echo 1 || echo 0)"
check "the check says the app can use helpers" "$($CLI pool check "$APP" | js 's.ok ? 1 : 0')"

step "3 copies: here, on helper-a and on helper-b"
$CLI scale "$APP" 3 --yes >"$SRC/scale3.json" 2>"$SRC/scale3.err" || { cat "$SRC/scale3.err"; bad "scale to 3"; }
sed 's/^/     /' "$SRC/scale3.err"
check "3 copies running" "$($CLI scale status "$APP" | js 's.apps[0].copies === 3 ? 1 : 0')"
LB=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" paasmcp-pool-lb)
get() { curl -s --max-time "${2:-10}" "http://$LB:$PORT${1:-/}"; }
hostsOf() { docker exec "$1" sh -c 'docker inspect -f "{{.Config.Hostname}}" $(docker ps -q --filter label=paasmcp.pool)' 2>/dev/null; }
HOST_O=$(docker inspect -f '{{.Config.Hostname}}' "paasmcp-$APP"); HOST_A=$(hostsOf "$HA"); HOST_B=$(hostsOf "$HB")
for i in $(seq 1 30); do get; echo; done > "$SRC/split.ndjson"
seen=$(node -e "const l=require('fs').readFileSync('$SRC/split.ndjson','utf8').trim().split('\n').map(JSON.parse);console.log([...new Set(l.map(x=>x.host))].sort().join(' '))")
check "visits reach all three copies (here $HOST_O, helper-a $HOST_A, helper-b $HOST_B)" \
  "$(for h in "$HOST_O" "$HOST_A" "$HOST_B"; do echo "$seen" | grep -qw "$h" || { echo 0; exit; }; done; echo 1)"
check "all copies share this server's Redis (30 visits counted once each)" \
  "$(node -e "const l=require('fs').readFileSync('$SRC/split.ndjson','utf8').trim().split('\n').map(JSON.parse).map(x=>x.hits).sort((a,b)=>a-b);console.log(new Set(l).size===30&&l[29]-l[0]===29?1:0)")"
check "all copies got the app's secret" \
  "$(node -e "const l=require('fs').readFileSync('$SRC/split.ndjson','utf8').trim().split('\n').map(JSON.parse);console.log(new Set(l.map(x=>x.secret)).size===1&&l[0].secret!=='e3b0c44298fc'?1:0)")"
check "copies are published only on the helper's address" \
  "$(docker exec "$HA" sh -c 'docker port $(docker ps -q --filter label=paasmcp.pool)' | grep -qx "3000/tcp -> $IPA:$PORT" && echo 1 || echo 0)"
check "the secret is not in the copy's container settings" \
  "$(docker exec "$HA" sh -c 'docker inspect $(docker ps -q --filter label=paasmcp.pool)' | grep -c "$SECRET" | grep -qx 0 && echo 1 || echo 0)"
check "the variables file lives in memory (tmpfs), in a private folder" \
  "$(docker exec "$HA" sh -c 'stat -f -c %T /run/paasmcp-worker; stat -c %a:%U /run/paasmcp-worker' | tr '\n' ' ' | grep -q '^tmpfs 700:paasmcp-worker' && echo 1 || echo 0)"
check "nothing on the helper's disk holds the secret while the copy runs" \
  "$(docker exec "$HA" sh -c "grep -rlsF '$SECRET' /var/lib /etc /root /home /opt /tmp /usr/local 2>/dev/null | head -1" | grep -q . && echo 0 || echo 1)"

step "helper-a pulled from the plug under load"
cat > "$SRC/load.js" <<'JS'
// 4 visitors in parallel, each giving up after 15 s; every visit is recorded (start, time, answer).
const [url, ms] = [process.argv[2], Number(process.argv[3])]; const end = Date.now() + ms; const t0 = Date.now(); const out = [];
const visitor = async () => { while (Date.now() < end) { const s = Date.now(); let host = null, ok = false;
  try { const r = await fetch(url, { signal: AbortSignal.timeout(15000) }); ok = r.ok; if (ok) host = (await r.json()).host; else await r.text(); } catch {}
  out.push({ at: s - t0, ms: Date.now() - s, ok, host }); } };
Promise.all([1, 2, 3, 4].map(visitor)).then(() => require("fs").writeFileSync(process.argv[4], JSON.stringify(out)));
JS
node "$SRC/load.js" "http://$LB:$PORT/" 30000 "$SRC/unplug.json" & LOAD_PID=$!
sleep 5; docker network disconnect "$NET" "$HA"; UNPLUG_AT=5000
wait "$LOAD_PID"; LOAD_PID=
node -e "
  const l = require('$SRC/unplug.json'), cut = $UNPLUG_AT, a = '$HOST_A';
  const lastA = Math.max(-1, ...l.filter((x) => x.host === a && x.at >= cut).map((x) => x.at));
  const after = l.filter((x) => x.at >= cut + 10000);
  const during = l.filter((x) => x.at >= cut - 15000 && x.at < cut + 10000);
  console.log('     ' + l.length + ' visits; last answer from helper-a started ' + (lastA < 0 ? 'before the cut' : (lastA - cut) + ' ms after it'));
  console.log('     around the cut: ' + during.length + ' visits, ' + during.filter((x) => !x.ok).length + ' lost (in progress on helper-a when it vanished), ' + during.filter((x) => x.ok && x.ms > 1000).length + ' slow (retried on another copy)');
  console.log('     from 10 s after the cut: ' + after.length + ' visits, ' + after.filter((x) => !x.ok).length + ' failed, slowest ' + Math.max(0, ...after.map((x) => x.ms)) + ' ms');
  require('fs').writeFileSync('$SRC/unplug.verdict', String(after.length > 20 && after.every((x) => x.ok && x.host !== a && x.ms < 1000) ? 1 : 0));"
check "10 s after the cut, every visit succeeds quickly on the copies left" "$(cat "$SRC/unplug.verdict")"
docker network connect --ip "$IPA" "$NET" "$HA"
sleep 8
check "helper-a back on the network: its copy is back in the traffic" \
  "$(for i in $(seq 1 15); do get; echo; done | grep -c "\"$HOST_A\"" | awk '{print ($1 > 0) ? 1 : 0}')"

step "Pause helper-b, then resume"
$CLI pool pause helper-b >/dev/null 2>"$SRC/pause.err"
check "paused: helper-b runs no copy and the app keeps 2" \
  "$([ -z "$(hostsOf "$HB")" ] && $CLI scale status "$APP" | js 's.apps[0].copies === 2 ? 1 : 0' | grep -qx 1 && echo 1 || echo 0)"
check "paused: no variables file left on helper-b" "$([ -z "$(docker exec "$HB" ls -A /run/paasmcp-worker)" ] && echo 1 || echo 0)"
$CLI pool resume helper-b >/dev/null 2>"$SRC/resume.err"
check "resumed: back to 3 copies" "$($CLI scale status "$APP" | js 's.apps[0].copies === 3 ? 1 : 0')"

step "A new deploy: the copies on helpers move to the new version"
echo v2 > "$SRC/VERSION"
deploy >"$SRC/deploy2.log" 2>&1 || { cat "$SRC/deploy2.log"; bad "redeploy"; }
for i in $(seq 1 15); do get; echo; done > "$SRC/v2.ndjson"
check "every copy answers with v2" "$(node -e "const l=require('fs').readFileSync('$SRC/v2.ndjson','utf8').trim().split('\n').map(JSON.parse);console.log(l.length===15&&l.every(x=>x.version==='v2')&&new Set(l.map(x=>x.host)).size===3?1:0)")"
check "the helpers keep only the newest image" "$(docker exec "$HA" docker image ls --format '{{.Repository}}' | grep -c '^paasmcp-pool/' | grep -qx 1 && echo 1 || echo 0)"

step "Back to one copy, then the PCs leave"
$CLI scale off "$APP" >/dev/null 2>"$SRC/off.err"
check "one copy, here; the balancer is gone" \
  "$($CLI scale status "$APP" | js 's.apps[0].copies === 1 ? 1 : 0' | grep -qx 1 && ! docker inspect paasmcp-pool-lb >/dev/null 2>&1 && echo 1 || echo 0)"
check "the app still answers here" "$(curl -s --max-time 5 "http://127.0.0.1:$PORT/" | grep -q '"version":"v2"' && echo 1 || echo 0)"
for h in "$HA" "$HB"; do
  check "$h: no copy, no variables file, nothing on disk holds the secret" \
    "$([ -z "$(hostsOf "$h")" ] && [ -z "$(docker exec "$h" ls -A /run/paasmcp-worker)" ] && [ -z "$(docker exec "$h" sh -c "grep -rlsF '$SECRET' /var/lib /etc /root /home /opt /tmp /usr/local /run 2>/dev/null | head -1")" ] && echo 1 || echo 0)"
done
$CLI pool remove helper-a --yes >/dev/null 2>"$SRC/remove.err"
check "removed: this server's key no longer opens helper-a" "$(sshw "paasmcp-worker@$IPA" list 2>&1 | grep -q 'Permission denied' && echo 1 || echo 0)"
docker exec "$HB" node /opt/paasmcp/dist/cli.js pool leave --yes >/dev/null 2>&1
check "left: helper-b has no worker user, key or worker copy" \
  "$(docker exec "$HB" sh -c 'id paasmcp-worker >/dev/null 2>&1 || [ -e /var/lib/paasmcp-worker ] || [ -e /usr/local/lib/paasmcp-worker ]' && echo 0 || echo 1)"
echo
[ "$fail" = 0 ] && echo "All checks passed." || echo "Some checks FAILED."
exit $fail
