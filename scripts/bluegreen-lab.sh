#!/bin/bash
# Real-Docker check of the blue/green deploy: a healthy version goes live, a crashing one and a 500 one
# are refused while the old version keeps serving, and a swap under load drops no request on the Docker
# network (the Cloudflare Tunnel path). Isolated root and network; needs Docker and `npm run build`.
# Usage: sudo scripts/bluegreen-lab.sh
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-bg-lab
APP=bg-lab; SRC=$(mktemp -d); fail=0
if node -e 'require("net").connect(4000,"127.0.0.1").on("connect",()=>process.exit(0)).on("error",()=>process.exit(1))'; then
  echo "127.0.0.1:4000 is in use (a real PaaSMCP app?); the lab's fresh state would allocate it. Stop it first."; exit 1
fi
cleanup() {
  docker compose -f "$PAASMCP_ROOT/paasmcp/apps/$APP/compose.yaml" down --rmi all >/dev/null 2>&1 \
    || docker compose -f "$(find "$PAASMCP_ROOT" -name compose.yaml | head -1)" down --rmi all >/dev/null 2>&1
  docker rm -f "paasmcp-$APP" "paasmcp-$APP-candidate" >/dev/null 2>&1
  docker rmi "paasmcp/$APP:previous" "paasmcp/$APP:latest" >/dev/null 2>&1
  docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT

cat > "$SRC/app.js" <<'JS'
const v = require("fs").readFileSync("/app/VERSION", "utf8").trim();
if (v === "crash") { console.error("Error: DATABASE_URL is not set"); process.exit(1); }
require("http").createServer((q, s) => { if (v === "err500") { s.writeHead(500); return s.end(); } s.end(v); }).listen(3000);
JS
printf 'FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
cat > "$SRC/load.js" <<'JS'
const [url, ms] = [process.argv[2], Number(process.argv[3])]; const end = Date.now() + ms; let ok = 0, fail = 0; const seen = {};
(async () => { while (Date.now() < end) { try { const t = await (await fetch(url, { signal: AbortSignal.timeout(2000) })).text(); ok++; seen[t] = (seen[t] || 0) + 1; } catch { fail++; } await new Promise((r) => setTimeout(r, 20)); } console.log(JSON.stringify({ ok, fail, seen })); })();
JS

deploy() { # version [extra JSON options]
  echo "$1" > "$SRC/VERSION"
  node --input-type=module -e "
    const d = await import('$REPO/dist/deployer.js');
    try { const r = await d.deployApp({ appName: '$APP', repoSource: '$SRC', internalPort: 3000, healthcheckTimeoutSeconds: 5, ...${2:-{\}} });
      console.log('deployed', r.cutover, JSON.stringify(r.healthcheck || {})); }
    catch (e) { console.log('refused', e.name, JSON.stringify(e.message.split('\n').slice(-1)[0])); process.exitCode = 3; }"
}
check() { # description, expected (0/3), actual exit, expected body
  local body; for i in $(seq 1 20); do body=$(curl -s 127.0.0.1:4000/); [ "$body" = "$4" ] && break; sleep 0.25; done
  if [ "$3" = "$2" ] && [ "$body" = "$4" ]; then echo "ok   $1 (serving: $body)"; else echo "FAIL $1 (exit $3, serving: '$body')"; fail=1; fi
}

deploy v1; check "first deploy goes live" 0 $? v1
deploy crash; check "crashing version refused, v1 kept" 3 $? v1
deploy err500; check "HTTP 500 version refused, v1 kept" 3 $? v1
[ "$(docker run --rm "paasmcp/$APP:latest" cat /app/VERSION)" = v1 ] && echo "ok   :latest still points at v1" || { echo "FAIL :latest moved"; fail=1; }

docker run --rm --network "$PAASMCP_DOCKER_NETWORK" -v "$SRC/load.js:/load.js:ro" node:20-alpine \
  node /load.js "http://paasmcp-$APP:3000/" 25000 > "$SRC/net.out" &
sleep 2; deploy v2; rc=$?; wait
check "v2 swapped in" 0 $rc v2
net=$(cat "$SRC/net.out"); echo "     docker-network traffic during the swap: $net"
# A request in flight on the old container when it stops can still fail (the app has no graceful shutdown).
dropped=$(echo "$net" | sed -E 's/.*"fail":([0-9]+).*/\1/')
[ "$dropped" -le 2 ] && echo "$net" | grep -q '"v2"' || { echo "FAIL $dropped requests dropped on the Docker network"; fail=1; }

node --input-type=module -e "const d = await import('$REPO/dist/deployer.js'); d.manageAppLifecycle('$APP', 'rollback');"
check "rollback returns to v1" 0 $? v1
[ -z "$(docker ps -aq -f name=paasmcp-$APP-candidate)" ] && echo "ok   no candidate container left" || { echo "FAIL candidate left behind"; fail=1; }
exit $fail
