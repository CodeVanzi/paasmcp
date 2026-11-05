#!/bin/bash
# Real-Docker check of the live deploy status: a deploy started from the dashboard goes through its
# phases (fetching, building, checking, live) while the dashboard keeps answering, a broken commit ends
# "failed" with the previous version still serving, and the commit message and date are recorded.
# Isolated root, port and network; needs Docker, git and `npm run build`. About 2 min.
# Usage: sudo scripts/deploy-status-lab.sh
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-status-lab
APP=status-lab; SRC=$(mktemp -d); DASH_PORT=4199; fail=0
if node -e 'require("net").connect(4000,"127.0.0.1").on("connect",()=>process.exit(0)).on("error",()=>process.exit(1))'; then
  echo "127.0.0.1:4000 is in use (a real PaaSMCP app?); the lab's fresh state would allocate it. Stop it first."; exit 1
fi
cleanup() {
  [ -n "${DASH_PID:-}" ] && kill "$DASH_PID" 2>/dev/null
  docker compose -f "$PAASMCP_ROOT/apps/$APP/compose.yaml" down --rmi all >/dev/null 2>&1
  docker rm -f "paasmcp-$APP" "paasmcp-$APP-candidate" >/dev/null 2>&1
  docker rmi "paasmcp/$APP:previous" "paasmcp/$APP:latest" >/dev/null 2>&1
  docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# A git repository the deploy clones (file:// URL): each version's build takes a few seconds.
git -C "$SRC" init -q -b main
cat > "$SRC/app.js" <<'JS'
const v = require("fs").readFileSync("/app/VERSION", "utf8").trim();
if (v === "crash") { console.error("Error: DATABASE_URL is not set"); process.exit(1); }
require("http").createServer((q, s) => s.end(v)).listen(3000);
JS
printf 'FROM node:20-alpine\nWORKDIR /app\nRUN sleep 6\nCOPY . .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
commit() { echo "$1" > "$SRC/VERSION"; git -C "$SRC" add -A; git -C "$SRC" -c user.name="Lab Dev" -c user.email=lab@example.com commit -q -m "$2"; }

# The dashboard runs in this process tree, not in its container ('paasmcp dashboard start' builds one).
node --input-type=module -e "const d = await import('$REPO/dist/dashboard.js'); d.startDashboardServer($DASH_PORT, '127.0.0.1');" >"$SRC/dash.log" 2>&1 &
DASH_PID=$!
for i in $(seq 1 40); do curl -s -o /dev/null "127.0.0.1:$DASH_PORT/" && break; sleep 0.25; done
TOKEN=$(node "$REPO/dist/cli.js" dashboard token | sed -nE 's/.*"dashboardToken": "([^"]+)".*/\1/p')
COOKIE=$(curl -s -D - -o /dev/null -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}" "127.0.0.1:$DASH_PORT/api/login" | sed -nE 's/^[Ss]et-[Cc]ookie: ([^;]+).*/\1/p')
[ -n "$COOKIE" ] || { echo "FAIL could not log in to the lab dashboard"; cat "$SRC/dash.log"; exit 1; }

# Deploy from the dashboard and watch /api/deploys while it runs; each answer must come quickly.
watch_deploy() { # label
  : > "$SRC/phases"
  curl -s -m 300 -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
    -d "{\"appName\":\"$APP\",\"repoSource\":\"file://$SRC\",\"internalPort\":3000,\"healthcheckTimeoutSeconds\":6}" \
    "127.0.0.1:$DASH_PORT/api/deploy" > "$SRC/deploy.out" &
  local cpid=$! slow=0
  while kill -0 $cpid 2>/dev/null; do
    local start end
    start=$(date +%s%N)
    curl -s -m 5 -H "Cookie: $COOKIE" "127.0.0.1:$DASH_PORT/api/deploys" \
      | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const d=JSON.parse(s).deploys['$APP'];if(d&&d.active)console.log(d.active.phase)})" >> "$SRC/phases"
    end=$(date +%s%N)
    [ $(( (end - start) / 1000000 )) -gt 1500 ] && slow=$((slow + 1))
    sleep 0.3
  done
  wait $cpid
  echo "     $1 phases seen: $(uniq "$SRC/phases" | tr '\n' ' ')"
  [ "$slow" -eq 0 ] && ok "$1: the dashboard kept answering during the build" || bad "$1: $slow slow answers (event loop blocked?)"
}
summary() { curl -s -H "Cookie: $COOKIE" "127.0.0.1:$DASH_PORT/api/deploys" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const d=JSON.parse(s).deploys['$APP'];console.log(JSON.stringify(d))})"; }

commit v1 "First version"
watch_deploy "v1"
grep -q building "$SRC/phases" && ok "v1: building was visible while it ran" || bad "v1: building never seen"
S=$(summary)
echo "$S" | grep -q '"phase":"live"' && ok "v1: last deploy is live" || bad "v1: $S"
echo "$S" | grep -q '"message":"First version"' && echo "$S" | grep -q '"author":"Lab Dev"' && ok "v1: commit message and author recorded" || bad "v1 commit: $S"
[ "$(curl -s 127.0.0.1:4000/)" = v1 ] && ok "v1 serving" || bad "v1 not serving"

commit crash "Break the app"
watch_deploy "crash"
grep -q checking "$SRC/phases" && ok "crash: checking was visible" || bad "crash: checking never seen"
S=$(summary)
echo "$S" | grep -q '"phase":"failed"' && ok "crash: last deploy failed" || bad "crash: $S"
echo "$S" | grep -q 'DATABASE_URL is not set' && ok "crash: the candidate's log is kept with the error" || bad "crash log: $S"
echo "$S" | grep -q '"running":{[^}]*"message":"First version"' && ok "crash: running version is still v1" || bad "crash running: $S"
[ "$(curl -s 127.0.0.1:4000/)" = v1 ] && ok "v1 still serving after the failed deploy" || bad "v1 gone"

node "$REPO/dist/cli.js" deploys "$APP" | grep -q '"trigger": "dashboard"' && ok "CLI 'paasmcp deploys' lists the runs" || bad "CLI deploys"
exit $fail
