#!/bin/bash
# Builds and runs every fixture in test/fixtures with the Dockerfile PaaSMCP generates, then curls it.
# Needs Docker, network for base images / packages, and a build (npm run build). Usage: scripts/dockerfile-lab.sh [fixture...]
set -u
cd "$(dirname "$0")/.."
FIXTURES=${*:-$(ls test/fixtures)}
port=18080; fail=0
for fx in $FIXTURES; do
  work=$(mktemp -d); cp -a "test/fixtures/$fx/." "$work"
  plan=$(node --input-type=module -e "const g=await import('./dist/github.js');console.log(JSON.stringify(g.detectOrGenerateDockerfile('$work')))")
  cport=$(echo "$plan" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).detectedPort))')
  img="paasmcp-fixture-$fx"
  if ! docker build -q -f "$work/Dockerfile.paasmcp" -t "$img" "$work" >/tmp/build-$fx.log 2>&1; then
    echo "FAIL build $fx (see /tmp/build-$fx.log)"; fail=1; continue
  fi
  docker rm -f "$img" >/dev/null 2>&1
  docker run -d --name "$img" -e PORT="$cport" -p 127.0.0.1:$port:$cport "$img" >/dev/null
  body=""; for i in $(seq 1 30); do body=$(curl -s "http://127.0.0.1:$port/" || true); [ -n "$body" ] && break; sleep 1; done
  if echo "$body" | grep -q "ok"; then echo "ok   $fx -> $(echo "$body" | head -c 40)"; else echo "FAIL run $fx: $(docker logs "$img" 2>&1 | tail -3)"; fail=1; fi
  docker rm -f "$img" >/dev/null; rm -rf "$work"; port=$((port+1))
done
exit $fail
