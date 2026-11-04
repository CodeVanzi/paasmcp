#!/bin/bash
# Real-Docker check of active-active on one Docker host: server A (Postgres + control channel) and
# server B (live copy + the app) share a lab network. B builds the exact commit A publishes, its app
# reads and writes A's database through the shared-service names, a commit A has not published is
# ignored, the self-hosted edge (Caddy) serves B's copy and skips a dead backend, B runs A's tunnel
# connector and steps out of it while its copy is sick, and after A dies
# B is promoted and the app moves to the local copy.
# Usage: sudo env PATH=$PATH scripts/active-lab.sh   (needs Docker and `npm run build`)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)
docker info >/dev/null 2>&1 || { echo "Docker is not reachable." >&2; exit 1; }
for c in paasmcp-postgres paasmcp-mirror-server-a paasmcp-shop paasmcp-edge paasmcp-tunnel-active; do
  if docker inspect "$c" >/dev/null 2>&1; then
    echo "Container '$c' already exists (a real PaaSMCP?). This lab never touches it: run it in a VM or a machine without PaaSMCP." >&2
    exit 1
  fi
done
for p in 80 443 4100 5432 5433; do
  if (ss -ltn 2>/dev/null || true) | grep -qE "[:.]$p "; then echo "Port $p is in use; free it or run elsewhere." >&2; exit 1; fi
done
export PAASMCP_DOCKER_NETWORK=paasmcp-aa-lab
A=$(mktemp -d); B=$(mktemp -d); SRC=$(mktemp -d)
docker network create "$PAASMCP_DOCKER_NETWORK" >/dev/null
cleanup() {
  echo; echo "=== cleanup"
  docker rm -f paasmcp-postgres paasmcp-mirror-server-a paasmcp-shop paasmcp-shop-candidate paasmcp-edge paasmcp-tunnel-active >/dev/null 2>&1 || true
  docker rmi paasmcp/shop:latest paasmcp/shop:previous >/dev/null 2>&1 || true
  docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1 || true
  docker run --rm -v "$A:/a" -v "$B:/b" alpine:3.20 sh -c 'rm -rf /a/* /b/*' >/dev/null 2>&1 || true
  rm -rf "$A" "$B" "$SRC"
}
trap cleanup EXIT
step() { echo; echo "=== $*"; }
runA() { PAASMCP_ROOT=$A node --input-type=module -e "$1"; }
runB() { PAASMCP_ROOT=$B node --input-type=module -e "$1"; }
pa() { docker exec -i paasmcp-postgres psql -U paasmcp_admin -d "${2:-postgres}" -tA -c "$1"; }
check() { if [ "$2" = "$3" ]; then echo "ok   $1 ($2)"; else echo "FAIL $1: got '$2', expected '$3'"; exit 1; fi; }

step "A: Postgres, cluster key, the shop's database"
for s in A:server-a B:server-b; do
  PAASMCP_ROOT=$( [ "${s%%:*}" = A ] && echo "$A" || echo "$B") node --input-type=module -e "const c=await import('$REPO/dist/config.js');const s=c.loadState();s.federation={...s.federation,nodeId:'node-${s#*:}',nodeName:'${s#*:}'};c.saveState(s);"
done
runA "const d=await import('$REPO/dist/database.js');d.ensureSharedPostgresCluster();const f=await import('$REPO/dist/federation.js');f.getOrCreateFederationClusterKey();"
# The image's first start restarts Postgres once after init: wait until it really accepts queries.
for i in $(seq 1 30); do pa "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
pa "CREATE ROLE user_shop LOGIN PASSWORD 'shoppass'" >/dev/null
pa "CREATE DATABASE db_shop OWNER user_shop" >/dev/null
docker exec -i paasmcp-postgres psql -U user_shop -d db_shop -c "CREATE TABLE pedidos(id serial primary key, origem text); INSERT INTO pedidos(origem) VALUES ('a'),('a'),('a');" >/dev/null
KEY=$(runA "const v=await import('$REPO/dist/vault.js');console.log(v.getSecrets('system').FEDERATION_CLUSTER_KEY)")

step "Mirror A -> B"
TOKEN=$(runA "const m=await import('$REPO/dist/mirror.js');const r=await m.offerMirror({peerName:'server-b',peerCidr:'172.16.0.0/12',advertiseHost:'paasmcp-postgres',withBackups:false});console.log(r.token)")
runB "const v=await import('$REPO/dist/vault.js');v.setSecretEntries('system',{FEDERATION_CLUSTER_KEY:'$KEY'});const m=await import('$REPO/dist/mirror.js');m.acceptMirror('$TOKEN');"
# On real servers the origin advertises its Tailscale IP; here A's container IP plays that role.
AIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$PAASMCP_DOCKER_NETWORK\").IPAddress}}" paasmcp-postgres)
runB "const c=await import('$REPO/dist/config.js');const s=c.loadState();s.mirror.replicas['server-a'].peerHost='$AIP';c.saveState(s);"
echo "A's 'Tailscale IP' in this lab: $AIP"

step "The shop's repository (two commits)"
cat > "$SRC/app.js" <<'JS'
const { execFileSync } = require("child_process");
const v = require("fs").readFileSync("/app/VERSION", "utf8").trim();
const q = (url, sql) => execFileSync("psql", [url, "-tAc", sql], { encoding: "utf8" }).trim().split("\n")[0];
require("http").createServer((req, res) => {
  try {
    if (req.url === "/healthz") return res.end(`${v} ${q(process.env.DATABASE_URL, "SELECT count(*) FROM pedidos")}`);
    if (req.url === "/buy") return res.end(q(process.env.DATABASE_URL, "INSERT INTO pedidos(origem) VALUES ('b') RETURNING id"));
    if (req.url === "/replica") return res.end(q(process.env.DATABASE_REPLICA_URL, "SELECT count(*) FROM pedidos"));
    res.end(v);
  } catch (e) { res.writeHead(500); res.end(String(e.message).split("\n")[0]); }
}).listen(3000);
JS
# Node + psql without package downloads: the node binary on top of the Postgres image.
printf 'FROM node:20-alpine AS node\nFROM postgres:16-alpine\nCOPY --from=node /usr/local/bin/node /usr/local/bin/node\nWORKDIR /app\nCOPY . .\nCMD ["node", "app.js"]\n' > "$SRC/Dockerfile"
git -C "$SRC" init -q -b main && git -C "$SRC" config user.email lab@example.com && git -C "$SRC" config user.name lab
echo v1 > "$SRC/VERSION"; git -C "$SRC" add -A; git -C "$SRC" commit -qm v1; C1=$(git -C "$SRC" rev-parse HEAD)
echo v2 > "$SRC/VERSION"; git -C "$SRC" commit -qam v2; C2=$(git -C "$SRC" rev-parse HEAD)
echo v3-unpublished > "$SRC/VERSION"; git -C "$SRC" commit -qam v3; C3=$(git -C "$SRC" rev-parse HEAD)

# A's side, as after 'paasmcp deploy' + 'paasmcp active on' (A does not run the app in this lab: same host, same port).
publishA() { # commit
  runA "const c=await import('$REPO/dist/config.js');const v=await import('$REPO/dist/vault.js');const s=c.loadState();
    s.apps.shop={name:'shop',repoUrl:'file://$SRC',branch:'main',localPort:4100,internalPort:3000,containerName:'paasmcp-shop',appDir:'$A/apps/shop',runtimeType:'node',databases:[],domains:[],createdAt:'x',updatedAt:'x',lastCommit:'$1'.slice(0,7),lastCommitSha:'$1',healthcheckPath:'/healthz',healthcheckTimeoutSeconds:120,activeActive:true};
    c.saveState(s);v.saveSecrets('shop',{DATABASE_URL:'postgresql://user_shop:shoppass@paasmcp-postgres:5432/db_shop'});
    const a=await import('$REPO/dist/active.js');console.log(JSON.stringify(a.publishActiveState()));"
}
syncB() { runB "const a=await import('$REPO/dist/active.js');const r=await a.syncActivePeers();console.log(JSON.stringify(r.map(x=>({peer:x.peer,status:x.status,deployed:x.deployed,errors:x.errors,detail:x.detail}))))"; }

step "A publishes commit v1 through its own Postgres"
publishA "$C1"
check "manifest stored in paasmcp_meta" "$(pa 'SELECT count(*) FROM active_manifest' paasmcp_meta)" "1"
check "app users cannot connect to paasmcp_meta" "$(docker exec -i paasmcp-postgres psql -U user_shop -d paasmcp_meta -tAc 'SELECT 1' 2>&1 | grep -c 'permission denied' || true)" "1"
sleep 2
check "the copy on B already has it" "$(docker exec -i paasmcp-mirror-server-a psql -U paasmcp_admin -d paasmcp_meta -tAc 'SELECT count(*) FROM active_manifest')" "1"

step "B syncs: imports the app and builds v1 (blue/green)"
syncB
check "B serves v1, counting A's rows" "$(curl -s 127.0.0.1:4100/healthz)" "v1 3"
grep -q "paasmcp-postgres:$AIP" "$B/apps/shop/compose.yaml" && echo "ok   compose maps the shared services to A ($AIP)"
check "B writes into A's database" "$(curl -s 127.0.0.1:4100/buy)" "4"
check "A sees B's order" "$(pa "SELECT count(*) FROM pedidos WHERE origem='b'" db_shop)" "1"
sleep 1
check "reads from B's local copy (DATABASE_REPLICA_URL)" "$(curl -s 127.0.0.1:4100/replica)" "4"

step "A deploys v2 and publishes; v3 is on the branch but A has not published it"
publishA "$C2"
sleep 2
syncB
check "B runs exactly A's commit" "$(curl -s 127.0.0.1:4100/healthz)" "v2 4"
check "a second sync changes nothing" "$(syncB | grep -c '"status":"unchanged"')" "1"

step "Self-hosted edge on B: Caddy splits requests, skips the dead backend"
runB "const c=await import('$REPO/dist/config.js');const s=c.loadState();s.edge={sites:{}};c.saveState(s);const e=await import('$REPO/dist/edge.js');console.log(JSON.stringify(e.addEdgeSite('shop','shop.localhost').backends));await e.installEdge();"
cat "$B/paasmcp-edge/conf/Caddyfile"
# Wait for Caddy to start and issue its local certificate.
for i in $(seq 1 30); do curl -sk --max-time 2 --resolve shop.localhost:443:127.0.0.1 https://shop.localhost/healthz >/dev/null && break; sleep 1; done
ok=0
for i in $(seq 1 30); do
  out=$(curl -sk --max-time 5 --resolve shop.localhost:443:127.0.0.1 https://shop.localhost/healthz || true)
  [ "${out%% *}" = "v2" ] && ok=$((ok+1))
  sleep 0.3
done
check "30 requests through the edge (A's backend is down in this lab)" "$ok" "30"
runB "const e=await import('$REPO/dist/edge.js');console.log(JSON.stringify((await e.edgeStatus()).sites))"

step "Tunnel for apps on both servers: B runs A's connector, steps out while its copy is sick"
# A's side as after 'paasmcp active tunnel on' (no Cloudflare account in a lab: the token is a dummy).
LABTOKEN=eyJhIjoibGFiIiwidCI6ImxhYiJ9LABTOKEN
runA "const c=await import('$REPO/dist/config.js');const v=await import('$REPO/dist/vault.js');const s=c.loadState();
  s.activeTunnel={tunnelId:'22222222-2222-4222-8222-222222222222',name:'paasmcp-active-server-a',createdAt:'x',routes:{}};c.saveState(s);
  v.setSecretEntries('system',{ACTIVE_TUNNEL_TOKEN:'$LABTOKEN'});const a=await import('$REPO/dist/active.js');console.log(JSON.stringify(a.publishActiveState()));"
sleep 2
check "B starts the connector from the control channel" "$(runB "const a=await import('$REPO/dist/active.js');console.log((await a.syncActivePeers())[0].tunnel)")" "started"
check "cloudflared got the token from its private env file" "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' paasmcp-tunnel-active | grep -c "^TUNNEL_TOKEN=$LABTOKEN$")" "1"
check "pinned image" "$(docker inspect -f '{{.Config.Image}}' paasmcp-tunnel-active)" "cloudflare/cloudflared:2025.8.1"
# The dummy token cannot connect to Cloudflare; a sleeping container stands in for the connector from here on.
docker rm -f paasmcp-tunnel-active >/dev/null
docker run -d --name paasmcp-tunnel-active alpine:3.20 sleep 3600 >/dev/null
TICKS="const t=await import('$REPO/dist/activetunnel.js');const out=[];for(let i=0;i<2;i++){out.push((await t.tunnelWatchTick()).action);}console.log(out.join(','))"
check "healthy copy stays in" "$(runB "$TICKS")" "none,none"
docker pause paasmcp-postgres >/dev/null   # the link to A's database breaks; B's /healthz stops answering
check "sick copy steps out after two rounds" "$(runB "$TICKS")" "none,leave"
check "connector stopped" "$(docker inspect -f '{{.State.Running}}' paasmcp-tunnel-active)" "false"
docker unpause paasmcp-postgres >/dev/null
for i in $(seq 1 20); do curl -s --max-time 3 127.0.0.1:4100/healthz | grep -q '^v2' && break; sleep 1; done
check "healthy again: back in after two rounds" "$(runB "$TICKS")" "none,return"
check "connector running" "$(docker inspect -f '{{.State.Running}}' paasmcp-tunnel-active)" "true"
runA "const c=await import('$REPO/dist/config.js');const v=await import('$REPO/dist/vault.js');const s=c.loadState();delete s.activeTunnel;c.saveState(s);
  v.deleteSecretKey('system','ACTIVE_TUNNEL_TOKEN');const a=await import('$REPO/dist/active.js');console.log(JSON.stringify(a.publishActiveState()));"
sleep 2
check "A turns it off: B removes its connector" "$(runB "const a=await import('$REPO/dist/active.js');console.log((await a.syncActivePeers())[0].tunnel)")" "removed"
check "container gone" "$(docker inspect paasmcp-tunnel-active >/dev/null 2>&1 && echo present || echo gone)" "gone"

step "A dies; B is promoted; the app moves to B's copy"
docker stop paasmcp-postgres >/dev/null
runB "const m=await import('$REPO/dist/mirror.js');console.log(JSON.stringify(await m.promoteMirror('server-a')))"
grep -q "extra_hosts" "$B/apps/shop/compose.yaml" && { echo "FAIL extra_hosts still points at A"; exit 1; } || echo "ok   compose no longer points at A"
check "B serves v2 from its own copy" "$(curl -s 127.0.0.1:4100/healthz)" "v2 4"
# (ids jump after a promotion: Postgres logs sequences ahead, so count rows instead)
curl -s 127.0.0.1:4100/buy >/dev/null
check "B accepts orders alone" "$(curl -s 127.0.0.1:4100/healthz)" "v2 5"
check "edge still answers" "$(curl -sk --max-time 5 --resolve shop.localhost:443:127.0.0.1 https://shop.localhost/healthz)" "v2 5"
echo; echo "All active-active lab checks passed."
