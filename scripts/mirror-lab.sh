#!/bin/bash
# Two "servers" on one Docker daemon: A = paasmcp-postgres (root /tmp/labA), B = replica (root /tmp/labB).
# Needs Docker and a build (npm run build). Uses its own Docker network (paasmcp-lab-net), /tmp/labA, /tmp/labB
# and ports 127.0.0.1:5432/5433. Refuses to run where PaaSMCP already runs (same container names); removes only what it created.
set -e
cd "$(dirname "$0")/.."
docker info >/dev/null 2>&1 || { echo "Docker is not reachable." >&2; exit 1; }
for c in paasmcp-postgres paasmcp-mirror-server-a; do
  if docker inspect "$c" >/dev/null 2>&1; then
    echo "Container '$c' already exists (a real PaaSMCP?). This lab never touches it: run it in a VM or a machine without PaaSMCP." >&2
    exit 1
  fi
done
for p in 5432 5433; do
  if (ss -ltn 2>/dev/null || true) | grep -q "127.0.0.1:$p "; then echo "Port 127.0.0.1:$p is in use; free it or run elsewhere." >&2; exit 1; fi
done
export PAASMCP_DOCKER_NETWORK=paasmcp-lab-net
docker network inspect "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$PAASMCP_DOCKER_NETWORK" >/dev/null
rm -rf /tmp/labA /tmp/labB
step() { echo; echo "=== $*"; }
runA() { PAASMCP_ROOT=/tmp/labA node --input-type=module -e "$1"; }
runB() { PAASMCP_ROOT=/tmp/labB node --input-type=module -e "$1"; }
pa() { docker exec -i paasmcp-postgres psql -U paasmcp_admin -d postgres -tA -c "$1"; }
pb() { docker exec -i paasmcp-mirror-server-a psql -U paasmcp_admin -d postgres -tA -c "$1"; }

step "A: start Postgres, cluster key, data"
name() { node --input-type=module -e "const c=await import('./dist/config.js');const s=c.loadState();s.federation={...(s.federation||{nodeId:'node-'+'$1',role:'standalone',redundancyMode:'warm-standby',peers:{}}),nodeId:'node-$1',nodeName:'$1'};c.saveState(s);"; }
PAASMCP_ROOT=/tmp/labA name server-a; PAASMCP_ROOT=/tmp/labB name server-b
runA 'const d=await import("./dist/database.js");d.ensureSharedPostgresCluster();const f=await import("./dist/federation.js");f.getOrCreateFederationClusterKey();'
pa "CREATE TABLE notas(id serial primary key, txt text); INSERT INTO notas(txt) SELECT 'n'||g FROM generate_series(1,100) g;"
KEY=$(runA 'const v=await import("./dist/vault.js");console.log(v.getSecrets("system").FEDERATION_CLUSTER_KEY)')

step "A: offer mirror to server-b"
TOKEN=$(runA 'const m=await import("./dist/mirror.js");const r=await m.offerMirror({peerName:"server-b",peerCidr:"172.16.0.0/12",advertiseHost:"paasmcp-postgres",withBackups:false});console.log(r.token)')
echo "token: ${TOKEN:0:20}..."

step "B: same cluster key, accept (pg_basebackup + streaming container)"
runB "const v=await import('./dist/vault.js');v.setSecretEntries('system',{FEDERATION_CLUSTER_KEY:'$KEY'});"
runB "const m=await import('./dist/mirror.js');console.log(JSON.stringify(m.acceptMirror('$TOKEN').replica))"
sleep 4
echo "rows on B copy: $(pb 'SELECT count(*) FROM notas')"

step "A writes 50 more; B follows"
pa "INSERT INTO notas(txt) SELECT 'm'||g FROM generate_series(1,50) g;"
sleep 2
echo "rows on B copy: $(pb 'SELECT count(*) FROM notas')"
echo "B refuses writes: $(pb "INSERT INTO notas(txt) VALUES ('x')" 2>&1 | head -1)"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().receiving))'
runA 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().sending))'

step "B goes away; A keeps WAL for it; B comes back and catches up"
docker stop paasmcp-mirror-server-a >/dev/null
pa "INSERT INTO notas(txt) SELECT repeat('w',500) FROM generate_series(1,20000) g;"
runA 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().sending))'
docker start paasmcp-mirror-server-a >/dev/null; sleep 5
echo "rows on B copy: $(pb 'SELECT count(*) FROM notas')  (A: $(pa 'SELECT count(*) FROM notas'))"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().receiving))'

step "A dies; B is promoted"
docker stop paasmcp-postgres >/dev/null
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(await m.promoteMirror("server-a")))'
sleep 2
echo "B accepts writes now: $(pb "INSERT INTO notas(txt) VALUES ('after-failover') RETURNING id")"
echo "rows on B: $(pb 'SELECT count(*) FROM notas')"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus()))'

step "Failback: A comes back, rejoins as a copy of B, gets the data back"
docker start paasmcp-postgres >/dev/null; sleep 3
GW=$(docker network inspect "$PAASMCP_DOCKER_NETWORK" -f '{{(index .IPAM.Config 0).Gateway}}')
TOKEN2=$(runB "const m=await import('./dist/mirror.js');const r=await m.offerMirror({peerName:'server-a',peerCidr:'172.16.0.0/12',advertiseHost:'$GW',fromCopyOf:'server-a'});console.log(r.token)")
runA "const m=await import('./dist/mirror.js');const r=m.acceptMirror('$TOKEN2',{rejoin:true});console.log('A old data kept at', r.movedAside)"
sleep 3
pb "INSERT INTO notas(txt) SELECT 'b'||g FROM generate_series(1,5) g;" >/dev/null; sleep 2
echo "A (now a copy) rows: $(pa 'SELECT count(*) FROM notas')  B rows: $(pb 'SELECT count(*) FROM notas')"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(await m.handbackMirror("server-a")))'
runA 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(await m.promoteMirror("server-b")))'
sleep 2
echo "A accepts writes again: $(pa "INSERT INTO notas(txt) VALUES ('back-home') RETURNING id" | head -1)"

step "B rebuilds its stale copy from A"
TOKEN3=$(runA 'const m=await import("./dist/mirror.js");const r=await m.offerMirror({peerName:"server-b",peerCidr:"172.16.0.0/12",advertiseHost:"paasmcp-postgres",withBackups:false});console.log(r.token)')
runB "const m=await import('./dist/mirror.js');const r=m.acceptMirror('$TOKEN3');console.log('B stale copy kept at', r.movedAside)"
sleep 4
echo "rows A: $(pa 'SELECT count(*) FROM notas')  B copy: $(pb 'SELECT count(*) FROM notas')"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().receiving))'

step "cleanup"
docker rm -f paasmcp-postgres paasmcp-mirror-server-a >/dev/null
docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null
# Postgres files belong to the container user; remove them from a throwaway container.
docker run --rm -v /tmp:/t alpine:3.20 rm -rf /t/labA /t/labB
