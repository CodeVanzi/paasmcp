#!/bin/bash
# Three "servers" on one Docker daemon, in a star: A = origin (paasmcp-postgres, root /tmp/starA),
# B and C = copies of A (roots /tmp/starB, /tmp/starC), plus an arbiter on 127.0.0.1:4197.
# A fails: exactly one copy takes over, the other steps aside. Then, by default, failback, and the copy
# left behind is rebuilt from a new offer; with the argument "gone", A never comes back: the copy left
# behind follows the server that took over, which then fails too, and the copy takes over in turn.
# Needs Docker and a build (npm run build). Uses its own Docker network (paasmcp-lab-net) and ports
# 127.0.0.1:5432/5433/5443/4197. Refuses to run where PaaSMCP already runs (same container names);
# removes only what it created.
set -e
cd "$(dirname "$0")/.."
docker info >/dev/null 2>&1 || { echo "Docker is not reachable." >&2; exit 1; }
for c in paasmcp-postgres paasmcp-mirror-server-a paasmcp-mirror-server-a-c; do
  if docker inspect "$c" >/dev/null 2>&1; then
    echo "Container '$c' already exists (a real PaaSMCP?). This lab never touches it: run it in a VM or a machine without PaaSMCP." >&2
    exit 1
  fi
done
for p in 5432 5433 5443 4197; do
  if (ss -ltn 2>/dev/null || true) | grep -q "127.0.0.1:$p "; then echo "Port 127.0.0.1:$p is in use; free it or run elsewhere." >&2; exit 1; fi
done
export PAASMCP_DOCKER_NETWORK=paasmcp-lab-net
docker network inspect "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$PAASMCP_DOCKER_NETWORK" >/dev/null
rm -rf /tmp/starA /tmp/starB /tmp/starC /tmp/starArb
ARB_PID=""
cleanup() {
  echo; echo "=== cleanup"
  [ -n "$ARB_PID" ] && kill "$ARB_PID" 2>/dev/null || true
  docker rm -f paasmcp-postgres paasmcp-mirror-server-a paasmcp-mirror-server-a-c >/dev/null 2>&1 || true
  docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1 || true
  docker run --rm -v /tmp:/t alpine:3.20 rm -rf /t/starA /t/starB /t/starC /t/starArb >/dev/null 2>&1 || rm -rf /tmp/starA /tmp/starB /tmp/starC /tmp/starArb
}
trap cleanup EXIT
step() { echo; echo "=== $*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }
runA() { PAASMCP_ROOT=/tmp/starA node --input-type=module -e "$1"; }
runB() { PAASMCP_ROOT=/tmp/starB node --input-type=module -e "$1"; }
# C's copy needs its own container name and port on this shared Docker host.
runC() { PAASMCP_ROOT=/tmp/starC PAASMCP_MIRROR_NAME_SUFFIX=-c PAASMCP_MIRROR_PORT_BASE=5443 node --input-type=module -e "$1"; }
pa() { docker exec -i paasmcp-postgres psql -U paasmcp_admin -d postgres -tA -c "$1"; }
pb() { docker exec -i paasmcp-mirror-server-a psql -U paasmcp_admin -d postgres -tA -c "$1"; }
pc() { docker exec -i paasmcp-mirror-server-a-c psql -U paasmcp_admin -d postgres -tA -c "$1"; }
name() { node --input-type=module -e "const c=await import('./dist/config.js');const s=c.loadState();s.federation={...(s.federation||{role:'standalone',redundancyMode:'warm-standby',peers:{}}),nodeId:'node-$1',nodeName:'$1'};c.saveState(s);"; }
tick() { echo "  $1 watch: $("run$1" 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(await m.watchTick()))')"; }

step "A: start Postgres, cluster key, data"
PAASMCP_ROOT=/tmp/starA name server-a; PAASMCP_ROOT=/tmp/starB name server-b; PAASMCP_ROOT=/tmp/starC name server-c
runA 'const d=await import("./dist/database.js");d.ensureSharedPostgresCluster();const f=await import("./dist/federation.js");f.getOrCreateFederationClusterKey();'
# The image's first start runs a socket-only init server, then restarts: wait for the real one (TCP).
for _ in $(seq 60); do docker exec paasmcp-postgres psql -h 127.0.0.1 -U paasmcp_admin -d postgres -tAc 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
pa "CREATE TABLE notas(id serial primary key, txt text); INSERT INTO notas(txt) SELECT 'n'||g FROM generate_series(1,100) g;"
KEY=$(runA 'const v=await import("./dist/vault.js");console.log(v.getSecrets("system").FEDERATION_CLUSTER_KEY)')

step "A offers its data to B and to C (one replication slot each)"
offer() { runA "const m=await import('./dist/mirror.js');const r=await m.offerMirror({peerName:'$1',peerCidr:'172.16.0.0/12',advertiseHost:'paasmcp-postgres',withBackups:false});console.log(r.token)"; }
TB=$(offer server-b); TC=$(offer server-c)
runB "const v=await import('./dist/vault.js');v.setSecretEntries('system',{FEDERATION_CLUSTER_KEY:'$KEY'});"
runC "const v=await import('./dist/vault.js');v.setSecretEntries('system',{FEDERATION_CLUSTER_KEY:'$KEY'});"
runB "const m=await import('./dist/mirror.js');console.log(JSON.stringify(m.acceptMirror('$TB').replica))"
runC "const m=await import('./dist/mirror.js');console.log(JSON.stringify(m.acceptMirror('$TC').replica))"
pa "INSERT INTO notas(txt) SELECT 'm'||g FROM generate_series(1,50) g;"
sleep 4
echo "rows A: $(pa 'SELECT count(*) FROM notas')  B copy: $(pb 'SELECT count(*) FROM notas')  C copy: $(pc 'SELECT count(*) FROM notas')"
[ "$(pb 'SELECT count(*) FROM notas')" = 150 ] && [ "$(pc 'SELECT count(*) FROM notas')" = 150 ] || fail "both copies should have 150 rows"
runA 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().sending))'

step "Arbiter up; B and C may both take over A automatically"
ARB_KEY=$(runA 'const a=await import("./dist/arbiter.js");console.log(a.deriveArbiterKey())')
PAASMCP_ROOT=/tmp/starArb PAASMCP_ARBITER_KEY=$ARB_KEY node dist/cli.js arbiter serve --host 127.0.0.1 --port 4197 &
ARB_PID=$!
sleep 1
for s in A B C; do "run$s" 'const m=await import("./dist/mirror.js");m.setArbiterUrl("http://127.0.0.1:4197")'; done
for s in B C; do "run$s" 'const m=await import("./dist/mirror.js");m.setAutoFailover("server-a",true)'; done
tick A; tick B; tick C

step "A dies: one copy takes over, the other steps aside"
docker stop paasmcp-postgres >/dev/null
sleep 3
# The arbiter must lose A for over a minute.
echo "  waiting 65 s for the arbiter to lose A..."; sleep 65
tick C
tick B
C_PROMOTED=$(runC 'const c=await import("./dist/config.js");console.log(c.loadState().mirror.replicas["server-a"].promotedAt?"yes":"no")')
B_PROMOTED=$(runB 'const c=await import("./dist/config.js");console.log(c.loadState().mirror.replicas["server-a"].promotedAt?"yes":"no")')
echo "  promoted on B: $B_PROMOTED, on C: $C_PROMOTED"
[ "$C_PROMOTED" = yes ] && [ "$B_PROMOTED" = no ] || fail "C ticked first and should be the one that took over"
B_BEHIND=$(runB 'const c=await import("./dist/config.js");console.log(JSON.stringify(c.loadState().mirror.replicas["server-a"].supersededBy||null))')
echo "  B's copy: supersededBy $B_BEHIND"
echo "$B_BEHIND" | grep -q node-server-c || fail "B should have stepped aside for C"
echo "  B's copy is still read-only: $(pb 'SELECT pg_is_in_recovery()')"
echo "  C accepts writes: $(pc "INSERT INTO notas(txt) VALUES ('after-failover') RETURNING id" | head -1)"
pc "INSERT INTO notas(txt) SELECT 'c'||g FROM generate_series(1,9) g;" >/dev/null
tick B
runB 'const m=await import("./dist/mirror.js");m.promoteMirror("server-a").then(()=>{console.error("B promoted a copy left behind");process.exit(1)},e=>console.log("  B refuses to promote:",e.message.slice(0,90)))'

if [ "${1:-failback}" = gone ]; then
  step "A is gone for good: B follows C, the server that took over"
  TBC=$(runC "const m=await import('./dist/mirror.js');const r=await m.offerMirror({peerName:'server-b',peerCidr:'172.16.0.0/12',advertiseHost:'paasmcp-mirror-server-a-c',advertisePort:5432,fromCopyOf:'server-a'});console.log(r.token)")
  runB "const m=await import('./dist/mirror.js');const r=m.acceptMirror('$TBC');console.log('  B old copy kept at', r.movedAside, '· follows', r.replica.servedByName)"
  sleep 4
  pc "INSERT INTO notas(txt) SELECT 'd'||g FROM generate_series(1,5) g;" >/dev/null; sleep 2
  C_ROWS=$(pc 'SELECT count(*) FROM notas'); B_ROWS=$(pb 'SELECT count(*) FROM notas')
  echo "  rows C: $C_ROWS  B copy: $B_ROWS"
  [ "$C_ROWS" = 165 ] && [ "$B_ROWS" = 165 ] || fail "B should follow C with all 165 rows"
  tick C; tick B

  step "C dies too: B takes A's data over from its copy of C"
  docker stop paasmcp-mirror-server-a-c >/dev/null
  echo "  waiting 65 s for the arbiter to lose C..."; sleep 65
  tick B
  [ "$(runB 'const c=await import("./dist/config.js");console.log(c.loadState().mirror.replicas["server-a"].promotedAt?"yes":"no")')" = yes ] || fail "B should have taken over"
  echo "  B accepts writes: $(pb "INSERT INTO notas(txt) VALUES ('on-b') RETURNING id" | head -1)"
  B_ROWS=$(pb 'SELECT count(*) FROM notas'); echo "  rows on B: $B_ROWS"
  [ "$B_ROWS" = 166 ] || fail "B should have 166 rows"

  step "C comes back: another server holds that data now, so A's apps stop on C"
  docker start paasmcp-mirror-server-a-c >/dev/null; sleep 3
  OUT=$(runC 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(await m.watchTick()))'); echo "  C watch: $OUT"
  echo "$OUT" | grep -q '"lost:server-a"' || fail "C should see that B took the data over"
  runC 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().receiving))'
  echo; echo "=== all steps passed (gone)"
  exit 0
fi

step "A comes back fenced; failback from C"
docker start paasmcp-postgres >/dev/null; sleep 3
tick A
runA 'const c=await import("./dist/config.js");if(!c.loadState().mirror.fenced){console.error("A should be fenced");process.exit(1)}'
TOKEN2=$(runC "const m=await import('./dist/mirror.js');const r=await m.offerMirror({peerName:'server-a',peerCidr:'172.16.0.0/12',advertiseHost:'paasmcp-mirror-server-a-c',advertisePort:5432,fromCopyOf:'server-a'});console.log(r.token)")
runA "const m=await import('./dist/mirror.js');const r=m.acceptMirror('$TOKEN2',{rejoin:true});console.log('  A old data kept at', r.movedAside)"
sleep 4
runC 'const m=await import("./dist/mirror.js");console.log("  handback:",JSON.stringify(await m.handbackMirror("server-a")))'
runA 'const m=await import("./dist/mirror.js");console.log("  A promote:",JSON.stringify(await m.promoteMirror("server-c")))'
sleep 2
echo "  A accepts writes again: $(pa "INSERT INTO notas(txt) VALUES ('back-home') RETURNING id" | head -1)"
tick B
echo "  B's copy stays behind until rebuilt: $(runB 'const c=await import("./dist/config.js");console.log(c.loadState().mirror.replicas["server-a"].supersededBy?"yes":"no")')"

step "B rebuilds its copy from A (old copy moved aside)"
TB2=$(offer server-b)
runB "const m=await import('./dist/mirror.js');const r=m.acceptMirror('$TB2');console.log('  B old copy kept at', r.movedAside)"
sleep 4
A_ROWS=$(pa 'SELECT count(*) FROM notas'); B_ROWS=$(pb 'SELECT count(*) FROM notas')
echo "rows A: $A_ROWS  B copy: $B_ROWS"
[ "$A_ROWS" = "$B_ROWS" ] && [ "$A_ROWS" = 161 ] || fail "B should have all 161 rows"
tick B
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().receiving))'

echo; echo "=== all steps passed"
