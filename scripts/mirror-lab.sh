#!/bin/bash
# Two "servers" on one Docker daemon: A = paasmcp-postgres (root /tmp/labA), B = replica (root /tmp/labB).
# Needs Docker and a build (npm run build). Uses /tmp/labA, /tmp/labB and port 5432/5433 on this machine; removes them at the end.
set -e
cd /home/user/paasmcp
rm -rf /tmp/labA /tmp/labB; docker rm -f paasmcp-postgres paasmcp-mirror-primary-node >/dev/null 2>&1 || true
step() { echo; echo "=== $*"; }
runA() { PAASMCP_ROOT=/tmp/labA node --input-type=module -e "$1"; }
runB() { PAASMCP_ROOT=/tmp/labB node --input-type=module -e "$1"; }
pa() { docker exec -i paasmcp-postgres psql -U paasmcp_admin -d postgres -tA -c "$1"; }
pb() { docker exec -i paasmcp-mirror-primary-node psql -U paasmcp_admin -d postgres -tA -c "$1"; }

step "A: start Postgres, cluster key, data"
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
docker stop paasmcp-mirror-primary-node >/dev/null
pa "INSERT INTO notas(txt) SELECT repeat('w',500) FROM generate_series(1,20000) g;"
runA 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().sending))'
docker start paasmcp-mirror-primary-node >/dev/null; sleep 5
echo "rows on B copy: $(pb 'SELECT count(*) FROM notas')  (A: $(pa 'SELECT count(*) FROM notas'))"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus().receiving))'

step "A dies; B is promoted"
docker stop paasmcp-postgres >/dev/null
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(await m.promoteMirror("primary-node")))'
sleep 2
echo "B accepts writes now: $(pb "INSERT INTO notas(txt) VALUES ('after-failover') RETURNING id")"
echo "rows on B: $(pb 'SELECT count(*) FROM notas')"
runB 'const m=await import("./dist/mirror.js");console.log(JSON.stringify(m.mirrorStatus()))'

step "cleanup"
docker rm -f paasmcp-postgres paasmcp-mirror-primary-node >/dev/null
rm -rf /tmp/labA /tmp/labB
