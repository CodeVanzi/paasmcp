#!/bin/bash
# Real-Docker check of the uploaded-files copy (active-active): two Garage nodes on one host play
# server A (origin, ports 3900/3903) and server B (peer, ports 3910/3913). B creates the same bucket
# and imports the same key, copies A's objects (and later A's deletions), keeps serving them with the
# app's own key when A is down, on handback sends back what was uploaded during the outage, and never
# wipes its copy when A's bucket comes back empty.
# Usage: sudo env PATH=$PATH scripts/files-lab.sh   (needs Docker and `npm run build`)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)
docker info >/dev/null 2>&1 || { echo "Docker is not reachable." >&2; exit 1; }
for c in paasmcp-garage paasmcp-garage-b; do
  if docker inspect "$c" >/dev/null 2>&1; then
    echo "Container '$c' already exists (a real PaaSMCP?). This lab never touches it: run it in a VM or a machine without PaaSMCP." >&2
    exit 1
  fi
done
for p in 3900 3901 3903 3910 3913; do
  if (ss -ltn 2>/dev/null || true) | grep -qE "[:.]$p "; then echo "Port $p is in use; free it or run elsewhere." >&2; exit 1; fi
done
export PAASMCP_DOCKER_NETWORK=paasmcp-files-lab
IMAGE=$(node --input-type=module -e "const u=await import('$REPO/dist/updater.js');console.log(u.imageFor('garage'))")
A=$(mktemp -d); B=$(mktemp -d)
cleanup() {
  echo; echo "=== cleanup"
  docker rm -f paasmcp-garage paasmcp-garage-b >/dev/null 2>&1 || true
  docker network rm "$PAASMCP_DOCKER_NETWORK" >/dev/null 2>&1 || true
  docker run --rm -v "$A:/a" -v "$B:/b" alpine:3.20 sh -c 'rm -rf /a/* /b/*' >/dev/null 2>&1 || true
  rm -rf "$A" "$B"
}
trap cleanup EXIT
step() { echo; echo "=== $*"; }
runA() { PAASMCP_ROOT=$A node --input-type=module -e "$1"; }
# B's Garage answers on other ports; its peer (A) is reached on 127.0.0.1:3900 instead of a Tailscale IP.
runB() {
  PAASMCP_ROOT=$B PAASMCP_GARAGE_ADMIN_URL=http://127.0.0.1:3913 PAASMCP_GARAGE_S3_URL=http://127.0.0.1:3910 \
    PAASMCP_PEER_S3_URL=http://127.0.0.1:3900 node --input-type=module -e "$1" "${@:2}"
}
check() { if [ "$2" = "$3" ]; then echo "ok   $1 ($2)"; else echo "FAIL $1: got '$2', expected '$3'"; exit 1; fi; }
# Lists or writes the shop's bucket with the app's own key: ls <endpoint> | put <endpoint> <key> <text> | rm <endpoint> <key> | get <endpoint> <key>
S3JS="const f=await import('$REPO/dist/filesync.js');const v=await import('$REPO/dist/vault.js');const e=v.getSecrets('shop');
const t=(ep)=>({endpoint:ep,bucket:e.S3_BUCKET,accessKeyId:e.S3_ACCESS_KEY_ID,secretAccessKey:e.S3_SECRET_ACCESS_KEY});
const [op,ep,k,body]=process.argv.slice(1);
if(op==='ls'){console.log((await f.listObjects(t(ep))).map(o=>o.key).sort().join(','));}
else{const r=await f.s3Request(t(ep),op==='put'?'PUT':op==='rm'?'DELETE':'GET',k,op==='put'?{body:Buffer.from(body),contentType:'image/jpeg'}:{});
if(!r.ok&&r.status!==204)throw new Error(op+' '+k+': HTTP '+r.status);if(op==='get')console.log(await r.text());}"
s3A() { PAASMCP_ROOT=$A node --input-type=module -e "$S3JS" "$@"; }
s3B() { PAASMCP_ROOT=$B node --input-type=module -e "$S3JS" "$@"; }

step "A: Garage, the shop's bucket and key, two photos"
docker network create "$PAASMCP_DOCKER_NETWORK" >/dev/null
for s in A:a B:b; do
  PAASMCP_ROOT=$( [ "${s%%:*}" = A ] && echo "$A" || echo "$B") node --input-type=module -e "const c=await import('$REPO/dist/config.js');const s=c.loadState();s.federation={...s.federation,nodeId:'node-${s#*:}',nodeName:'server-${s#*:}'};c.saveState(s);"
done
runA "const f=await import('$REPO/dist/federation.js');f.getOrCreateFederationClusterKey();
const st=await import('$REPO/dist/storage.js');await st.provisionStorage('shop');
const c=await import('$REPO/dist/config.js');const s=c.loadState();
s.apps.shop={name:'shop',repoUrl:'acme/shop',branch:'main',localPort:4100,internalPort:3000,containerName:'paasmcp-shop',appDir:'/tmp/x',runtimeType:'node',databases:[],domains:[],createdAt:'x',updatedAt:'x',lastCommit:'aaaaaaa',lastCommitSha:'a'.repeat(40),activeActive:true};
c.saveState(s);"
s3A put http://127.0.0.1:3900 "fotos/camiseta azul.jpg" "AZUL"
s3A put http://127.0.0.1:3900 "fotos/caneca(1).jpg" "CANECA"
check "photos on A" "$(s3A ls http://127.0.0.1:3900)" "fotos/camiseta azul.jpg,fotos/caneca(1).jpg"
KEY=$(runA "const v=await import('$REPO/dist/vault.js');console.log(v.getSecrets('system').FEDERATION_CLUSTER_KEY)")
MANIFEST=$(runA "const a=await import('$REPO/dist/active.js');const c=await import('$REPO/dist/config.js');console.log(a.encodeManifest(a.buildActiveManifest(c.loadState())))")

step "B: its own Garage (empty), the cluster key, A as mirror peer"
runB "const v=await import('$REPO/dist/vault.js');v.setSecretEntries('system',{FEDERATION_CLUSTER_KEY:'$KEY',GARAGE_RPC_SECRET:'$(openssl rand -hex 32)',GARAGE_ADMIN_TOKEN:'labtokenb$(openssl rand -hex 8)'});
const c=await import('$REPO/dist/config.js');const s=c.loadState();
s.mirror={epoch:0,offers:{},replicas:{'server-a':{peerName:'server-a',peerNodeId:'node-a',peerHost:'127.0.0.1',slot:'s',container:'paasmcp-mirror-server-a',localPort:5433,dataDir:'/x',acceptedAt:'x'}}};c.saveState(s);"
mkdir -p "$B/garage-b"
TOKB=$(runB "const v=await import('$REPO/dist/vault.js');console.log(v.getSecrets('system').GARAGE_ADMIN_TOKEN)")
RPCB=$(runB "const v=await import('$REPO/dist/vault.js');console.log(v.getSecrets('system').GARAGE_RPC_SECRET)")
cat > "$B/garage-b/garage.toml" <<TOML
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "0.0.0.0:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$RPCB"
[s3_api]
s3_region = "garage"
api_bind_addr = "0.0.0.0:3900"
root_domain = ".s3.garage.localhost"
[admin]
api_bind_addr = "0.0.0.0:3903"
admin_token = "$TOKB"
TOML
docker run -d --name paasmcp-garage-b -p 127.0.0.1:3910:3900 -p 127.0.0.1:3913:3903 -v "$B/garage-b/garage.toml:/etc/garage.toml:ro" "$IMAGE" >/dev/null
# Layout for B's node (ensureGarage without Docker: the container above already runs).
runB "process.env.PAASMCP_OFFLINE_TEST='1';const st=await import('$REPO/dist/storage.js');await st.ensureGarage(1);"

# One round as on the peer: import/deploy (stubbed), then the bucket copy (run outside the lock by mirror watch).
SYNC="const a=await import('$REPO/dist/active.js');const p=await a.syncActivePeers({read:()=>process.argv[1],deploy:async()=>undefined});
if(p[0].errors.length)throw new Error(JSON.stringify(p[0].errors));
const f=await a.syncActiveFiles({now:Number(process.argv[2]||Date.now())});const errors=f.filter(x=>x.error).map(x=>({app:x.app,error:'files: '+x.error}));
console.log(JSON.stringify({status:errors.length?'error':f.length?'applied':'unchanged',files:f.filter(x=>!x.error).map(({peer,error,...x})=>x),errors}));"
syncB() { runB "$SYNC" "$MANIFEST" "${1:-}"; }

step "B imports the shop and copies its bucket (same name, same key)"
OUT=$(syncB); echo "$OUT"
check "B's first sync" "$(echo "$OUT" | node -pe 'const o=JSON.parse(require("fs").readFileSync(0));o.status+":"+JSON.stringify(o.files)')" 'applied:[{"app":"shop","copied":2,"removed":0}]'
check "photos on B" "$(s3B ls http://127.0.0.1:3910)" "fotos/camiseta azul.jpg,fotos/caneca(1).jpg"
check "content on B, read with the app's key" "$(s3B get http://127.0.0.1:3910 'fotos/caneca(1).jpg')" "CANECA"
check "same access key on both" "$(runB "const v=await import('$REPO/dist/vault.js');console.log(v.getSecrets('shop').S3_ACCESS_KEY_ID)")" "$(runA "const v=await import('$REPO/dist/vault.js');console.log(v.getSecrets('shop').S3_ACCESS_KEY_ID)")"

step "Throttle, then a new photo and a deletion on A"
OUT=$(syncB); check "second sync within a minute does nothing" "$(echo "$OUT" | node -pe 'JSON.parse(require("fs").readFileSync(0)).status')" "unchanged"
s3A put http://127.0.0.1:3900 "fotos/bone.jpg" "BONE"
s3A rm http://127.0.0.1:3900 "fotos/camiseta azul.jpg"
LATER=$(( $(date +%s%3N) + 61000 ))
OUT=$(syncB "$LATER"); echo "$OUT"
check "B follows A" "$(s3B ls http://127.0.0.1:3910)" "fotos/bone.jpg,fotos/caneca(1).jpg"

step "A goes down: B still serves the photos, and takes a new upload"
docker stop paasmcp-garage >/dev/null
check "photo on B with A down" "$(s3B get http://127.0.0.1:3910 'fotos/bone.jpg')" "BONE"
s3B put http://127.0.0.1:3910 "fotos/pedido-durante-queda.jpg" "QUEDA"
OUT=$(syncB "$(( LATER + 61000 ))"); echo "$OUT"
check "a failed copy is reported, not hidden" "$(echo "$OUT" | node -pe 'JSON.parse(require("fs").readFileSync(0)).status')" "error"
check "B's files untouched by the failed round" "$(s3B ls http://127.0.0.1:3910)" "fotos/bone.jpg,fotos/caneca(1).jpg,fotos/pedido-durante-queda.jpg"

step "A is back: handback copies the outage upload to A (nothing deleted)"
docker start paasmcp-garage >/dev/null
for i in $(seq 1 30); do s3A ls http://127.0.0.1:3900 >/dev/null 2>&1 && break; sleep 1; done
runB "const a=await import('$REPO/dist/active.js');const f=await import('$REPO/dist/filesync.js');const c=await import('$REPO/dist/config.js');const v=await import('$REPO/dist/vault.js');
const t=a.bucketTargets(c.loadState().mirror.replicas['server-a'],v.getSecrets('shop'));const r=await f.syncBucket(t.local,t.origin,'additive');
if(r.errors.length)throw new Error(r.errors.join('; '));console.log('copied back: '+r.copied);"
check "A has the outage upload" "$(s3A ls http://127.0.0.1:3900)" "fotos/bone.jpg,fotos/caneca(1).jpg,fotos/pedido-durante-queda.jpg"
check "content on A" "$(s3A get http://127.0.0.1:3900 'fotos/pedido-durante-queda.jpg')" "QUEDA"

step "A's bucket comes back empty (reinstall, wrong bucket): B keeps its copy"
for k in "fotos/bone.jpg" "fotos/caneca(1).jpg" "fotos/pedido-durante-queda.jpg"; do s3A rm http://127.0.0.1:3900 "$k"; done
OUT=$(syncB "$(( LATER + 200000 ))"); echo "$OUT"
check "refused" "$(echo "$OUT" | node -pe 'JSON.parse(require("fs").readFileSync(0)).errors[0].error.includes("nothing was deleted")')" "true"
check "B's copy kept" "$(s3B ls http://127.0.0.1:3910)" "fotos/bone.jpg,fotos/caneca(1).jpg,fotos/pedido-durante-queda.jpg"

echo; echo "All files-lab checks passed."
