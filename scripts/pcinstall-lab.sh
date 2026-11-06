#!/bin/bash
# Real check of "install PaaSMCP on another PC from the dashboard" (Connections > PCs). Two "PCs" are plain
# Ubuntu 24.04 containers with only the OpenSSH server, sudo and certificates: no git, no Docker, no Node
# (pc-a 172.31.251.11 with a sudo user and password, pc-b .12 with root and a password). A stand-in for
# systemctl starts dockerd once apt has installed it, and a stand-in tailscale answers `version`, `ip`
# and `set`. The dashboard runs here with a fake `tailscale status` listing both, and everything goes
# through its API, like the screen: log in with a wrong password (refused, counted), log in, check,
# install pc-a as a helper (invite here, `pool join` there, `pool add` here) and pc-b as an independent
# server (its own dashboard answers there). Checks: what the check reports, the steps, the password never
# lands in the job, the audit log, the PaaSMCP data folder or the PC's disk, no key is left on the PCs,
# the install script and the private connection folder are gone, the helper answers this server's key.
# The code installed there is this checkout's commit, fetched from GitHub: push it first.
# Needs Docker with privileged containers, `npm run build`, ssh and ssh-keygen; outbound HTTPS (apt,
# nodejs.org, GitHub, npm, Docker Hub) through HTTPS_PROXY when there is one. Takes 8-15 minutes.
# Usage: sudo env PATH=$PATH scripts/pcinstall-lab.sh
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
export PAASMCP_ROOT=$(mktemp -d) PAASMCP_DOCKER_NETWORK=paasmcp-pc-lab
NET=$PAASMCP_DOCKER_NETWORK GW=172.31.251.1 IPA=172.31.251.11 IPB=172.31.251.12
PA=paasmcp-lab-pc-a PB=paasmcp-lab-pc-b IMG=paasmcp-lab-pc:1 PORT=4198
SRC=$(mktemp -d) fail=0
PW_A="pw-a-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PW_B="pw-b-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CLI="node $REPO/dist/cli.js"
for c in "$PA" "$PB"; do
  if docker inspect "$c" >/dev/null 2>&1; then docker rm -fv "$c" >/dev/null; fi
done
cleanup() {
  echo; echo "=== cleanup"
  [ -n "${DASH_PID:-}" ] && kill "$DASH_PID" 2>/dev/null
  [ -n "${FWD_PID:-}" ] && kill "$FWD_PID" 2>/dev/null
  docker rm -fv "$PA" "$PB" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$PAASMCP_ROOT" "$SRC"
}
trap cleanup EXIT
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { if [ "$2" = 1 ]; then ok "$1"; else bad "$1"; fi; }
step() { echo; echo "=== $*"; }
js() { node -e "const s=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log($1)"; }

# The PCs reach the internet through this machine's proxy (when there is one), via the lab gateway.
PROXY_URL=""
if [ -n "${HTTPS_PROXY:-}" ]; then
  PHOST=$(node -e 'const u=new URL(process.argv[1]);console.log(u.hostname+":"+(u.port||80))' "$HTTPS_PROXY")
  PROXY_URL="http://$GW:3128"
fi
CA=""
for f in /root/.ccr/ca-bundle.crt "${NODE_EXTRA_CA_CERTS:-}"; do [ -n "$f" ] && [ -f "$f" ] && { CA=$f; break; }; done

step "PC image (Ubuntu with sshd and sudo only)"
mkdir -p "$SRC/img"
[ -n "$CA" ] && cp "$CA" "$SRC/img/extra-ca.crt" || : > "$SRC/img/extra-ca.crt"
cat > "$SRC/img/systemctl" <<'SH'
#!/bin/sh
# Lab stand-in for systemd: starts dockerd and sshd when asked, says yes to the rest.
case "$*" in
  *docker*)
    if command -v dockerd >/dev/null 2>&1 && ! pgrep -x dockerd >/dev/null; then
      (set -a; . /etc/environment; set +a; nohup dind dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd.log 2>&1 &)
      for _ in $(seq 40); do docker info >/dev/null 2>&1 && break; sleep 1; done
      [ -f /lab/dash.tar ] && docker load -i /lab/dash.tar >/dev/null 2>&1
    fi ;;
  *ssh*) mkdir -p /run/sshd; pgrep -x sshd >/dev/null || /usr/sbin/sshd ;;
esac
exit 0
SH
cat > "$SRC/img/tailscale" <<'SH'
#!/bin/sh
# Lab stand-in for the Tailscale CLI.
case "$1" in
  version) echo "1.80.0-lab" ;;
  ip) hostname -I | awk '{print $1}' ;;
  set) echo "$*" >> /var/log/tailscale-set.log ;;
  status) echo '{}' ;;
esac
SH
cat > "$SRC/img/start.sh" <<'SH'
#!/bin/sh
mkdir -p /run/sshd /run/systemd/system
/usr/sbin/sshd
exec sleep infinity
SH
cat > "$SRC/img/Dockerfile" <<'DF'
FROM docker:27-dind AS dind
FROM ubuntu:24.04
ARG PROXY_URL=""
COPY --from=dind /usr/local/bin/dind /usr/local/bin/dind
COPY extra-ca.crt /usr/local/share/ca-certificates/extra-ca.crt
RUN sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources \
 && if [ -n "$PROXY_URL" ]; then printf 'Acquire::https::Proxy "%s";\n' "$PROXY_URL" > /etc/apt/apt.conf.d/99proxy; fi \
 && printf 'Acquire::https::CaInfo "/usr/local/share/ca-certificates/extra-ca.crt";\n' > /etc/apt/apt.conf.d/98ca \
 && apt-get update -q \
 && apt-get install -y -q --no-install-recommends ca-certificates \
 && update-ca-certificates && rm /etc/apt/apt.conf.d/98ca \
 && apt-get install -y -q --no-install-recommends openssh-server sudo iptables procps xz-utils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash -G sudo graco \
 && printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' > /etc/ssh/sshd_config.d/lab.conf \
 && printf 'Defaults env_keep += "HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NODE_EXTRA_CA_CERTS"\n' > /etc/sudoers.d/lab-proxy \
 && if [ -n "$PROXY_URL" ]; then printf 'HTTPS_PROXY=%s\nhttps_proxy=%s\nNODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/extra-ca.crt\n' "$PROXY_URL" "$PROXY_URL" >> /etc/environment; fi
COPY systemctl tailscale start.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/systemctl /usr/local/bin/tailscale /usr/local/bin/start.sh
ENTRYPOINT ["/usr/local/bin/start.sh"]
DF
docker network create --subnet 172.31.251.0/24 --gateway "$GW" "$NET" >/dev/null || exit 1
if [ -n "$PROXY_URL" ]; then
  node -e '
    const net=require("net"); const [h,p]=process.argv[2].split(":");
    net.createServer(c=>{const u=net.connect(Number(p),h); c.pipe(u); u.pipe(c); c.on("error",()=>u.destroy()); u.on("error",()=>c.destroy());}).listen(3128, process.argv[1]);
  ' "$GW" "$PHOST" & FWD_PID=$!
  sleep 1
fi
# shellcheck disable=SC2086
docker build --network host --build-arg PROXY_URL="${PROXY_URL:+http://127.0.0.1:${PHOST##*:}}" -t "$IMG" "$SRC/img" >"$SRC/build.log" 2>&1 \
  || { tail -20 "$SRC/build.log"; echo "FAIL building the PC image"; exit 1; }
# Inside the running PCs the proxy is the lab gateway, not this machine's loopback.
for pc in "$PA:$IPA" "$PB:$IPB"; do
  docker run -d --privileged --name "${pc%%:*}" --hostname "${pc%%:*}" --network "$NET" --ip "${pc##*:}" --tmpfs /run:rw,mode=755 -v /var/lib/docker "$IMG" >/dev/null || exit 1
  if [ -n "$PROXY_URL" ]; then
    docker exec "${pc%%:*}" sh -c "sed -i 's|http://127.0.0.1:[0-9]*|$PROXY_URL|g' /etc/environment; printf 'Acquire::https::Proxy \"%s\";\n' '$PROXY_URL' > /etc/apt/apt.conf.d/99proxy"
  fi
done
docker exec "$PA" sh -c "echo 'graco:$PW_A' | chpasswd"
docker exec "$PB" sh -c "echo 'root:$PW_B' | chpasswd"
# pc-b becomes a server: its dashboard image stands in for the real one (this sandbox cannot reach the
# Alpine mirror the real image's `apk add` uses). Loaded by the systemctl stand-in once Docker is in.
TAG=$(node --input-type=module -e "const d=await import('$REPO/dist/dashboard.js'); console.log(d.dashboardImageTag())")
docker pull -q node:22.11.0-alpine3.20 >/dev/null && docker tag node:22.11.0-alpine3.20 "$TAG" && docker save "$TAG" -o "$SRC/dash.tar" \
  && docker exec "$PB" mkdir -p /lab && docker cp "$SRC/dash.tar" "$PB:/lab/dash.tar" || bad "stand-in dashboard image for pc-b"
for pc in "$PA" "$PB"; do
  check "$pc: no git, no Docker, no Node before" "$(docker exec "$pc" sh -c 'command -v git || command -v docker || command -v node' >/dev/null && echo 0 || echo 1)"
done

step "Dashboard here, with a Tailscale that lists the two PCs"
mkdir -p "$SRC/bin"
cat > "$SRC/status.json" <<JSON
{"Self":{"TailscaleIPs":["$GW"],"UserID":7},"Peer":{
 "a":{"HostName":"pc-a","OS":"linux","Online":true,"UserID":7,"TailscaleIPs":["$IPA"]},
 "b":{"HostName":"pc-b","OS":"linux","Online":true,"UserID":7,"TailscaleIPs":["$IPB"]},
 "c":{"HostName":"phone","OS":"android","Online":true,"UserID":7,"TailscaleIPs":["172.31.251.40"]}}}
JSON
printf '#!/bin/sh\n[ "$1" = status ] && cat %s && exit 0\n[ "$1" = ip ] && echo %s && exit 0\nexit 1\n' "$SRC/status.json" "$GW" > "$SRC/bin/tailscale"
chmod +x "$SRC/bin/tailscale"
node --input-type=module -e "const c=await import('$REPO/dist/config.js'); c.ensureDirectories(); const s=c.loadState(); s.pool={helpers:{},invites:{},bindIp:'$GW'}; c.saveState(s);"
PATH="$SRC/bin:$PATH" node "$REPO/dist/cli.js" dashboard serve --port "$PORT" >"$SRC/dash.log" 2>&1 & DASH_PID=$!
sleep 2
TOKEN=$($CLI dashboard token | js 's.dashboardToken')
J="$SRC/cookies"
curl -s -c "$J" -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}" "http://127.0.0.1:$PORT/api/login" >/dev/null
api() { curl -s -b "$J" -H 'Content-Type: application/json' "$@"; }
LIST=$(api "http://127.0.0.1:$PORT/api/pcs")
check "the list shows both PCs without PaaSMCP, OpenSSH answering" "$(echo "$LIST" | js 's.pcs.filter(p=>p.state==="installable"&&p.ssh==="openssh").length===2 ? 1 : 0')"
check "the phone is not offered" "$(echo "$LIST" | js 's.pcs.find(p=>p.name==="phone").why==="notLinux" ? 1 : 0')"

wait_job() { # phase list to stop at, max seconds
  for _ in $(seq "$2"); do
    JOB=$(api "http://127.0.0.1:$PORT/api/pcs/job")
    ph=$(echo "$JOB" | js 's.job ? s.job.phase : ""')
    case " $1 " in *" $ph "*) return 0 ;; esac
    sleep 2
  done
  return 1
}

step "Wrong password: refused, nothing kept"
api -d "{\"ip\":\"$IPA\",\"user\":\"graco\",\"password\":\"wrong-$PW_A\"}" "http://127.0.0.1:$PORT/api/pcs/check" >/dev/null
wait_job "failed done ready" 30
check "a wrong password ends in 'auth'" "$(echo "$JOB" | js 's.job.errorCode==="auth" ? 1 : 0')"

step "pc-a: log in with the password, check, install as a helper"
api -d "{\"ip\":\"$IPA\",\"user\":\"graco\",\"password\":\"$PW_A\"}" "http://127.0.0.1:$PORT/api/pcs/check" >"$SRC/check-a.json"
wait_job "ready failed" 60 || bad "pc-a check timed out"
echo "$JOB" > "$SRC/ready-a.json"
check "pc-a is ready, logged in with the password" "$(echo "$JOB" | js 's.job.phase==="ready"&&s.job.via==="password" ? 1 : 0')"
check "the check sees Ubuntu, sudo with the password, and git/Docker/Node missing" \
  "$(echo "$JOB" | js 's.job.facts.osId==="ubuntu"&&s.job.facts.sudo==="password"&&["git","docker","node"].every(x=>s.job.plan.install.includes(x)) ? 1 : 0')"
check "the host key was taken on first use and shown" "$(echo "$JOB" | js '/^SHA256:/.test(s.job.hostKey.fingerprint)&&s.job.hostKey.pinned===false ? 1 : 0')"
check "nothing changed on pc-a yet" "$(docker exec "$PA" sh -c 'command -v git || command -v docker' >/dev/null && echo 0 || echo 1)"
JID=$(echo "$JOB" | js 's.job.id')
R=$(api -o /dev/null -w '%{http_code}' -d "{\"jobId\":\"$JID\",\"role\":\"helper\",\"name\":\"pc-a\"}" "http://127.0.0.1:$PORT/api/pcs/install")
check "installing asks for confirmation first (409)" "$([ "$R" = 409 ] && echo 1 || echo 0)"
api -d "{\"jobId\":\"$JID\",\"role\":\"helper\",\"name\":\"pc-a\",\"confirmed\":true}" "http://127.0.0.1:$PORT/api/pcs/install" >/dev/null
wait_job "done failed" 900 || bad "pc-a install timed out"
echo "$JOB" > "$SRC/done-a.json"
check "pc-a installed as a helper" "$(echo "$JOB" | js 's.job.phase==="done"&&s.job.result.helper==="pc-a" ? 1 : 0')" || true
[ "$(echo "$JOB" | js 's.job.phase')" = done ] || { echo "$JOB" | js 's.job.error + "\n" + s.job.log.slice(-40).join("\n")'; }
check "every install step is ok" "$(echo "$JOB" | js 's.job.steps.every(x=>x.state==="ok") ? 1 : 0')"
check "pc-a is in this server's pool and answers its key" "$($CLI pool status 2>/dev/null | js '(s.helpers||[]).some(h=>h.name==="pc-a"&&h.state==="available") ? 1 : 0')"
check "pc-a runs the same commit as this checkout" "$([ "$(docker exec "$PA" git -C /opt/paasmcp rev-parse HEAD)" = "$(git rev-parse HEAD)" ] && echo 1 || echo 0)"
check "Node.js 20+ for all users on pc-a" "$(docker exec "$PA" su graco -c 'node -v' | grep -qE '^v(2[0-9]|[3-9][0-9])\.' && echo 1 || echo 0)"
check "the install script is gone from pc-a" "$(docker exec "$PA" sh -c 'ls /tmp/paasmcp-install-* 2>/dev/null' | grep -q . && echo 0 || echo 1)"
check "no key of this server in graco's or root's authorized_keys" "$(docker exec "$PA" sh -c 'cat /home/graco/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null' | grep -q . && echo 0 || echo 1)"

step "pc-b: root with a password, install as an independent server"
api -d "{\"ip\":\"$IPB\",\"user\":\"root\",\"password\":\"$PW_B\"}" "http://127.0.0.1:$PORT/api/pcs/check" >/dev/null
wait_job "ready failed" 60 || bad "pc-b check timed out"
check "pc-b is ready, as root" "$(echo "$JOB" | js 's.job.phase==="ready"&&s.job.facts.sudo==="root" ? 1 : 0')"
JID=$(echo "$JOB" | js 's.job.id')
api -d "{\"jobId\":\"$JID\",\"role\":\"server\",\"confirmed\":true}" "http://127.0.0.1:$PORT/api/pcs/install" >/dev/null
wait_job "done failed" 900 || bad "pc-b install timed out"
echo "$JOB" > "$SRC/done-b.json"
[ "$(echo "$JOB" | js 's.job.phase')" = done ] || { echo "$JOB" | js 's.job.error + "\n" + s.job.log.slice(-40).join("\n")'; }
check "pc-b installed as a server" "$(echo "$JOB" | js 's.job.phase==="done"&&s.job.result.role==="server" ? 1 : 0')"
check "pc-b's own dashboard answers there" "$(docker exec "$PB" sh -c 'for i in $(seq 30); do curl -fsS -o /dev/null http://127.0.0.1:4099/ && exit 0; sleep 1; done; exit 1' && echo 1 || echo 0)"
check "pc-b's paasmcp command works" "$(docker exec "$PB" paasmcp status >/dev/null 2>&1 && echo 1 || echo 0)"
LIST=$(api "http://127.0.0.1:$PORT/api/pcs")
check "the list now shows both with PaaSMCP" "$(echo "$LIST" | js 's.pcs.filter(p=>p.state==="paasmcp").length===2 ? 1 : 0')"

step "The passwords were kept nowhere"
for pair in "$PW_A:$PA" "$PW_B:$PB"; do
  pw=${pair%%:*} pc=${pair##*:}
  check "$pc: password not in the job, the API answers or the dashboard log" "$(cat "$SRC"/*.json "$SRC/dash.log" | grep -qF "$pw" && echo 0 || echo 1)"
  check "$pc: password not in PaaSMCP's data folder (state, audit log, installs)" "$(grep -rqF "$pw" "$PAASMCP_ROOT" && echo 0 || echo 1)"
  check "$pc: password not on its disk" "$(docker exec "$pc" sh -c "grep -rlsF '$pw' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null" | grep -q . && echo 0 || echo 1)"
done
check "the private connection folders are gone" "$(ls -d /dev/shm/paasmcp-pc-* /tmp/paasmcp-pc-* 2>/dev/null | grep -q . && echo 0 || echo 1)"
check "the audit log has the installs" "$(grep -c '"event":"pc.install.done"' "$PAASMCP_ROOT/paasmcp/audit.log" 2>/dev/null | grep -qx 2 && echo 1 || echo 0)"

echo
if [ "$fail" = 0 ]; then echo "ALL OK"; else echo "SOME CHECKS FAILED"; fi
exit "$fail"
