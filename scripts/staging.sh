#!/usr/bin/env bash
# Test environment ("staging") of PaaSMCP on the same server as the official one.
#
# The test copy runs inside its own box: a container with its own Docker engine, its own data and its
# own dashboard. Nothing in it can see or touch the official apps, containers, network or state
# (/opt/homelab). The dashboard inside follows a branch (default: staging) and updates itself after
# each merge, with the same build + tests + rollback as the official one.
# Every command below also works as "sudo paasmcp staging <command>".
#
#   sudo scripts/staging.sh up        Create the box, or start it again (first time: ~5-10 min)
#   sudo scripts/staging.sh status    Is it running, which branch and commit, how to open it
#   sudo scripts/staging.sh token     Login token of the test dashboard
#   sudo scripts/staging.sh update    Check the followed branch now (instead of waiting ~2 min)
#   sudo scripts/staging.sh domain <subdomain> [e-mail]
#                                     Publish the test dashboard at https://<subdomain>.<your domain>,
#                                     behind Cloudflare Access. First connect Cloudflare in the TEST
#                                     dashboard (Connections > Domain, "Create a new tunnel"). The e-mail
#                                     given here (or saved there) is the only one let in.
#   sudo scripts/staging.sh logs      Logs of the test dashboard
#   sudo scripts/staging.sh shell     A shell inside the box (paasmcp CLI of the test copy)
#   sudo scripts/staging.sh stop      Stop the box (data kept)
#   sudo scripts/staging.sh destroy   Delete the box and ALL its data (asks to type the name)
#
# Settings (environment variables, optional):
#   STAGING_BRANCH   branch the test copy follows            (default: staging)
#   STAGING_REPO     repository                              (default: https://github.com/CodeVanzi/paasmcp.git)
#   STAGING_PORT     port on 127.0.0.1 of this server        (default: 4199)
#   STAGING_LABEL    strip shown on every page of the panel  (default: AMBIENTE DE TESTES)
#   STAGING_NETWORK  Docker network of your cloudflared, so a public hostname can point to
#                    http://staging-paasmcp:4199             (default: homelab-network, if it exists)
set -euo pipefail

BOX="staging-paasmcp"            # never "paasmcp-*": that prefix belongs to the official install's containers
IMAGE="staging-paasmcp-box:1"
BRANCH="${STAGING_BRANCH:-staging}"
REPO="${STAGING_REPO:-https://github.com/CodeVanzi/paasmcp.git}"
PORT="${STAGING_PORT:-4199}"
LABEL="${STAGING_LABEL:-AMBIENTE DE TESTES}"
NETWORK="${STAGING_NETWORK:-homelab-network}"
INNER_PORT=4199                  # socat inside the box -> the test dashboard (127.0.0.1:4099 in the box)
SRC=/srv/paasmcp                 # code used to install; afterwards the dashboard runs the followed release

die() { echo "❌ $*" >&2; exit 1; }
# How to call this again in messages: "paasmcp staging" when started by the CLI, else this script.
ME="${PAASMCP_STAGING_CMD:-$0}"
say() { echo "▶ $*"; }

[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ && "$BRANCH" != -* ]] || die "Invalid branch name: $BRANCH"
[[ "$REPO" =~ ^(https://|git@)[A-Za-z0-9._/:@-]+$ ]] || die "Invalid repository URL: $REPO"
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1024 && PORT <= 65535 )) || die "Invalid port: $PORT"
[[ "$PORT" != 4099 && "$PORT" != 4097 ]] || die "Port $PORT is the official dashboard/judge port. Pick another (default 4199)."
command -v docker >/dev/null || die "Docker is not installed."
docker info >/dev/null 2>&1 || die "Cannot talk to Docker. Run with sudo."

exists()  { docker container inspect "$BOX" >/dev/null 2>&1; }
running() { [ "$(docker container inspect -f '{{.State.Running}}' "$BOX" 2>/dev/null)" = "true" ]; }
inbox()   { docker exec -i "$BOX" "$@"; }
cli()     { docker exec -i -w "$SRC" "$BOX" node dist/cli.js "$@"; }

build_image() {
  docker image inspect "$IMAGE" >/dev/null 2>&1 && return
  say "Building the box image ($IMAGE)..."
  docker build -t "$IMAGE" - <<'DOCKERFILE'
FROM docker:27.3.1-dind
RUN apk add --no-cache nodejs npm git openssh-client socat bash
ENV PAASMCP_ROOT=/opt/homelab
# The inner engine listens only on its unix socket. (The image's default entrypoint would also open
# tcp 0.0.0.0:2375 without a password, which any container on the same network could use as root.)
RUN printf '%s\n' '#!/bin/sh' \
  'socat TCP-LISTEN:4199,fork,reuseaddr TCP:127.0.0.1:4099 &' \
  'exec dind dockerd --host=unix:///var/run/docker.sock' > /usr/local/bin/staging-entry && chmod +x /usr/local/bin/staging-entry
ENTRYPOINT ["staging-entry"]
CMD []
DOCKERFILE
}

wait_docker() {
  for _ in $(seq 1 60); do inbox docker info >/dev/null 2>&1 && return; sleep 2; done
  die "The Docker engine inside the box did not start. See: docker logs $BOX"
}

cmd_up() {
  build_image
  if exists; then
    running || { say "Starting the box..."; docker start "$BOX" >/dev/null; }
  else
    say "Creating the box $BOX (own Docker engine, own data)..."
    # --privileged is what a Docker engine inside a container needs; it is the same trust the
    # official dashboard already has (it holds the server's Docker socket).
    docker run -d --name "$BOX" --hostname paasmcp-teste --privileged --restart unless-stopped \
      --label com.centurylinklabs.watchtower.enable=false \
      -p "127.0.0.1:${PORT}:${INNER_PORT}" \
      -e PAASMCP_ENV_LABEL="$LABEL" \
      -v staging-paasmcp-docker:/var/lib/docker \
      -v staging-paasmcp-data:/opt/homelab \
      -v staging-paasmcp-src:/srv \
      "$IMAGE" >/dev/null
  fi
  if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    docker network connect "$NETWORK" "$BOX" 2>/dev/null || true
  fi
  wait_docker
  # The strip on the test dashboard: kept in its data, so every new version of the dashboard shows it.
  inbox sh -c 'mkdir -p /opt/homelab/paasmcp && printf "%s" "$PAASMCP_ENV_LABEL" > /opt/homelab/paasmcp/environment-label'

  if ! inbox test -f "$SRC/dist/cli.js"; then
    say "Installing PaaSMCP ($BRANCH) inside the box..."
    inbox rm -rf "$SRC"
    inbox git clone --quiet --branch "$BRANCH" -- "$REPO" "$SRC" \
      || die "Could not clone branch '$BRANCH' of $REPO. Does the branch exist?"
    docker exec -w "$SRC" "$BOX" sh -c 'npm ci --no-audit --no-fund && npm run build' >/dev/null
    cli init --dashboard >/dev/null
    say "Making the test dashboard follow '$BRANCH' (build + tests, a few minutes)..."
    cli dashboard follow --repo "$REPO" --branch "$BRANCH" --yes >/dev/null \
      || echo "⚠️  The first build of '$BRANCH' failed; the dashboard keeps running the installed code. See: sudo $ME status"
  fi
  cmd_status
}

cmd_status() {
  exists || { echo "No test environment yet. Create it with: sudo $ME up"; return; }
  if ! running; then echo "The box $BOX exists but is stopped. Start it with: sudo $ME up"; return; fi
  echo "Test environment: running"
  echo "  Dashboard:  http://127.0.0.1:${PORT}  (only on this server)"
  if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "  For a public hostname in your Cloudflare tunnel, use the service: http://${BOX}:${INNER_PORT}"
  fi
  echo "  Login:      sudo $ME token"
  cli dashboard follow status 2>/dev/null | grep -E '"(branch|current|failedCommit|lastError)"' | sed 's/^ */  /' || true
}

cmd_domain() {
  local sub="${1:-}"
  [[ "$sub" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
    || die "Usage: $ME domain <subdomain>   (only the first part, e.g. testepaasmcp for testepaasmcp.yourdomain.com)"
  running || die "The box is not running. Start it with: sudo $ME up"
  local email="${2:-}"
  if [ -n "$email" ]; then
    [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "Invalid e-mail: $email"
    cli config --zero-trust-emails "$email" >/dev/null || die "Could not save the e-mail in the test copy."
  fi
  # What is missing in the test copy's Cloudflare settings: tunnel, domain, e-mail for Access.
  local missing
  missing=$(cli config 2>/dev/null | inbox node -e '
    let d = ""; process.stdin.on("data", (c) => (d += c)).on("end", () => {
      const cf = JSON.parse(d).cloudflare || {};
      const m = [];
      if (!cf.tunnelId) m.push("tunnel");
      if (!cf.baseDomain || cf.baseDomain === "example.com") m.push("domain");
      if (!(cf.zeroTrustEmails || []).length) m.push("e-mail");
      console.log(m.join(", "));
    });') || die "Could not read the test copy's settings."
  if [ "$missing" = "e-mail" ]; then
    die "Missing the e-mail allowed in (Cloudflare Access). Run: sudo $ME domain $sub you@example.com"
  fi
  [ -z "$missing" ] || die "Missing in the TEST dashboard: $missing. Open it, go to Connections > Domain, paste the Cloudflare token, pick the domain and choose \"Create a new tunnel\". Then run: sudo $ME domain $sub you@example.com"
  say "Publishing the test dashboard at ${sub}.<domain> (own tunnel of the test copy, Cloudflare Access)..."
  cli dashboard start --expose zero-trust --subdomain "$sub" --yes \
    | grep -E '"(url|details)"' | sed 's/^ */  /' || true
}

cmd_destroy() {
  exists || docker volume inspect staging-paasmcp-data >/dev/null 2>&1 || { echo "Nothing to delete."; return; }
  echo "This deletes the test box and ALL its data (apps, databases, settings of the test copy)."
  echo "The official PaaSMCP is not touched."
  read -r -p "Type \"$BOX\" to confirm: " answer
  [ "$answer" = "$BOX" ] || die "Not confirmed. Nothing was deleted."
  docker rm -f "$BOX" >/dev/null 2>&1 || true
  docker volume rm staging-paasmcp-docker staging-paasmcp-data staging-paasmcp-src >/dev/null 2>&1 || true
  echo "✅ Test environment deleted."
}

case "${1:-status}" in
  up|start) cmd_up ;;
  status)   cmd_status ;;
  token)    running || die "The box is not running."; cli dashboard token ;;
  update)   running || die "The box is not running."; cli dashboard update --force ;;
  domain)   cmd_domain "${2:-}" "${3:-}" ;;
  logs)     running || die "The box is not running."; inbox docker logs --tail "${2:-200}" paasmcp-dashboard ;;
  shell)    running || die "The box is not running."; docker exec -it -w "$SRC" "$BOX" bash ;;
  stop)     exists && docker stop "$BOX" >/dev/null; echo "Stopped (data kept). Start again with: sudo $ME up" ;;
  destroy)  cmd_destroy ;;
  *) sed -n '2,29p' "$0"; exit 1 ;;
esac
