# 🏛️ PaaSMCP Technical Architecture & Security Model

This document details the internal design, cryptographic guarantees, multi-node federation protocol, and future engineering specifications of **PaaSMCP**.

---

## 1. Directory & State Layout (`/opt/homelab`)

By default, PaaSMCP stores all runtime state under `PAASMCP_ROOT` (`/opt/homelab`):

```text
/opt/homelab/
├── paasmcp/
│   ├── .master.key               # 256-bit (32-byte) hex key (mode 0600)
│   ├── state.json                # Registered apps, ports, DBs, backups & federation peers (mode 0600)
│   ├── ssh/
│   │   ├── paasmcp_deploy_ed25519      # Private SSH deploy key (mode 0600)
│   │   └── paasmcp_deploy_ed25519.pub  # Public SSH deploy key (+ SHA256 fingerprint)
│   ├── vault/
│   │   ├── system.enc.json       # Encrypted platform tokens (CF_API_TOKEN, GITHUB_TOKEN, WEBHOOK_SECRET, FEDERATION_CLUSTER_KEY)
│   │   └── <app-slug>.enc.json   # Encrypted environment variables per application
│   ├── backups/
│   │   └── <id>.enc.bak          # Binary AES-256-GCM encrypted pg_dump / Redis / volume snapshots (mode 0600)
│   └── mirror/<peer>/            # Streaming copy of a peer's Postgres (its own compose.yaml + data/)
├── paasmcp-postgres/             # Shared PostgreSQL 16 cluster (127.0.0.1:5432)
├── paasmcp-redis/                # Shared Redis 7 cluster (127.0.0.1:6379)
├── paasmcp-garage/               # Garage S3 object storage (127.0.0.1:3900, admin 127.0.0.1:3903)
└── apps/
    └── <app-slug>/
        ├── repo/                 # Cloned Git repository + Dockerfile.paasmcp
        ├── .env.runtime          # Decrypted runtime env file (mode 0600)
        └── compose.yaml          # Sanitized Docker Compose stack bound to 127.0.0.1:<port>
```

---

## 2. Cryptographic Vault & Binary Backup Format (`src/vault.ts`, `src/database.ts`)

1. **JSON Vault Cipher:** `aes-256-gcm` via Node.js native `node:crypto` with a fresh 96-bit (12-byte) random IV per write and 16-byte GCM authentication tag.
2. **Binary Encrypted Backups (`PMCP` Wire Format):**
   - Database dumps (`pg_dump` or Redis `dump.rdb`) are encrypted in memory before touching disk:
     `[4-byte magic "PMCP"][1-byte version 0x01][12-byte IV][16-byte GCM AuthTag][Ciphertext]`
   - On restore (`paas_db_backup(action="restore")`), PaaSMCP verifies the outer `SHA-256` hash, verifies the inner `AES-256-GCM` tag in memory, and pipes the plaintext SQL stream directly to `docker exec -i paasmcp-postgres psql` via `stdin` — **zero unencrypted dump files are ever written to disk**.
3. **Constant-Time Authentication (`timingSafeCompare`):**
   - All token comparisons (`DASHBOARD_TOKEN`, `X-Hub-Signature-256` GitHub webhooks, and `paasmcp-join://` Federation HMACs) hash both operands with SHA-256 and compare via `crypto.timingSafeEqual` to eliminate timing side-channels.

---

## 3. Multi-Service Compose Sanitization & Network Isolation (`src/deployer.ts`)

- **Loopback Binding Only:** Every deployed application binds strictly to `127.0.0.1:<allocatedPort>:<internalPort>` in the range `4000–4998` (`4099` reserved for the Control Plane).
- **Untrusted `docker-compose.yml` Sanitization (`generateSanitizedComposeFromRepo`):**
  When deploying a repository containing its own `docker-compose.yml`:
  1. Dangerous container-escape fields (`privileged`, `network_mode`, `pid`, `ipc`, `userns_mode`, `cap_add`, `devices`, `security_opt`) are automatically stripped.
  2. Host bind-mounts (volumes starting with `/` or containing `..`) are stripped; only named Docker volumes are permitted.
  3. `.env.runtime` (from the encrypted Vault) and `homelab-network` are injected into all services.
  4. Only the primary web service binds to `127.0.0.1:<allocatedPort>:<internalPort>`; background workers (`worker`, `cron`, `queue`) have external `ports` removed so they run completely isolated inside the bridge network.
  5. A primary service that is built (has `build` and no `image`) is tagged `paasmcp/<app>:latest`, so the blue/green cutover can restore it and `rollback` works for compose apps too.

### Blue/green cutover with healthcheck (`deployApp`)

Every deploy builds the new image while the running version keeps serving, then checks it before anything is replaced:

1. The running version's image is held as `paasmcp/<app>:pre-deploy` (with the containerd image store an untagged image can disappear), then `docker compose build`.
2. The new image runs as a one-off candidate (`docker compose run -d --name paasmcp-<app>-candidate`) published on a free loopback port (`127.0.0.1:<random>`). It gets the same env file, network, volumes and limits as production; `depends_on` services are started if missing.
3. `GET http://127.0.0.1:<candidatePort><healthcheckPath>` is polled every 0.5 s for up to 20 s (`healthcheckTimeoutSeconds`, max 300). Any status below 500 passes (redirects are not followed). If the candidate exits, the check stops at once.
4. **Unhealthy:** the candidate's last 80 log lines are captured, the candidate is removed, the `:latest` tag goes back to the running version's image and the deploy fails with `HealthcheckFailedError` (the logs are in the message, so the MCP agent sees them). Nothing that was running is touched and the app record is not changed.
5. **Healthy:** the candidate gets the network alias `paasmcp-<app>` on `homelab-network`, so Cloudflare Tunnel (which routes by container name) keeps reaching a healthy copy while `docker compose up -d --no-build` recreates production. Once production answers on `127.0.0.1:<localPort>`, the candidate is removed and the replaced image becomes `:previous`.

Traffic that reaches the app through the Docker network never finds the name unanswered; a request that is in flight on the old container when it stops can still fail unless the app shuts down gracefully (the lab sees 0–1 failed requests out of ~1,150 during a swap). Traffic to the loopback port itself (`tailscale serve`, `curl 127.0.0.1:<port>`) still has the short recreate gap, because only one container can own that port. Apps that do not serve HTTP deploy with `skipHealthcheck: true` (CLI `--no-healthcheck`), which restores the direct replace. `healthcheckPath`, `healthcheckTimeoutSeconds` and `skipHealthcheck` are stored on the app, so webhook and polling redeploys use them. Nothing stays running between deploys: the candidate exists only during `deployApp`.

---

## 4. Multi-Server High Availability (HA) Handshake & Federation (`src/federation.ts`)

PaaSMCP enables optional multi-server redundancy without the RAM overhead of Kubernetes or etcd:

1. **Cryptographic Pairing Handshake (`paasmcp-join://`):**
   - The primary node generates a `256-bit` `FEDERATION_CLUSTER_KEY` and issues an expiring (15-minute) Join Token signed with `HMAC-SHA256`, containing the primary node ID, endpoint URL, SSH key SHA-256 fingerprint, and redundancy mode.
2. **Redundancy Modes:**
   - **Mode A — `active-active-tunnel` (Stateless & Edge Failover):** Both the primary server (e.g. Homelab) and replica server (e.g. VPS) run the application containers and connect `cloudflared` to the same Cloudflare Tunnel ID. Cloudflare Edge automatically load-balances traffic and fails over in milliseconds if the primary server loses power or ISP connectivity.
   - **Mode B — `warm-standby` (Encrypted State & Vault Sync):** The primary node exports an AES-256-GCM encrypted + HMAC-signed sync bundle containing all app manifests and Vault scopes (`POST /api/federation/sync`), keeping the standby server ready for immediate promotion.

> Mode B is now implemented as the **mirror** (section 5). The sync bundle is still used to copy app
> manifests and vault scopes; the data itself travels by Postgres streaming replication.

---

## 5. Mirror: each server keeps a live copy of the other (`src/mirror.ts`)

1. `paasmcp mirror offer` creates a replication slot (`max_slot_wal_keep_size = 10GB`, so a peer that
   disappears never fills the disk) and a one-time token carrying host, port, slot, credentials, the
   off-site backup target and the current **epoch**.
2. `paasmcp mirror accept` runs `pg_basebackup -R` into `paasmcp/mirror/<peer>/` and starts a read-only
   standby container that follows the peer. Apps and vault scopes come over through the federation bundle.
3. **Promote** (`mirror promote`, guard tier *strong*): `pg_promote()`, epoch + 1, the peer's apps start
   here and Cloudflare points at this server.
4. **Fencing:** a server that comes back and sees a higher epoch from its peer marks itself `fenced`
   and refuses deploys, so two servers never write the same data.
5. **Failback** is guided, never automatic: `offer --from-copy-of <peer>` on the server that took over,
   `accept --rejoin` on the returning server (rebuilds its Postgres from the copy), then
   `mirror handback` stops the apps here and `mirror promote` on the original server takes them back.

## 6. Arbiter and automatic failover (`src/arbiter.ts`)

Automatic failover with only two servers would split the brain when the link between them breaks.
`mirror auto on` is therefore **forbidden without an arbiter** and *strong* with one.

- The arbiter (`paasmcp arbiter serve`) runs on any small third machine and knows only a key derived
  from the cluster key (`HMAC-SHA256(clusterKey, "paasmcp-arbiter-v1")`); it cannot read tokens or vaults.
- Each server sends signed heartbeats (`mirror watch`, systemd timer). A server may take over its peer's
  data only if the arbiter has **also** not heard from that peer for 60 s and the requested epoch is
  higher than the current owner's. Requests older than 60 s of clock skew are rejected.
- `paasmcp arbiter install-service --key <k> [--host tailscale] [--port 4097]` keeps it running under
  systemd; the key lives in `/etc/paasmcp-arbiter.env` (0600), never in the unit or argv. `GET /health`
  is an unsigned liveness probe that reveals nothing.
- `checkArbiter` (`paasmcp arbiter check [url]`, dashboard `GET /api/mirror/arbiter[?url=]`) sends one
  normal heartbeat and explains the result: reachable, key accepted, clock in sync, which servers the
  arbiter hears and how long ago, and whether `mirror watch` runs here. `POST /api/mirror/arbiter` saves
  the address alone (the server that only sends a copy still needs it to heartbeat and be fenced).

### Active-active: an app on both servers (`src/active.ts`, `src/edge.ts`)

`paasmcp active on <app>` (guard `app.active`, confirm; MCP `paas_active`; dashboard **Second server → App on
both servers**) makes an app run on the origin server **and** on the mirror peer, both taking requests.
There is still **one writer**: the origin's Postgres.

- **Readiness** (`activeReadiness`): the app comes from git and has a recorded full commit
  (`lastCommitSha`), a peer receives a copy of this server (`mirror offer`) published on a Tailscale IP
  (`bindIp`), the app has an HTTP health check; warnings for `/` as health path (should query the database)
  and for named volumes (files would differ per server: use S3).
- **Control channel through Postgres:** the origin writes an encrypted manifest (AES-256-GCM with the
  cluster key: app record whitelist, vault scope, full commit, config hash) into `paasmcp_meta.active_manifest`
  on its own Postgres (`REVOKE ALL ... FROM PUBLIC`: app users cannot connect). The peer's live copy receives it
  within seconds; no new port or service. It is written after every deploy of an active app and on
  `active on/off`, skipped when identical or when this server is fenced.
- **Peer side** (`syncActivePeers`, run by `mirror watch` every ~15 s, by `paasmcp poll` and by `paasmcp active
  sync`): reads the manifest from the local copy, refuses a different node id or an older epoch, validates every
  field (ports 4000-4998, env keys, branch, health path, resource limits), never overwrites an app of its own,
  requires the same port as the origin, then deploys the **exact commit** (blue/green) when the commit or the
  config hash changed. Apps the origin turned off are stopped.
- **Shared services:** on the peer, the app's containers get `extra_hosts` mapping `paasmcp-postgres`,
  `paasmcp-redis` and `paasmcp-garage` to the origin's Tailscale IP, so `DATABASE_URL`, `REDIS_URL` and
  `S3_ENDPOINT` are identical on both servers. Redis is now also published on the mirror's Tailscale IP
  (password required). `DATABASE_REPLICA_URL` points at the local copy on the peer (at the primary on the
  origin) for read-only queries that tolerate a few seconds of lag.
- **Ports:** an active app is also published on this server's Tailscale IP, same port on both servers, so an
  edge on either server can reach both copies.
- **Failover:** `promoteMirror` redeploys the app without `extra_hosts` (the copy is local now), points
  `DATABASE_URL` at the promoted copy and `REDIS_URL` / `LOCAL_REDIS_URL` at this server's Redis (sessions
  start empty), keeping the commit it already ran.
- **Entry, option 1 — Cloudflare Tunnel:** run `cloudflared` with the same tunnel token on both servers. The
  tunnel's ingress points at `http://paasmcp-<app>:<port>`, which exists on both. Cloudflare does not health
  check origins: if the link between the servers breaks while both stay up, the peer's share of requests fails.
- **Entry, option 2 — self-hosted edge** (`paasmcp edge install|add|remove|status|uninstall`): a pinned Caddy
  (`caddy:2.8.4-alpine`, host network, admin API on a unix socket in its 0700 data folder) on a server with a
  public IP. `edge install` is guard `edge.install` (*strong*: opens 80/443), `edge add <app> <hostname>` is
  `app.expose` public. The Caddyfile lists this server's copy (`127.0.0.1:<port>`) and the peer's copy
  (`<Tailscale IP>:<port>`) with round robin, active health checks on the app's `healthcheckPath` every 5 s
  and passive failure tracking; certificates come from Let's Encrypt. `edge status` probes each backend once.

## 7. Backups off-site (`src/backup.ts`)

- Nightly systemd timer (`paasmcp backup install-timer`): database dumps, named volumes, upload to any
  S3-compatible bucket (`BACKUP_S3_*` in the `system` vault scope), signed with native SigV4.
- Local copies are pruned **only after** they exist off-site. `backup test <id>` restores into a
  scratch container to prove the backup actually opens.

## 8. Object storage and email for apps (`src/storage.ts`, `src/email.ts`)

- **Storage:** one Garage node per server; `paas_storage_provision` creates a bucket and a key per app and
  injects both `S3_*` and `AWS_*` variables (boto3 and the AWS SDKs work without code changes).
- **Email:** one relay (Brevo, SES, Mailgun...) configured once in the `system` vault; `paas_email_provision`
  injects `SMTP_*`, `EMAIL_URL` and `DEFAULT_FROM_EMAIL`. The built-in test client refuses to send the
  password without TLS.

## 9. Pinned images and updates (`src/updater.ts`)

Shared services run pinned images (`postgres:16.15-alpine`, `redis:7.4.12-alpine`, `dxflrs/garage:v1.3.1`).
`update check` lists newer releases of the **same major** (same major.minor for Redis); `update apply`
backs up every database, updates mirror copies first, waits up to 60 s for health and rolls everything
back on failure. Major upgrades are refused: they need a migration.

## 10. Deploy on push without a public webhook (`src/poller.ts`)

`paas_deploy(autoDeploy="poll")` marks an app; a systemd oneshot timer runs `paasmcp poll` every 2 minutes,
compares `git ls-remote` with the last deployed commit and redeploys when it changed. Nothing stays in
memory and nothing needs to be reachable from the internet.

## 11. Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PAASMCP_ROOT` | `/opt/homelab` | Where all state lives (section 1). |
| `PAASMCP_DOCKER_NETWORK` | `homelab-network` | Docker network shared by apps and services (the labs use their own). |
| `PAASMCP_BASE_DOMAIN` | `example.com` | Domain used for app hostnames. |
| `PAASMCP_CF_ACCOUNT_ID`, `PAASMCP_CF_TUNNEL_ID` | — | Cloudflare account and tunnel. |
| `PAASMCP_GARAGE_ADMIN_URL` | `http://127.0.0.1:3903` | Garage admin API. |
| `PAASMCP_GARAGE_CAPACITY_GB` | `100` | Capacity declared for this server's Garage node. |
| `PAASMCP_ARBITER_KEY` | — | Key for `paasmcp arbiter serve` (from `paasmcp arbiter key`), instead of `--key`. |
| `PAASMCP_OFFLINE_TEST` | — | `1` in unit tests: skips Docker and network calls. |

## 12. Test labs

- `npm test`: unit tests, no Docker.
- `scripts/bluegreen-lab.sh`: real Docker run of the blue/green deploy (healthy version goes live, crashing and HTTP 500
  versions are refused while the old one keeps serving, swap under load on the Docker network, rollback).
- `scripts/dockerfile-lab.sh`: builds and runs each fixture in `test/fixtures/` (Node, Vite, CRA, FastAPI,
  Django, Go, Go `cmd/`, static).
- `scripts/mirror-lab.sh`: two simulated servers on one Docker host (own network, ports 5432/5433):
  offer, accept, replication, promote, fencing, failback and handback. Refuses to run over an existing
  install and removes everything it created on exit.
- `scripts/active-lab.sh`: active-active on one Docker host. A publishes through `paasmcp_meta`, B's copy
  receives it, B builds A's exact commit (and ignores a newer unpublished one), B's app reads and writes A's
  database through the shared-service names and reads its local copy, the Caddy edge serves B and skips A's
  dead backend, and after A dies B is promoted and keeps serving from its copy.
