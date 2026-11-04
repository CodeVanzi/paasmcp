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
> manifests and vault scopes; the data itself travels by Postgres streaming replication. Mode A is now
> **active-active** (section 5, "Active-active"): sharing the main tunnel turned out to be wrong, because
> Cloudflare spreads a tunnel's requests over its connectors without looking at the hostname, so apps that
> run on one server only would fail on the other. Apps on both servers get a tunnel of their own instead.

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
6. **Several servers (star).** One server can offer its data to any number of others (`mirror offer`
   once per server, one slot each); every copy follows it, and active-active apps run on all of them
   (each copy reads the same manifest; the tunnel and the edge list every copy). When the origin fails,
   the arbiter grants the takeover to exactly one copy. Every other copy of it is then **superseded**
   (`supersededBy` on the replica record, set by `mirror watch` when the arbiter names another owner,
   or by hand with `mirror retire <peer>`, guard *confirm*): it misses every write from then on, so its
   app copies stop, it leaves the tunnel, it never takes over, and `mirror promote` refuses it without
   `--stale`. It stays on disk, read-only; once the origin is home again (failback), a new offer
   rebuilds it and the old folder is moved aside (`.superseded-<time>`), never deleted.
   **Origin gone for good:** the server that took over offers its promoted copy to the others
   (`mirror offer <peer> --peer-ip <ip> --from-copy-of <origin>` there). The token names the data's
   origin (`dataOf`), so the copy is still recorded as the origin's data, with `servedByNodeId` = the
   server it streams from. Its liveness (not the dead origin's) decides an automatic takeover, so the
   data can move on again if that server fails too. The origin's apps run only on the server that holds
   the data meanwhile (no active-active from a promoted copy). Such offers are keyed `<peer>:<origin>`
   and never count as this server's own peers (`ownOffers`: edge backends, tunnel, readiness).
   A server that had taken some data over and lost it to a later takeover (it was away for over a
   minute; only an arbiter entry with a higher epoch than its own takeover counts) stops those apps at
   its next watch round, refuses to deploy them, and can follow the new home the same way (its folder
   is moved aside as `.taken-over-elsewhere-<time>`).
7. **Trust for an automatic takeover:** `mirror watch` records when it last saw a copy streaming
   (`streamedAt`, refreshed every 4 minutes while the origin is alive). A copy last seen streaming over
   15 minutes before the origin vanished (or never) does not take over on its own; the watch says so once.

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
- **One arbiter, several clusters.** `PAASMCP_ARBITER_KEY` holds a comma-separated list (at most 32).
  Each key is one cluster, named by an id `sha256("paasmcp-arbiter-cluster:" + key)[0:16]` that reveals
  nothing about the key. Servers send `X-Paasmcp-Cluster`; the arbiter checks the signature only against
  that cluster's key (older servers without the header: whichever key verifies). State is kept per
  cluster (`{v:2, clusters}`), so two clusters can reuse node names without touching each other; a
  single-cluster state file is read as the first key's cluster. On the arbiter device,
  `arbiter add-key <k>`, `arbiter remove-key <id>` (never the last one) and `arbiter clusters` (ids
  only) edit the 0600 env file and restart the service; `install-service` on a device that already has
  keys adds to them instead of replacing them.
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
- **Uploaded files** (`src/filesync.ts`): for each active app with S3 secrets, the peer creates the same bucket
  on its own Garage and imports the **same access key** (admin API, `ensureBucketWithImportedKey`), so the app's
  `S3_*` variables keep working there after a failover. `syncActiveFiles` runs in the background of `mirror watch`,
  outside the state lock, so a slow or unreachable origin never delays a failover check or a deploy (`active sync`
  and `poll run` call it directly, with a 5-minute budget). It stops between objects as soon as this server takes
  over. At most once a minute (sooner after an error or an unfinished run) it lists both buckets with the app's key (SigV4) and copies new or changed objects from the origin's
  S3 API on its Tailscale IP, deleting what the origin deleted. Objects go through memory one at a time; above
  512 MB they are skipped and counted in the status. An empty origin bucket next to a non-empty copy is refused
  (nothing deleted). `mirror handback` first copies back, without deleting, what was uploaded on the peer while
  it served the data, and hands nothing back if that fails. No admin token leaves its server.
- **Entry, option 1 — Cloudflare Tunnel** (`src/activetunnel.ts`; `paasmcp active tunnel on|off|status`, guard
  `active.tunnel` confirm; MCP `paas_active` `tunnel_*`; button in the dashboard card). Cloudflare spreads a
  tunnel's requests over all its connectors whatever the hostname, so the main tunnel must not run on the peer
  (apps that live only on the origin would fail there). Instead:
  - The origin creates a second tunnel (`paasmcp-active-<node>`, remotely managed) with the same `CF_API_TOKEN`,
    keeps its token in the vault (`ACTIVE_TUNNEL_TOKEN`) and runs a pinned `cloudflare/cloudflared:2025.8.1`
    (`paasmcp-tunnel-active`, Docker network only, token in a 0600 `.env`). The token reaches the peer inside the
    encrypted manifest; the peer runs the same container (`applyPeerTunnel`) and removes it when the origin turns
    the tunnel off. Nothing is changed in DNS until the origin's connector is connected.
  - `routeActiveTunnel` writes the tunnel's ingress (the active apps' public and zero-trust hostnames, then a 404
    catch-all), then moves each hostname's CNAME to the new tunnel **only once the app answers on the peer's
    Tailscale IP** (its copy may still be building); a routed hostname stays. Hostnames of apps that stop running on
    both go back to the main tunnel, whose ingress still lists them. It runs after `active on/off`, after exposing
    an active app, in every round of `mirror watch` and in `poll run`, and calls Cloudflare only when something
    changed (ingress hash).
  - **Health watch** (`tunnelWatchTick`, each `mirror watch` round, outside the state lock): probes the health path
    of this server's active apps on `127.0.0.1`. A copy whose apps fail two rounds in a row (~30 s) stops its
    connector, so Cloudflare sends everything to the other one; two healthy rounds start it again. The origin keeps
    its connector unless it is fenced (then it steps out at once), so both never step out together.
  - The manifest also lists the hostnames the tunnel serves. After a failover the peer leaves their DNS alone
    (its connector already receives them) and re-exposes only the other hostnames on its own tunnel. Last result in `paasmcp-tunnel-active/watch.json`.
  - `active tunnel off` moves the hostnames back, empties the ingress, removes the token and the connector here and,
    through the manifest, on the peer. The tunnel object stays in the Cloudflare account and is reused next time.
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

## 10a. Measuring for automatic scaling, phase 1 (`src/scale.ts`, `src/loadtest.ts`)

Phase 1 of the automatic scaling plan only measures and rehearses; it never starts or stops a copy.

- **Round:** `paasmcp scale tick`, run by a systemd oneshot timer (`scale install-timer [--seconds 15]`,
  `AccuracySec=1s`, `Nice=10`), so nothing stays in memory between rounds. One `docker stats --no-stream`
  call for all containers, then a GET of each running app's health path on `127.0.0.1:<port>` (3 s
  timeout, `ok` = status < 500, apps with the health check off are not probed). The round only reads
  `state.json` and skips the state lock, so a long deploy never pauses it; a lock file in `scale/`
  (stale after 120 s) stops two rounds from overlapping.
- **Files** (`paasmcp/scale/`, dir 0700, files 0600): `<app>.json` (last 10 minutes of samples, network
  counters, rehearsal state; rewritten each round, a few KB), `<app>.history.ndjson` (one averaged point
  per finished minute, appended once a minute and trimmed to 24 h), `diary.ndjson` (7 days, at most
  2000 entries). A sample is `{t, cpu (% of one core), mem (MiB), rx, tx (bytes/s from the counter delta;
  null after a container restart), lat (ms), ok}`. `paas_app_lifecycle purge` deletes an app's files.
- **Rehearsal** (`rehearse`, pure): CPU per copy = measured CPU / app CPU limit (one core if none) /
  copies the rehearsal is running. Above `targetCpu` (default 70) for `upRounds` (3) rounds in a row →
  "would add a copy" (up to `max`, default 3); below half the target for `downAfterSeconds` (600) →
  "would remove one" (down to `min`, default 1); `cooldownSeconds` (120) between steps; a gap in the data
  longer than max(90 s, 3 rounds) resets the streaks; three unanswered probes stop decisions until the
  app answers again. The rule lives in `app.scale.rule` (`scale rule`, dashboard, `paas_scale rule`).
- **Decision diary:** entries are a code plus numbers (`would_up`, `would_down`, `at_max`, `no_answer`,
  `answered_again`, `rule_changed`, `capacity`); `renderDiary` writes the sentence in `pt` or `en` when
  read, so changing `state.scale.language` (`scale language pt|en`) rewrites the whole history. Only
  numbers, slugs and validated paths go in, and the MCP tool marks it as data.
- **Capacity test** (`scale test <app>`, guard `scale.test`, confirm): GET only, only the app's own
  loopback port, path validated (no scheme, no `//`, at most 200 characters), concurrency doubles from 1
  up to `--max-concurrency` (default 32, at most 64), 2 to 30 s per step. It stops at more than 5% errors,
  a p95 over 2 s, or two steps without 10% more requests per second. While each step runs it reads the
  app's and `paasmcp-postgres`'s CPU and its own CPU, and classifies what choked: `app_cpu` (≥ 85% of the
  limit), `database` (Postgres ≥ 80% of one core), `client` (the test itself ≥ 90% of one core), `errors`,
  `latency`, `none` or `unknown`. The result (`app.scale.capacity`) suggests 70% of the best rate as a
  per-copy target. The client runs on the same server, so the numbers are a lower bound.
- **Not measured yet:** requests per second per app in live traffic. Cloudflare Tunnel and the Caddy edge
  (2.8) do not split their counters by site, so phase 1 decides on CPU and uses the capacity test for
  requests per second; a per-app counter comes when the balancer of phase 3 sits in the traffic path.

## 11. Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PAASMCP_ROOT` | `/opt/homelab` | Where all state lives (section 1). |
| `PAASMCP_DOCKER_NETWORK` | `homelab-network` | Docker network shared by apps and services (the labs use their own). |
| `PAASMCP_BASE_DOMAIN` | `example.com` | Domain used for app hostnames. |
| `PAASMCP_CF_ACCOUNT_ID`, `PAASMCP_CF_TUNNEL_ID` | — | Cloudflare account and tunnel. |
| `PAASMCP_GARAGE_ADMIN_URL` | `http://127.0.0.1:3903` | Garage admin API. |
| `PAASMCP_GARAGE_S3_URL` | `http://127.0.0.1:3900` | This server's Garage S3 API, used by the file copy (the labs change it). |
| `PAASMCP_CF_API_URL` | `https://api.cloudflare.com/client/v4` | Cloudflare API base used by the tunnel for apps on both servers (tests point it at a fake). |
| `PAASMCP_PEER_S3_URL` | `http://<peer Tailscale IP>:3900` | The origin's Garage S3 API as seen from the peer (labs only). |
| `PAASMCP_GARAGE_CAPACITY_GB` | `100` | Capacity declared for this server's Garage node. |
| `PAASMCP_ARBITER_KEY` | — | Key(s) for `paasmcp arbiter serve` (from `paasmcp arbiter key`), comma-separated for several clusters, instead of `--key`. |
| `PAASMCP_ARBITER_ENV_FILE` | `/etc/paasmcp-arbiter.env` | Where the arbiter device keeps its keys (0600). |
| `PAASMCP_MIRROR_NAME_SUFFIX`, `PAASMCP_MIRROR_PORT_BASE` | —, `5433` | Labs only: copy container name suffix and first local port, so several copies of one server fit on one Docker host. |
| `PAASMCP_OFFLINE_TEST` | — | `1` in unit tests: skips Docker and network calls. |

## 12. Test labs

- `npm test`: unit tests, no Docker.
- `scripts/scale-lab.sh`: scale phase 1 with real Docker: a 0.5-core app is measured idle, under 50 s of
  steady load and after it. CPU must reach the limit under load (and not read far above it), traffic and a
  slower answer must show, the rehearsal must climb and come back to one copy without flapping, the
  history must get one point per minute, files must be 0600, and the capacity test must blame the app's CPU.
- `scripts/bluegreen-lab.sh`: real Docker run of the blue/green deploy (healthy version goes live, crashing and HTTP 500
  versions are refused while the old one keeps serving, swap under load on the Docker network, rollback).
- `scripts/dockerfile-lab.sh`: builds and runs each fixture in `test/fixtures/` (Node, Vite, CRA, FastAPI,
  Django, Go, Go `cmd/`, static).
- `scripts/mirror-lab.sh`: two simulated servers on one Docker host (own network, ports 5432/5433):
  offer, accept, replication, promote, fencing, failback and handback. Refuses to run over an existing
  install and removes everything it created on exit.
- `scripts/star-lab.sh`: three simulated servers in a star plus a real arbiter (ports 5432/5433/5443/4197). A
  offers to B and C and both follow; A dies, the first copy to ask takes over and the other steps aside and
  refuses to be promoted; A comes back fenced, failback; the copy left behind is rebuilt from a new offer and
  has every row. With `gone`, A never comes back: B follows C, C dies, B takes over with every row, and C
  stops A's apps when it returns.
- `scripts/active-lab.sh`: active-active on one Docker host. A publishes through `paasmcp_meta`, B's copy
  receives it, B builds A's exact commit (and ignores a newer unpublished one), B's app reads and writes A's
  database through the shared-service names and reads its local copy, the Caddy edge serves B and skips A's
  dead backend, B starts A's tunnel connector from the control channel (token in its env file, pinned image),
  steps out of the tunnel while its copy is sick and back in when it recovers, removes the connector when A turns
  the tunnel off, and after A dies B is promoted and keeps serving from its copy.
- `scripts/files-lab.sh`: two real Garage nodes (ports 3900/3903 and 3910/3913). B creates the same bucket and
  key, copies A's files and later A's deletions, serves them with the app's key while A is down, sends the
  upload made during the outage back to A, and keeps its copy when A's bucket comes back empty.
