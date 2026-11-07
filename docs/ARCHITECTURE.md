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
│   │   ├── <app-slug>.enc.json   # Encrypted environment variables per application
│   │   └── <scope>.meta.enc.json # Encrypted per-key description, created and last-changed dates (never the values)
│   ├── backups/
│   │   └── <id>.enc.bak          # Binary AES-256-GCM encrypted pg_dump / Redis / volume snapshots (mode 0600)
│   ├── mirror/<peer>/            # Streaming copy of a peer's Postgres (its own compose.yaml + data/)
│   ├── scale/                    # Measurements, decision diary, <app>.step.json while a scaling step runs (0700, files 0600)
│   └── pool/                     # Helper pool: pool_ed25519 (own SSH key, 0600), known_hosts (pinned PCs), seen.json (last answers)
├── paasmcp-pool-lb/              # Pool balancer (Caddy), only while an app uses helper PCs (copies or automatic scaling)
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

### Live deploy status (`src/deploys.ts`)

Deploys start in several processes (dashboard, CLI, MCP, the `paasmcp poll` timer, webhooks inside the dashboard), so
progress lives on disk, not in memory: `deployApp` opens a run (`startDeployRun`) and writes each phase to
`paasmcp/deploys/<app>.json` (0600, atomic rename, last 10 runs). Phases: `detected` (poll/webhook saw a new
commit; its SHA is shown until the code is fetched), `fetching`, `building`, `checking` (candidate + health check),
`switching`, then `live` or `failed`. After the fetch the run records the commit's subject, author and commit date
(`headCommitInfo`, control characters stripped, length capped). A failed run keeps the first line of the error and
the last 30 lines of output, with credentials in URLs and GitHub tokens removed (`redactCredentials`). Each run notes
its process id: a run whose process died shows as interrupted instead of building forever.

`docker compose build` runs asynchronously (`runAsync`), so a dashboard-started or webhook build no longer blocks
the dashboard's event loop and `/api/deploys` keeps answering. `deploySummary` gives the dashboard (and `paas_status`)
one entry per app: the run in progress, the last finished one, the running commit and the GitHub links. Links are
built only from the `owner/repo` parsed out of `repoUrl` (`githubSource`) and full 40-hex SHAs, so a token inside a
stored clone URL never reaches the page. The dashboard reads `/api/deploys` every 10 s (2.5 s while a deploy runs, not
while the tab is hidden) and reloads the app list when a deploy ends. A brand-new app shows as its own row during its
first deploy.

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
- Signed arbiter replies also carry `about` (`os.hostname()`, PaaSMCP version, start time, number of
  clusters); `/health` stays anonymous. `checkArbiter` adds the round-trip time, the `owners` table with
  names, and `watch`: `mirror watch` writes its last successful heartbeat and last failure to
  `<data>/mirror-watch.json` every round. The dashboard's **Arbiter** tab shows all of it.
- `POST /api/mirror/arbiter/install` (dashboard, authenticated, `Cache-Control: no-store`, audited as
  `mirror.arbiter-key-shown`) returns `arbiterInstallCommand()`: clone/pull + build +
  `arbiter install-service --key <k>`. The repository URL comes from the dashboard's followed repo or the
  clone's `origin`, through `publicRepoUrl()` (https only, user/token stripped, SSH github.com turned into
  https, anything odd falls back to the public repo), so no credential reaches the command. Since
  `install-service` merges keys, the same command adds a cluster to an arbiter that already serves another.
- **Pairing by code** (`src/arbiter.ts`, `src/judge.ts`). On the arbiter device, `openArbiterPairing()`
  (`paasmcp arbiter pair`, or the dashboard's “Be the arbiter of another pair”) writes
  `<data>/arbiter/pairing.json` (0600): a 6-digit code, 10 minutes, 5 tries. While it is open, `/health`
  adds `pairing: true` and `POST /pair` answers. The server (`pairWithArbiter`, `arbiter pair-with`,
  dashboard `POST /api/mirror/arbiter/pair`) sends a nonce; the arbiter answers with its own nonce and
  `HMAC(scrypt(code), nonces)` (each hello costs a try), so a device that does not show the code never gets
  anything. Then the key goes sealed with AES-256-GCM under `scrypt(code)` (nonces as AAD); the arbiter
  stores it in its key file, closes the window and serves the cluster at once (`startArbiterServer`
  re-reads `keyFile` when it changes, and can start with no key). Tailscale authenticates and encrypts
  the link; the code is the person confirming both ends.
- **A PC with PaaSMCP as arbiter** (`src/judge.ts`): `ensureLocalJudge` starts container
  `paasmcp-arbiter` (`node:22` alpine, host network, `--restart unless-stopped`, 128 MB) unless an
  arbiter already answers on this PC's Tailscale IP. Its code is a copy of `JUDGE_FILES` (arbiter.js and
  the built-in-only modules it imports; a test runs the copy) in `<data>/arbiter/code`, so a dashboard
  update never removes it; keys and state live next to it. `findJudgeCandidates` lists the online devices
  of `tailscale status --json` (`listTailscalePeers`, which keeps every device) and probes `:4097/health`.
- The control-channel manifest (`active.ts`) carries `arbiterUrl`; the other server adopts it in
  `syncActivePeers` only when it has none (audited `mirror.arbiter-from-peer`). Saving or pairing an
  arbiter in the dashboard republishes the manifest.

### Active-active: an app on both servers (`src/active.ts`, `src/edge.ts`)

`paasmcp active on <app>` (guard `app.active`, confirm; MCP `paas_active`; dashboard **Second server → App on
both**) makes an app run on the origin server **and** on the mirror peer, both taking requests.
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
- Where they go is set per provider (`src/offsite.ts`): `buildOffsiteTarget` turns the few fields a provider
  asks for (R2 account id, S3/B2/Wasabi region, Google HMAC key, a custom endpoint, or the access code of
  another PaaSMCP) into a full S3 destination; `saveOffsiteTarget` writes, reads back and deletes a test file
  first, then asks a person only when a working destination is replaced (guard `backup.target`). Plain
  http is accepted only for private, loopback and Tailscale addresses.
- The other direction: `createBackupGrant` (guard `backup.grant`, confirm) gives another computer its own
  bucket and key on this server's Garage, with an optional quota, reachable on the Tailscale IP (only the
  S3 port; `state.backupShare.bindIp` when no mirror or helper pool published it). The secret is returned
  once and never stored outside Garage; `revokeBackupGrant` deletes the key and keeps the data.
- Opt-in HTTPS (`enablePublicStorage`, guard `storage.public`, or a grant with `internet`): the S3 API only
  (`http://paasmcp-garage:3900`) becomes `https://s3.<baseDomain>` on the main tunnel via
  `routeHostnameOnTunnel` (exposure.ts: ingress rule + proxied CNAME). `disablePublicStorage` removes the
  rule and only the CNAME that points at this tunnel. Uploads above 50 MB use S3 multipart (`putMultipart`,
  aborted on failure) to fit Cloudflare's 100 MB request limit.
- Local copies are pruned **only after** they exist off-site. `backup test <id>` restores into a
  scratch container to prove the backup actually opens.

## 8. Object storage and email for apps (`src/storage.ts`, `src/email.ts`)

- **Storage:** one Garage node per server; `paas_storage_provision` creates a bucket and a key per app and
  injects both `S3_*` and `AWS_*` variables (boto3 and the AWS SDKs work without code changes).
  `useExternalStorage` (offsite.ts) does the same with the person's own account (any provider of the
  off-site picker), tested first; the record keeps `provider` + `host`, the secret stays in the vault.
  Switching an app's storage is guard `storage.app.replace`; `provisionStorage` refuses to replace an
  external bucket unless the dashboard passes `replaceExternal` after that confirmation. The mirror and
  active-active only copy buckets in this server's Garage (`usesLocalGarage`).
- **Email:** one relay (Brevo, SES, Mailgun...) configured once in the `system` vault; `paas_email_provision`
  injects `SMTP_*`, `EMAIL_URL` and `DEFAULT_FROM_EMAIL`. The built-in test client refuses to send the
  password without TLS.

## 9. Pinned images and updates (`src/updater.ts`)

Shared services run pinned images (`postgres:16.15-alpine`, `redis:7.4.12-alpine`, `dxflrs/garage:v1.3.1`).
`update check` lists newer releases of the **same major** (same major.minor for Redis); `update apply`
backs up every database, updates mirror copies first, waits up to 60 s for health and rolls everything
back on failure. Major upgrades are refused: they need a migration.

## 10. Deploy on push without a public webhook (`src/poller.ts`)

`paas_deploy(autoDeploy="poll")` marks an app; `paasmcp poll run` every 2 minutes compares `git ls-remote`
with the last deployed commit and redeploys when it changed. Nothing needs to be reachable from the internet.

Who runs it, with no step for the person (`ensurePollSchedule`, called by `poll enable` and `dashboard follow`):
the dashboard when it is running (`src/pollloop.ts`: inside the dashboard container, `PAASMCP_IN_DASHBOARD=1`,
it starts `poll run` as a child process every `PAASMCP_POLL_SECONDS`, default 120; a crash in a round never
takes the dashboard down). Otherwise a oneshot systemd timer: system-wide when run as root, the user's own
timer (`~/.config/systemd/user`, lingering turned on) otherwise. `sudo paasmcp poll install-timer` still exists.
`poll run` takes the state lock only for the app deploys.

### 10-1. The dashboard follows a branch (`src/selfupdate.ts`)

Opt-in (`paasmcp dashboard follow`, or the button on the dashboard's row; guard `dashboard.follow`, confirm:
whoever can push to that branch controls the server). The default repository is the `origin` of the
installed copy, the default branch `main`; only remote git URLs are accepted. State in
`paasmcp/control-plane/follow.json`.

Each `poll run` (outside the state lock, own lock file `control-plane/update.lock`):
1. `git ls-remote`; nothing to do when it is the running commit, or the commit that already failed.
2. Clone exactly that commit into `control-plane/releases/<sha>` (temporary name until it passes), then
   `npm ci`, `npm run build`, `npm test`, each in a `docker run` of the dashboard image (same Node and tools
   as where it will run), as the owner of the data folder.
3. Swap: rewrite the dashboard's compose file to mount that release at `/app`, `compose up`, wait up to 60 s
   for an answer. If it does not answer, the previous code comes back and the commit is marked failed.
   Only the running and the previous release are kept.

A container cannot replace itself and check the result, so inside the dashboard the swap runs in a short-lived
helper container (`paasmcp-dashboard-swap`, the known-good code, on the Docker network) that checks the new
dashboard by name. Phases go to the dashboard's deploy record (deploy progress, section 3), and the helper finishes the same
run (`continueDeployRun`). The dashboard record never gets a `repoUrl`: webhooks, the mirror and polling
redeploy every app that has one.

## 10a. Measuring for automatic scaling, phase 1 (`src/scale.ts`, `src/loadtest.ts`)

Phase 1 of the automatic scaling plan measures and rehearses; the rehearsal never starts or stops a copy.
Phase 4 (section 10c) lets the same rule act for apps with automatic scaling on.

- **Round:** `paasmcp scale tick`, run by a systemd oneshot timer (`scale install-timer [--seconds 15]`,
  `AccuracySec=1s`, `Nice=10`), so nothing stays in memory between rounds. One `docker stats --no-stream`
  call for all containers, then a GET of each running app's health path on `127.0.0.1:<port>` (3 s
  timeout, `ok` = status < 500, apps with the health check off are not probed). Measuring only reads
  `state.json` and skips the state lock, so a long deploy never pauses it (a step of automatic scaling
  takes the lock, section 10c); a lock file in `scale/` naming the round's process (stale when that
  process is gone, or after 2 h) stops two rounds from overlapping.
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
- **Visits per second:** only for apps behind the pool balancer (section 10b), which counts each app's
  requests (section 10c). Cloudflare Tunnel and the Caddy edge (2.8) do not split their counters by site,
  so apps that run only here decide on CPU, and the capacity test gives a per-copy reference.
- **With copies on helpers** (phase 3), this server's copy carries only its share of the visits, so the
  rehearsal estimates the whole load as its CPU times the copies really running (`realCopies`);
  `scale status` shows both numbers.

## 10b. Helper pool, phase 3: your own PCs, copies set by hand (`src/pool.ts`, `src/poolproto.ts`, `src/worker.ts`, `src/pooljoin.ts`)

The origin keeps everything (vault, image, decisions, entry); a helper PC only runs stateless copies when
told. Nothing is resident on a helper: each order is one SSH session that runs `worker.js` and exits.

- **Join** (`pool invite <name>`, guard `pool.invite`, confirm): first, `preparePool` picks this server's
  Tailscale IP (`--advertise`, else the mirror's, else `tailscale ip -4`; a mirror on a different address
  is refused) and republishes Postgres, Redis and Garage there (`tailnetBindIp`, a few seconds of restart,
  once). The invite is `paasmcp-pool://` + base64url JSON: name, this server's node id, name, Tailscale IP,
  the pool's public key (`pool/pool_ed25519`, created once, never the Git deploy key), a proof key and an
  expiry (15 min, checked against the PC's clock). The proof key is HMAC(`POOL_INVITE_KEY` in the system
  vault, invite id), so `state.json` keeps only the id. On the PC, `sudo node dist/cli.js pool join`
  (`pooljoin.ts`, guard text `pool.join`, asked at the terminal, nothing written to PaaSMCP's own files)
  checks Docker, the `docker` group and sshd, then: a system user `paasmcp-worker` (password `*`, in the
  `docker` group); a root-owned copy of `worker.js` + `poolproto.js` in `/usr/local/lib/paasmcp-worker`
  (Node.js must be installed for every user); `authorized_keys` with one line,
  `from="<origin IP>",command="<node> /usr/local/lib/paasmcp-worker/worker.js",restrict <key>`;
  `worker.json` (0600: origin, invite id, proof key, what the owner gives: `--cpus`, `--memory`, default
  half); and `/etc/tmpfiles.d/paasmcp-worker.conf` for `/run/paasmcp-worker` (0700, tmpfs, recreated at
  boot, no service). It then runs `worker.js --selftest` as that user. `pool add <name> <ip>` (within an
  hour) connects with `StrictHostKeyChecking=accept-new` under `HostKeyAlias=paasmcp-pool-<name>`, sends
  `hello` with a fresh nonce and accepts the PC only if it answers HMAC(proof key, id, nonce, name); the
  PC deletes its proof key after answering, so an invite works once. From then on every SSH call uses
  `StrictHostKeyChecking=yes`, `BatchMode`, `IdentitiesOnly`, the pool's own `known_hosts` and a 6 s
  connect timeout. `pool update-worker` reinstalls the worker after PaaSMCP is updated on the PC;
  `pool leave` undoes everything there.
- **Orders** (`parseOrder`): `SSH_ORIGINAL_COMMAND` is an order name and at most two arguments, each
  matched against a fixed pattern: `hello`, `facts`, `list`, `has-image <tag> <fingerprint>`,
  `load <tag> <fingerprint>` (image on stdin), `run` (JSON spec on stdin, at most 1 MB), `stop <copy>`,
  `logs <copy>` (40 lines), `forget`. Anything else, including no command, is refused; the answer is one
  JSON line. Everything a PC sends back is validated (`validateFacts`, `validateCopyList`: names, numbers
  clamped, versions stripped) and treated as data.
- **Image:** the fingerprint is SHA-256 over the layer digests and the config a container runs with
  (architecture, OS, entrypoint, cmd, env, user, workdir, ports), because the image `Id` differs between
  Docker's classic and containerd stores. If the PC lacks it, the origin tags `paasmcp-pool/<app>:<fp12>`,
  pipes `docker save` through `ssh -C` into `docker load`, and the PC removes it unless its fingerprint
  matches. Each PC keeps only the newest image of each app; a PC of another CPU architecture is skipped.
- **Copies** (`buildRunArgs`): `docker run -d --restart no --memory --cpus --pids-limit 1024
  --security-opt no-new-privileges`, published only on the IP the order arrived on (`SSH_CONNECTION`,
  the PC's Tailscale IP), `--add-host` for `paasmcp-postgres`, `paasmcp-redis` and `paasmcp-garage`
  pointing at the origin, so the app's variables are the same as here. CPU and memory are the app's limits
  capped by what the owner gave (the whole share if the app has none); the worker refuses a copy that would
  pass the share. **Variables:** the spec carries the same values as this server's `.env.runtime`; the
  worker writes them as one shell-quoted file in `/run/paasmcp-worker` (it checks: a real directory of
  this user, mode 700, tmpfs) and bind-mounts it read-only at `/run/paasmcp/env`; the entrypoint becomes
  `/bin/sh -c 'set -a; . /run/paasmcp/env; set +a; exec "$@"'` followed by the image's own entrypoint and
  command. Never `--env`/`--env-file`, which Docker keeps in the container's config on disk. The file is
  deleted when the copy stops; a reboot wipes the folder and copies do not restart by themselves.
- **Balancer** (`paasmcp-pool-lb`, Caddy 2.8, `mem_limit 128m`, on the Docker network, no published port,
  admin on a unix socket): one site per pooled app on the app's own port number, with this server's
  container and each helper copy (`<PC IP>:<port>`), round robin, `lb_try_duration 5s`, active health
  checks on the app's health path every 3 s (2 s timeout, 2xx, out after 2 failures, back after 1). It
  exists only while an app uses helpers (copies, or automatic scaling even at one copy). Each app's site is
  a named server (`servers :<port> { name <app>; metrics }`, `port-<n>` for a name that is not a plain
  slug) so the metrics on the admin socket count its requests (section 10c). Turning copies on moves the app's Cloudflare Tunnel hostnames to
  `http://paasmcp-pool-lb:<port>` (`appServiceUrl`, also used by `expose`), and `scale off` moves them
  back before the balancer forgets the app. A self-hosted edge on this server lists the helper copies as
  backends directly (`edgeBackends`).
- **Reconcile** (`reconcilePool`, under the state lock): asks every PC what it runs (`list`, in
  parallel), then (1) copies that are gone, stopped, on paused PCs or beyond the number wanted leave the
  balancer, get `PAASMCP_POOL_DRAIN_SECONDS` (30) and stop; a PC that does not answer keeps its copy in the
  balancer only if it is current, where the health checks decide; copies no record knows are stopped;
  (2) copies with an older image, other variables or other limits are replaced one at a time on the same
  PC (image sent first, old copy drained and stopped, new one must answer its health path with 2xx from
  here); (3) missing copies go to reachable, unpaused PCs of the same architecture with room, the one with
  the most free CPU first, at most one copy of an app per PC. It runs after `scale set`, deploys,
  rollbacks, restarts, start/stop, destroy (`poolAfterLifecycle`) and pool changes. A fenced server
  (`mirror watch`) stops every helper copy at once, without draining.
- **Who may use it:** `poolReadiness` refuses the dashboard, apps in the trash, apps from a peer,
  active-active apps (a pooled app is refused by `activeReadiness` too), apps with their own compose,
  trusted apps, apps without an HTTP health check, and a fenced server; it warns about a `/` health path,
  missing limits, zero-trust apps (copies sit on Tailscale IPs, outside Cloudflare Access), variables
  pointing at `localhost` or at containers that exist only here, and no PC added yet. Enabling also
  requires this server's copy to answer its health path with 2xx.
- **Guard:** `pool.invite` and `pool.remove` confirm; `app.pool` confirms the first time an app goes above
  one copy and whenever it goes above its scale rule's `max`; moving within that is free (the plan's
  "within limits a person already set"). MCP: `paas_pool` and `paas_scale set|off`.
- **Tailscale:** `pool acl` prints rules for the tag `tag:paasmcp-helper`: this server reaches helpers on
  22 and 4000-4998; helpers reach only 5432, 6379 and 3900 here. Helpers are not given an auth key: a
  node that sleeps (a notebook) must not drop off the Tailnet as an ephemeral one would.
- **Limits of this phase:** only the owner's own PCs (whoever controls a PC can read the variables of the
  copies it runs); requests in progress on a PC that vanishes are lost (new ones go elsewhere within about
  6 s, retried while connecting); copies of one app may briefly run two versions during a rolling
  replace. Automatic decisions: section 10c.

## 10c. Automatic scaling, phase 4: the rule acts (`src/autoscale.ts`, `src/scale.ts`)

- **On and off:** `scale auto on <app> [--min --max]` (guard `scale.auto`, always confirm; MCP
  `paas_scale auto enabled=true` needs a destroy token and a person) checks `poolReadiness`, refuses a
  maximum below 2, sets `app.scale.auto = {since, by}` and calls `setCopies(fromDecider)` with the copies
  it has, kept within the limits: the first time this puts the app behind the pool balancer at one copy,
  so its visits are counted before any decision. `scale auto off` only clears the flag (copies stay).
  `scale off` / dashboard **Stop everything** (`disablePool`) clears the flag first, then goes back to one
  copy here. While it is on, `scale set` and the dashboard selector are refused (`setCopies` without
  `fromDecider`).
- **Visits:** each round reads the balancer's Prometheus metrics on its admin unix socket (`/metrics`,
  empty `Host`, 3 s timeout, 8 MB at most; nothing listens on a port): `caddy_http_requests_total` with
  `handler="reverse_proxy"` per named server, and `caddy_reverse_proxy_upstreams_healthy` per copy
  address. Visits per second = counter delta / seconds since the last round (a smaller counter, after a
  balancer restart, gives no rate). Only visits that pass the balancer count (Cloudflare Tunnel or edge
  entries); Tailscale Serve still goes straight to the container. Before reading, a round rewrites the
  balancer when its Caddyfile differs from the state (an update of PaaSMCP, a hand edit) or it is down.
- **Decision** (`observe`, pure, shared with the rehearsal): pressure = the larger of CPU per copy /
  `targetCpu` and visits per copy / `targetRps` (when set; visits are divided by the copies the balancer
  sees healthy). Above 1 for `upRounds` rounds → one copy up; both below half for `downAfterSeconds` →
  one copy down; never past `min`/`max`, `cooldownSeconds` after each step. Going down from n to n-1
  multiplies the load per copy by at most 2, so it never lands above the target (no flapping). A rule
  whose limits now exclude the copies running moves them to the nearest limit (`why: min|max`). Nothing
  changes while the app's health path fails. A step is committed (`commitStep`) only after it happened.
- **Step** (`applyStep`): under the state lock, waiting at most 2 s (`StateLockBusyError` → asked again
  next round). Inside it, the app is checked again (automatic scaling still on, copies still what the
  round saw, not stopped or fenced), `scale/<app>.step.json` is written (`pid`, host, time), and the same
  `setCopies`/`reconcilePool` as a manual change runs: a new copy joins the balancer only after its health
  path answers 2xx, a copy leaving is taken out and drained before it stops. If fewer copies could run
  than asked, the copies asked go back to what runs. Before a load step up, Postgres is asked how many
  client connections it has (`pg_stat_activity`, via `docker exec ... psql` as the admin user); at 80% of
  `max_connections - superuser_reserved_connections` the step is held (`db_busy`).
- **Held steps** (`holdStep`): no room on helpers (`no_room`), a copy that did not start (`start_failed`)
  or `db_busy` wait min(30 min, max(60 s, cooldown) × 2^(n-1)) before the next try, and are written to the
  diary once per reason until the load eases or a step happens.
- **Repair:** a `step.json` whose process is gone (the server restarted, the round was killed), or older
  than 2 h, makes the next round run `reconcilePool` for that app before deciding anything for it: the
  helpers are asked what they run, missing copies come back and copies no record knows stop. The same
  repair runs at most every 10 minutes when the balancer has seen a helper copy unhealthy for 8 rounds.
  The systemd service allows a round 45 minutes (an image to send, draining).
- **Guard:** moving within `min`/`max` is free; `scale.auto` always confirms; `scale.rule` confirms only
  a higher `max` while automatic scaling is on. Audit: `scale.auto.on`, `scale.auto.off`, `scale.copies`
  (by `decider`), `pool.reconcile`, `scale.off`.
- **Diary:** `up`, `down` (with the signal, the numbers and the helper), `held` (with the reason and the
  wait), `repaired`, `auto_on`, `auto_off`, `stopped_all`; same codes-and-numbers format as phase 1.
- **Not in this phase:** a step is one copy at a time, so a sudden peak takes a few rounds to cover.
  Courteous mode: section 10d. Waking sleeping PCs (Wake-on-LAN): section 10e.

## 10d. Courteous mode: the PC's owner comes first (`src/courtesy.ts`, `src/worker.ts`, `src/poolproto.ts`)

- **What the helper measures:** nothing runs on the PC between orders, so the worker measures with two
  counters at each `facts` or `list` order: the whole PC's busy CPU time (the cgroup v2 root's `cpu.stat`,
  the cgroup v1 `cpuacct.usage`, or `/proc/stat`) and each running copy's (its main process's cgroup, from
  `/proc/<pid>/cgroup`; a PC that is itself a container sees the host's path, so leading parts are dropped
  until the file is found). The last snapshot stays in `owner.json` (0600) in the worker's home. The owner's
  share (`ownerShare`, pure) = (PC time − copies' time) / (window × CPUs), in % of the PC's CPUs (a CPU
  quota on the PC's own cgroup counts). Unsure, and reported as a code instead of a number: a window under
  10 s (the previous reading is repeated) or over 15 min (the worker measures 3 s instead), an image load or
  a copy start in it (`load`/`run` mark `heavy`: that CPU is Docker's), a copy that left during it (its last
  time is unknown), a counter that went back. A copy that started inside the window counts with all its
  time. Older workers send no reading; the dashboard asks for `pool update-worker` there.
- **What the origin decides** (`courtesyRound`, called by every scale round, so it needs the timer): at
  most once a minute (`PAASMCP_COURTESY_EVERY_SECONDS`), only while some app uses the pool (or a PC is still
  marked busy), it asks every helper not paused and not in mode off (`probeHelpers`). `courtesyObserve`
  (pure, streaks in `pool/courtesy.json`): the owner's share at or above the PC's limit (`courtesy.cpuPct`,
  50% by default, 10-95) for 2 readings in a row → `ownerBusy = {since, cpuPct}`; below 80% of the limit
  for 5 minutes (`PAASMCP_COURTESY_CALM_SECONDS`) → cleared; in between, the calm while starts over; unsure
  readings and PCs that do not answer change nothing. The change is made under the state lock (2 s wait;
  busy → the next check redoes it), audited (`pool.owner.busy`, `pool.owner.free`) and written to the
  diary for each app with a copy there (`owner_busy`, `owner_calm`).
- **Modes** (`pool courtesy <name> auto|warn|off [--cpu 50]`, MCP `paas_pool action=courtesy`, dashboard;
  free, audited `pool.courtesy`): `auto` (default): a busy PC is treated like a paused one by
  `reconcilePool` (its copies leave the balancer, drain and stop, then placement looks for another PC with
  room; the copies asked for stay, so they come back when it is free). `warn`: the copies stay, the diary
  says so. Both: `pickHelpers` gives no new copy to a busy PC, nor to one whose last answer is at or above
  its limit. `off`: not asked, any mark cleared. Copies still leave the busy PC before a replacement
  starts elsewhere: the owner gets the PC back first; this server's copy keeps serving meanwhile.
- **Limits:** CPU only (memory pressure and a full disk are not watched); the reaction takes 2 readings,
  so about 1-2 minutes plus the drain; a PC that is itself busy with something that is not its owner (a
  backup, an update) counts as its owner.

## 10e. Wake-on-LAN: waking sleeping helpers (`src/wol.ts`, `src/wake.ts`, `src/pool.ts`)

- **What the helper reports:** at each `facts`/`list` order the worker adds `lan` (`lanFacts`, no root): the
  interface of the default route in `/proc/net/route` (main table, so Tailscale's routes do not count), its
  MAC (`/sys/class/net/<if>/address`), its IPv4 and prefix, whether it is Wi-Fi (`wireless`/`phy80211`) and
  whether `pool wake-setup` armed it (`/etc/paasmcp-wol.json`). Validated on arrival (`validateLan`: a
  unicast MAC, a plain interface name, prefix 8-30) and kept in `seen.json`, so it is known while the PC
  sleeps. Older workers send nothing.
- **On the helper, once** (`sudo paasmcp pool wake-setup [--interface eth0]`, root, `setupWake`): refuses
  Wi-Fi and cards whose `ethtool` lacks `g`; runs `ethtool -s <if> wol g`; installs the oneshot unit
  `paasmcp-wol.service` that sets it again at every boot (many systems reset it), tells NetworkManager
  (`802-3-ethernet.wake-on-lan magic`) when it manages the card, and writes the marker. `--undo` and
  `pool leave` remove the unit and the marker, set `wol d` and NetworkManager back to `default`. Waking from
  power off may also need the BIOS/UEFI option; waking from suspend usually needs only this.
- **On the origin** (`pool wake <name> on|off|now [--mac --broadcast --port]`, MCP `paas_pool action=wake`,
  dashboard; free, audited `pool.wake`): `on` takes the MAC and the network from the last answer, computes
  the broadcast address (`broadcastFor`) and requires this server to have an address on that network
  (`originAddressFor`: magic packets do not cross routers); a broadcast given by hand only warns. The
  broadcast must be a real broadcast address (the last of a /30 or larger network, never one machine's) on
  a private network (10/8, 172.16/12, 192.168/16), or 255.255.255.255, and the port 9 or 7
  (`validateBroadcast`, `validateWakePort`, checked again whenever they are used, so a hand-edited state or
  a token cannot aim UDP at the internet or at one host's service). Warnings: Wi-Fi, card not armed, a MAC different from the reported one. Stored as
  `helper.wake = {mac, broadcast, port, since, by}`; `off` deletes it and forgets the tries.
- **The packet** (`sendMagicPacket`): 6 × `0xff` and the MAC 16 times (102 bytes), UDP to `broadcast:port`
  (9 by default), sent twice 100 ms apart from an ephemeral port with `SO_BROADCAST`. Nothing secret: anyone
  on the network can send it; what decides is the person who turned it on for the PC.
- **Who wakes a PC:** placement in `reconcilePool`. (1) A copy must start and no awake helper fits
  (`pickHelpers` found none): `wakeForRoom` runs `pickHelpers` again over the PCs that do not answer, have
  Wake-on-LAN on and were not given up on (same rules: not paused, owner not busy, same architecture,
  room), at most one per missing copy, and the report lists them in `waking`. (2) A PC holding a copy that is
  kept (current, still wanted) does not answer: it is woken. A manual `scale set` answers with "Waking ...";
  the copy starts when the PC answers (next paragraph). The decider (`applyStep`) turns a step that could
  not place its copy while a PC wakes into `held: "waking"`: the copies asked go back to what runs, and
  `holdStep` retries after `PAASMCP_WAKE_RECHECK_SECONDS` (60) without the growing wait of `no_room`, with
  one diary line.
- **Tries** (`pool/wake.json`, 0600, apart from state.json so sending needs no lock; `wakeStatus`, pure): a
  PC gets `PAASMCP_WAKE_WAIT_SECONDS` (180) to answer before another packet, 3 packets at most; then
  `gaveUpAt` is set, the diary says it did not wake (`wake_failed`, audited `pool.wake.failed`) and it is
  neither asked nor woken again by itself until it answers or a person uses `pool wake <name> now` (which
  starts the tries over). Every packet is audited (`pool.wake.sent`).
- **Follow-up** (`wakeRound`, called by every scale round after the courteous check, so it needs the timer):
  asks only the PCs being woken. Any probe that gets an answer from one (`recordWakeAnswers`) ends its tries,
  writes `woke` (with the seconds since the first packet) to the diary of each app that needed it, and puts
  it on the follow-up list; under the state lock (2 s wait, busy → next round, for up to 30 minutes), apps
  missing copies or with a copy on that PC are reconciled, so a copy asked by hand starts there and a copy
  lost to a reboot comes back. PCs that do not answer yet get their next try, or are given up on.
- **Status:** a PC that does not answer shows `asleep` when it can be woken, `waking` while packets are
  on their way (`waking: {since, tries}`), and `gone` otherwise or once given up (`waking.gaveUp`).
- **Limits:** the PC must share a network (layer 2) with this server, by cable; it takes 30 s to a minute to
  answer, so it helps load that lasts (the decider already wants `upRounds` rounds above the target).
  Going back to sleep is the PC's own power settings: nothing puts it to sleep, and a PC whose automatic
  suspend is shorter than the load sleeps with copies on it (the balancer stops sending it visits within
  about 6 s, and it is woken again while its copy is still wanted).

## 10e-1. PCs of your Tailscale (`src/pcinstall.ts`)

**Connections → PCs** lists every device of `tailscale status --json` (`listTailscalePeers`, which now
also keeps `ShareeNode`, the owner compared with `Self.UserID`, valid tags and valid `sshHostKeys`) and
marks each one: *runs PaaSMCP* (an IP this server already knows as the other server of a pair, a helper, a
federation peer or a PC installed from this dashboard, or an arbiter answering on `:4097`), *no PaaSMCP*
(online Linux device of the owner), *off*, or *not possible here* (not Linux, shared from another
account, another user's device, no IPv4). Only online Linux devices of the owner are probed, with two
read-only probes: the arbiter's `/health` and the first line of port 22 (`SSH-2.0-Tailscale` vs OpenSSH),
which says how the dashboard could log in there. The list itself logs in nowhere.

**Installing from there** (`src/pcremote.ts`, one job at a time, `/api/pcs/check|install|job|cancel`):

1. *Log in.* Only to an IP the list shows as the owner's online Linux PC without PaaSMCP (or one this
   dashboard installed). One OpenSSH connection to the Tailscale IP, kept open as a ControlMaster in a
   private folder under `/dev/shm`: by Tailscale SSH (no password; a `check` rule's login link, sent as
   the SSH banner, is shown on the screen) or by the PC's password, passed once through a one-shot askpass
   file that is deleted right after the login. No public-key login is offered, so no key of this server
   is used or left there. Host key: pinned to the `sshHostKeys` Tailscale reports when it has them
   (Tailscale SSH on), otherwise accepted on first use (the Tailscale IP already identifies the device)
   and its fingerprint shown. Three wrong logins on one PC block it for 10 minutes.
2. *Check (read-only, as the login user).* `CHECK_SCRIPT` prints `key=value` lines (OS, CPU type, memory,
   free disk, systemd, git/node/docker/compose/tailscale versions, sshd, PaaSMCP already in
   `/opt/paasmcp`, how root is reached); `parseFacts` keeps known keys only, printable and capped;
   `planFor` says what is missing and what blocks (not Debian/Ubuntu, CPU type, no systemd, under 1.5 GB
   free, no sudo, no Tailscale). When sudo wants the password, `sudo -S -v` checks it before anything is
   offered. The job waits 15 minutes for the person's choice.
3. *Install (root, after guard `pc.install`, confirm).* The script (`installScript`, every value validated
   and single-quoted) is written to `/tmp/paasmcp-install-<id>.sh` (0600) and run with `bash`, `sudo -n`
   or `sudo -S` (the password on stdin, never in argv), then deleted. Steps, marked `@@step`: apt packages
   (git, ca-certificates, curl, xz-utils, `docker.io` when Docker is missing, a compose package until
   `docker compose` works, `openssh-server` for a helper); Node.js 20+ (kept when there; else apt when it
   has 20+; else the official v22 tarball checked against `NODE_SHA256`); the code (`git clone` of this
   server's repository at this server's exact commit into `/opt/paasmcp`, `npm ci`, build, links in
   `/usr/local/bin`); the role. Server: `init` + `dashboard`. Helper: invite made here, `pool join --yes`
   there, Tailscale SSH switched off (its own SSH server would bypass the forced command the helper key
   relies on), then `pool add` here. Arbiter (only when this server has a pair): `arbiter be-judge` there
   and `pairArbiterAndSave` here with the code it prints. Optionally (always for a helper) Tailscale SSH
   is switched off at the end, detached so it outlives the session it closes.
4. *Records.* `audit.log` (`pc.install.connect|start|done|failed|cancelled`, no password),
   `<data>/pcinstall/installs.json` (name, IP, role, commit, who), so the list knows the PC.

## 10e-2. Disconnecting a linked PC (`src/unpair.ts`)

The first card of **Connections → PCs** (`GET /api/paired`) lists what ties this server to others:

- **Paired servers.** `pairedServers` groups, per server, its `federation.peers` records, the mirror
  offers this server sends it and the copies it keeps of it. Copies and pairing records merge by node id;
  offers only carry the name a person typed, so they merge by name. The generic `primary-node` never
  merges two servers. Each entry carries `effects` (what a disconnect does) and `blockers` (refused while
  this server is fenced by it, serves its data, follows it in a failback, or runs apps on both servers /
  the active-active tunnel with it).
- **The judge this server uses** (`mirror.arbiterUrl`), **helper PCs** (existing `pool remove`), and the
  **pairs this PC judges** (`judgedPairs`, from the arbiter container's key file and state; one served by
  the systemd service is removed with `arbiter remove-key`).

`unpairServer` (guard `pc.unpair`, strong: the name is typed): stops copies of its apps that run here
(active-active peer side) and its tunnel connector; `dropOffers` removes the peer's `pg_hba` replication
line (unless another offer of the same source uses that address), ends its walsender and drops its
replication slot (retried while the slot is still in use; an offer whose slot cannot be dropped stays
listed), and deletes the Garage keys named `mirror-<peer>` (the backups it sent stay); `dropCopy` removes
the copy container and renames its data folder `data.disconnected-<time>` (never deleted, never the
server's own database); off-site backups that went to that server's Garage are unset; its pairing records
go. When no paired server is left, `FEDERATION_CLUSTER_KEY` is replaced (the old one let the other server
push `/api/federation/sync` bundles here and sign arbiter requests) and the judge is unset; when no offer
is left, `MIRROR_REPLICATOR_PASSWORD` and the role's password change (that role can also log in to the
databases). The other server keeps its own records until it disconnects too. `unpairJudge` (guard
`judge.unpair`) unsets the judge and automatic takeover; `forgetJudgedPair` (guard `judge.forget`)
removes one key from the arbiter container's key file (re-read on change) and stops the container when
none is left. The same actions: CLI `node paired|unpair|unpair-judge`, MCP `paas_mirror`
`paired|unpair|unpair_judge|judge_forget` (a person approves each). Audit events `pc.unpair`,
`mirror.offers-dropped`, `mirror.copy-dropped`, `judge.unpair`, `judge.forget`.

## 10f. Dashboard layout (`src/dashboard.ts`)

One page, three columns: a side menu, the page, and telemetry (host, resources, and a "quick health" box whose lines
open the page that fixes them). The menu groups pages under Apps, Servers, Integrations and System (each section opens and closes,
remembered in `paasmcp_nav_closed`; going to a page opens its section), collapses to
icons (`paasmcp_nav_collapsed` in localStorage) and becomes a drawer below 720 px; between 720 and 1240 px it shows icons
only and the telemetry moves under the page. A page with several parts lists them in `PAGE_SUBS`; each card carries
`data-sub="<part>"`, and `goTo(tab, part)` shows only that part's cards, marks the folder tab and the nested menu item,
and writes `#<tab>/<part>` to the URL (back button and bookmarks work). Code that needs a field on another part calls
`revealEl(id)`, which opens the right page and part first. Menu counters are hidden at zero and their tooltip says
what is counted (the AI count comes from `mcpToolCount` in `paas_status`). Each page shows a breadcrumb, its title
with the menu counter and a one-line lead (`lead_<tab>`); anything with `data-tip` gets the same small tooltip.
Opening and closing the menu, its sections and the phone drawer are animated (off with reduced motion). The light theme uses blue-grey tones, not
white.

The **Resource usage** card (`src/resources.ts`) shows the whole server split in two: **PaaSMCP** (every `paasmcp-*`
container: apps, copies, shared databases, the dashboard) and **Others** (the system, other programs and other
containers), plus what is free. CPU is the share of all cores, read from `os.cpus()` around the same `docker stats`
call that feeds the per-app numbers (`resourceSnapshot` in mcp-server.ts), so both describe the same second; memory
uses `MemAvailable`; the disk is the one holding `PAASMCP_ROOT` (`statfs`, no `df` parsing). `/proc/stat`,
`/proc/meminfo` and the bind-mounted data folder describe the host, so the numbers are the same inside the dashboard
container. The card refreshes every 15 s from `GET /api/resources` while the page is visible. PaaSMCP's share is
capped at the server's total, since the two readings come from different sources a moment apart.

The disk line is split too: apps (code folders, app volumes, the part of each `paasmcp/<app>` image no other image
shares), databases (Postgres and Redis folders), backups and trash, app files (Garage), others. Walking folders takes
a while, so `src/usage.ts` measures it in the background every 10 minutes (`du -k -x -d 1`, `docker system df -v`),
writes `usage/latest.json`, and the card reads that file (`diskSplit`). Folders sum to at most the disk's used space,
in case Docker's data sits on another disk.

The same round asks Postgres for each database's size (`pg_database_size`) and Redis for keys per logical database
(password sent on stdin, never on a command line), and once an hour appends the sizes to `usage/db-history.ndjson`
(90 days) for the growth charts on the Databases page (compact sparklines or full charts, `paasmcp_db_view`). The
databases share one Postgres, so nothing is reserved per database: a database can get a **warning size**
(`warnSizeMb` on its record, `POST /api/databases/limit`, 1 MB = 1,000,000 bytes); the page shows the share used and
the round sends a notice (notify.ts) when it crosses 80% and 100% (`usage/db-warned.json`; dropping below 80% re-arms
it). Nothing is blocked. `GET /api/usage?refresh=1` measures now (at most once every 30 s); `PAASMCP_USAGE=0`
turns the loop off.

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
| `PAASMCP_POOL_DRAIN_SECONDS` | `30` | Seconds a helper copy keeps its visits in progress after it leaves the balancer, before it stops. |
| `PAASMCP_COURTESY_EVERY_SECONDS`, `PAASMCP_COURTESY_CALM_SECONDS` | `60`, `300` | Labs only: how often the courteous check asks the helpers, and how long a PC must stay free before it takes copies again. |
| `PAASMCP_WAKE_WAIT_SECONDS`, `PAASMCP_WAKE_RECHECK_SECONDS` | `180`, `60` | Labs only: how long a woken PC gets to answer before another magic packet, and how soon the decider retries a step it held for a PC waking up. |
| `PAASMCP_WORKER_HOME`, `PAASMCP_WORKER_RUN_DIR` | `/var/lib/paasmcp-worker`, `/run/paasmcp-worker` | Tests only: where the helper's worker keeps its settings and the in-memory variables folder. |
| `PAASMCP_WORKER_ALLOW_DISK` | — | Tests only: `1` lets the worker write variables outside tmpfs. |
| `PAASMCP_PC_SSH_PORT` | `22` | Labs only: the SSH port used to install PaaSMCP on another PC. |
| `PAASMCP_OFFLINE_TEST` | — | `1` in unit tests: skips Docker and network calls. |

## 12. Test labs

- `npm test`: unit tests, no Docker.
- `scripts/scale-lab.sh`: scale phase 1 with real Docker: a 0.5-core app is measured idle, under 50 s of
  steady load and after it. CPU must reach the limit under load (and not read far above it), traffic and a
  slower answer must show, the rehearsal must climb and come back to one copy without flapping, the
  history must get one point per minute, files must be 0600, and the capacity test must blame the app's CPU.
- `scripts/pool-lab.sh`: scale phase 3 with real Docker. Two Ubuntu containers with Docker inside and sshd
  play helper PCs on a lab network whose gateway plays this server's Tailscale IP. Both join and are added;
  the SSH key gives no command, no shell, no terminal, no forwarding, and is refused from another machine;
  an app that counts visits in Redis runs 3 copies and every copy answers, shares Redis and got the secret,
  which is in no container setting and nowhere on a PC's disk; under 4 parallel visitors a PC is cut off
  the network: from 10 s after the cut every visit succeeds in under a second; pause and resume; a new
  deploy rolls every copy to v2; `scale off`, `pool remove` (the key stops working) and `pool leave`.
  Builds its helper image if missing (`POOL_LAB_BUILD_FLAGS` passes extra build flags).
- `scripts/pcinstall-lab.sh`: installing PaaSMCP on other PCs from the dashboard, through its API. Two
  plain Ubuntu containers (sshd, sudo, certificates; no git, Docker or Node) play the PCs; stand-ins for
  `systemctl` and `tailscale`, and a fake `tailscale status` here. A wrong password ends in `auth`; pc-a
  (sudo user + password) is checked (nothing changes there), asks for confirmation, and becomes a helper
  that answers this server's key, with the same commit and Node 20+; pc-b (root + password) becomes a
  server whose dashboard answers there. The passwords are in no answer, log, data file or PC disk; no key
  is left in any `authorized_keys`; the script and the connection folders are gone. Needs the checkout's
  commit on GitHub.
- `scripts/autoscale-lab.sh`: scale phase 4 with real Docker, on the same kind of helper PCs. An app with
  Postgres gets automatic scaling (1 to 3 copies, 20 visits/s per copy) and rounds run by hand. The
  balancer must count exactly the visits sent through it; under 50 visits/s copies go 1 → 2 → 3 on the
  helpers with no failed visit, and back 3 → 2 → 1 when the load stops; 10 s waves only add copies;
  lowering the maximum is free and raising it asks; with 80 idle Postgres connections no copy is added
  (the diary says why) until they close; a round killed while its new copy warms up on a helper leaves a
  `step.json`, and the next round stops the orphan and leaves the helpers with exactly the copies this
  server knows; "stop everything" leaves one copy here and nothing on the helpers.
- `scripts/courtesy-lab.sh`: courteous mode with real Docker, on the same kind of helper PCs, checks every
  10 s and a 30 s calm while. An app runs 2 copies by hand under 20 visits/s. Both PCs report their owner's
  CPU; two busy loops on the PC with the copy move it to the other PC (which does not count that CPU as its
  owner's), the diary says why and where, and the PC is free again after the calm while; in warn mode the
  copy stays and a third copy goes to the other PC; mode off clears the mark and watches nothing; no visit
  fails while the owner's PCs hand their copies over, and no round errors (visits lost in the manual `scale
  set` steps, a balancer reload racing a keep-alive connection, are reported apart).
- `scripts/wake-lab.sh`: Wake-on-LAN with real Docker, on the same kind of helper PCs. A PC "sleeps" frozen
  (`docker pause`: no answer, copies kept in memory, like a suspend), and a listener on the lab network
  plays its card: a magic packet with its MAC unfreezes it 5 s later. Checks: the PC reports its card and
  Wake-on-LAN is turned on from it (a public broadcast is refused; `wake-setup` refuses a card it cannot
  arm); a manual third copy with no awake room wakes the PC with one packet and starts there, and the diary
  says it woke; automatic scaling holds its step while the PC wakes and then steps up there; a PC that falls
  asleep holding a copy is woken and the copy survives; a PC that never answers gets 3 packets, then none,
  until a person wakes it by hand; with it off, nothing is sent.
- `scripts/bluegreen-lab.sh`: real Docker run of the blue/green deploy (healthy version goes live, crashing and HTTP 500
  versions are refused while the old one keeps serving, swap under load on the Docker network, rollback).
- `scripts/deploy-status-lab.sh`: real Docker deploys started from the dashboard API: the phases are seen while
  they run, `/api/deploys` keeps answering quickly during the build, a crashing commit ends `failed` with its log
  while the previous version keeps serving, and the commit's message and author are recorded.
- `scripts/dockerfile-lab.sh`: builds and runs each fixture in `test/fixtures/` (Node, Vite, CRA, FastAPI,
  Django, Go, Go `cmd/`, static, C# / ASP.NET in `src/<name>/`).
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
