# Contributing & Engineering Roadmap — PaaSMCP

Thank you for contributing to **PaaSMCP**! This document serves as both a contributor guide and a **detailed engineering specification for AI Agents (LLMs) and human developers**.

---

## 🛠️ Development & Verification Workflow

1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Build TypeScript (`src/` -> `dist/`):**
   ```bash
   npm run build
   ```
3. **Run the automated security & unit test suite:**
   ```bash
   npm test
   ```

---

## 🔒 Mandatory Security & Privacy Invariants

Every PR or AI Agent modification **must** enforce these rules:

1. **Zero Personal / Proprietary Data in Git:** Never commit personal domains, Cloudflare Account/Tunnel IDs, email addresses, API tokens, or proprietary references. All user-specific state belongs strictly in `/opt/homelab/paasmcp/state.json` or encrypted `.enc.json` Vault files.
2. **No Shell String Interpolation:** Always use `execFileSync("docker", [...args])` or `execFileSync("git", [...args])` with argument arrays. Validate user inputs with `sanitizeSlug()`, `validateEnvKey()`, `validateBranchName()`, and `validateResourceLimit()`.
3. **Loopback-First Networking (`127.0.0.1`):** Never bind container ports to `0.0.0.0` on the host.
4. **Constant-Time Secret Verification:** Always use `timingSafeCompare(a, b)` in `src/vault.ts` when verifying tokens or HMAC signatures.
5. **Zero Plaintext Leak:** Mask secrets (`sk_l****def`) in all MCP tool responses, CLI outputs, and UI responses.

---

## ✅ Completed Milestones (v1.1)

- [x] **GitHub Push Webhook Receiver (`/api/webhooks/github` in `src/federation.ts` & `src/dashboard.ts`):** Constant-time `X-Hub-Signature-256` HMAC verification and automatic branch-matched rebuilds.
- [x] **Encrypted Database Snapshots & Restore (`paas_db_backup` in `src/database.ts`):** Binary `AES-256-GCM` encryption (`PMCP` wire format) + `SHA-256` verification + zero-plaintext-disk restore via `stdin`.
- [x] **Multi-Service `docker-compose.yml` Pass-Through (`generateSanitizedComposeFromRepo` in `src/deployer.ts`):** Strips `privileged`, `network_mode: host`, and host bind-mounts while injecting Vault `.env.runtime` and enforcing `127.0.0.1` binding on the primary web service.
- [x] **Lightweight Per-App Resource Metrics (`getContainerMetrics` in `src/deployer.ts`):** On-demand `docker stats --no-stream` snapshot integrated into `paas_system_status` and the Web Workspace.
- [x] **1-Second Image Rollback & `paas_doctor` Diagnostics (`src/deployer.ts`):** Automatic `:previous` image tagging and `OOMKilled` / crash-loop inspection.
- [x] **Multi-Server HA Handshake & Federation (`paas_node_federation` in `src/federation.ts`):** Signed `paasmcp-join://` tokens (`HMAC-SHA256` + SSH fingerprint) and encrypted Vault/State bundle synchronization.

---

## ✅ Security Base (v1.2)

- [x] Risk policy in `src/guard.ts` (free / confirm / strong / forbidden) with agent approval requests, audit log and dashboard/CLI confirmations.
- [x] 30-day app trash (`destroy` → `restore` / `purge`), safety backup before every restore, archive of deleted secrets.
- [x] Trusted apps: host-access compose fields kept only after a strong confirmation; disguised host mounts (long syntax, `~`, `$VAR`, `driver_opts`, `volumes_from`, `extends`, `additional_contexts`) are caught.
- [x] Atomic state/vault writes and a cross-process state lock; dashboard runs from a pinned prebuilt image.

## 🧭 Plan Order

1. Security base (done above).
2. ✅ MCP over HTTP (Streamable HTTP, stateless) with personal tokens and levels (read / deploy / destroy), loopback/Tailscale only; TOTP second factor and signed sessions for the dashboard. Follow-up: OAuth 2.1 + PKCE login so web assistants (ChatGPT / Claude.ai connectors) can use a public URL.
3. ✅ Off-site encrypted backups (item 4 below, native SigV4 to R2/B2/S3/Garage) including app volumes, a restore test tool, a daily systemd timer and safe local pruning (only what is already off-site). Big volumes still go through memory; restic replaces that in item 5.
4. ✅ S3 storage for apps (Garage, pinned image, admin API on loopback): `paas_storage_provision` creates a bucket + key per app and injects `S3_*` + `AWS_*`. Open: a public S3 endpoint for presigned browser URLs, and removing the bucket on purge (today it is kept).
5. ✅ Federation as a mirror, part 1 (`src/mirror.ts`, lab: `scripts/mirror-lab.sh`). Done: Postgres streaming with a slot (10 GB cap), backups to the peer's Garage, status, manual strong-confirmed promote with epoch + redeploy + DNS. Changed from the plan: no Garage 2-zone layout yet (replication factor cannot change on a live cluster; app buckets still need a peer copy) and volumes go through the existing backup sync instead of restic. Original text: per-app modes `mirror` / `stateless` / `local`; each server streams its Postgres to the other over Tailscale (item 5 below, both directions), Garage in two zones, hourly restic of volumes, replication lag in status, manual failover with confirmation, epoch number and DNS switch.
6. ✅ Mirror, part 2 (`src/arbiter.ts`, `mirror watch|auto|handback`, `accept --rejoin`, `offer --from-copy-of`): HMAC-signed arbiter with derived key, claims only when the arbiter also lost the peer, epochs only go up, fencing stops own apps and blocks deploys, guided failback tested in `scripts/mirror-lab.sh`. Original text: optional arbiter (tiny VPS, Raspberry or Cloudflare Worker) for automatic failover; guided failback. Automatic failover without an arbiter stays forbidden.
7. ✅ Email: one relay (Brevo, SES…) configured once (`paasmcp email set`, password never on the command line), `paas_email_provision` injects SMTP_* / EMAIL_FROM / EMAIL_URL / BREVO_API_KEY per app, `email test` with a dependency-free SMTP client that refuses to authenticate without TLS. Open: per-app credentials (today every app holds the relay key; a local relay container would isolate them).
8. ✅ Updater (`src/updater.ts`, `paas_update`, `paasmcp update`; tested on a real container: 16.15 → 16.10 with data kept, then a broken image rolled back in 61 s). Not covered: cloudflared (host package) and the dashboard base image. Original text: Updater: pinned versions for Postgres/Redis/Garage/cloudflared, `paas_update check|apply` with backup, health check and rollback (mirror replicas first).
9. ✅ (`src/poller.ts`, `scripts/dockerfile-lab.sh`, fixtures in `test/fixtures`; static/node/go/go-cmd built and served for real, vite/cra/python need package downloads and run on a real server) Remaining promises: GitHub polling mode (0 MB idle auto-deploy) and per-language tests for generated Dockerfiles.
10. ✅ Blue/green deploy (blueprint item 2; `deployApp` in `src/deployer.ts`, lab: `scripts/bluegreen-lab.sh`). Every deploy runs the new image as a candidate (`docker compose run`) on a free loopback port and needs `GET healthcheckPath` < 500 within 20 s (`healthcheckTimeoutSeconds`, max 300); a failure keeps the running version, puts `:latest` back on its image and returns the candidate's logs (`HealthcheckFailedError`). During the swap the candidate holds the container name as a network alias, so the Cloudflare Tunnel path keeps a healthy target. Changed from the plan: `exposure.ts` needed no change; the running image is held as `:pre-deploy` because the containerd image store drops untagged images. Open: the loopback port (`tailscale serve`) still has the ~0.5 s recreate gap; apps without HTTP use `skipHealthcheck`.
11. ✅ Active-active (`src/active.ts`, `src/edge.ts`, lab: `scripts/active-lab.sh`). An app runs on both mirrored servers with one writer (the origin's Postgres); the peer follows the origin's exact commit through an encrypted manifest in `paasmcp_meta` that rides the existing Postgres stream (no new port or daemon). Entry: a Cloudflare Tunnel just for these apps on both servers, with a health watch that takes a sick copy out (`src/activetunnel.ts`), or a self-hosted Caddy edge with health checks. App buckets are copied to the peer every minute with the same key, and come back on handback (`src/filesync.ts`, lab: `scripts/files-lab.sh`). One arbiter serves several clusters (one key per cluster, separate state, `arbiter add-key`). N servers in a star: one origin, a copy on each other server; on failure exactly one copy takes over and the others step aside until rebuilt after failback (lab: `scripts/star-lab.sh`). When the origin is gone for good, the other copies follow the server that took over (`--from-copy-of`), which can then fail over again (`scripts/star-lab.sh gone`).
12. Automatic scaling on enabled machines ("helpers"), in phases: 1 measure, 2 scale to zero (postponed: the origin always keeps one copy, only helpers go to zero), 3 pool of own machines with manual scaling, 4 automatic decider, 5 less trusted machines (optional). Own implementation over SSH with a forced command + Docker, 0 MB idle on helpers; no Nomad/k3s. Phase 1 ✅ (`src/scale.ts`, `src/loadtest.ts`, lab: `scripts/scale-lab.sh`): a oneshot timer measures CPU, memory, traffic and health-path response time per app (24 h, one point per minute), a rehearsal runs the rule and writes what it would do to a pt/en decision diary, and `scale test` measures one copy's capacity. Phase 3 ✅ (`src/pool.ts`, `src/poolproto.ts`, `src/worker.ts`, `src/pooljoin.ts`, lab: `scripts/pool-lab.sh`): helper PCs join with a one-time invite and an SSH key limited to one forced command from the origin's Tailscale IP; `scale <app> <n>` places copies (image by fingerprint, variables only in the helper's tmpfs), a Caddy balancer on the origin splits visits over Tailscale with health checks, and every deploy rolls the copies. Changed from the plan: the Tailscale tag is `tag:paasmcp-helper` and helpers get no auth key (a sleeping notebook must stay in the Tailnet); active-active apps and apps with their own compose are excluded for now. Open for phase 4: the automatic decider, and requests per second per app (the phase 3 balancer is in the path and can count them).

## 🗺️ Next Improvements Blueprint (For LLMs & Contributors)

Each item below is designed to preserve **0 MB Idle Daemon Overhead** while expanding PaaSMCP's capabilities:

### 1. Ephemeral Pull Request Preview Environments (`paas_app_preview`)
- **Goal:** Spin up temporary staging deployments (e.g., `https://pr-42-my-saas.example.com`) for a Git branch or PR and tear them down automatically when merged.
- **Implementation Spec:**
  - **Files:** `src/deployer.ts`, `src/database.ts`, `src/exposure.ts`, `src/mcp-server.ts`.
  - **Logic:** Given `appName` and `prNumber` / `branch`, create a derived slug `${appName}-pr-${prNumber}`, clone the target branch, optionally clone the schema/data of `db_${appName}` into `db_${appName}_pr_${prNumber}` (`CREATE DATABASE ... TEMPLATE`), allocate an ephemeral port (`4500–4899`), and expose via `exposeApplication` with a `ttlHours` metadata field in `AppRecord`.

### 2. ✅ Zero-Downtime Blue/Green Healthchecked Cutover (`deployApp` enhancement)
- **Done:** see item 10 in the roadmap above and "Blue/green cutover with healthcheck" in [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).

### 3. Serverless Scheduled Jobs / Cron Containers (`paas_job_schedule`)
- **Goal:** Run periodic scripts (scrapers, billing jobs, cleanup workers) inside Docker with full access to Vault secrets and `paasmcp-postgres`, consuming **0 MB of RAM** when not executing.
- **Implementation Spec:**
  - **Files:** `src/jobs.ts` (new), `src/mcp-server.ts`, `src/cli.ts`.
  - **Logic:** Build the repository image `paasmcp/job-${slug}:latest`, write `.env.runtime` (`0600`), and generate a native Linux `systemd` user timer (`~/.config/systemd/user/paasmcp-job-${slug}.timer` + `.service`) or `/etc/cron.d/` entry that runs `docker run --rm --network homelab-network --env-file .env.runtime paasmcp/job-${slug}:latest`.

### 4. Automated Off-Site Encrypted Backup Sync (Cloudflare R2 / S3) & Systemd Timer
- **Goal:** Automatically upload `.enc.bak` files from `/opt/homelab/paasmcp/backups/` to an S3-compatible bucket (Cloudflare R2, Backblaze B2, AWS S3) on a daily schedule.
- **Implementation Spec:**
  - **Files:** `src/database.ts`.
  - **Logic:** Read `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, and `S3_SECRET_ACCESS_KEY` from the `system` Vault. Use AWS Signature V4 (`node:crypto` native HMAC-SHA256 — zero heavy SDK dependencies) to `PUT` the already-encrypted `.enc.bak` file to R2/S3, and prune local backups older than `retentionDays`.

### 5. Automated PostgreSQL Streaming Replication over Tailscale (HA Phase 2)
- **Goal:** Upgrade `warm-standby` federation nodes to real-time PostgreSQL streaming replicas over a private Tailscale mesh (`100.x.y.z`).
- **Implementation Spec:**
  - **Files:** `src/federation.ts`, `src/database.ts`.
  - **Logic:** Configure a dedicated replication role (`paasmcp_replicator`) on the primary node's `paasmcp-postgres` bound to the host's Tailscale IP (`tailscale ip -4`), run `pg_basebackup` on the replica node during `paasmcp node join`, and add a `paas_node_failover` tool that executes `pg_ctl promote` on the replica if the primary is unreachable.
