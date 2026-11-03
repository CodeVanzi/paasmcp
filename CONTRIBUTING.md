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
4. S3 storage for apps (Garage): `paas_storage_provision` creates a bucket + key per app.
5. Federation as a mirror, part 1: per-app modes `mirror` / `stateless` / `local`; each server streams its Postgres to the other over Tailscale (item 5 below, both directions), Garage in two zones, hourly restic of volumes, replication lag in status, manual failover with confirmation, epoch number and DNS switch.
6. Mirror, part 2: optional arbiter (tiny VPS, Raspberry or Cloudflare Worker) for automatic failover; guided failback. Automatic failover without an arbiter stays forbidden.
7. Email: one relay (Brevo, SES…) configured once, per-app variables.
8. Updater: pinned versions for Postgres/Redis/Garage/cloudflared, `paas_update check|apply` with backup, health check and rollback (mirror replicas first).
9. Remaining promises: GitHub polling mode (0 MB idle auto-deploy) and per-language tests for generated Dockerfiles.

## 🗺️ Next Improvements Blueprint (For LLMs & Contributors)

Each item below is designed to preserve **0 MB Idle Daemon Overhead** while expanding PaaSMCP's capabilities:

### 1. Ephemeral Pull Request Preview Environments (`paas_app_preview`)
- **Goal:** Spin up temporary staging deployments (e.g., `https://pr-42-my-saas.example.com`) for a Git branch or PR and tear them down automatically when merged.
- **Implementation Spec:**
  - **Files:** `src/deployer.ts`, `src/database.ts`, `src/exposure.ts`, `src/mcp-server.ts`.
  - **Logic:** Given `appName` and `prNumber` / `branch`, create a derived slug `${appName}-pr-${prNumber}`, clone the target branch, optionally clone the schema/data of `db_${appName}` into `db_${appName}_pr_${prNumber}` (`CREATE DATABASE ... TEMPLATE`), allocate an ephemeral port (`4500–4899`), and expose via `exposeApplication` with a `ttlHours` metadata field in `AppRecord`.

### 2. Zero-Downtime Blue/Green Healthchecked Cutover (`deployApp` enhancement)
- **Goal:** Eliminate the 1–2 second container recreation gap during `paas_app_deploy` and automatically abort if the new container fails its HTTP healthcheck.
- **Implementation Spec:**
  - **Files:** `src/deployer.ts`, `src/exposure.ts`.
  - **Logic:**
    1. Start the newly built image in a transient candidate container `paasmcp-${slug}-candidate` on an ephemeral loopback port.
    2. Poll `http://127.0.0.1:${candidatePort}${healthcheckPath || "/"}` for up to 20 seconds.
    3. If healthy (`status < 500`), swap the production container and promote `candidate` to `paasmcp-${slug}:latest`.
    4. If unhealthy, capture the candidate's `stderr` logs, destroy the candidate container, leave the existing container untouched, and return the crash logs to the MCP agent.

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
