# AGENTS.md — AI Agent Instructions for PaaSMCP

## Project Overview
**PaaSMCP** is an Agent-First & Security-First Micro-PaaS & Model Context Protocol (MCP) Server written in TypeScript (Node.js ESM).

## Codebase Structure
- `src/guard.ts`: Risk policy (free / confirm / strong / forbidden), approval requests for agents, audit log.
- `src/config.ts`: State management (atomic writes + `withStateLock` across MCP, CLI and dashboard) (`/opt/homelab/paasmcp/state.json`), port allocator (`4000-4998`, `4099` for dashboard), slug sanitization, and strict security validators (`validateEnvKey`, `validateBranchName`, `validateResourceLimit`).
- `src/vault.ts`: AES-256-GCM encryption/decryption for per-app and `system` JSON secrets, binary AES-256-GCM (`PMCP` wire format) for database backups & sync bundles, and constant-time `timingSafeCompare`.
- `src/database.ts`: Shared PostgreSQL 16 and Redis 7 cluster provisioning, isolated SQL user/database creation, Vault secret injection, and encrypted `pg_dump` / Redis backup & zero-plaintext-disk restore (`paas_db_backup`).
- `src/mirror.ts`: two-server mirror. `offerMirror` (replication role, slot, pg_hba for the peer, Tailscale bind, backups bucket, token encrypted with the federation cluster key), `acceptMirror` (pg_basebackup + read-only streaming container `paasmcp-mirror-<peer>`), `mirrorStatus`, `promoteMirror` (guard `mirror.promote`, strong; epoch++, DATABASE_URL to the copy, redeploy, re-expose).
- `src/arbiter.ts`: arbiter server/client for automatic failover (`arbiterDecide` is the pure rule set: claim only when the owner looks dead to the arbiter too, epochs only go up, only the owner hands back). Key derived from the cluster key.
- `src/updater.ts`: pinned images (`PINNED`, `imageFor` keeps an old install's image until updated), `checkUpdates` (Docker Hub tags, same major), `applyUpdate` (backup, mirror copies first, 60 s health check, rollback). Guard `update.apply` is confirm.
- `src/email.ts`: relay settings in the `system` vault, per-app SMTP/EMAIL variables (`paas_email_provision`), minimal SMTP client for `email test` (STARTTLS or 465; refuses AUTH without TLS).
- `src/storage.ts`: Garage (pinned image, admin API on loopback only), single-zone layout on first start, one bucket + key per app (`paas_storage_provision`), `S3_*` / `AWS_*` injected into the app vault.
- `src/backup.ts`: Docker volume backups, restore test (temporary database), native S3 SigV4 off-site sync/fetch (`BACKUP_S3_*` in the `system` vault), pruning that only removes local copies already off-site, nightly run and systemd timer.
- `src/github.ts`: SSH Ed25519 deploy key generation + SHA256 fingerprint, GitHub API deploy key registration, git clone/pull, Zero-Config Dockerfile generator, and multi-service `docker-compose.yml` detector.
- `src/deployer.ts`: Docker Compose generation, untrusted `docker-compose.yml` security sanitization (`generateSanitizedComposeFromRepo`), CPU/RAM resource limits, `:previous` image tagging for 1-second rollback, live `docker stats` metrics (`getContainerMetrics`), and `paas_doctor` diagnostics (`runPaaSDoctor`).
- `src/federation.ts`: GitHub Push Webhook HMAC-SHA256 verification (`verifyGitHubWebhookSignature`, `handleGitHubPushWebhook`) and Multi-Server HA Handshake & Encrypted State/Vault Synchronization (`paasmcp-join://` tokens).
- `src/exposure.ts`: Cloudflare Tunnel ingress API, Cloudflare DNS CNAME management, Cloudflare Zero Trust Access policy creation, and Tailscale Serve integration.
- `src/dashboard.ts`: Modern Web Workspace Control Plane (`127.0.0.1:4099`) with CSP/security headers, login rate-limiting, XSS escaping, PT-BR/EN i18n, Dark/Light themes, and Webhook/Federation HTTP endpoints.
- `src/mcp-server.ts`: `createMcpServer(level)` with all 16 `paas_*` tools (stdio entry point runs with full level).
- `src/mcp-http.ts`: Stateless Streamable HTTP endpoint `/mcp` (bearer token, loopback/Tailscale only).
- `src/tokens.ts`: Personal MCP tokens (hashed, levels read/deploy/destroy).
- `src/totp.ts`: RFC 6238 TOTP for the dashboard second factor.
- `src/cli.ts`: Command-line interface (`paasmcp`).
- `src/test.ts`: Node.js native security & unit test runner suite (`node --test`).

## Rules for Agents Modifying PaaSMCP
1. **Never hardcode personal domains, Cloudflare IDs, email addresses, or proprietary names** in `src/` or `docs/`. All server-specific configuration must live in `/opt/homelab/paasmcp/state.json` or encrypted `.enc.json` files.
2. **Enforce strict security boundaries:**
   - Never pass unsanitized strings to a shell; always use `execFileSync` with argument arrays.
   - Always use `timingSafeCompare` when comparing tokens or HMAC signatures.
   - Never bind application or database ports to `0.0.0.0` on the host (`127.0.0.1` only).
   - Never return plaintext secret values from MCP tools or API endpoints.
   - Every risky action goes through `src/guard.ts`: classify it in `assessRisk`, call `authorizeAgent` from MCP tools and `authorizeHuman` from the dashboard/CLI. Agents must never be able to approve their own requests.
   - Prefer "allow with warning + confirmation" over removing a feature; forbid only what has no safe use.
3. **Always run `npm run build && npm test`** after modifying any TypeScript file in `src/`.
