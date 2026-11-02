# AGENTS.md — AI Agent Instructions for PaaSMCP

## Project Overview
**PaaSMCP** is an Agent-First & Security-First Micro-PaaS & Model Context Protocol (MCP) Server written in TypeScript (Node.js ESM).

## Codebase Structure
- `src/config.ts`: State management (`/opt/homelab/paasmcp/state.json`), port allocator (`4000-4998`, `4099` for dashboard), slug sanitization, and strict security validators (`validateEnvKey`, `validateBranchName`, `validateResourceLimit`).
- `src/vault.ts`: AES-256-GCM encryption/decryption for per-app and `system` JSON secrets, binary AES-256-GCM (`PMCP` wire format) for database backups & sync bundles, and constant-time `timingSafeCompare`.
- `src/database.ts`: Shared PostgreSQL 16 and Redis 7 cluster provisioning, isolated SQL user/database creation, Vault secret injection, and encrypted `pg_dump` / Redis backup & zero-plaintext-disk restore (`paas_db_backup`).
- `src/github.ts`: SSH Ed25519 deploy key generation + SHA256 fingerprint, GitHub API deploy key registration, git clone/pull, Zero-Config Dockerfile generator, and multi-service `docker-compose.yml` detector.
- `src/deployer.ts`: Docker Compose generation, untrusted `docker-compose.yml` security sanitization (`generateSanitizedComposeFromRepo`), CPU/RAM resource limits, `:previous` image tagging for 1-second rollback, live `docker stats` metrics (`getContainerMetrics`), and `paas_doctor` diagnostics (`runPaaSDoctor`).
- `src/federation.ts`: GitHub Push Webhook HMAC-SHA256 verification (`verifyGitHubWebhookSignature`, `handleGitHubPushWebhook`) and Multi-Server HA Handshake & Encrypted State/Vault Synchronization (`paasmcp-join://` tokens).
- `src/exposure.ts`: Cloudflare Tunnel ingress API, Cloudflare DNS CNAME management, Cloudflare Zero Trust Access policy creation, and Tailscale Serve integration.
- `src/dashboard.ts`: Modern Web Workspace Control Plane (`127.0.0.1:4099`) with CSP/security headers, login rate-limiting, XSS escaping, PT-BR/EN i18n, Dark/Light themes, and Webhook/Federation HTTP endpoints.
- `src/mcp-server.ts`: Stdio MCP Server exposing all 15 `paas_*` tools.
- `src/cli.ts`: Command-line interface (`paasmcp`).
- `src/test.ts`: Node.js native security & unit test runner suite (`node --test`).

## Rules for Agents Modifying PaaSMCP
1. **Never hardcode personal domains, Cloudflare IDs, email addresses, or proprietary names** in `src/` or `docs/`. All server-specific configuration must live in `/opt/homelab/paasmcp/state.json` or encrypted `.enc.json` files.
2. **Enforce strict security boundaries:**
   - Never pass unsanitized strings to a shell; always use `execFileSync` with argument arrays.
   - Always use `timingSafeCompare` when comparing tokens or HMAC signatures.
   - Never bind application or database ports to `0.0.0.0` on the host (`127.0.0.1` only).
   - Never return plaintext secret values from MCP tools or API endpoints.
3. **Always run `npm run build && npm test`** after modifying any TypeScript file in `src/`.
