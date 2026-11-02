# AGENTS.md — AI Agent Instructions for PaaSMCP

## Project Overview
**PaaSMCP** is an Agent-First Micro-PaaS & Model Context Protocol (MCP) Server written in TypeScript (Node.js ESM).

## Codebase Structure
- `src/config.ts`: State management (`/opt/homelab/paasmcp/state.json`), port allocator (`4000-4999`), slug sanitization, and platform config.
- `src/vault.ts`: AES-256-GCM encryption/decryption for per-app and `system` secrets.
- `src/database.ts`: Shared PostgreSQL 16 and Redis 7 cluster provisioning, isolated SQL user/database creation, and automatic Vault secret injection.
- `src/github.ts`: SSH Ed25519 deploy key generation, GitHub API deploy key registration, git clone/pull, and Zero-Config Dockerfile generator.
- `src/deployer.ts`: Docker Compose generation, image build, container lifecycle management, and Homepage dashboard YAML synchronization.
- `src/exposure.ts`: Cloudflare Tunnel ingress API, Cloudflare DNS CNAME management, Cloudflare Zero Trust Access policy creation, and Tailscale Serve integration.
- `src/mcp-server.ts`: Stdio MCP Server exposing the `paas_*` tools.
- `src/cli.ts`: Command-line interface (`paasmcp`).
- `src/test.ts`: Node.js native test runner suite (`node --test`).

## Rules for Agents Modifying PaaSMCP
1. **Never hardcode personal domains, Cloudflare IDs, or email addresses** in `src/`. All server-specific configuration must live in `/opt/homelab/paasmcp/state.json`.
2. **Always run `npm run build && npm test`** after modifying any TypeScript file in `src/`.
3. **Preserve secret masking:** Never return plaintext secret values from MCP tools.
