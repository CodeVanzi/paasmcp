# Contributing to PaaSMCP

Thank you for your interest in contributing to **PaaSMCP**!

## Development Workflow

1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Build TypeScript:**
   ```bash
   npm run build
   ```
3. **Run the automated test suite:**
   ```bash
   npm test
   ```

## Security Guidelines

- **Never commit personal identifiers, tokens, domains, or keys.** All environment-specific configuration belongs in `/opt/homelab/paasmcp/state.json` or encrypted `.enc.json` vault files.
- **Loopback-first networking:** Any new database or service template must bind host ports to `127.0.0.1` by default, never `0.0.0.0`.
- **Mask secrets in all tool outputs:** Never return unmasked secret values in MCP tool responses or CLI stdout.

## Roadmap & Ideas for Contribution

- [ ] Webhook receiver container (`paasmcp-webhooks`) for automatic rebuilds on `git push`.
- [ ] Automated `pg_dump` snapshot scheduling and restore tool (`paas_db_backup` / `paas_db_restore`).
- [ ] Support for multi-service repositories (`docker-compose.yml` pass-through with Vault injection).
- [ ] Optional lightweight resource metrics per app (`docker stats` snapshot in `paas_system_status`).
