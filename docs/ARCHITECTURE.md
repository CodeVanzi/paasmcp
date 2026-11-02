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
│   └── backups/
│       └── <id>.enc.bak          # Binary AES-256-GCM encrypted pg_dump / Redis snapshots (mode 0600)
├── paasmcp-postgres/             # Shared PostgreSQL 16 cluster (127.0.0.1:5432)
├── paasmcp-redis/                # Shared Redis 7 cluster (127.0.0.1:6379)
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

---

## 4. Multi-Server High Availability (HA) Handshake & Federation (`src/federation.ts`)

PaaSMCP enables optional multi-server redundancy without the RAM overhead of Kubernetes or etcd:

1. **Cryptographic Pairing Handshake (`paasmcp-join://`):**
   - The primary node generates a `256-bit` `FEDERATION_CLUSTER_KEY` and issues an expiring (15-minute) Join Token signed with `HMAC-SHA256`, containing the primary node ID, endpoint URL, SSH key SHA-256 fingerprint, and redundancy mode.
2. **Redundancy Modes:**
   - **Mode A — `active-active-tunnel` (Stateless & Edge Failover):** Both the primary server (e.g. Homelab) and replica server (e.g. VPS) run the application containers and connect `cloudflared` to the same Cloudflare Tunnel ID. Cloudflare Edge automatically load-balances traffic and fails over in milliseconds if the primary server loses power or ISP connectivity.
   - **Mode B — `warm-standby` (Encrypted State & Vault Sync):** The primary node exports an AES-256-GCM encrypted + HMAC-signed sync bundle containing all app manifests and Vault scopes (`POST /api/federation/sync`), keeping the standby server ready for immediate promotion.
