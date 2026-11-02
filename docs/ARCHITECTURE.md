# 🏛️ PaaSMCP Technical Architecture

This document details the internal design and security model of **PaaSMCP**.

---

## 1. Directory & State Layout (`/opt/homelab`)

By default, PaaSMCP stores all runtime state under `PAASMCP_ROOT` (`/opt/homelab`):

```text
/opt/homelab/
├── paasmcp/
│   ├── .master.key               # 256-bit (32-byte) hex key (mode 0600)
│   ├── state.json                # Registered apps, ports, DBs, and tunnel metadata (mode 0600)
│   ├── ssh/
│   │   ├── paasmcp_deploy_ed25519      # Private SSH deploy key (mode 0600)
│   │   └── paasmcp_deploy_ed25519.pub  # Public SSH deploy key
│   └── vault/
│       ├── system.enc.json       # Encrypted platform tokens (CF_API_TOKEN, GITHUB_TOKEN, DB admin pass)
│       └── <app-slug>.enc.json   # Encrypted environment variables per application
├── paasmcp-postgres/             # Shared PostgreSQL 16 cluster (127.0.0.1:5432)
├── paasmcp-redis/                # Shared Redis 7 cluster (127.0.0.1:6379)
└── apps/
    └── <app-slug>/
        ├── repo/                 # Cloned Git repository + auto-generated Dockerfile.paasmcp
        ├── .env.runtime          # Decrypted runtime env file (mode 0600)
        └── compose.yaml          # Isolated Docker Compose stack bound to 127.0.0.1:<port>
```

---

## 2. Cryptographic Vault (`src/vault.ts`)

- **Cipher:** `aes-256-gcm` via Node.js native `node:crypto`.
- **Per-Write Random IV:** Every save generates a fresh 96-bit (12-byte) cryptographic IV and records the 16-byte GCM authentication tag (`authTag`).
- **Zero Plaintext Leak in MCP Responses:** `paas_secret_list` and `paas_secret_set` always mask secret values (`sk_l****def`) in JSON-RPC responses so secrets never pollute LLM context windows.
- **File-Based Secret Ingestion:** Supports reading a secret value directly from a temporary file (`secretFromFile`), enabling out-of-band secret prompts (such as T3 Code's `request_secret` with `delivery: "file"`).

---

## 3. Port Allocation & Network Isolation (`src/config.ts`, `src/deployer.ts`)

- **Loopback Binding Only:** Every deployed application binds strictly to `127.0.0.1:<allocatedPort>:<internalPort>` in the range `4000–4999`. No container port is ever exposed on `0.0.0.0`.
- **Internal Service Mesh (`homelab-network`):** Containers join the external Docker bridge network `homelab-network`, allowing:
  - `cloudflared-tunnel` to route traffic directly to `http://paasmcp-<app>:<internalPort>`.
  - Application containers to reach `paasmcp-postgres:5432` and `paasmcp-redis:6379` over the private Docker bridge without traversing the host LAN.

---

## 4. Zero-Config Buildpack Engine (`src/github.ts`)

When `paas_app_deploy` clones a repository:
1. If a `Dockerfile` is present in the repository root, it is used directly and its `EXPOSE` port is parsed.
2. Otherwise, PaaSMCP inspects project manifests and generates `Dockerfile.paasmcp`:
   - `package.json` with Vite/Astro/CRA and no `start` script → Multi-stage `node:22-alpine` builder + `nginx:alpine` static server.
   - `package.json` with Next.js or Node server → Production `node:22-alpine` image.
   - `requirements.txt` / `pyproject.toml` → `python:3.12-slim` with automatic detection for `uvicorn` (FastAPI), `gunicorn` (Flask/Django), or standard `main.py`.
   - `go.mod` → Multi-stage `golang:1.23-alpine` static binary build + `alpine:3.20`.
   - `index.html` → Lightweight `nginx:alpine` container.
