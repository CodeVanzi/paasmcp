# 🚀 PaaSMCP — Agent-First Micro-PaaS & MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js >= 20](https://img.shields.io/badge/Node.js-%3E%3D20.0.0-brightgreen)](https://nodejs.org)
[![MCP Compatible](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple)](https://modelcontextprotocol.io)

> **Turn any Linux server or Homelab into a modern automated Cloud PaaS operated directly by AI Agents via MCP (Model Context Protocol) or Humans via a sleek Web Control Plane — with zero idle RAM overhead.**  
> 🇧🇷 **[Leia a Documentação Completa em Português aqui (docs/PT-BR.md)](./docs/PT-BR.md)**

---

## 💡 Why PaaSMCP?

Traditional self-hosted PaaS dashboards are great for manual clicking, but they:
1. Consume **300MB–1GB+ of RAM** continuously just to run their control plane daemons and internal queues.
2. Require manual multi-step setup for SSH deploy keys, database bindings, and Cloudflare Tunnel / Zero Trust rules.
3. Were **not designed from day one to be operated by AI Agents via MCP**.

**PaaSMCP** takes a radically lightweight, **Agent-First & Security-First** approach:
- **0 MB Idle Daemon Overhead:** Runs on-demand via MCP stdio or CLI, orchestrating native Docker Compose stacks directly on your host. (The optional web dashboard and GitHub webhook receiver are a small always-on service.)
- **Human-in-the-loop for risky actions:** Agents run safe actions freely; destroying, purging, restoring, deleting secrets, public exposure, trusted apps and federation changes wait for a person to approve them in the dashboard or with `paasmcp approve <id>`. Destroyed apps go to a 30-day trash. See [Security model](#-security-model).
- **AES-256-GCM Encrypted Secrets & Backups Vault:** Secrets (`/opt/homelab/paasmcp/vault/<app>.enc.json`) and database snapshots (`/opt/homelab/paasmcp/backups/<id>.enc.bak`) are encrypted at rest with a `0600` master key. Values are masked in MCP outputs (`sk_l****def`) and can be ingested directly from files so sensitive keys never pass through LLM chat histories.
- **Instant Multi-Tenant Databases + Encrypted Snapshots:** Provision isolated PostgreSQL 16 databases (`db_<app>` + `user_<app>`) or Redis 7 logical instances in 1 second, automatically injecting `DATABASE_URL` and `REDIS_URL`, with 1-click encrypted `pg_dump` backup & zero-plaintext-disk restore.
- **Zero-Config Buildpacks + Multi-Service Docker Compose Pass-Through:** Automatically builds repositories with a custom `Dockerfile`, sanitized multi-service `docker-compose.yml` (stripping unsafe `privileged`/`host` flags and injecting Vault secrets), or generates optimized multi-stage Dockerfiles for **Node.js, Next.js, Vite/React/Astro SPAs, Python (FastAPI/Flask/Django), Go, and Static HTML**.
- **Zero-Downtime Blue/Green Deploys:** Each new version first runs as a candidate container on a free loopback port and must answer an HTTP healthcheck (`healthcheckPath`, default `/`, status < 500, 20 s) before it replaces the running one. If it crashes or keeps failing, the running version is left untouched and the deploy returns the candidate's logs to the agent. During the swap the candidate also answers for the app's container name, so Cloudflare Tunnel traffic keeps reaching a healthy copy while production is recreated (`scripts/bluegreen-lab.sh`).
- **1-Second Image Rollback & `paas_doctor` Diagnostics:** Automatically tags the previous working image (`paasmcp/<app>:previous`) before every deploy for instant 1-second rollback, and inspects containers for `OOMKilled`, crash-loops, and live CPU/RAM metrics (`docker stats`).
- **Two-Server Mirror:** Pair a second server (`paasmcp-join://`, `HMAC-SHA256` + SSH fingerprint), then `paasmcp mirror offer/accept`: each server keeps a live read-only copy of the other's Postgres (physical streaming over Tailscale, a replication slot keeps up to 10 GB of changes while the peer is away) and receives the other's backups in its Garage. `paas_mirror status` shows streaming / caught up / seconds behind; `promote` is a manual failover with a strong confirmation that raises an epoch number, redeploys the peer's apps and points their DNS here. Automatic failover needs an arbiter (`paasmcp arbiter install-service` on a small third device, which can serve several clusters with `arbiter add-key`; forbidden without one; the dashboard walks through it step by step and `paasmcp arbiter check` / its "Test" button shows whether the arbiter answers and hears both servers): `mirror watch` heartbeats, takes over only when both it and the arbiter lost the peer and the copy stopped streaming, and **fences** a server whose data moved (its apps stop, deploys are refused). Guided failback: `offer --from-copy-of`, `accept --rejoin` (old data moved aside, never deleted), `handback` (waits for zero lag), `promote`. One server can also send copies to several others (star): on failure exactly one copy takes over and the others step aside until rebuilt (`mirror retire` for a manual failover). The full outage → failover → failback cycle runs in `scripts/mirror-lab.sh` and, with three servers and a real arbiter, in `scripts/star-lab.sh` (real Postgres containers).
- **Active-active (app on both servers):** `paasmcp active on <app>` (confirmation) runs a mirrored app on both servers at once. Writes still go to the origin's Postgres; the peer reaches it, Redis and S3 over Tailscale, and builds the **exact commit** the origin runs, received through an encrypted manifest that travels inside the existing Postgres stream (no new port or daemon). Entry: `paasmcp active tunnel on` (a Cloudflare Tunnel just for those apps, run on both servers; a sick copy steps out of it by itself), or the self-hosted **edge** (`paasmcp edge install` / `edge add <app> <hostname>`): a Caddy with Let's Encrypt, round robin and health checks every 5 s, no cloud needed. Uploaded files in the app's S3 bucket are copied to the peer every minute with the same key, and come back on handback. Tested in `scripts/active-lab.sh` and `scripts/files-lab.sh`.
- **Measuring for automatic scaling (phase 1: measure and rehearse, never act):** `sudo paasmcp scale install-timer` runs a systemd oneshot timer every 15 s (nothing stays in memory between rounds). Each round reads every running app's CPU, memory and network traffic (`docker stats`) and times an answer of its health path, keeping the last 10 minutes at full detail and one point per minute for 24 hours under `paasmcp/scale/`. A **rehearsal** runs the scaling rule on those numbers (add a copy when CPU per copy stays above the target for 3 rounds, remove one after 10 minutes below half of it, 2 minutes between steps) and writes what it *would* do, with the reason, to a **decision diary** shown in Portuguese or English (`paasmcp scale diary`, `scale language pt|en`). `paasmcp scale test <app>` (confirmation) is a **capacity test**: it doubles parallel GET requests on the app's own loopback port until it chokes and says how many requests per second one copy handles and whether the app's CPU or the database gave out. Dashboard: 24 h charts, the rehearsal line, the rule and the diary on the Apps tab. Tested in `scripts/scale-lab.sh`.
- **Helper PCs (scale phase 3: your own machines, copies set by hand):** your other Linux PCs can run extra copies of an app. `paasmcp pool invite <name>` (confirmation) gives a one-use invite (15 min); on the PC, `sudo node dist/cli.js pool join '<invite>'` (no `init`, nothing left running) creates a `paasmcp-worker` user whose only SSH key is this server's, accepted **only from this server's Tailscale IP** and **only to run the worker** (`restrict`: no terminal, no forwarding); `paasmcp pool add <name> <ip>` checks the PC holds the invite (HMAC of a fresh nonce) and pins its host key. Then `paasmcp scale <app> 3` (confirmation the first time) runs this server's copy plus two on helpers: the image travels by `docker save | ssh | docker load` and is checked by fingerprint, the app's variables go with the order into a **tmpfs** folder on the PC (never its disk, never `docker inspect`), copies are published only on the PC's Tailscale IP and reach Postgres, Redis and S3 here. Visitors still enter only through this server: a small Caddy (`paasmcp-pool-lb`, only while an app uses helpers) splits the visits with health checks every 3 s, and Cloudflare Tunnel (or the edge) points at it. Copies follow deploys, rollbacks and restarts one at a time; `pool pause` drains a PC before its owner needs it; `scale off <app>` goes back to one copy; `pool remove` revokes the key on the PC. Only single-container apps with an HTTP health check that run only on this server qualify. `paasmcp pool acl` prints the Tailscale access rules that fence helpers in. Dashboard: a **Helpers** tab with the step-by-step guide and a copies selector on the Apps tab. Tested in `scripts/pool-lab.sh` (two Docker-in-Docker PCs: traffic split, a PC pulled from the network leaves the traffic within 10 s, no secret on a PC's disk, the key opens no terminal).
- **Built-in Workspace Web UI (`paasmcp-dashboard`):** Optional ultra-lightweight dark/light web workspace (protected by constant-time `DASHBOARD_TOKEN`, login rate-limiting, CSP headers, and Cloudflare Zero Trust Access) with built-in **GitHub Push Webhook (`X-Hub-Signature-256`)** auto-deploy receiver.

---

## 🏗️ Architecture

```mermaid
flowchart LR
    Agent["AI Agent (MCP Client)"] <-->|Stdio JSON-RPC| MCP["PaaSMCP MCP Server & CLI"]
    Human["Developer / Operator"] <-->|HTTPS + Zero Trust| Dash["PaaSMCP Workspace UI\n127.0.0.1:4099"]
    GitHub["GitHub Repositories"] -->|Push Webhook HMAC-SHA256| Dash
    
    subgraph Server1 ["Primary Linux Server / Homelab"]
        MCP --> Vault["AES-256-GCM Vault & Backups"]
        Dash --> MCP
        
        subgraph Docker ["Docker Engine (homelab-network)"]
            PG[("Shared PostgreSQL 16\n127.0.0.1:5432")]
            RD[("Shared Redis 7\n127.0.0.1:6379")]
            App1["App Container 1\n127.0.0.1:4000"]
            CF["cloudflared-tunnel"]
        end
    end

    subgraph Server2 ["Optional Replica Server (VPS / Node 2)"]
        Peer["PaaSMCP Replica Node"]
    end

    MCP <-->|Encrypted Sync Bundle\npaasmcp-join:// Handshake| Peer
    CF <-->|Multi-Connector QUIC Tunnel| Cloudflare["Cloudflare Edge + Zero Trust Access"]
    Peer <-->|Failover QUIC Tunnel| Cloudflare
```

---

## ⚡ Quick Installation

### Requirements
- Linux (Ubuntu/Debian/Fedora/Arch)
- Docker Engine & Docker Compose plugin (`docker compose`)
- Node.js `>= 20.0.0` & `git`

### 1-Command Setup
```bash
git clone <repository-url>
cd paasmcp
./scripts/install.sh
```

### Installing on a homelab that already runs other things

PaaSMCP lives next to your other services. After installing, run `paasmcp doctor` (or open **Diagnostics** in the dashboard): besides your apps, it checks the server around them and says what to fix. These are the usual traps:

- **DNS on the same machine.** If AdGuard Home or Pi-hole runs as a container on this server and the host uses only it, the host loses DNS whenever that container does not come back, and with it Cloudflare Tunnel, image pulls and deploys. Give the host a fallback: `FallbackDNS=1.1.1.1 9.9.9.9` in `/etc/systemd/resolved.conf`, with `/etc/resolv.conf` pointing to systemd-resolved.
- **Watchtower.** It restarts containers whenever their image changes upstream. Every container PaaSMCP creates carries `com.centurylinklabs.watchtower.enable=false`, because PaaSMCP pins and updates its own images. Containers created before this label existed get it on their next recreate; running Watchtower with `WATCHTOWER_LABEL_ENABLE=true` covers them right away. Pause Watchtower while you test active-active or scaling.
- **Docker networks.** Docker hands out 172.17-172.31 first, then 192.168.x.0/20, which can cover a home LAN like 192.168.31.0/24. Set `"default-address-pools": [{"base": "10.200.0.0/16", "size": 24}]` in `/etc/docker/daemon.json` before you get there.
- **Ports.** Apps get loopback ports 4000-4998, skipping 4097 (arbiter), 4099 (dashboard) and anything already listening. The self-hosted entry (`paasmcp edge on`) needs ports 80 and 443 free; with Nginx Proxy Manager or another proxy there, keep Cloudflare Tunnel or put the entry on another machine.
- **Your own Cloudflare Tunnel container.** PaaSMCP sends public addresses to apps by container name on the `homelab-network` Docker network, so the `cloudflared` container must be on it.
- **Wired network for servers.** Active-active and the arbiter judge a server by whether it answers; flaky Wi-Fi causes false alarms.

---

## 🛡️ Security Model

| Level | Actions |
| :--- | :--- |
| Free | status, logs, doctor, deploy, provision DBs, create backups, restart, rollback, expose via Tailscale or Zero Trust |
| Confirm | destroy (to 30-day trash), restore a backup (a safety backup is taken first), delete a secret (old value archived), public exposure, exposing the dashboard, federation join/import, inviting or removing a helper PC, the first copies of an app on helpers (and going above its scale rule's maximum) |
| Strong (type the name) | promote a mirror copy (failover), purge from trash, mark an app as trusted (keeps privileged / host network / host folders / docker.sock in its compose), publish the dashboard on the open internet (only with 2FA on) |
| Forbidden | plaintext secrets in outputs, dashboard on the open internet without 2FA, MCP over HTTP outside loopback/Tailscale, non-loopback ports, compose `extends` / `additional_contexts`, unsigned webhooks |

MCP tokens have levels: `read` (status, logs, diagnostics), `deploy` (default: also deploy, provision, back up, expose privately) and `destroy` (can *request* risky actions, which still need a person). Local stdio runs with full level because it already runs on the server.

MCP calls that need confirmation return `confirmationRequired` with an `approvalId`. A person approves it in the dashboard (Pending confirmations) or with `paasmcp approve <id>` on the server, then the agent repeats the call with `approvalId`. Requests expire in 10 minutes, are bound to the exact parameters and work once. Everything is logged to `audit.log`.

Limit: this protects against an agent acting **through MCP**. An agent with a shell on the server and access to Docker can bypass any rule (the `docker` group is root-equivalent); run such agents as a user without Docker access.

---

## 🔌 MCP Server Configuration (23 Tools)

### Remote clients (MCP over HTTP)

Any MCP client that supports Streamable HTTP with a bearer header (Claude Desktop/Code, Cursor, VS Code, Codex, local-model clients…) can connect from another machine on your Tailnet:

```bash
paasmcp token create laptop --level deploy        # shown once; only a hash is stored
paasmcp mcp serve --port 4098                      # listens on 127.0.0.1 (or --host tailscale)
paasmcp mcp install-service                       # same, as a systemd service on the Tailscale address (survives reboots)
tailscale serve --bg --https=8443 http://127.0.0.1:4098
```

```json
{
  "mcpServers": {
    "paasmcp": {
      "type": "http",
      "url": "https://<your-server>.ts.net:8443/mcp",
      "headers": { "Authorization": "Bearer pmcp_..." }
    }
  }
}
```

Web-only assistants (ChatGPT / Claude.ai connectors) need a public URL with an OAuth login; that is planned, and a bearer token alone on the open internet is refused on purpose. `sudo paasmcp mcp install-service` keeps it up as a systemd service (this is the one always-on part of remote MCP). The dashboard tab **Connect AI** creates tokens and shows the exact command or config for Claude Code, Codex, Cursor, VS Code and Gemini CLI.

### Two-factor login for the dashboard

```bash
paasmcp dashboard 2fa enable     # scan the otpauth link, type the first code to activate
```

With 2FA on, login needs token + code, the token alone (header or cookie) stops working, and the dashboard may be published on the open internet after a strong confirmation.

### Local client (stdio)

Add `paasmcp` to your MCP client configuration:

```json
{
  "mcpServers": {
    "paasmcp": {
      "command": "node",
      "args": ["/path/to/paasmcp/dist/mcp-server.js"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
| :--- | :--- |
| `paas_approvals` | Lists confirmation requests and their status. Agents can read them but never approve. |
| `paas_system_status` | Returns server hardware stats (CPU/RAM/Disk), live per-container CPU/RAM (`docker stats`), SSH deploy key, masked tokens, DBs, backups, and federation state. |
| `paas_bootstrap` | Initializes `/opt/homelab/paasmcp`, master encryption key, SSH deploy key, Docker network, and shared Postgres/Redis. |
| `paas_dashboard` | Starts the Web Workspace UI (`127.0.0.1:4099`) + GitHub Webhook receiver and optionally exposes it (`zero-trust`, `public`, or `tailscale`). |
| `paas_configure` | Configures Cloudflare `accountId`, `tunnelId`, `baseDomain`, `zeroTrustEmails`, and `tailscaleDomain`. |
| `paas_github_key` | Retrieves the SSH Ed25519 public deploy key + SHA256 fingerprint or auto-registers it on a GitHub repository via API. |
| `paas_secret_set` | Encrypts and stores secrets in AES-256-GCM Vault (from key-values, `.env`, or secret file path). |
| `paas_secret_list` | Lists secret keys for an app or `system` with masked values (`sk_l****def`). |
| `paas_secret_delete` | Deletes a secret key from the encrypted vault. |
| `paas_db_provision` | Creates an isolated PostgreSQL or Redis database and binds `DATABASE_URL` / `REDIS_URL` into the app's vault. |
| `paas_update` | `check` newer Postgres/Redis/Garage releases within the same major; `apply` (confirmation) backs up, switches (mirror copies first), health-checks and rolls back on failure. |
| `paas_email_provision` | Lets an app send email through the server's relay (Brevo, SES...): injects `SMTP_*`, `EMAIL_FROM`, `EMAIL_URL` (and `BREVO_API_KEY`), sender `<app>@<domain>`. |
| `paas_storage_provision` | Gives an app its own S3 bucket and key on this server (Garage, started on first use) and injects `S3_*` / `AWS_*` into its vault. |
| `paas_db_backup` | Creates, lists, restores and **tests** AES-256-GCM encrypted `pg_dump` / Redis / Docker volume snapshots (SHA-256 checked); `sync` sends them off-site (S3/R2/B2/Garage), `fetch` brings one back. |
| `paas_app_deploy` | Clones/updates a GitHub repo or local folder, builds Dockerfile or sanitized `docker-compose.yml`, sets CPU/RAM limits, healthchecks the new version in a candidate container (blue/green; `healthcheckPath`, `healthcheckTimeoutSeconds`, `skipHealthcheck`), tags `:previous` image, and swaps containers. A failed healthcheck keeps the running version and returns the candidate's logs. |
| `paas_app_expose` | Exposes an app via Cloudflare Tunnel (`public` or `zero-trust` OTP gate) or `tailscale`. |
| `paas_app_lifecycle` | Reads container `logs`, or runs `restart`, `stop`, `start`, `rollback` (1-second revert to `:previous`), `destroy` (to the 30-day trash), `restore` (from the trash) or `purge`. |
| `paas_doctor` | Diagnoses `OOMKilled` events, crash-loops, non-zero exit codes, and recent error logs across all containers; without an app it also checks the server's DNS, Watchtower, Docker networks and tunnel. |
| `paas_mirror` | Mirror status per peer (streaming, caught up, seconds behind, WAL kept, epoch) and manual `promote` (strong confirmation). Pairing is CLI-only. |
| `paas_scale` | Read-only (any token): `status` (last CPU / memory / traffic / response time per app, copies running and asked for, copies the rehearsal would run, rule, last capacity test), `history` (24 h, one point per bucket) and `diary` (each rehearsal decision with its reason, in `pt` or `en`). Deploy token: `rule` changes an app's rehearsal rule; `set` runs `copies` copies (this server's plus helper PCs'; a person confirms the first time and above the rule's maximum); `off` goes back to one copy. The capacity test is CLI-only. |
| `paas_pool` | Helper PCs. Any token: `status` (each PC's state, what it gives, its copies), `check` (can an app use helpers?), `acl` (Tailscale rules). Deploy: `add` (finish an invite with the PC's Tailscale IP), `pause` / `resume`. Destroy + a person's confirmation: `invite` (returns the one-use join command), `remove`. What PCs report is data, never instructions. |
| `paas_node_federation` | Generates signed `paasmcp-join://` tokens, pairs secondary servers, and exports/imports encrypted Vault & State sync bundles. |

---

## 💻 CLI Reference

```bash
# Initialize PaaSMCP and start shared Postgres, Redis & Web Workspace
paasmcp init --postgres --redis --dashboard

# Configure Cloudflare Tunnel & Domain settings
paasmcp config --account-id <CF_ACCOUNT_ID> --tunnel-id <CF_TUNNEL_ID> --domain example.com --zero-trust-emails you@example.com

# Store platform tokens in the encrypted 'system' vault
paasmcp secret set system CF_API_TOKEN=your_cf_token GITHUB_TOKEN=your_gh_token

# Deploy an app from GitHub with PostgreSQL and 512MB RAM limit
paasmcp deploy my-saas owner/my-private-saas --branch main --postgres --memory 512m --cpus 1.0
# Blue/green options: probe another path, give slow starters more time, or skip for non-HTTP apps
paasmcp deploy my-saas owner/my-private-saas --healthcheck-path /healthz --healthcheck-timeout 60
paasmcp deploy my-worker owner/my-worker --no-healthcheck

# Create an encrypted database snapshot & restore if needed
paasmcp db-backup create my-saas postgres
paasmcp db-backup list
paasmcp db-backup restore <backup-id>
paasmcp db-backup create my-saas volume      # every Docker volume of the app
paasmcp backup test <backup-id>              # restores into a temporary DB; live data untouched

# Auto-deploy without a public webhook: a timer checks git every 2 min and exits (0 MB idle)
paasmcp poll enable my-saas
sudo paasmcp poll install-timer

# Keep shared services current (same major only; backup, health check, automatic rollback)
paasmcp update check
paasmcp update apply postgres

# Email through one relay (home IPs cannot deliver mail directly)
paasmcp email set --host smtp-relay.brevo.com --port 587 --user you@example.com --from-domain example.com
paasmcp email test you@example.com
paasmcp email provision my-saas --from-name "My SaaS"

# S3 bucket + key for an app on this server (Garage); redeploy to load S3_* / AWS_*
paasmcp storage provision my-saas

# Off-site copies (R2, B2, S3, Garage): set BACKUP_S3_ENDPOINT, BACKUP_S3_BUCKET,
# BACKUP_S3_ACCESS_KEY_ID, BACKUP_S3_SECRET_ACCESS_KEY (+ optional BACKUP_S3_REGION, BACKUP_S3_PREFIX)
# in the "system" vault scope, then:
sudo paasmcp backup install-timer --hour 3   # daily: DB + volume backups, upload, prune local copies older than 7 days (only if already off-site)
paasmcp backup export-key                    # store the master key OUTSIDE the server; off-site backups are useless without it
paasmcp backup fetch <backup-id>             # on a fresh server: bring a backup back, then restore it

# Measure every app for 24 h and rehearse scaling decisions (phase 1: it never starts or stops copies)
sudo paasmcp scale install-timer             # one round every 15 s, nothing running in between
paasmcp scale status                         # last numbers and how many copies the rehearsal would run
paasmcp scale diary my-saas --lang en        # why: each decision with its reason (pt or en)
paasmcp scale rule my-saas --max 4 --target-cpu 60
sudo paasmcp scale test my-saas --path /     # capacity test: requests/s one copy handles and what chokes

# Your own PCs as helpers (phase 3: you set the copies)
paasmcp pool invite notebook                 # one-use invite, 15 min (publishes Postgres/Redis/S3 on the Tailscale IP once)
sudo node dist/cli.js pool join '<invite>' --cpus 2 --memory 4g   # on the PC, in its PaaSMCP folder
paasmcp pool add notebook 100.x.y.z          # here, with the PC's Tailscale IP
paasmcp pool acl                             # Tailscale access rules that fence helpers in
paasmcp scale my-saas 3                      # this server's copy + 2 on helpers (scale off my-saas = back to one)
paasmcp pool status                          # each PC: available / working / paused / not answering
paasmcp pool pause notebook                  # its copies drain and move; pool resume notebook
paasmcp pool remove notebook                 # copies stop, this server's key is removed from the PC

# Run health diagnostics (apps, plus DNS, Watchtower, Docker networks and tunnel without an app) or 1-second rollback
paasmcp doctor
paasmcp rollback my-saas

# Approve what an AI agent asked for (people only)
paasmcp approvals
paasmcp approve c-7F3K2A

# Remote MCP clients and dashboard 2FA
paasmcp token create laptop --level deploy
paasmcp mcp serve --host tailscale
paasmcp dashboard 2fa enable

# Trash: destroy is reversible for 30 days
paasmcp destroy my-saas
paasmcp restore my-saas
paasmcp trash purge-expired   # run daily from cron

# Pair a secondary server (config & vault sync; data mirror in progress)
paasmcp node invite https://paas.example.com --mode active-active-tunnel
paasmcp node join paasmcp-join://...
```

---

## 📚 Additional Documentation

- 🇧🇷 **[Guia Completo em Português (`docs/PT-BR.md`)](./docs/PT-BR.md)**
- 🏛️ **[Technical Architecture, Security Model & Roadmap Specs (`docs/ARCHITECTURE.md`)](./docs/ARCHITECTURE.md)**
- 🤝 **[Contributing & Detailed Roadmap for Developers / LLMs (`CONTRIBUTING.md`)](./CONTRIBUTING.md)**
- 🤖 **[AI Agent Development Rules (`AGENTS.md`)](./AGENTS.md)**

---

## 📄 License

Released under the [MIT License](./LICENSE).
