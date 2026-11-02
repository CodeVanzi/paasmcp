# 🇧🇷 PaaSMCP — Guia Completo em Português

O **PaaSMCP** é um Micro-PaaS open-source *"Agent-First & Security-First"* (feito sob medida para ser operado tanto por **Agentes de IA via MCP** quanto por **Humanos via Workspace Web e CLI**).

Ele transforma qualquer servidor Linux ou Homelab em uma plataforma de nuvem pessoal automatizada, com **0 MB de consumo ocioso de RAM**.

---

## 🎯 Tudo o que o PaaSMCP faz por você

1. **Inicialização Segura (`init` / `paas_bootstrap`):** Prepara `/opt/homelab/paasmcp` com permissão `0700`/`0600`, rede Docker isolada (`homelab-network`), chave mestra AES-256-GCM e par de chaves SSH `Ed25519`.
2. **Cofre Criptografado (`secret` / `paas_secret_*`):** Variáveis de ambiente são criptografadas em repouso com **AES-256-GCM** (IV aleatório por gravação + tag de autenticação). Valores nunca aparecem abertos nas respostas da IA (`sk_l****def`) e chaves inválidas são bloqueadas contra injeção.
3. **Bancos Multi-Tenant + Backups Criptografados (`db` / `db-backup`):**
   - Cria bancos e usuários exclusivos no **PostgreSQL 16** (`db_<app>` / `user_<app>`) ou **Redis 7** e injeta `DATABASE_URL` / `REDIS_URL` automaticamente no container.
   - Gera snapshots (`pg_dump` / Redis RDB) criptografados com a chave mestra do Vault (`.enc.bak`), verifica integridade `SHA-256` e restaura direto em memória sem nunca gravar dump em texto aberto no disco.
4. **Buildpacks Zero-Config + Multi-Service Docker Compose:**
   - Detecta automaticamente **Node.js, Next.js, Vite/React/Astro, Python (FastAPI/Flask/Django), Go, HTML Estático** ou `Dockerfile` próprio.
   - Suporta repositórios complexos com `docker-compose.yml`: o PaaSMCP audita e sanitiza o arquivo (removendo `privileged: true`, `network_mode: host` e volumes inseguros do host), injeta o `.env.runtime` do Cofre em todos os serviços e expõe apenas o container web em `127.0.0.1:<porta>`.
5. **Rollback em 1 Segundo & Diagnóstico `paas_doctor`:**
   - Antes de cada deploy, a imagem funcional anterior é salva como `paasmcp/<app>:previous`. Se o novo deploy apresentar problema, `paasmcp rollback <app>` reverte em 1 segundo sem precisar recompilar.
   - O `paas_doctor` inspeciona containers parados, mortes por falta de memória (`OOMKilled`), contadores de crash e métricas em tempo real (`docker stats`).
6. **Auto-Deploy via GitHub Webhook (`HMAC-SHA256`):**
   - Endpoint integrado `/api/webhooks/github` que valida a assinatura `X-Hub-Signature-256` em tempo constante (`timingSafeEqual`) e reconstrói automaticamente o app quando você dá `git push` na branch configurada.
7. **Handshake Multi-Servidor & Redundância (`node` / `paas_node_federation`):**
   - Pareie um segundo servidor (ex: uma VPS barata + seu Homelab) usando um token assinado `paasmcp-join://` com expiração de 15 minutos.
   - Opera em **Active-Active via Cloudflare Tunnel** (dois servidores rodando o mesmo túnel com failover automático na borda da Cloudflare se cair a energia/internet de um deles) ou **Warm Standby** (sincronização criptografada de Cofre e estado).

---

## 🖥️ Workspace Web para Humanos

Suba o painel web interativo com suporte a temas **Dark / Light** e idiomas **PT-BR / EN**:

```bash
# Iniciar em 127.0.0.1:4099 e expor em https://paas.seudominio.com protegido por Zero Trust:
paasmcp dashboard start --expose zero-trust --subdomain paas

# Consultar seu token administrativo:
paasmcp dashboard token
```

A interface é dividida em 6 abas rápidas na barra lateral:
- **📦 Aplicações & Deploy:** Tabela com CPU/RAM ao vivo, botões de Rollback em 1s, Logs, Restart, presets de deploy e limites de memória/CPU.
- **🔐 Cofre AES-256-GCM:** Gerenciamento visual de segredos por escopo (`system` ou por aplicação).
- **🗄️ Bancos & Backups:** Provisionamento 1-click de PostgreSQL/Redis e criação/restauração de snapshots `.enc.bak`.
- **🌐 Multi-Server HA & Webhook:** Gerador de Join Token `paasmcp-join://`, exportação de bundle criptografado e URL/Secret do Webhook do GitHub.
- **🩺 Doctor & Diagnóstico:** Inspeção de saúde dos containers e alertas de `OOMKilled`.
- **🤖 Studio IA (MCP) & Guia:** Configuração pronta para copiar em clientes MCP e explicação visual da arquitetura de segurança.
