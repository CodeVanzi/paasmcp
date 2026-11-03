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

### Primeira configuração e credenciais

As integrações externas são opcionais. Bootstrap, deploy de pastas locais, repositórios públicos, bancos locais e uso do painel não precisam de token Cloudflare ou GitHub. Guarde credenciais em **Cofre → escopo `system`**; segredos usados pelo código de uma aplicação ficam no escopo do slug dela. O painel mostra valores mascarados depois de salvar.

| Item | Quando é necessário | Como obter/configurar |
| --- | --- | --- |
| `DASHBOARD_TOKEN` | Entrar no painel | Gerado automaticamente. Consulte no host com `paasmcp dashboard token`; não é necessário criar token externo. |
| Chave SSH Ed25519 | Clonar repositórios privados por SSH ou usar chave de deploy | A chave é criada no bootstrap. Na aba Webhook, copie a chave pública e adicione em GitHub → repositório → Settings → Deploy keys. Mantenha acesso somente leitura. |
| `GITHUB_TOKEN` | Opcional: registrar a Deploy Key via API ou clonar repositório privado por HTTPS | Crie um fine-grained personal access token, restrito ao repositório necessário, com `Administration: read and write` para a API de Deploy Keys. Essa permissão é exigida pelo endpoint do GitHub mesmo quando a chave registrada é somente leitura. Se não quiser concedê-la, adicione a chave SSH manualmente e deixe o token vazio. [Criar token](https://github.com/settings/personal-access-tokens/new) · [Permissões do endpoint](https://docs.github.com/en/rest/deploy-keys/deploy-keys#create-a-deploy-key). |
| `CF_API_TOKEN` | Opcional: publicar via Cloudflare Tunnel/DNS; também cria política Access no modo Zero Trust | Crie token restrito à conta e zona usadas. Necessário: Account → Cloudflare Tunnel: Edit e Zone → DNS: Edit. Para Zero Trust, inclua Account → Access: Apps and Policies: Edit. [Criar token](https://dash.cloudflare.com/profile/api-tokens) · [Guia oficial de tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/). Salve-o no Cofre `system`. |
| Account ID, Tunnel ID e domínio base | Exposição via Cloudflare | Obtenha Account ID na área Overview da conta, Tunnel ID na lista de Tunnels e use um domínio cuja zona DNS esteja na Cloudflare. Configure por `paasmcp config --account-id ... --tunnel-id ... --domain ... --zero-trust-emails ...` ou MCP `paas_configure`. Para Zero Trust, informe os emails autorizados. |
| `WEBHOOK_SECRET` | Opcional: rebuild automático ao receber Push do GitHub | Gerado automaticamente pelo PaaSMCP. Na aba Webhook, copie a URL e revele/copiei o secret; no GitHub → Settings → Webhooks, crie webhook com Content type `application/json`, secret correspondente e evento `Push`. O endpoint precisa estar acessível pelo GitHub. |
| `CF_API_TOKEN` não necessário com Tailscale | Publicação privada via Tailnet | Instale e autentique Tailscale no host; use o modo Tailscale. Não requer DNS Cloudflare nem credencial adicional no PaaSMCP. |

**Fluxo recomendado:** (1) inicialize com `paasmcp init`; (2) recupere o token do painel; (3) para código privado, escolha Deploy Key SSH manual ou token GitHub restrito; (4) configure Cloudflare somente se for publicar por Tunnel; (5) faça deploy e adicione segredos próprios da aplicação no escopo do app; (6) confira Logs/Doctor e publique serviços com autenticação própria como públicos, reservando Zero Trust/Tailscale para interfaces administrativas.

Para o primeiro teste, use uma pasta local ou repositório público e um preset SPA; não configure tokens externos até que uma funcionalidade precise deles. PostgreSQL/Redis podem ser provisionados durante o deploy e as URLs são injetadas no escopo da aplicação.
