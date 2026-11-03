# 🇧🇷 PaaSMCP — Guia Completo em Português

O **PaaSMCP** é um Micro-PaaS open-source *"Agent-First & Security-First"* (feito sob medida para ser operado tanto por **Agentes de IA via MCP** quanto por **Humanos via Workspace Web e CLI**).

Ele transforma qualquer servidor Linux ou Homelab em uma plataforma de nuvem pessoal automatizada, com **0 MB de consumo ocioso de RAM** quando usado só pelo MCP e pela linha de comando. O painel web e o webhook do GitHub, se ligados, são um serviço sempre ativo (pequeno, mas não zero).

---

## 🎯 Tudo o que o PaaSMCP faz por você

1. **Inicialização Segura (`init` / `paas_bootstrap`):** Prepara `/opt/homelab/paasmcp` com permissão `0700`/`0600`, rede Docker isolada (`homelab-network`), chave mestra AES-256-GCM e par de chaves SSH `Ed25519`.
2. **Cofre Criptografado (`secret` / `paas_secret_*`):** Variáveis de ambiente são criptografadas em repouso com **AES-256-GCM** (IV aleatório por gravação + tag de autenticação). Valores nunca aparecem abertos nas respostas da IA (`sk_l****def`) e chaves inválidas são bloqueadas contra injeção.
3. **Bancos Multi-Tenant + Backups Criptografados (`db` / `db-backup`):**
   - Cria bancos e usuários exclusivos no **PostgreSQL 16** (`db_<app>` / `user_<app>`) ou **Redis 7** e injeta `DATABASE_URL` / `REDIS_URL` automaticamente no container.
   - Gera snapshots (`pg_dump` / Redis RDB / volumes Docker do app) criptografados com a chave mestra do Vault (`.enc.bak`), verifica integridade `SHA-256` e restaura direto em memória sem nunca gravar dump em texto aberto no disco.
   - `paasmcp backup test <id>` prova que o backup volta: carrega num banco temporário e apaga em seguida, sem tocar nos dados em uso.
   - Cópia fora do servidor (R2, B2, S3 ou Garage): coloque `BACKUP_S3_ENDPOINT`, `BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY_ID` e `BACKUP_S3_SECRET_ACCESS_KEY` no escopo `system` do Cofre e rode `sudo paasmcp backup install-timer`. Todo dia ele faz backup dos bancos e volumes, envia e apaga do disco local só o que tem mais de 7 dias **e já está fora**.
   - **Guarde a chave mestra fora do servidor** (`paasmcp backup export-key`, num gerenciador de senhas): sem ela os backups de fora não abrem. Num servidor novo, `paasmcp backup fetch <id>` traz um backup de volta.
3b. **Arquivos e imagens (`storage` / `paas_storage_provision`):** cada app ganha um bucket S3 próprio neste servidor, com chave só dele (Garage, que sobe na primeira vez). O PaaSMCP coloca `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_REGION` e os equivalentes `AWS_*` no Cofre do app; basta reimplantar. Por enquanto o endereço só é visível para os apps do servidor (links assinados para o navegador ainda não), e excluir o app de vez não apaga o bucket.
3c. **E-mail (`email` / `paas_email_provision`):** e-mail enviado direto de casa não chega (porta 25 bloqueada, IP residencial em listas de bloqueio), então os apps mandam por um relay (Brevo, SES, Mailgun...) configurado uma vez: `paasmcp email set --host smtp-relay.brevo.com --user <login> --from-domain <seu domínio>` (a senha é perguntada, nunca vai na linha de comando) e `paasmcp email test <seu e-mail>`. Depois, `paasmcp email provision <app>` coloca `SMTP_*`, `EMAIL_FROM`, `EMAIL_URL` (e `BREVO_API_KEY`, se houver chave da API) no Cofre do app, com remetente `<app>@<domínio>`. Atenção: por enquanto todos os apps usam a mesma chave do relay.
3e. **Deploy automático sem webhook (`poll`):** para servidores só no Tailscale, sem endereço público para o GitHub chamar. `paasmcp poll enable <app>` e `sudo paasmcp poll install-timer`: a cada 2 minutos um timer do systemd confere o último commit do branch (`git ls-remote`), reimplanta se mudou e encerra, sem nada ocupando memória entre as verificações. No MCP: `autoDeploy: "poll"` no `paas_app_deploy`.
3d. **Atualizações (`update` / `paas_update`):** Postgres, Redis e Garage rodam em versões fixas. `paasmcp update check` mostra versões novas dentro da mesma versão principal; `paasmcp update apply postgres` (pede confirmação) faz backup dos bancos, troca a imagem (as cópias do espelho primeiro), espera até 60 s o serviço responder e, se não responder, volta sozinho para a versão anterior. Trocar de versão principal (Postgres 16 → 17, Garage v1 → v2) é recusado, porque muda o formato dos dados. Com espelho, atualize primeiro o servidor que guarda a cópia.
4. **Buildpacks Zero-Config + Multi-Service Docker Compose:**
   - Detecta automaticamente **Node.js, Next.js, Vite/React/Astro, Python (FastAPI/Flask/Django), Go, HTML Estático** ou `Dockerfile` próprio.
   - Suporta repositórios complexos com `docker-compose.yml`: o PaaSMCP audita e sanitiza o arquivo (removendo `privileged: true`, `network_mode: host` e volumes inseguros do host), injeta o `.env.runtime` do Cofre em todos os serviços e expõe apenas o container web em `127.0.0.1:<porta>`.
5. **Deploy Blue/Green sem Queda:**
   - A nova versão sobe primeiro como container candidato numa porta loopback livre e precisa responder a um healthcheck HTTP (`healthcheckPath`, padrão `/`, status < 500, até 20 s) antes de substituir a que está no ar. Se ela cair ou continuar falhando, a versão atual segue intacta e o deploy devolve os logs do candidato ao agente. Durante a troca o candidato também responde pelo nome do container, então o tráfego do Cloudflare Tunnel continua chegando numa cópia saudável enquanto a produção é recriada (`scripts/bluegreen-lab.sh`). Apps que não falam HTTP usam `skipHealthcheck: true` (`--no-healthcheck` na CLI).
6. **Rollback em 1 Segundo & Diagnóstico `paas_doctor`:**
   - Antes de cada deploy, a imagem funcional anterior é salva como `paasmcp/<app>:previous`. Se o novo deploy apresentar problema, `paasmcp rollback <app>` reverte em 1 segundo sem precisar recompilar.
   - O `paas_doctor` inspeciona containers parados, mortes por falta de memória (`OOMKilled`), contadores de crash e métricas em tempo real (`docker stats`).
7. **Auto-Deploy via GitHub Webhook (`HMAC-SHA256`):**
   - Endpoint integrado `/api/webhooks/github` que valida a assinatura `X-Hub-Signature-256` em tempo constante (`timingSafeEqual`) e reconstrói automaticamente o app quando você dá `git push` na branch configurada.
8. **Dois servidores em espelho (`node`, `mirror` / `paas_mirror`):**
   - Parear: `paasmcp node invite` num servidor e `paasmcp node join` no outro (token assinado, expira em 15 minutos). A sincronização de configuração e Cofre nunca sobrescreve um app que já existe no servidor de destino, e troca a porta se houver conflito.
   - Espelhar: no servidor A, `paasmcp mirror offer B --peer-ip <IP do Tailscale de B>`; ele mostra um comando `paasmcp mirror accept ...` para rodar em B em até 1 hora. B passa a ter uma cópia viva, só de leitura, do Postgres de A, e os backups de B passam a ir para o Garage de A. Repita no sentido contrário para um ser o espelho do outro.
   - Se B ficar fora do ar, A guarda até 10 GB de alterações e B se atualiza sozinho quando volta. `paasmcp mirror status` mostra se está transmitindo, se está em dia e quantos segundos atrás.
   - Troca manual: se A cair, `paasmcp mirror promote A` em B (pede para digitar o nome). B assume os apps de A com a cópia, sobe o número de época, aponta o DNS para si. **Confirme que A caiu mesmo**: se os dois ficarem ligados, cada um aceitaria alterações.    - Troca automática: só com um **árbitro**, um terceiro aparelho pequeno (Raspberry, VPS) que dá o voto de desempate. Nele: `paasmcp arbiter serve --host <IP do Tailscale> --key <saída de 'paasmcp arbiter key'>`. Nos servidores: `paasmcp mirror auto on A --arbiter http://<árbitro>:4097` (pede para digitar o nome) e `sudo paasmcp mirror install-watch`. B só assume se ele **e** o árbitro perderam A por mais de um minuto **e** a cópia parou de receber. Sem árbitro, a troca automática é proibida (numa queda de rede, os dois assumiriam).
   - Cerca: quando A volta e o árbitro diz que B serve os dados dele, A para os próprios apps e recusa deploy até a volta guiada.
   - Volta guiada (A volta a ser o principal):
     1. Em B: `paasmcp mirror offer A --peer-ip <IP de A> --from-copy-of A`.
     2. Em A: `paasmcp mirror accept <token> --rejoin` (o banco antigo de A é movido para o lado, nunca apagado, e A vira cópia de B).
     3. Em B: `paasmcp mirror handback A` (para os apps de A em B e espera A ter tudo).
     4. Em A: `paasmcp mirror promote B`.
     5. Para B voltar a ser espelho: `mirror offer B ...` em A e `mirror accept` em B (a cópia velha é movida para o lado).
   - Testado com containers Postgres reais (`scripts/mirror-lab.sh`: cópia, queda do espelho, troca, volta completa); falta repetir em duas máquinas.
9. **Confirmações e lixeira (segurança sem cortar funções):** veja a seção abaixo.

---

## 🛡️ O que a IA faz sozinha, o que pede confirmação e o que é proibido

- **Livre:** status, logs, diagnóstico, deploy, criar banco e backup, reiniciar, voltar versão, expor app pelo Tailscale ou Zero Trust.
- **Pede confirmação de uma pessoa:** excluir app (vai para a **lixeira por 30 dias**, com banco e volumes), restaurar backup (sempre faz um backup do estado atual antes), apagar segredo (o valor antigo fica no arquivo de apagados do Cofre), expor app na internet aberta, expor o painel por Tailscale/Zero Trust, parear servidores e importar pacote de sincronização.
- **Confirmação forte (digitar o nome):** apagar de vez da lixeira (`purge`) e marcar um app como **confiável** (`--trusted`), o que mantém no `docker-compose.yml` modo privilegiado, rede do servidor, capabilities, dispositivos e pastas do servidor, inclusive `/var/run/docker.sock`.
- **Proibido:** devolver segredo em texto aberto; publicar o painel na internet aberta protegido só por token (use Zero Trust ou Tailscale); portas de app ou banco fora de `127.0.0.1`; `extends` e `additional_contexts` no compose; webhook sem assinatura.

Como a confirmação funciona com IA: a ferramenta MCP não executa e devolve um pedido (`approvalId`, ex. `c-7F3K2A`), que vale 10 minutos e só para aqueles parâmetros. Uma pessoa aprova no painel (cartão "Confirmações pendentes") ou no servidor com `paasmcp approve c-7F3K2A`; depois a IA repete a chamada com `approvalId`. Tudo fica registrado em `/opt/homelab/paasmcp/audit.log`.

Na linha de comando, a pergunta aparece na tela; `--yes` serve para scripts nas confirmações comuns e `--confirm-name <nome>` nas fortes. Para a lixeira expirar sozinha, agende `paasmcp trash purge-expired` uma vez por dia (cron ou timer do systemd).

### IA em outra máquina (MCP pela rede) e dois fatores no painel

```bash
paasmcp token create notebook --level deploy   # o token aparece uma vez; só o hash fica guardado
paasmcp mcp serve --port 4098                  # escuta em 127.0.0.1 (ou --host tailscale)
paasmcp mcp install-service                   # o mesmo, como serviço do systemd no endereço Tailscale (volta depois de reiniciar)
tailscale serve --bg --https=8443 http://127.0.0.1:4098
```

No cliente MCP (Claude Desktop/Code, Cursor, VS Code, Codex, clientes de modelos locais), use `https://<seu-servidor>.ts.net:8443/mcp` com o cabeçalho `Authorization: Bearer pmcp_...`. Níveis do token: `read` (só consultar), `deploy` (padrão: também implantar, criar banco, backup, expor por Tailscale/Zero Trust) e `destroy` (pode *pedir* ações arriscadas, que continuam precisando de uma pessoa). O MCP pela rede só escuta em `127.0.0.1` ou no endereço do Tailscale; ChatGPT e Claude.ai na web precisam de endereço público com login OAuth, que está planejado.

`paasmcp dashboard 2fa enable` liga o código de 6 dígitos no painel (Aegis, Google Authenticator, 1Password…). Com ele ligado, o token sozinho não entra mais, e o painel pode ir para a internet aberta com confirmação forte. Sem 2FA, isso continua proibido.

> Limite honesto: as confirmações protegem contra a IA agindo **pelo MCP**. Um agente que tem terminal no próprio servidor com acesso ao Docker (por exemplo um CLI de IA rodando lá) consegue contornar qualquer regra, porque o grupo `docker` equivale a root. Dê a esses agentes um usuário sem acesso ao Docker.

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
