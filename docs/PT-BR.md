# 🇧🇷 PaaSMCP — Guia Completo em Português

O **PaaSMCP** é um Micro-PaaS open-source *"Agent-First"* (feito sob medida para ser operado por Agentes de IA via **Model Context Protocol - MCP** e linha de comando **CLI**).

Ele permite hospedar aplicações web, APIs e bancos de dados no seu próprio servidor Linux ou Homelab com a mesma praticidade do **Render**, **Railway** ou **Fly.io**, mas sem consumir memória RAM com painéis pesados em background.

---

## 🎯 O que o PaaSMCP resolve?

1. **Dependências & Inicialização (`init`):** Prepara diretórios seguros (`/opt/homelab/paasmcp`), rede Docker isolada (`homelab-network`), chave mestra de criptografia e chaves SSH de deploy em um único comando.
2. **Acesso Seguro ao GitHub (`github-key`):** Gera um par de chaves SSH `Ed25519` exclusivo para o servidor clonar repositórios privados (com opção de cadastrar a chave automaticamente no repositório via API do GitHub).
3. **Cofre de Variáveis de Ambiente (`secret`):** Todas as variáveis de ambiente e chaves de API são criptografadas em disco com **AES-256-GCM**. Os valores nunca aparecem abertos na listagem (`sk_l****def`) e podem ser importados de arquivos temporários para que suas senhas nunca fiquem salvas no histórico de chat da IA.
4. **Banco de Dados Instantâneo (`db`):** Sobe uma instância compartilhada de **PostgreSQL 16** e/ou **Redis 7** e, para cada nova aplicação, cria um banco e usuário isolados com senha aleatória forte, injetando a `DATABASE_URL` automaticamente no container da aplicação.
5. **Exposição Segura à Internet (`expose`):** Integra diretamente com a API do **Cloudflare Tunnel (`cloudflared`)** e **Cloudflare Zero Trust Access**, criando subdomínios HTTPS públicos ou protegidos por login OTP por e-mail sem abrir nenhuma porta no roteador. Também suporta exposição privada via **Tailscale Serve**.

---

## 🛠️ Instalação Passo a Passo (Em qualquer Servidor Linux)

### 1. Pré-requisitos
- Ubuntu 22.04 / 24.04 LTS, Debian 12+ ou similar
- **Docker** e **Docker Compose** instalados
- **Node.js 20+** e **Git**

### 2. Clonar e Instalar
```bash
git clone <repository-url>
cd paasmcp
./scripts/install.sh
```

O script `install.sh` irá:
- Instalar as dependências e compilar o TypeScript (`dist/`).
- Criar os atalhos globais `~/.local/bin/paasmcp` e `~/.local/bin/paasmcp-mcp`.
- Inicializar o cofre `/opt/homelab/paasmcp` com permissão `0600` e gerar a chave SSH de deploy.

---

## ⚙️ Configurando Cloudflare Tunnel e GitHub (Opcional, para Automação Total)

Para que o PaaSMCP crie subdomínios públicos e cadastre chaves no GitHub sozinho:

```bash
# 1. Configure os IDs do seu Cloudflare Tunnel e domínio principal
paasmcp config \
  --account-id SEU_ACCOUNT_ID \
  --tunnel-id SEU_TUNNEL_ID \
  --domain seudominio.com \
  --zero-trust-emails seuemail@gmail.com

# 2. Salve os tokens de API no cofre criptografado 'system'
paasmcp secret set system CF_API_TOKEN=seu_token_cloudflare GITHUB_TOKEN=seu_token_github
```

> **Permissões recomendadas para o `CF_API_TOKEN` na Cloudflare:**
> - `Account -> Cloudflare Tunnel -> Edit`
> - `Account -> Access: Apps and Policies -> Edit`
> - `Zone -> DNS -> Edit`

---

## 🤖 Exemplos de Prompts para usar com IA (via MCP)

Depois de conectar o `paasmcp-mcp` no seu agente (T3 Code, Claude Code, Cursor), você pode pedir em linguagem natural:

- *"Verifique o status do PaaSMCP e me mostre a chave SSH pública de deploy."*
- *"Crie um banco PostgreSQL para o app `financeiro` e faça o deploy do repositório `meu-usuario/financeiro-api`."*
- *"Adicione a variável `JWT_SECRET` no cofre do app `financeiro` e reinicie o container."*
- *"Exponha o app `financeiro` em `fin.seudominio.com` protegido por Zero Trust."*
- *"Mostre as últimas 100 linhas de log do app `financeiro`."*

---

## 🖥️ Painel Web Próprio (PaaSMCP Control Plane Dashboard)

O **PaaSMCP** inclui um painel web interativo próprio (modo escuro, super leve e protegido por token de sessão `HttpOnly` + suporte nativo ao **Cloudflare Zero Trust Access**) que pode ser hospedado em um subdomínio do próprio servidor:

```bash
# Subir o painel web localmente (127.0.0.1:4099) e já publicar em https://paas.seudominio.com protegido por Zero Trust:
paasmcp dashboard start --expose zero-trust --subdomain paas

# Consultar o token de login administrativo do painel:
paasmcp dashboard token
```

Pelo painel web você consegue:
- Visualizar CPU, RAM, Disco, status dos containers e copiar a Deploy Key SSH.
- Fazer novos deploys do GitHub marcando checkboxes para criar **PostgreSQL 16** e **Redis 7**.
- Ler logs em tempo real, reiniciar, parar ou excluir aplicações.
- Gerenciar variáveis criptografadas no **Cofre AES-256-GCM** sem expor os valores salvos.
- Publicar rotas de qualquer aplicação no Cloudflare Tunnel ou Tailscale.
