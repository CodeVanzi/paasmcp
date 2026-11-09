#!/usr/bin/env bash
set -euo pipefail

echo "🚀 Installing PaaSMCP — Agent-First Micro-PaaS & MCP Server..."

# 1. Check required dependencies
for cmd in git node npm docker; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "❌ Error: '$cmd' is not installed. Please install Docker, Node.js (>=20), and Git first."
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PAAS_ROOT="${PAASMCP_ROOT:-/opt/homelab}"

echo "📦 Ensuring storage root at $PAAS_ROOT..."
if [ ! -d "$PAAS_ROOT" ]; then
  sudo mkdir -p "$PAAS_ROOT"
  sudo chown -R "$USER:$USER" "$PAAS_ROOT"
fi

echo "🔨 Installing npm dependencies and building TypeScript..."
cd "$PROJECT_ROOT"
npm install
npm run build
chmod +x dist/cli.js dist/mcp-server.js

mkdir -p "$HOME/.local/bin"
ln -sf "$PROJECT_ROOT/dist/cli.js" "$HOME/.local/bin/paasmcp"
ln -sf "$PROJECT_ROOT/dist/mcp-server.js" "$HOME/.local/bin/paasmcp-mcp"

# Also link into /usr/local/bin so 'sudo paasmcp' and system-wide PATH find it
if [ -w /usr/local/bin ]; then
  ln -sf "$PROJECT_ROOT/dist/cli.js" /usr/local/bin/paasmcp
  ln -sf "$PROJECT_ROOT/dist/mcp-server.js" /usr/local/bin/paasmcp-mcp
elif command -v sudo >/dev/null 2>&1; then
  sudo ln -sf "$PROJECT_ROOT/dist/cli.js" /usr/local/bin/paasmcp 2>/dev/null || true
  sudo ln -sf "$PROJECT_ROOT/dist/mcp-server.js" /usr/local/bin/paasmcp-mcp 2>/dev/null || true
fi

echo "🔐 Initializing PaaSMCP state, AES-256-GCM Master Key & SSH Deploy Key..."
node "$PROJECT_ROOT/dist/cli.js" init

echo ""
echo "✅ PaaSMCP installed successfully!"
echo "   CLI binary: $HOME/.local/bin/paasmcp (and /usr/local/bin/paasmcp)"
echo "   MCP binary: $HOME/.local/bin/paasmcp-mcp"
echo ""
echo "🔌 Add this to your MCP Client configuration:"
cat <<EOF
{
  "mcpServers": {
    "paasmcp": {
      "command": "node",
      "args": ["$PROJECT_ROOT/dist/mcp-server.js"]
    }
  }
}
EOF
