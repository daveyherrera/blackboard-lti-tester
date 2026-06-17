#!/usr/bin/env bash
set -euo pipefail
# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m' W='\033[1m' N='\033[0m'

echo -e "${W}╔══════════════════════════════╗${N}"
echo -e "${W}║   BB LTI 1.3 Tester          ║${N}"
echo -e "${W}╚══════════════════════════════╝${N}"
echo ""

# ── Preflight checks ──────────────────────────────
SKIP_NGROK=false

check_command() {
  if ! command -v "$1" &>/dev/null; then
    echo -e "${R}✗ $1 not found.${N} $2"; return 1
  fi
  echo -e "${G}✓${N} $1 found"; return 0
}

check_command python3 "Install from https://python.org" || exit 1
check_command ngrok "Install: brew install ngrok/ngrok/ngrok  OR  https://ngrok.com/download" || {
  echo -e "${Y}  Continuing without ngrok — local testing only${N}"
  SKIP_NGROK=true
}
echo ""

# ── Virtual environment ────────────────────────────
if [ ! -d "venv" ]; then
  echo -e "📦 Creating virtual environment..."
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

echo "📦 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${G}✓${N} Dependencies ready"
echo ""

# ── Kill any existing processes ───────────────────
lsof -ti:8080 2>/dev/null | xargs kill -9 2>/dev/null || true
pkill -f "ngrok http 8080" 2>/dev/null || true
sleep 1

# ── Start FastAPI ─────────────────────────────────
echo "🌐 Starting FastAPI server..."
uvicorn server:app --port 8080 --log-level warning &
SERVER_PID=$!

# Wait until server responds
for i in {1..20}; do
  if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
    echo -e "${G}✓${N} Server ready at http://localhost:8080"
    break
  fi
  sleep 0.5
done
echo ""

# ── Start ngrok ───────────────────────────────────
NGROK_URL=""
NGROK_PID=""
if [ "$SKIP_NGROK" = false ]; then
  echo "🔗 Starting ngrok tunnel..."
  ngrok http 8080 --log stdout > /tmp/bb-lti-ngrok.log 2>&1 &
  NGROK_PID=$!

  # Wait for ngrok API
  for i in {1..20}; do
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((t['public_url'] for t in d.get('tunnels',[]) if t['proto']=='https'),''))" 2>/dev/null || echo "")
    [ -n "$NGROK_URL" ] && break
    sleep 0.5
  done

  if [ -n "$NGROK_URL" ]; then
    echo -e "${G}✓${N} ngrok tunnel: $NGROK_URL"
  else
    echo -e "${Y}⚠ ngrok started but URL not detected. Check http://localhost:4040${N}"
  fi
fi

# ── Print registration info ───────────────────────
echo ""
echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
if [ -n "$NGROK_URL" ]; then
  echo -e "${W}Register these in the Blackboard Developer Portal:${N}"
  echo ""
  echo -e "  OIDC Login URL  ${G}$NGROK_URL/oidc-login${N}"
  echo -e "  Redirect URL    ${G}$NGROK_URL/redirect${N}"
  echo -e "  JWKS URL        ${G}$NGROK_URL/jwks${N}"
else
  echo -e "${Y}  ngrok not running — public URLs unavailable${N}"
  echo -e "  Local only: http://localhost:8080"
fi
echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""
echo -e "  Dashboard: ${W}https://daveyherrera.github.io/blackboard-lti-tester/${N}"
echo -e "  Local UI:  ${W}http://localhost:8080/${N}"
echo ""
echo -e "  Press ${W}Ctrl+C${N} to stop all services"
echo ""

# Open browser
sleep 1
open "https://daveyherrera.github.io/blackboard-lti-tester/" 2>/dev/null \
  || xdg-open "https://daveyherrera.github.io/blackboard-lti-tester/" 2>/dev/null || true

# ── Graceful shutdown ─────────────────────────────
cleanup() {
  echo -e "\n🛑 Shutting down..."
  kill "$SERVER_PID" 2>/dev/null || true
  if [ "$SKIP_NGROK" = false ] && [ -n "$NGROK_PID" ]; then
    kill "$NGROK_PID" 2>/dev/null || true
  fi
  echo -e "${G}✓${N} All services stopped"
  exit 0
}
trap cleanup INT TERM

wait "$SERVER_PID"
