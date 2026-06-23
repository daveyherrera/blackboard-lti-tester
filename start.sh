#!/usr/bin/env bash
set -euo pipefail
# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1m' N='\033[0m'

echo -e "${W}╔══════════════════════════════╗${N}"
echo -e "${W}║   BB LTI 1.3 Tester          ║${N}"
echo -e "${W}╚══════════════════════════════╝${N}"
echo ""

# ── Preflight checks ──────────────────────────────

check_command() {
  if ! command -v "$1" &>/dev/null; then
    echo -e "${R}✗ $1 not found.${N} $2"; return 1
  fi
  echo -e "${G}✓${N} $1 found"; return 0
}

check_command python3 "Install from https://python.org" || exit 1
check_command ngrok "Run: brew install ngrok/ngrok/ngrok  then: ngrok config add-authtoken <TOKEN>" || {
  echo ""
  echo -e "${R}ngrok is required — Blackboard needs a public HTTPS URL to send launches back to.${N}"
  echo -e "Without it the OIDC redirect will never reach this tool and no launches will appear."
  echo ""
  echo -e "  1. Sign up free at ${W}https://ngrok.com${N}"
  echo -e "  2. ${W}brew install ngrok/ngrok/ngrok${N}"
  echo -e "  3. ${W}ngrok config add-authtoken <YOUR_TOKEN>${N}"
  echo -e "  4. Run ${W}./start.sh${N} again"
  echo ""
  exit 1
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

# ── Load .env / .env.example if present ──────────
for envfile in .env .env.example; do
  if [ -f "$envfile" ]; then
    # shellcheck disable=SC1090
    set -a; source "$envfile"; set +a
    break
  fi
done

# ── Start ngrok ───────────────────────────────────
echo "🔗 Starting ngrok tunnel..."
NGROK_CMD="ngrok http 8080 --log stdout"
if [ -n "${NGROK_DOMAIN:-}" ]; then
  echo -e "  Using static domain: ${G}$NGROK_DOMAIN${N}"
  NGROK_CMD="ngrok http 8080 --domain=$NGROK_DOMAIN --log stdout"
fi
eval "$NGROK_CMD" > /tmp/bb-lti-ngrok.log 2>&1 &
NGROK_PID=$!

NGROK_URL=""
for i in {1..30}; do
  NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((t['public_url'] for t in d.get('tunnels',[]) if t['proto']=='https'),''))" 2>/dev/null || echo "")
  [ -n "$NGROK_URL" ] && break
  sleep 0.5
done

if [ -n "$NGROK_URL" ]; then
  echo -e "${G}✓${N} ngrok tunnel: $NGROK_URL"
else
  echo -e "${R}✗ ngrok tunnel did not start. ngrok output:${N}"
  echo ""
  tail -20 /tmp/bb-lti-ngrok.log 2>/dev/null || echo "  (no log output)"
  echo ""
  echo -e "  Open ${W}http://localhost:4040${N} for the ngrok dashboard."
  kill "$SERVER_PID" 2>/dev/null || true
  kill "$NGROK_PID" 2>/dev/null || true
  exit 1
fi

# ── Print registration info ───────────────────────
echo ""
echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo -e "${W}Register these URLs in the Blackboard Developer Portal:${N}"
echo ""
echo -e "  Login Initiation URL  ${G}$NGROK_URL/oidc-login${N}"
echo -e "  Tool Redirect URL(s)  ${G}$NGROK_URL/redirect${N}"
echo -e "  Tool JWKS URL         ${G}$NGROK_URL/jwks${N}"
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
  kill "$NGROK_PID" 2>/dev/null || true
  echo -e "${G}✓${N} All services stopped"
  exit 0
}
trap cleanup INT TERM

wait "$SERVER_PID"
