#!/bin/bash
set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}🔧 BB LTI Tester${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if ! command -v python3 &>/dev/null; then
  echo "❌ Python 3 not found. Please install Python 3.8+"; exit 1
fi

if ! command -v ngrok &>/dev/null; then
  echo -e "${YELLOW}⚠ ngrok not found.${NC}"
  echo "  Install: brew install ngrok/ngrok/ngrok"
  echo "  Or download from: https://ngrok.com/download"
  echo "  Then run: ngrok config add-authtoken <your-token>"
  echo ""
  echo "  Continuing without ngrok (local only)..."
  NGROK=false
else
  NGROK=true
fi

if [ ! -d "venv" ]; then
  echo "📦 Setting up virtual environment..."
  python3 -m venv venv
fi
source venv/bin/activate
pip install -q -r requirements.txt

lsof -ti:8080 | xargs kill -9 2>/dev/null || true

echo "🌐 Starting server on http://localhost:8080 ..."
uvicorn server:app --port 8080 --reload --log-level warning &
SERVER_PID=$!
sleep 2

if [ "$NGROK" = true ]; then
  pkill -f "ngrok http" 2>/dev/null || true
  sleep 1
  echo "🔗 Starting ngrok tunnel..."
  ngrok http 8080 --log=stdout > /tmp/ngrok.log 2>&1 &
  NGROK_PID=$!
  sleep 3

  NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tunnels = data.get('tunnels', [])
    https = next((t['public_url'] for t in tunnels if t['proto']=='https'), None)
    print(https or '')
except: print('')
" 2>/dev/null)
fi

echo ""
echo -e "${GREEN}✅ Ready!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Local:  ${BOLD}http://localhost:8080${NC}"
if [ -n "$NGROK_URL" ]; then
  echo -e "  Public: ${BOLD}$NGROK_URL${NC}"
  echo ""
  echo -e "${BOLD}Register these in the Blackboard Developer Portal:${NC}"
  echo -e "  OIDC Login URL: ${GREEN}$NGROK_URL/oidc-login${NC}"
  echo -e "  Redirect URL:   ${GREEN}$NGROK_URL/redirect${NC}"
  echo -e "  JWKS URL:       ${GREEN}$NGROK_URL/jwks${NC}"
else
  echo -e "  ${YELLOW}ngrok not running — public URLs not available${NC}"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Press Ctrl+C to stop"
echo ""

sleep 1
open "http://localhost:8080" 2>/dev/null || xdg-open "http://localhost:8080" 2>/dev/null || true

cleanup() {
  echo -e "\n🛑 Stopping..."
  kill $SERVER_PID 2>/dev/null || true
  [ "$NGROK" = true ] && kill $NGROK_PID 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

wait $SERVER_PID
