#!/usr/bin/env bash
echo "Stopping BB LTI Tester..."
pkill -f "uvicorn server:app --port 8080" 2>/dev/null && echo "✓ Server stopped" || echo "  Server was not running"
pkill -f "ngrok http 8080" 2>/dev/null && echo "✓ ngrok stopped" || echo "  ngrok was not running"
