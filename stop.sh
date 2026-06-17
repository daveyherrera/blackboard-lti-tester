#!/bin/bash
pkill -f "uvicorn server:app" 2>/dev/null && echo "✅ Server stopped" || echo "Server was not running"
pkill -f "ngrok http" 2>/dev/null && echo "✅ ngrok stopped" || echo "ngrok was not running"
