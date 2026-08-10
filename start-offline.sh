#!/usr/bin/env bash
# Start CYBER_SENTINEL.AI (API + built dashboard).
# Default: live network threat detection, reachable on the LAN.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

MODE="${COLLECTION_MODE:-network}"
HOST="${BIND_HOST:-0.0.0.0}"
PORT="${BIND_PORT:-8000}"

if [[ ! -d backend/.venv ]]; then
  echo "Creating Python virtual environment..."
  python3 -m venv backend/.venv
fi

# shellcheck disable=SC1091
source backend/.venv/bin/activate

if ! python -c "import fastapi, uvicorn, psutil" >/dev/null 2>&1; then
  echo "Installing Python dependencies (needs internet the first time only)..."
  python -m pip install --upgrade pip
  python -m pip install -r backend/requirements.txt
fi

if [[ ! -d frontend/dist ]]; then
  if [[ ! -d frontend/node_modules ]]; then
    echo "Installing frontend dependencies (needs internet the first time only)..."
    (cd frontend && npm install)
  fi
  echo "Building frontend..."
  (cd frontend && npm run build)
fi

# Discover a LAN IP for the operator message (bind may be 0.0.0.0).
LAN_IP="$(python - <<'PY'
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
    s.close()
except Exception:
    print("127.0.0.1")
PY
)"

echo ""
echo "CYBER_SENTINEL.AI — ${MODE} detection mode"
echo "  Local     : http://127.0.0.1:${PORT}"
echo "  LAN       : http://${LAN_IP}:${PORT}"
echo "  API docs  : http://${LAN_IP}:${PORT}/docs"
echo "  Collect   : live LAN host/port/connection scan (COLLECTION_MODE=${MODE})"
echo ""

cd backend
export COLLECTION_MODE="$MODE"
export BIND_HOST="$HOST"
export BIND_PORT="$PORT"
exec python run.py --host "$HOST" --port "$PORT"
