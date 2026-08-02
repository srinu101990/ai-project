#!/usr/bin/env bash
# Start Aegis Intel fully offline (API + built dashboard on one port).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ ! -d backend/.venv ]]; then
  echo "Creating Python virtual environment..."
  python3 -m venv backend/.venv
fi

# shellcheck disable=SC1091
source backend/.venv/bin/activate

if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  echo "Installing Python dependencies (needs internet the first time only)..."
  python -m pip install --upgrade pip
  python -m pip install -r backend/requirements.txt
fi

if [[ ! -d frontend/dist ]]; then
  if [[ ! -d frontend/node_modules ]]; then
    echo "Installing frontend dependencies (needs internet the first time only)..."
    (cd frontend && npm install)
  fi
  echo "Building frontend for offline use..."
  (cd frontend && npm run build)
fi

echo ""
echo "Aegis Intel offline mode"
echo "  Dashboard : http://127.0.0.1:8000"
echo "  API docs  : http://127.0.0.1:8000/docs"
echo "  No internet required while running."
echo ""

cd backend
exec python run.py --host 127.0.0.1 --port 8000
