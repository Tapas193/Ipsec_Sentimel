#!/usr/bin/env bash
# IPsec Sentinel — bootstrap helper.
#
#   ./scripts/bootstrap.sh
#
# Installs backend (Python) and frontend (Node) dependencies and validates
# the toolchain. Safe to re-run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> [1/3] Backend: creating virtualenv + installing deps"
python3 -m venv "${ROOT}/.venv"
"${ROOT}/.venv/bin/pip" install -e "${ROOT}/backend[dev]"

echo "==> [2/3] Frontend: installing npm dependencies"
npm --prefix "${ROOT}/frontend" install

echo "==> [3/3] Toolchain summary"
echo "  Python : $("${ROOT}/.venv/bin/python" --version)"
echo "  Node   : $(node --version)"
echo "  npm    : $(npm --version)"

echo "==> Done. Copy .env.example to .env and run 'make dev'."