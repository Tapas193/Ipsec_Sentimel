#!/usr/bin/env bash
# IPsec Sentinel — verify Phase 1 foundations are live.
#
#   ./scripts/verify.sh          # assumes backend on :8000
#   BACKEND_URL=http://... ./scripts/verify.sh
set -euo pipefail

BASE="${BACKEND_URL:-http://localhost:8000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="${ROOT}/.venv/bin/python"

echo "==> Platform"
echo "  host arch : $(uname -m) ($(uname -s))"
echo "  python    : $("${VENV_PY}" -c 'import platform; print(platform.machine(), "-", platform.python_version())' 2>/dev/null || python3 -c 'import platform; print(platform.machine(), "-", platform.python_version())')"
echo

echo "==> GET ${BASE}/api/v1/health"
curl -sf "${BASE}/api/v1/health" | python3 -m json.tool

echo
echo "==> GET ${BASE}/api/v1/stats/dashboard"
curl -sf "${BASE}/api/v1/stats/dashboard" | python3 -m json.tool

echo
echo "==> OpenAPI schema reachable:"
curl -fsS -o /dev/null -w "  ${BASE}/openapi.json -> HTTP %{http_code}\n" "${BASE}/openapi.json"