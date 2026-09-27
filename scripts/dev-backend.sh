#!/usr/bin/env bash
# IPsec Sentinel — start the backend against PostgreSQL (Docker or local).
#
#   DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/ipsec_sentinel \
#       ./scripts/dev-backend.sh
#
# Defaults to the local SQLite database for quick development.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DATABASE_URL="${DATABASE_URL:-sqlite:///./ipsec_sentinel.db}"

echo "==> Applying migrations against: ${DATABASE_URL}"
(cd "${ROOT}/backend" && "${ROOT}/.venv/bin/alembic" upgrade head)

echo "==> Starting API on http://localhost:8000 (docs at /docs)"
cd "${ROOT}/backend"
"${ROOT}/.venv/bin/uvicorn" app.main:app --host 0.0.0.0 --port 8000 --reload