#!/usr/bin/env bash
# IPsec Sentinel — start the Vite dev server.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Starting frontend on http://localhost:5173 (API proxied to :8000)"
npm --prefix "${ROOT}/frontend" run dev