# Testing — IPsec Sentinel (Phase 2)

## 1. Backend suite (pytest)

Run from `backend/` with the project virtualenv:

```bash
.venv/bin/python -m pytest tests/ -q
```

39 tests (33 in the current run) covering:

- `test_health.py` — liveness, DB connectivity, response envelope
- `test_response_envelope.py` — envelope shape, error envelopes
- `test_capture_validation.py` — extension/magic/size validation, SHA-256,
  filename traversal rejection, storage naming, delete
- `test_packet_parser.py` — parser unit tests (IKE/ESP/AH/IPv4/IPv6/ESP-over-4500,
  non-ESP marker, malformed payload handling)
- `test_analysis_workflow.py` — upload → analyze → job lifecycle → summary →
  sub-resources → exports (full pipeline against SQLite)
- `test_database.py` — models, migrations, enum round-trips

Configured gate commands:

```bash
.venv/bin/python -m pytest tests/ -q        # tests
.venv/bin/python -m ruff check app tests    # lint
.venv/bin/python -m mypy app                # static types
```

Current status: **33 passed, ruff clean, mypy clean (65 source files).**

## 2. Test isolation

`backend/tests/conftest.py`:

- autouse `_clean_tables` fixture truncates all tables before each test
- swaps the session to an in-memory/temporary SQLite database
- overrides `UPLOAD_DIR` to a temp dir so test files never touch real storage

## 3. Synthetic capture

`backend/tests/synthetic_pcap.py` generates a deterministic IPsec capture
(22 packets: 4 IKE, 12 ESP, 3 AH, filler). Fixed content ⇒ fixed
SHA-256 `411fef80…cfd78f`, which is asserted in tests and in the PostgreSQL E2E.

## 4. PostgreSQL E2E script

`backend/scripts/pg_e2e.py` runs the real flow against PostgreSQL 5433:

```bash
DATABASE_URL="postgresql+psycopg://ipsec_sentinel:ipsec_sentinel_dev_password@localhost:5433/ipsec_sentinel" \
  .venv/bin/python scripts/pg_e2e.py
```

Verifies: health → upload (SHA-256 match) → analyze → job completes → summary
(`protocol=yes`, ike/esp/ah, confidence `high`) → observations/ike/esp/ah/flows/
features counts → all four exports → delete. Expected output ends with
`E2E PASSED against PostgreSQL`.

## 5. Migration round-trip

```bash
DATABASE_URL="postgresql+psycopg://ipsec_sentinel:ipsec_sentinel_dev_password@localhost:5433/ipsec_sentinel" \
  .venv/bin/python -m alembic upgrade head
# … enumerate the tests, then:
.venv/bin/python -m alembic downgrade -1 && .venv/bin/python -m alembic upgrade head
```

The Phase 2 migration (`4f9c6d7e2a81`) was verified **both directions** on PG.
Enums store SQLAlchemy member *names* (uppercase: `VALID`, `RUNNING`,
`PACKET_READING`, …) on both SQLite and PostgreSQL.

## 6. Frontend gates

Run from `frontend/`:

```bash
npm run typecheck   # tsc -b --noEmit
npm run lint        # eslint .
npm run build       # tsc -b && vite build
```

Current status: **typecheck clean, lint 0 errors (2 pre-existing fast-refresh
warnings in ui/badge.tsx and ui/button.tsx), build clean.**

## 7. Manual end-to-end acceptance

1. `backend` on `:8000` (or `DATABASE_URL` → PG 5433).
2. Frontend dev on `:2456` (proxy routes `/api` to `:8000`).
3. Captures page → upload `backend/tests/synthetic_pcap.py` output
   (or any real `.pcap`/`.pcapng`).
4. Click **Analyze** → job completes (page polls).
5. Open the analysis → Overview/Protocol/IKE/ESP/Packets/Flows/Features tabs;
   verify counts match the capture.
6. Download each export; confirm non-empty files.
7. Settings → Packet tools shows the active reader and installed tools.
8. Delete the capture; file removed from disk and record gone.

## 8. Honesty verification

- Values in the UI come only from the API; no fake analysis anywhere.
- Unknown decodes are shown as `unknown`/`UNKNOWN` — not guessed.
- The synthetic capture's SHA-256 is deterministic and asserted in tests, so
  fabricated results would break the suite.