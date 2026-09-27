# Architecture — IPsec Sentinel

**IPsec Sentinel** — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment
Framework. This document describes the Phase 1 (foundation), Phase 2 (packet
analysis) and Phase 3 (deterministic security assessment) architecture.

## 1. High-level overview

```
┌────────────────────────┐        ┌──────────────────────────┐        ┌──────────────┐
│  Frontend (React SPA)  │  HTTP  │  Backend (FastAPI)       │  SQL   │  PostgreSQL  │
│  Vite · Tailwind CSS   │ ─────▶ │  /api/v1 REST interface  │ ─────▶ │  persistent  │
│  TanStack Query        │  JSON  │  SQLAlchemy ORM          │        │  storage     │
└────────────────────────┘        └──────────────────────────┘        └──────────────┘
        :8080 / :2456                    :8000                          :5432
```

Every layer talks to the next over a plain, versioned contract:

1. **Browser → Frontend** — React Router serves the dashboard; TanStack Query
   owns server state.
2. **Frontend → Backend** — a single typed API client (`apiClient`) calls
   `GET /api/v1/*`. Dev traffic is proxied by Vite; container traffic by nginx.
3. **Backend → Database** — FastAPI endpoints read/write via SQLAlchemy 2.0
   models. Schema is versioned with Alembic migrations.

## 2. Repo layout

```
ipsec-sentinel/
├── frontend/            # React + Vite + Tailwind SPA
├── backend/             # FastAPI + SQLAlchemy + Alembic service
│   ├── app/             #   application package (api, core, db, models, schemas)
│   ├── alembic/         #   migration scripts
│   └── tests/           #   pytest suite
├── docs/                # architecture + implementation plan
├── scripts/             # dev/bootstrap/verify helpers
├── configs/             # environment overrides
├── tests/               # (reserved) future integration/end-to-end tests
├── examples/            # (reserved) sample captures
├── docker-compose.yml   # frontend + backend + postgres
├── Makefile             # developer commands
└── .env.example         # environment template
```

## 3. Backend

### 3.1 API contract

All responses use a consistent envelope (see `app/schemas/common.py`):

```json
{ "success": true, "data": { }, "error": null, "meta": { } }
```

Errors:

```json
{ "success": false, "data": null, "error": { "code": "NOT_FOUND", "message": "...", "details": {} } }
```

Phase 1 endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Liveness + DB connectivity |
| `GET` | `/api/v1/system/info` | Non-sensitive runtime facts |
| `GET` | `/api/v1/stats/dashboard` | Database-backed dashboard counters |
| `GET` | `/api/v1/captures` | Capture list (paginated) |
| `GET` | `/api/v1/analysis-jobs` | Job list (paginated) |
| `GET` | `/api/v1/analyses` | Analysis list (paginated) |
| `GET` | `/api/v1/findings` | Finding list (paginated) |
| `GET` | `/api/v1/reports` | Report list (paginated) |
| `GET` | `/api/v1/system/tools` | Installed packet tools + active reader |
| `POST` | `/api/v1/captures` | Upload + validate + SHA-256 (Phase 2) |
| `POST` | `/api/v1/captures/{key}/analyze` | Start analysis job (Phase 2) |
| `GET` | `/api/v1/captures/{key}` | Capture detail (Phase 2) |
| `DELETE` | `/api/v1/captures/{key}` | Delete capture + file (Phase 2) |
| `GET` | `/api/v1/analysis-jobs/{key}` | Job detail (Phase 2) |
| `GET` | `/api/v1/analyses/{key}` | Analysis summary (Phase 2) |
| `GET` | `/api/v1/analyses/{key}/…` | Sub-resources + exports (Phase 2) |
| `POST` | `/api/v1/analyses/{key}/assess` | Run deterministic security rules (Phase 3) |
| `GET` | `/api/v1/analyses/{key}/findings` | Paginated findings, newest first (Phase 3) |
| `GET` | `/api/v1/analyses/{key}/findings/{key}` | Single finding by `SEC-…` id / UUID (Phase 3) |

Interactive docs: `/docs` (Swagger) and `/redoc` at the backend root.

### 3.2 Configuration

Loaded by `app/core/config.py` from environment variables (pydantic-settings).
Nothing sensitive is stored in source. Key variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./ipsec_sentinel.db` | `postgresql+psycopg://user:pass@host:port/db` in Docker |
| `CORS_ORIGINS` | `http://localhost:2456,…` | Comma-separated allowed origins |
| `UPLOAD_DIR` | `<repo>/data/uploads` | Storage for future uploads |
| `LOG_LEVEL` | `INFO` | Logging level |
| `ENVIRONMENT` | `development` | `development | test | demo | production` |

### 3.3 Database

SQLAlchemy 2.0 typed ORM models in `app/models/`:

- `captures` — one row per uploaded capture file (id, refs, SHA-256, format,
  packet counts, status, storage path)
- `analysis_jobs` — asynchronous analysis progress tracking (stage, progress 0–1)
- `analyses` — completed analysis records (protocol detection, confidence, counts)
- `protocol_observations` — per-protocol stats for an analysis
- `ike_messages` / `ike_proposals` — parsed IKE messages and their SA proposals
- `esp_packets` / `ah_packets` — parsed encapsulates (SPI, seq, direction)
- `flows` — reconstructed bidirectional flows with endpoint/IPsec counts
- `flow_features` — per-flow feature sets (`feature_json`, schema versioned)
- `security_findings` — Phase 3: human `finding_id` (`SEC-000001`), severity/
  confidence/status enums, `rule_version`, `source`, observed/expected values,
  `evidence_json`, `evidence_digest` (unique with analysis+rule)
- `reports` — generated reports

The migrations (`backend/alembic/versions/…`) create the tables with native
PostgreSQL enums. The Phase 2 migration `4f9c6d7e2a81` adds the analysis tables;
the Phase 3 migration `b7f0a1e2034a` adds the finding enums/columns/indexes.
Enums store SQLAlchemy member **names** (uppercase: `VALID`, `RUNNING`,
`PACKET_READING`, `HIGH`, `OPEN`, …) — verified against both SQLite and
PostgreSQL. PG schema was reset and re-migrated cleanly from scratch; the
downgrade→upgrade round-trip is verified for both Phase 2 and Phase 3
migrations.

A synchronous engine is used deliberately: the same code path runs against
SQLite (tests / local dev) and PostgreSQL (Docker / production). Async I/O can
be introduced later without churn in the domain models.

### 3.4 Packet analysis pipeline (Phase 2)

```
upload → validate (magic/size/ext) → SHA-256 → store (generated name) → job:
VALIDATION → PACKET_READING → PROTOCOL_DETECTION → IKE_ANALYSIS → ESP_ANALYSIS
→ FLOW_BUILDING → FEATURE_EXTRACTION → PERSISTENCE → COMPLETED
```

- **Readers** (`app/analyzers/packet_analyzer/reader.py`): tshark (subprocess,
  arg-list only, no `shell=True`), scapy, and a dependency-free builtin pcap/
  pcapng reader. Same parser downstream regardless of reader.
- **Parser** (`parser.py` + `protocols/*`): Ethernet/VLAN/IPv4/IPv6, IKE (500),
  NAT-T (4500), ESP (incl. ESP-over-4500), AH.
- **Detection** (`protocol_detector.py`): `yes/no` + confidence + per-protocol
  and per-IP-version booleans + observations.
- **IKE/ESP/AH models**: message records with proposals (encryption/integrity/PRF/
  DH), SPI, seq, direction. `encryption_algorithm=UNKNOWN` when undecodable;
  no decryption ever.
- **Flows & features**: bidirectional flows with burst/timing/size statistics
  conforming to `configs/feature_schema.yaml` (v1.0).
- Honesty rule: every value is derived from real parsed packets; unknowns stay
  unknown.

See `backend/docs/packet-analysis.md` and `backend/docs/pcap-format.md` for the
full treatment. The tool chain state is reported by `GET /api/v1/system/tools`
(tshark is **not installed** on the reference host; scapy 2.7.0 + builtin reader
are active).

### 3.5 Security assessment engine (Phase 3)

A deterministic, rule-based engine (`app.security` + `app.services.security_service`)
evaluates **persisted Phase 2 rows only** — no re-parsing, no decryption, no
shell, no AI/ML:

```
POST /analyses/{key}/assess
  → load AssessmentContext (ike_messages/proposals, esp/ah, flows, observations)
  → for each of the 10 RULES (registry, RULES_VERSION="1.0.0"):
      evaluate → FindingDrafts → evidence_digest (canonical SHA-256)
      dedupe on (analysis_id, rule_id, evidence_digest)
      persist SecurityFinding (SEC-000001…, status=OPEN, stamped rule_version)
  → stamp analyses.rule_version → AssessmentResultRead
```

- **10 rules** across cryptography, key exchange, PFS, IKE, SA, replay,
  composite and metadata categories — full catalogue in
  [`docs/security-rules.md`](security-rules.md), design in
  [`docs/security-assessment.md`](security-assessment.md).
- **Evidence-backed:** every finding carries machine-readable evidence
  (`version`, items with source/field/observed/expected/observation_status,
  `packet_ids`, `message_ids`, notes). No evidence → no finding; `UNKNOWN`
  never becomes a finding.
- **Idempotent:** re-running `assess` creates 0 new findings.
- **Severity from the explicit rule table** (`INFO…CRITICAL`), **confidence**
  (`HIGH/MEDIUM/LOW/UNKNOWN`) separately reflects observation strength.
  No global security score is computed (Phase 5, grounded in real findings).
- API: `POST …/assess`, `GET …/findings`, `GET …/findings/{SEC-…}`
  (409 `ANALYSIS_NOT_ASSESSABLE` unless analysis completed; 404s for unknown
  analysis/finding).
- React **Security** tab: *Run assessment*, severity-count cards, findings
  table with expandable evidence.

## 4. Frontend

- **Stack** — React 19 + TypeScript + Vite + Tailwind CSS v4 + shadcn/ui-style
  components + Lucide icons + TanStack Query + React Router.
- **API data flow** — components never call `fetch`. All requests go through
  `src/lib/api-client.ts`, wrapped in React Query hooks under `src/hooks`.
- **Data integrity** — the dashboard shows only values returned by the backend.
  With an empty database every counter renders `0`/empty state. No fake or
  hardcoded results exist.
- **Pages** — Dashboard, Captures (upload w/ progress + list + analyze/delete),
  Analysis (list + job polling), Analysis detail (Overview/Protocol/IKE/ESP/
  Packets/Flows/Features/**Security** tabs, CSV/JSON exports + *Run
  assessment*), Findings, Reports, Settings (system info + packet tools). Each
  page presents honest empty/error states until real data exists.
- **Routing** — client-side routing via React Router; the Vite dev server
  proxies `/api/*` to `:8000`.

## 5. Docker

`docker-compose.yml` orchestrates three services on one network:

| Service | Image | Exposed port | Architectures |
| --- | --- | --- | --- |
| `postgres` | `postgres:16-alpine` | `5432` | amd64 + arm64 |
| `backend` | built from `backend/Dockerfile` | `8000` | amd64 + arm64 |
| `frontend` | built from `frontend/Dockerfile` (nginx) | `8080` | amd64 + arm64 |

The backend waits for the DB healthcheck, applies `alembic upgrade head`, then
starts uvicorn. nginx serves the SPA and proxies `/api/*` to `backend:8000`.

All pinned images are official multi-arch builds, so Apple Silicon (arm64) and
Intel (amd64) hosts pull native variants automatically — no emulation.
`make docker-build-multi` cross-builds both platforms via BuildKit for
publishing. `DOCKER_PLATFORM` (compose) / `DOCKER_PLATFORM` (make) force a
platform when needed.

## 6. Environment & platform constraints

The project targets an **Apple Silicon M2 (arm64) MacBook Air**:

- **Host toolchain** — CPython, Homebrew PostgreSQL, Node run natively (`arm64`);
  nothing assumes `x86_64`-only binaries.
- **Containers** — all images carry `linux/arm64`; compose resolves the host
  architecture automatically.
- **No GPU** — CUDA/NVIDIA is never a requirement. The Phase 4 ML stack is
  CPU-only (ONNX Runtime CPU, llama.cpp, sklearn), keeping inference on the M2
  neural-engine-less cores in the tens-of-megabytes model range.
- **Memory budget** — the stack runs comfortably in unified memory: 1 uvicorn
  worker, Alpine PostgreSQL, nginx static hosting. The Phase 3+ StrongSwan
  testbed is provisioned as a **Linux/arm64 VM** (lima, default 2 vCPU / 4 GiB,
  both overridable) rather than on macOS.

## 7. Security posture (current)

- No secrets in source; configuration via environment only.
- `AUTH_ENABLED=false` by default — authentication is not implemented and is
  explicitly out of Phase 1 scope.
- Upload validation: extension + magic-byte allow-list, size limit, no path
  separators in filenames, SHA-256 integrity, storage under generated names via
  atomic temp-then-rename. Deletion touches only the DB-recorded path.
- Subprocess use is restricted to the tshark reader with argument lists and a
  120 s timeout; no `shell=True` anywhere.
- No packet contents are decrypted or injected into the network; analysis is
  read-only over captured files.
- Phase 3 assessment is read-only over the database: no user-controlled SQL,
  no shell, no code execution; findings are evidence-backed and idempotent.
- Later phases add AI/ML scoring, recommendations and the StrongSwan testbed;
  live capture and injection remain out of scope.