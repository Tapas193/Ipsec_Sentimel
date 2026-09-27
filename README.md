# IPsec Sentinel

**AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework**

Problem statement ID: **26160**.

IPsec Sentinel is a cybersecurity platform that analyzes IPsec VPN packet
captures, detects protocol misconfigurations, and produces security
assessments. This repository currently contains **Phase 1 — the foundation**,
**Phase 2 — packet analysis**, and **Phase 3 — deterministic security
assessment**:

- **Phase 1**: full-stack skeleton, database schema, a real REST API, a
  professional dark cybersecurity dashboard, and containerized deployment.
- **Phase 2**: PCAP/PCAPNG ingestion with SHA-256 integrity, dependency-free
  parsing (IKE/ESP/AH over IPv4/IPv6), IPsec protocol detection, bidirectional
  flow reconstruction and feature extraction, PostgreSQL persistence, CSV/JSON
  exports, and a React dashboard with upload, job polling and analysis tabs.
- **Phase 3**: a deterministic, rule-based assessment engine (10 versioned
  rules) that turns persisted analysis data into evidence-backed
  `SecurityFinding` records — `POST /analyses/{key}/assess`, idempotent
  findings APIs, and a React **Security** tab with severity counts and
  expandable evidence.

> ⚠️ **Honest scope warning:** Phases 1–3 implement *no* AI/ML, no global
> security score, no recommendations, no live capture, and no report
> generation. Every value reported by the API and dashboard is derived from
> **real parsed packets** — nothing is fabricated, and undecodable values are
> shown as `unknown` / `UNKNOWN` (never silently classified as weak or
> strong). These remaining capabilities are planned and tracked in
> [`docs/implementation-plan.md`](docs/implementation-plan.md).

## What IPsec Sentinel is

- **Analyzer** — ingests PCAP/PCAPNG capture files, parses IKE/ESP/AH, detects
  IPsec, and reconstructs VPN flows (implemented in Phase 2)
- **Assessment framework** — evaluates captures against security policies and
  best practices to surface findings with severity and confidence
  (implemented in Phase 3: 10 deterministic rules, evidence-backed findings,
  idempotent assessment)
- **AI-assisted** — machine learning will power confidence scoring, anomaly
  detection, and summaries in later phases
- **Reporting** — generates executive, technical, and JSON reports (future phases)

## Technology stack

| Layer | Technology |
| --- | --- |
| Frontend | React 19 · TypeScript · Vite · Tailwind CSS v4 · shadcn/ui · Lucide · TanStack Query · React Router |
| Backend | Python 3.11+ · FastAPI · Pydantic v2 · SQLAlchemy 2.0 · Alembic |
| Database | PostgreSQL 16 (SQLite fallback for local/dev) |
| Deployment | Docker Compose (frontend · backend · postgres) — multi-arch amd64/arm64 |

## Platform & hardware compatibility (Apple Silicon M-series)

This project is developed on a **MacBook Air M2 (arm64)** and is explicitly
**Apple Silicon–compatible**:

- **Native arm64 toolchain** — CPython, Homebrew PostgreSQL, and Node all run
  as native `arm64` binaries (no x86 translation / Rosetta).
- **Multi-arch Docker** — every pinned image (`python:3.12-slim`,
  `node:24-alpine`, `nginx:1.27-alpine`, `postgres:16-alpine`) publishes
  `linux/arm64`, so Compose pulls the arm64 variant automatically. To force a
  platform, `export DOCKER_PLATFORM=linux/arm64` (see `docker-compose.yml`).
- **Cross-builds** — `make docker-build-multi` builds `linux/amd64` +
  `linux/arm64` images via BuildKit for anyone on Intel machines.
- **No NVIDIA/CUDA** — no GPU dependencies exist. The AI edge for later phases
  is explicitly **CPU-only** (e.g. ONNX Runtime CPU / llama.cpp).
- **Memory-conscious** — the default stack uses one backend worker, a tiny
  nginx frontend, and an Alpine PostgreSQL; it fits comfortably in an M2's
  unified memory. The testbed VM defaults to 2 vCPU / 4 GiB
  (`TESTBED_CPUS`, `TESTBED_MEMORY` overridable).
- **StrongSwan testbed posture** — macOS cannot host strongSwan natively.
  In later phases the IPsec testbed runs inside a **Linux/arm64 VM or
  container**. The foundation is already provided:
  `make testbed-up` → creates a lima VM (Ubuntu 24.04 arm64) with the repo
  mounted; `make testbed-shell` drops you inside. See
  `scripts/arm64-testbed.sh`.

## Repository layout

```
├── frontend/            # React SPA (dashboard)
├── backend/             # FastAPI service + migrations + tests
├── docs/                # architecture & implementation plan
├── scripts/             # bootstrap / dev / verify helpers
├── configs/             # environment overrides
├── docker-compose.yml
├── .env.example
├── Makefile
└── README.md
```

## Getting started

### Prerequisites

- Python 3.11+
- Node.js 20+
- (optional) Docker Desktop / Docker Engine with Compose v2
- (optional) PostgreSQL 16 — not required if you use Docker

### 1. Install dependencies

```bash
make install            # or: ./scripts/bootstrap.sh
```

### 2. Configure environment

```bash
cp .env.example .env
# edit DATABASE_URL etc. in .env as needed
```

### 3. Run locally (no Docker)

Terminal 1 — backend:

```bash
make migrate            # applies the initial schema
make dev-backend        # uvicorn on http://localhost:8000
```

Terminal 2 — frontend:

```bash
make dev-frontend       # Vite on http://localhost:5173
```

> **Packet readers (optional):** analysis works out of the box with the built-in
> pcap/pcapng reader. Install `scapy` for a second reader, or Wireshark/TShark
> for the fastest one (`brew install wireshark`); ingestion runs fine without
> them. The active reader is shown on the Settings → Packet tools card.

### 4. Or run with Docker

```bash
make docker-up          # builds and starts all three services
make docker-logs        # tail container logs
make docker-down        # stop everything
```

## URLs

| Service | URL |
| --- | --- |
| Frontend (local) | http://localhost:5173 |
| Frontend (docker) | http://localhost:8080 |
| Backend API | http://localhost:8000 |
| Health check | http://localhost:8000/api/v1/health |
| Swagger docs | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |

## Testing & quality

```bash
make test        # backend pytest suite (no DB required — SQLite in-memory)
make lint        # ruff (backend) + eslint (frontend)
make typecheck   # mypy (backend) + tsc (frontend)
make build       # production frontend build
```

## API (what actually works)

Phase 1 foundation:

- `GET /api/v1/health` — service + database health
- `GET /api/v1/system/info` — runtime facts
- `GET /api/v1/stats/dashboard` — real DB counters
- `GET /api/v1/captures` · `/analysis-jobs` · `/analyses` · `/findings` · `/reports`
  — paginated lists

Phase 2 packet analysis:

- `POST /api/v1/captures` — upload PCAP/PCAPNG (magic-byte validation + SHA-256)
- `POST /api/v1/captures/{key}/analyze` — start a background analysis job
- `GET /api/v1/analyses/{key}` — summary + job state
- `GET /api/v1/analyses/{key}/{protocol-observations|ike-messages|esp-packets|ah-packets|flows|features}`
  — paginated sub-resources
- `GET /api/v1/analyses/{key}/export/{flows|ike|esp|features}` — CSV/JSON exports
- `GET /api/v1/system/tools` — active reader + installed packet tools

Phase 3 deterministic security assessment:

- `POST /api/v1/analyses/{key}/assess` — run the 10 rule set (409 unless the
  analysis is completed; idempotent — re-run creates 0 findings)
- `GET /api/v1/analyses/{key}/findings` — paginated findings for the analysis
- `GET /api/v1/analyses/{key}/findings/{SEC-…}` — single finding with
  machine-readable evidence

## Docs

- [`docs/architecture.md`](docs/architecture.md) — system design
- [`docs/implementation-plan.md`](docs/implementation-plan.md) — phases and scope
- [`docs/security-assessment.md`](docs/security-assessment.md) — Phase 3 engine design
- [`docs/security-rules.md`](docs/security-rules.md) — the 10-rule catalogue
- [`docs/phase-3-report.md`](docs/phase-3-report.md) — Phase 3 final report
- [`backend/docs/packet-analysis.md`](backend/docs/packet-analysis.md) — analysis pipeline
- [`backend/docs/pcap-format.md`](backend/docs/pcap-format.md) — supported formats
- [`backend/docs/testing.md`](backend/docs/testing.md) — test & verification guide
- [`configs/feature_schema.yaml`](configs/feature_schema.yaml) — feature schema

## License

Apache-2.0 (see `backend/pyproject.toml`).