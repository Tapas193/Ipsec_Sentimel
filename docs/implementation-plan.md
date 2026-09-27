# Implementation Plan — IPsec Sentinel

**IPsec Sentinel** — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment
Framework. **Problem statement ID: 26160.**

This plan describes what was built in Phases 1–3 and what remains for later
phases. Only items explicitly marked *implemented* are in the codebase today.

## Phase 1 — Foundation (implemented)

Goal: a runnable, tested, deployable skeleton with an honest UI. No analysis,
AI, parsing, or scoring.

### 1.1 Backend — implemented
- [x] FastAPI application with standard response envelope
- [x] `GET /api/v1/health` (verifies DB connectivity)
- [x] `GET /api/v1/system/info`
- [x] Database-backed dashboard stats (`/api/v1/stats/dashboard`) — zero when empty
- [x] Paginated read endpoints for captures / analysis jobs / analyses / findings / reports
- [x] SQLAlchemy 2.0 models: `captures`, `analysis_jobs`, `analyses`,
      `security_findings`, `reports`
- [x] Initial Alembic migration (native PostgreSQL enums)
- [x] pytest suite: health, database connectivity/tables, response envelope
- [x] Ruff lint + format clean; mypy strict clean

### 1.2 Frontend — implemented
- [x] React 19 + TypeScript + Vite + Tailwind CSS v4 + shadcn/ui-style components
- [x] Single typed API client; React Query hooks; React Router
- [x] Dark cybersecurity dashboard: sidebar, header, IPsec Sentinel branding
- [x] Pages: Dashboard, Captures, Analysis, Findings, Reports, Settings
      (honest empty states, live health/database status, real DB counters)
- [x] `npm run build`, `npm run typecheck`, `npm run lint` all green

### 1.3 Ops — implemented
- [x] `docker-compose.yml` (postgres + backend + frontend on one network)
- [x] `Dockerfile` for backend and frontend (nginx serving SPA + `/api` proxy)
- [x] `.env.example`, `Makefile`, `scripts/`, `configs/`, `docs/`

### 1.4 Platform (Apple Silicon / arm64) — implemented
- [x] Native `arm64` toolchain only (CPython, Homebrew PostgreSQL, Node)
- [x] All Docker images multi-arch (`linux/arm64` + `linux/amd64`); compose
      resolves host architecture; `make docker-build-multi` cross-builds
- [x] No NVIDIA/CUDA dependency anywhere; AI roadmap is CPU-only
- [x] `scripts/arm64-testbed.sh` + `make testbed-up` — lima Linux/arm64 VM with
      the repo mounted, for the later StrongSwan testbed (2 vCPU / 4 GiB default)

## Phase 2 — Capture ingestion & packet analysis (implemented)

**Goal:** upload → validate → hash → parse → detect IPsec → analyze IKE/ESP/AH →
build flows/features → persist → present in the React dashboard. All results are
derived from **real parsed packets**; nothing is fabricated.

### Backend — implemented
- [x] PCAP/PCAPNG upload with extension + magic-byte validation, size limit, and
      SHA-256 integrity; stored under generated names (atomic write) — no path
      traversal, no `shell=True`
- [x] Capture metadata extraction (format, SHA-256, packet/byte counts, times)
      persisted to `captures`
- [x] Pluggable packet readers: tshark (subprocess, arg-list, 120 s timeout),
      scapy 2.7.0, and a dependency-free builtin pcap/pcapng reader; the active
      reader is reported by `GET /api/v1/system/tools`
- [x] Dependency-free parser: Ethernet/VLAN/IPv4/IPv6/UDP/TCP, IKE(500),
      NAT-T(4500), ESP (incl. ESP-over-4500 w/ non-ESP-marker handling), AH
- [x] Protocol detection: `yes/no`, confidence low/medium/high, per-protocol and
      per-IP-version booleans, observations list
- [x] IKE analysis → `ike_messages` + `ike_proposals` (version, exchange, SPIs,
      direction, transform table with encryption/integrity/PRF/DH, confidence)
- [x] ESP/AH records → `esp_packets` / `ah_packets` (SPI, seq, direction;
      `encryption_algorithm=UNKNOWN` where undecodable; **no decryption**)
- [x] Bidirectional flow reconstruction → `flows` with IKE/ESP/AH counts, SPI
      lineage, direction
- [x] Feature extraction per flow → `flow_features` conforming to
      `configs/feature_schema.yaml` (v1.0): sizes, interarrival, bursts, histogram
- [x] `analysis_jobs` lifecycle: VALIDATION → PACKET_READING →
      PROTOCOL_DETECTION → IKE_ANALYSIS → ESP_ANALYSIS → FLOW_BUILDING →
      FEATURE_EXTRACTION → PERSISTENCE → COMPLETED (progress 0–1), run via
      FastAPI `BackgroundTasks`
- [x] Paginated sub-resource endpoints + CSV/JSON exports
      (`export/{flows|ike|esp|features}`)
- [x] Alembic migration `4f9c6d7e2a81` (uppercase enum names) — PG 5433
      downgrade/upgrade round-trip verified; schema reset + re-migrate clean
- [x] `backend/scripts/pg_e2e.py` — full-flow E2E against PostgreSQL (PASSED)
- [x] Tests: 33 passed; ruff clean; mypy clean (65 source files)

### Frontend — implemented
- [x] Captures page: file upload with progress bar (XHR), list w/ SHA-256,
      validate/analyze/delete actions
- [x] Capture detail: metadata, magic-status, analyze with job-linkage
- [x] Analysis list with running-job polling (progress bars auto-refresh)
- [x] Analysis detail tabs: Overview, Protocol, IKE, ESP, Packets (AH), Flows,
      Features — sub-resource tables, counts, export download buttons
- [x] Settings → Packet tools: active reader + installed tools (tshark/tcpdump/
      scapy/builtin), honest `installed/missing`
- [x] `typecheck`, `lint`, `build` all green

### Phase 2 verification evidence
- [x] PG E2E via `scripts/pg_e2e.py`: 22-packet synthetic capture → upload →
      SHA-256 `411fef80…` matches → analyze → job completed → summary
      `protocol=yes`, `ike/esp/ah=True`, confidence `high` → 5 observations,
      4 IKE messages, 12 ESP, 3 AH, 4 flows, 4 feature sets → all exports → delete
- [x] Live HTTP run against the dev server (SQLite) with the same capture and
      results; frontend Vite proxy serves `/api` correctly
- [x] Upload-validation probes: bad extension → `UNSUPPORTED_FORMAT`;
      garbage `.pcap` → magic-byte rejected; empty valid-magic pcap → valid,
      parsed defensively; path-traversal key → 404

### Phase 2 known limitations — reported honestly
- tshark not installed on the reference host (`brew install wireshark` hint
  surfaced in the UI); scapy 2.7.0 + builtin reader are active
- Docker unavailable on the reference host → compose stack not exercised; PG
  verified against the local Homebrew instance on `:5433`
- Live capture, injection and decryption deliberately out of scope; SA proposal
  status is inferred from direction and documented as such

## Phase 3 — Deterministic security assessment engine (implemented)

**Goal:** rule-based, evidence-backed assessment over persisted Phase 2 data —
no AI/ML (Phase 4), no decryption, no global security score (Phase 5).

### Backend — implemented
- [x] `app.security` package: enums (`Severity`, `FindingType`,
      `FindingConfidence`, `FindingStatus`), `FindingEvidence`, evidence digest
      (canonical SHA-256), `AssessmentContext`, 10-rule registry
      (`RULES_VERSION="1.0.0"`), `SecurityFinding` model evolution
- [x] Rules: `IPSEC-CRYPTO-001/002`, `IPSEC-DH-001`, `IPSEC-PFS-001`,
      `IPSEC-IKE-001`, `IPSEC-SA-001`, `IPSEC-REPLAY-001`,
      `IPSEC-COMPOSITE-001`, `IPSEC-META-001/002` — severity from explicit
      rule table, confidence from observation strength, UNKNOWN → no finding,
      "no evidence → no finding"
- [x] `app.services.security_service.assess_analysis`: loads context, runs
      rules, dedupes on `(analysis_id, rule_id, evidence_digest)`, assigns
      `SEC-000001…` ids via `next_sequence_id`, stamps `analyses.rule_version`,
      structured `ipsec_sentinel.security` logging
- [x] Endpoints: `POST /api/v1/analyses/{key}/assess` (409 unless completed),
      `GET …/findings` (paginated, newest first), `GET …/findings/{SEC-…}`
      (404-safe, human id or UUID); exceptions
      `AnalysisNotAssessableError`, `FindingNotFoundError`
- [x] Alembic migration `b7f0a1e2034a` (6 columns, PG type-convert +
      SQLite batch rebuild, unique `(analysis_id, rule_id, evidence_digest)`
      + unique `finding_id`) — **upgrade/downgrade round-trip verified on
      SQLite and PostgreSQL 5433**

### Frontend — implemented
- [x] Analysis detail **Security** tab: *Run assessment*, severity-count cards
      (total/critical/high/medium/low/info — **no** single score), findings
      table, expandable finding detail + machine-readable evidence block
- [x] `SecurityFinding`/`AssessmentResult` types, `listFindings`/`getFinding`/
      `assessAnalysis` client methods, `useFindingsQuery`/`useAssessMutation`
      hooks (invalidation), StatusBadge mappings for `critical`/`info`/
      `open`/`acknowledged`/`resolved`

### Phase 3 verification evidence
- [x] pytest **101 passed** (rules unit tests: every rule positive+negative,
      digest determinism, wrap/cap cases; API tests: assess → expected
      findings, idempotent re-run → 0 created, plaintext → 0 findings,
      409/404 paths, sequential SEC ids; DB uniqueness tests)
- [x] `ruff check` (app/tests/new migration) clean; `mypy app alembic` clean
      (84 files); frontend `typecheck`/`lint`/`build` green
- [x] PG E2E `scripts/pg_e2e.py`: upload → analyze → **assess →
      version=1.0.0 rules_run=10 created=3 total=3 → finding SEC-000001
      IPSEC-CRYPTO-001 → re-assess created=0 → delete** — PASSED
- [x] Docs: `docs/security-assessment.md`, `docs/security-rules.md`, updated
      architecture/implementation-plan/README

### Phase 3 known limitations — reported honestly
- Assessment consumes only persisted Phase 2 rows; an analysis must be
  `completed` first (409 otherwise)
- Evidence digests ignore notes text (editorial changes do not spawn
  duplicate findings); changing a rule's semantics requires a `RULES_VERSION`
  bump
- Replay and "IKE may be incomplete" rules are deliberately conservative
  (normal reordering / partial captures are consistent with the observation)

## Phase 4 — AI/ML-assisted analysis (planned)

Constraints fixed at design time: **CPU-only, no GPU/CUDA**, arm64-compatible,
memory-bounded for an M2 (single-digit-GiB working set, small models).

- Feature extraction from parsed flows (already persisted in `flow_features`)
- Offline/online ML models (model versioning on `analyses` already reserved:
  `analyzer_version`, `model_version`, `rule_version`, `dataset_version`)
- Model runtime candidates are CPU-first: ONNX Runtime (CPU EP), llama.cpp,
  scikit-learn — all ship `linux/arm64` + macOS `arm64`
- Confidence scoring and risk-level determination
- Summarization into `analyses.summarization_json`
- Findings produced this way must carry observation status
  `MODEL_PREDICTED` (reserved, unused by the Phase 3 engine)

## Phase 5 — Reporting & scoring (planned)

- Security score computation grounded in *real* findings (never hardcoded)
- Executive / technical / JSON report generation → `reports`
- Severity-based triage views in the Findings page
- Export & scheduling

## Cross-cutting concerns (ongoing)

- Authentication & authorization (`AUTH_ENABLED` currently `false`)
- HTTPS / production nginx, observability (structured logging), CI pipelines
- Multi-arch CI (build + test on `linux/arm64`; publish `linux/amd64,linux/arm64`)
- Integration/end-to-end test suite under root `tests/` (runs against the arm64
  testbed VM in Phase 4+)

## Principle

No feature is marked implemented until it ships with real behavior and tests.
Dashboard numbers always originate from the database. Reserved schema fields
never report fabricated values.