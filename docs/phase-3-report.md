# Phase 3 — Final Report

**IPsec Sentinel — Problem Statement 26160** · Deterministic Security
Assessment Engine · 10 rules · evidence-backed · idempotent · CPU-only, no
AI/ML, no decryption, no global score.

---

## 1. Files created — security engine (`backend/app/security/`)

| File | Lines | Purpose |
| --- | --- | --- |
| `__init__.py` | 12 | docstring-only (no eager imports → no model↔security import cycle) |
| `enums.py` | 53 | `Severity`, `FindingType`, `FindingConfidence`, `FindingStatus` (DB stores member **names**, API serializes `.value`) |
| `evidence.py` | 88 | `EvidenceItem` / `FindingEvidence` (`version` key), `evidence_digest` — canonical SHA-256 (sorted items, deduped packet/message ids, notes excluded) |
| `base.py` | 53 | `Rule` ABC + `FindingDraft` |
| `context.py` | 31 | `AssessmentContext` — immutable snapshot of persisted Phase 2 rows |
| `helpers.py` | 25 | wrap-aware replay analysis, sequence helpers |
| `registry.py` | 50 | `RULES_VERSION="1.0.0"`, ordered 10-rule tuple, import-time validation (unique `IPSEC-*` ids, category membership) |
| `rules/__init__.py` | 28 | rule exports |
| `rules/crypto.py` | 235 | `IPSEC-CRYPTO-001` (unverifiable encryption), `IPSEC-CRYPTO-002` (weak-crypto table) |
| `rules/kex.py` | 171 | `IPSEC-DH-001` (weak DH), `IPSEC-PFS-001` (PFS, only with visible child SA) |
| `rules/ike.py` | 222 | `IPSEC-IKE-001` (negotiation may be incomplete), `IPSEC-SA-001` (unresolved/conflicting proposals) |
| `rules/esp.py` | 203 | `IPSEC-REPLAY-001` (wrap-aware, 25-cap), `IPSEC-COMPOSITE-001` (ESP+AH same SA) |
| `rules/meta.py` | 173 | `IPSEC-META-001` (non-IPsec alongside), `IPSEC-META-002` (elevated IKE initiation) |

Plus: `app/services/security_service.py` (241 lines — assess, dedupe, `SEC-000001`
sequence ids, `rule_version` stamping, structured logging), evolved
`app/models/finding.py` (101), `app/schemas/finding.py` (51),
`app/schemas/security.py` (26), exceptions in `app/core/exceptions.py`.

## 2. Files created — migration, tests, scripts

- `backend/alembic/versions/b7f0a1e2034a_phase_3_security_assessment_schema.py`
  — 6 new columns, native PG enum types (`finding_confidence`, `finding_status`
  + severity/type/confidence usage), `USING` casts on PG, `batch_alter_table`
  rebuild on SQLite, unique `(analysis_id, rule_id, evidence_digest)` +
  unique `finding_id` index; downgrade maps enum→float 1.0/0.7/0.4/0.0 on PG.
- `backend/tests/test_security_rules.py` (655) — unit tests: registry, digest
  determinism/order-independence, every rule positive+negative, wrap/cap cases;
  factory helpers `make_analysis/make_message/make_proposal/make_esp/make_ah/
  make_observation/build_ctx`.
- `backend/tests/test_security_api.py` (171) — assess → expected findings,
  idempotent re-run → `created=0`, plaintext → 0 findings, 409/404 paths,
  sequential SEC ids, `rule_version` stamped.
- `backend/tests/test_database.py` — extended: 13-table check, enum
  round-trip, unique `(analysis, rule, evidence)`, unique `finding_id`.
- `backend/tests/synthetic_pcap.py` — added `build_plaintext_pcap()`.
- `backend/scripts/pg_e2e.py` — extended Phase 3 block (assess → findings →
  detail → idempotent re-assess).

## 3. Files created — frontend

- `src/pages/analysis-detail-page.tsx` (854) — **Security** tab:
  `SecurityTab`, `SeverityStat` (6 count cards, **no** score),
  `SecurityFindingsTable`, `FindingDetail`, `DetailLine`, `EvidenceBlock`.
- `src/types/api.ts` (345) — `FindingEvidenceItem`, `FindingEvidence`
  (key `version`), `SecurityFinding`, `RuleAssessment`, `AssessmentResult`.
- `src/lib/api-client.ts` (199) — `listFindings`, `getFinding`, `assessAnalysis`.
- `src/hooks/use-api.ts` (189) — `useFindingsQuery`, `useAssessMutation`
  (invalidates findings/analysis/analyses/dashboard-stats).
- `src/components/status-badge.tsx` (36) — `critical→danger`, `info→info`,
  `open→secondary`, `acknowledged→warning`, `resolved→success`.

## 4. Files created — docs

- `docs/security-assessment.md` — engine design, architecture, API contract,
  idempotency, versioning, guardrails.
- `docs/security-rules.md` — full catalogue of the 10 rules with severity /
  confidence / firing conditions.
- `docs/architecture.md` — Phase 3 section 3.5, API table, DB notes, Security
  tab, security posture updated.
- `docs/implementation-plan.md` — Phase 3 **implemented** (old AI/ML plan
  renumbered to Phase 4).
- `README.md` — Phase 3 scope, honest-scope warning, API + docs lists.
- `docs/phase-3-report.md` — this report.

## 5. Commands run (all PASSED)

```bash
# backend gates
python -m pytest tests                     → 101 passed, 2 warnings in 0.80s
python -m ruff check app tests <migration> → All checks passed!
python -m mypy app alembic                 → Success: no issues in 84 files

# migrations — SQLite
alembic upgrade head && alembic downgrade 4f9c6d7e2a81   → round-trip OK

# migrations — PostgreSQL 5433
DATABASE_URL=postgresql+psycopg://…@localhost:5433/ipsec_sentinel alembic …
                                            → round-trip OK (both directions)

# PostgreSQL E2E
DATABASE_URL=… python scripts/pg_e2e.py     → E2E PASSED against PostgreSQL

# frontend gates
npm run typecheck  → clean
npm run lint       → 0 errors (2 pre-existing warnings in badge.tsx/button.tsx)
npm run build      → ✓ built in 451ms (395.40 kB js / 23.54 kB css)
```

## 6. Live acceptance (PostgreSQL E2E, synthetic 22-packet capture)

```
upload: ref=CAP-000001 sha256=411fef80…
analysis: ANL-000001 completed — protocol=yes ike=True esp=True ah=True
          confidence=high packets=22 ike_msgs=4 esp=12 ah=3 flows=4
assess: version=1.0.0 rules_run=10 created=3 total=3 duration_ms=28
findings: total=3
finding detail: SEC-000001 IPSEC-CRYPTO-001
re-assess idempotent: created=0
  deleted capture CAP-000001
E2E PASSED against PostgreSQL
```

Exactly the three expected findings: `IPSEC-CRYPTO-001`, `IPSEC-IKE-001`,
`IPSEC-META-001`.

## 7. Assessment engine (design)

```
POST /analyses/{key}/assess
  → load AssessmentContext (ike_messages/proposals, esp/ah, flows, observations)
  → for each of 10 RULES: evaluate → FindingDrafts → evidence_digest (SHA-256)
      dedupe on (analysis_id, rule_id, evidence_digest)
      persist SecurityFinding (SEC-000001…, status=OPEN, rule_version stamped)
  → stamp analyses.rule_version → AssessmentResultRead
```

- Pure functions of persisted rows: no PCAP re-read, no decryption, no shell,
  no user-controlled SQL, no ML.
- `AssessmentContext` loads `ike_messages`, `ike_proposals`, `esp_packets`,
  `ah_packets`, `flows`, `protocol_observations` for one completed analysis.
- Structured logging to `ipsec_sentinel.security` with `analysis_id`,
  `rule_id`, `duration_ms`, per-rule created/skipped counts.

## 8. Security rules (10, `RULES_VERSION=1.0.0`)

| Rule | Severity | Fires when |
| --- | --- | --- |
| `IPSEC-CRYPTO-001` | LOW | ESP/IKE encryption unverifiable (`UNKNOWN`) — never for recognized algos |
| `IPSEC-CRYPTO-002` | CRITICAL/HIGH/MEDIUM | static weak table: NULL→CRITICAL, DES-family→HIGH, 3DES→MEDIUM, AES key<128→HIGH |
| `IPSEC-DH-001` | HIGH/MEDIUM | DH groups {1,2,3,22}; absent/unknown groups never fire |
| `IPSEC-PFS-001` | MEDIUM | child SA (CREATE_CHILD_SA/QUICK_MODE) visible **without** KE/DH; no child exchange → UNKNOWN → **no finding** |
| `IPSEC-IKE-001` | LOW | setup exchanges present, no later-stage exchange, ESP/AH present (capture may be partial — stated) |
| `IPSEC-SA-001` | MEDIUM/HIGH | unresolved SELECTED transforms (MEDIUM) or conflicting SELECTED proposals (HIGH, conf LOW) |
| `IPSEC-REPLAY-001` | MEDIUM | non-increasing seq per (SPI, direction); 2³¹ wrap-aware; anomalies capped at 25; ESP/AH separate |
| `IPSEC-COMPOSITE-001` | INFO | same (SPI, direction) carries both ESP and AH — informational only |
| `IPSEC-META-001` | INFO | non-IPsec protocols (DNS/HTTP…) alongside `protocol_detected=yes`; IPv4/IPv6/ARP ignored |
| `IPSEC-META-002` | INFO | ≥20 IKE setup requests per (src, dst) endpoint pair |

Full catalogue with confidence semantics: [`docs/security-rules.md`](security-rules.md).

## 9. Database & migration

- Migration `b7f0a1e2034a` (down `4f9c6d7e2a81`): adds `finding_id`,
  `rule_version`, `confidence`, `status`, `source`, `observed_value`,
  `expected_value`, `evidence_digest`; creates native PG enums
  `finding_confidence` / `finding_status` (plus type/severity/confidence
  column types), `USING` casts on PG, `batch_alter_table` rebuild on SQLite.
- Constraints: `UNIQUE(analysis_id, rule_id, evidence_digest)`, unique
  `finding_id` + supporting indexes.
- Enum convention: DB stores uppercase member names (`HIGH`, `OPEN`), API
  serializes `.value` (`"high"`, `"open"`). Evidence JSON key is `version`.
- **Verified:** upgrade→downgrade→upgrade round-trip on SQLite
  (`/tmp/p3_migrate2.db`) **and** PostgreSQL 5433. Tables were empty →
  conversion lossless.

## 10. API

| Method | Path | Behavior |
| --- | --- | --- |
| `POST` | `/api/v1/analyses/{key}/assess` | run 10 rules, persist new findings → `AssessmentResultRead` (`analysis_id`, `rule_version`, `rules_run`, `created`, `skipped`, `total_findings`, `duration_ms`, per-rule breakdown); **409** `ANALYSIS_NOT_ASSESSABLE` unless analysis `completed`; **404** unknown analysis |
| `GET` | `/api/v1/analyses/{key}/findings` | paginated findings, newest first (`_paginate_findings`) |
| `GET` | `/api/v1/analyses/{key}/findings/{key}` | by `SEC-000001` human id **or** row UUID; **404** `FINDING_NOT_FOUND` |

Finding items carry `finding_id`, `rule_id`, `rule_version`, severity/
confidence/status (lower-case), `category`, `observed_value`/`expected_value`,
and full machine-readable `evidence` (`version`, items with
source/field/observed/expected/`observation_status`, `packet_ids`,
`message_ids`, `notes`). Standard envelope throughout; Swagger at `/docs`.

## 11. Frontend

- **Security** tab on analysis detail: *Run assessment* button (`RefreshCw`),
  six severity-count stat cards (total/critical/high/medium/low/info — **no
  single score**), findings table, click-to-expand `FindingDetail` with
  metadata (`DetailLine`) + `EvidenceBlock` (JSON evidence rendered
  readably).
- Empty states until an assessment has run; assess mutation invalidates
  findings + analysis + analyses + dashboard stats so counters refresh.
- StatusBadge covers `critical` (danger), `high` (destructive), `medium`
  (warning), `low` (secondary), `info` (info), `open` (secondary),
  `acknowledged` (warning), `resolved` (success).
- Gates: `typecheck` clean, `lint` 0 errors (2 pre-existing warnings),
  `build` ✓ 395.40 kB.

## 12. Tests (101 passed)

- `test_security_rules.py` — registry validation; evidence digest
  deterministic and order-independent; **every rule positive + negative**;
  replay wrap (2³¹) and 25-cap; PFS no-child-exchange → no finding; weak-DH
  unknown-group → no finding.
- `test_security_api.py` — assess creates the expected rule set; re-assess →
  `created=0`; plaintext capture → 0 findings; 409 before completion; 404
  analysis/finding; findings list/detail by SEC id and UUID; sequential SEC
  ids; `rule_version` stamped.
- `test_database.py` — 13 tables present, enum round-trip, unique
  `(analysis, rule, evidence_digest)`, unique `finding_id`.
- `synthetic_pcap.py` — `build_plaintext_pcap()` added for the zero-findings
  case.

## 13. Idempotency & evidence (how honesty is enforced)

- Dedupe key `(analysis_id, rule_id, evidence_digest)`; digest = canonical
  SHA-256 over sorted evidence items + sorted/deduped packet/message ids +
  observed value (notes excluded → editorial edits never duplicate findings).
- Evidence items always carry `observation_status`
  (`observed`/`inferred`/`not_observable`/`unknown`/…); a draft is only
  produced when the underlying observation supports the claim.
- **`UNKNOWN` never becomes a finding**; unverifiable encryption is reported
  as `IPSEC-CRYPTO-001` visibility `informational`, never as "weak".
- No evidence → no finding (PFS, weak-DH, weak-crypto, replay all proven by
  negative tests).

## 14. Severity vs confidence (explicit, never computed)

- `severity` comes only from the rule/condition tables in
  [`docs/security-rules.md`](security-rules.md) — never averaged, never
  scored.
- `confidence` reflects observation strength: `HIGH` directly observed,
  `MEDIUM` inferred/aggregated, `LOW` structurally hard to confirm (e.g.
  conflicting SELECTED proposals). A finding may be HIGH severity / LOW
  confidence simultaneously.
- **No global security score exists anywhere in Phase 3** — that is Phase 5,
  grounded in real findings.

## 15. Known limitations (reported honestly)

1. Assessment reads only persisted Phase 2 rows — the analysis must be
   `completed` (409 otherwise); no live re-parsing.
2. ESP payloads are never decrypted; encryption verification depends on what
   IKE/ESP metadata the capture exposes (`IPSEC-CRYPTO-001` exists precisely
   for this gap).
3. `IPSEC-IKE-001` and `IPSEC-REPLAY-001` are deliberately conservative: a
   truncated capture or normal reordering is consistent with the same
   observation — findings state this in their evidence notes.
4. Changing a rule's semantics requires a `RULES_VERSION` bump; existing
   findings keep the version that produced them (no retroactive rewrite).
5. tshark not installed / Docker unavailable on the reference host (scapy +
   builtin readers active; PG verified directly on `:5433`) — unchanged from
   Phase 2.
6. No authentication (`AUTH_ENABLED=false`), no report generation, no AI/ML —
   out of Phase 3 scope.

## 16. Example assessment output (live, synthetic capture)

```json
{
  "analysis_id": "ANL-000001",
  "rule_version": "1.0.0",
  "rules_run": 10,
  "created": 3,
  "skipped": 0,
  "total_findings": 3,
  "duration_ms": 28.2,
  "rules": [
    {"rule_id": "IPSEC-CRYPTO-001", "created": 1, "skipped": 0},
    {"rule_id": "IPSEC-IKE-001",    "created": 1, "skipped": 0},
    {"rule_id": "IPSEC-META-001",   "created": 1, "skipped": 0}
  ],
  "completed_at": "2026-09-23T21:40:00Z"
}
```

First finding detail:

```json
{
  "finding_id": "SEC-000001",
  "rule_id": "IPSEC-CRYPTO-001",
  "severity": "low",
  "confidence": "high",
  "status": "open",
  "observed_value": "UNKNOWN",
  "expected_value": "A recognized algorithm such as AES_CBC or AES_GCM_16",
  "evidence": {
    "version": "1",
    "items": [{"source": "esp_packets", "field": "encryption_algorithm",
               "observed_value": "UNKNOWN", "observation_status": "observed"}],
    "packet_ids": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
    "notes": ["12 ESP packet(s) recorded without a verifiable encryption algorithm (payloads are not decrypted)."]
  }
}
```

## 17. Next recommended step

**STOP — Phase 3 complete.** Do not start Phase 4.

Natural successors (tracked in [`docs/implementation-plan.md`](implementation-plan.md)):

- **Phase 4 — AI/ML-assisted analysis:** CPU-only models over the persisted
  `flow_features`, producing findings with observation status
  `MODEL_PREDICTED` (reserved, currently unused), `analyzer_version`/
  `model_version` stamping, summarization into
  `analyses.summarization_json`.
- **Phase 5 — Reporting & scoring:** security score grounded strictly in real
  findings (never hardcoded), executive/technical/JSON reports, severity-based
  triage on the Findings page, export & scheduling.
- Cross-cutting: authentication, structured logging/observability, CI,
  root-level integration suite against the arm64 StrongSwan testbed.