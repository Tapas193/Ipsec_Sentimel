# Deterministic Security Assessment — IPsec Sentinel

Phase 3 implements the security assessment layer of the framework as a
**deterministic, rule-based engine**. Given the constraints of Problem
Statement 26160 (CPU-only, no GPU, honest results, no fabricated values),
security assessment is *not* AI/ML-assisted here: every finding is produced by
an explicit, versioned rule that evaluates the **persisted Phase 2 data** of a
completed analysis and attaches machine-readable evidence.

This document covers the engine design, the API surface, idempotency, and how
to run and extend assessments. The rule catalogue lives in
[`docs/security-rules.md`](security-rules.md).

---

## 1. Guiding principles

1. **Deterministic.** The same analysis re-assessed with the same rules yields
   exactly the same findings. No randomness, no model weights, no ML.
2. **Evidence-backed.** Every finding carries evidence items (source, field,
   observed value, expected value, observation status) plus the packet/IKE
   message ids that support it — a reviewer can trace every conclusion.
3. **No evidence → no finding.** Values the parser could not resolve stay
   `UNKNOWN` and are reported as unverifiable, never silently classified as
   weak or strong. Observation status `UNKNOWN` never raises a finding.
4. **No decryption, no shell.** The engine consumes only persisted database
   rows. ESP payloads are never decrypted; rules never execute code or shell
   commands.
5. **Severity ≠ confidence.** `severity` comes from the explicit rule/condition
   table; `confidence` reflects how strongly the observation supports the
   claim (and may be LOW even for a HIGH-severity claim).
6. **Idempotent.** Re-running `assess` creates nothing new.

## 2. Engine architecture

```
                       persisted Phase 2 rows
  ike_messages ─┬─ ike_proposals  esp_packets  ah_packets
                 │   flows  flow_features  protocol_observations
                 ▼
        ┌──────────────── An assessment run ────────────────┐
        │  for each Rule in RULES (app.security.registry):   │
        │      drafts = rule.evaluate(AssessmentContext)     │
        │      for each draft:  digest = evidence_digest()   │
        │        exists (analysis, rule, digest)?            │
        │           yes → skip (idempotent)                  │
        │           no  → persist SecurityFinding (SEC-…)    │
        │  stamp analysis.rule_version = RULES_VERSION       │
        └────────────────────────────────────────────────────┘
```

- **`app.security.rules`** — the rule implementations (pure functions of an
  `AssessmentContext`; no DB access).
- **`app.security.context.AssessmentContext`** — an immutable snapshot of the
  analysis and its persisted sub-resources.
- **`app.security.evidence`** — `EvidenceItem` / `FindingEvidence`, the
  evidence schema version, and `evidence_digest` (canonical SHA-256 used for
  idempotency).
- **`app.security.registry`** — `RULES_VERSION` + the ordered rule tuple;
  validates rule ids (`IPSEC-*`), uniqueness and category membership at import.
- **`app.services.security_service`** — loads context, runs rules, dedupes,
  assigns `SEC-000001`-style ids, stamps `analysis.rule_version`, commits, and
  returns an assessment summary. Structured logging goes to the
  `ipsec_sentinel.security` logger with `analysis_id`, `rule_id`, `duration_ms`
  and per-rule counts.

### Enumerations

| Enum | Values | Stored / serialized |
| --- | --- | --- |
| `Severity` | `INFO LOW MEDIUM HIGH CRITICAL` | member **name** in DB, `.value` in API |
| `FindingType` | `VULNERABILITY_INDICATOR POLICY_DEVIATION CONFIGURATION_RISK INFORMATIONAL UNKNOWN` | name / value |
| `FindingConfidence` | `HIGH MEDIUM LOW UNKNOWN` | name (`finding_confidence`) / value |
| `FindingStatus` | `OPEN ACKNOWLEDGED RESOLVED` | name (`finding_status`) / value |
| `ObservationStatus` | `OBSERVED INFERRED MODEL_PREDICTED NOT_OBSERVABLE USER_PROVIDED UNKNOWN` | value |

Following the codebase convention, DB columns store uppercase `SAEnum` member
names (`HIGH`, `OPEN`) while the API serializes the lower-case StrEnum value
(`"high"`, `"open"`).

## 3. The `SecurityFinding` row

Phase 3 fields added to `security_findings`:

| Column | Type | Notes |
| --- | --- | --- |
| `finding_id` | `String(32)`, unique, indexed | human readable `SEC-000001` (via `next_sequence_id`) |
| `rule_version` | `String(32)` | rules version that produced the finding |
| `confidence` | `finding_confidence` enum (default `HIGH`) | observation strength |
| `status` | `finding_status` enum (default `OPEN`) | lifecycle; starts `OPEN` |
| `source` | `String(64)` | `assessment_engine` (future: other producers) |
| `observed_value` / `expected_value` | `Text` | human-oriented claim text |
| `evidence_digest` | `String(64)` | canonical SHA-256 over evidence |

Idempotency and uniqueness: `UniqueConstraint(analysis_id, rule_id,
evidence_digest)` plus a unique index on `finding_id`. A dedicated index backs
`ix_security_findings_analysis_rule_evidence`.

`evidence_json` holds the machine-readable evidence (schema version, items,
`packet_ids`, `message_ids`, notes); the model exposes it as a parsed
`evidence` property.

## 4. API

All under `/api/v1`, using the standard response envelope.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/analyses/{analysis_key}/assess` | Run the rules, persist new findings, return `AssessmentResultRead` |
| `GET` | `/analyses/{analysis_key}/findings` | Paginated findings for the analysis, newest first |
| `GET` | `/analyses/{analysis_key}/findings/{finding_key}` | Single finding by `SEC-…` human id or row UUID |

Errors:

| Code | Status | When |
| --- | --- | --- |
| `ANALYSIS_NOT_ASSESSABLE` | 409 | analysis not `completed` |
| `ANALYSIS_NOT_FOUND` | 404 | unknown analysis key |
| `FINDING_NOT_FOUND` | 404 | unknown finding key |

### `POST /analyses/{key}/assess` response (abridged)

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
    {"rule_id": "IPSEC-CRYPTO-001", "created": 1, "skipped": 0}
  ],
  "completed_at": "2026-09-23T21:40:00Z"
}
```

`created` counts findings persisted by this run; `skipped` counts drafts that
were already present (idempotent re-runs report `created: 0`). The action also
stamps `analyses.rule_version`, which the Overview tab surfaces.

### `GET /analyses/{key}/findings` item (abridged)

```json
{
  "finding_id": "SEC-000001",
  "rule_id": "IPSEC-CRYPTO-001",
  "rule_version": "1.0.0",
  "severity": "low",
  "confidence": "high",
  "status": "open",
  "category": "VISIBILITY",
  "observed_value": "UNKNOWN",
  "expected_value": "A recognized algorithm such as AES_CBC or AES_GCM_16",
  "evidence": {
    "version": "1",
    "items": [
      {"source": "esp_packets", "field": "encryption_algorithm",
       "observed_value": "UNKNOWN", "expected_value": "…",
       "observation_status": "observed"}
    ],
    "packet_ids": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
    "message_ids": [],
    "notes": ["12 ESP packet(s) recorded without a verifiable encryption algorithm (payloads are not decrypted)."]
  }
}
```

## 5. Idempotency under the hood

Dedupe key = `(analysis.rule_version-independent of run)`: `analysis_id +
rule_id + evidence_digest`. `evidence_digest` is a SHA-256 over the canonical
evidence (items sorted, `observed_value` JSON-normalized, packet/message ids
deduplicated and sorted; notes intentionally excluded so editorial text does
not create duplicate findings). Two rule runs that produce identical evidence
therefore resolve to the same digest and the second is skipped.

## 6. Rules versioning

`RULES_VERSION = "1.0.0"` is stamped onto every persisted finding and onto
`analyses.rule_version`, so results are reproducible across engine releases.
Bumping the version is a deliberate act; existing findings keep the version
that produced them.

## 7. Running an assessment

```bash
# Backend must be running and the analysis completed.
curl -X POST http://localhost:8000/api/v1/analyses/ANL-000001/assess
curl http://localhost:8000/api/v1/analyses/ANL-000001/findings
```

From the React dashboard: open an analysis → **Security** tab → *Run
assessment* → severity counts (total/critical/high/medium/low/info, not a
single score), findings table, expandable evidence per finding.

## 8. Testing

- `backend/tests/test_security_rules.py` — unit tests for every rule
  (positive + negative branches), evidence digest determinism, registry.
- `backend/tests/test_security_api.py` — assess/findings endpoints,
  idempotency, 409/404 error paths, plaintext-capture zero-findings case.
- `backend/tests/test_database.py` — enum round-trip, `(analysis, rule,
  evidence)` uniqueness, `finding_id` uniqueness.
- `backend/scripts/pg_e2e.py` — full-flow E2E against PostgreSQL 5433
  including assess → findings → idempotent re-run.

## 9. Scope guardrails

- No single "security score" is computed (Phase 5, grounded in real findings).
- No AI/ML model predicts findings — observation status `MODEL_PREDICTED` is
  reserved and unused by the current engine.
- ESP payloads are never decrypted; unknown encryption stays unknown.
- Live capture / injection / StrongSwan automation remain out of scope.