# Phase 4 — Final Report

**IPsec Sentinel — Problem Statement 26160** · AI/ML-assisted analysis ·
CPU-only scikit-learn · 27-feature schema contract · capture-level splitting ·
abstaining classifier · **ships with no model, by design** · ML never becomes a
security claim.

---

## 1. The headline

Phase 4 implements a real, versioned, reproducible ML pipeline — and it ships
**inert**, because this repository contains no operator-supplied ground truth.

```
POST /api/v1/ml/train
200 OK
{ "status": "INSUFFICIENT_LABELED_DATA", "trained": false, "metrics": null }
```

No model is fitted. No artifact is written. The API explains why and tells the
operator what to do. That refusal is the acceptance criterion, and it is
verified end-to-end against real PostgreSQL (§6).

This is the difference between *implementing ML* and *claiming ML results*. The
first is delivered. The second would be false.

---

## 2. What was built

### 2.1 Feature contract

`configs/ml_feature_schema.yaml` (181 lines) is the authoritative contract between
the Phase 2 feature store and any model: 27 approved features with units,
bounds and nullability; a declared class vocabulary; a **reasoned exclusion
set**; the preprocessing spec; and the split/seed/sample-floor parameters. A
feature list that intersects the exclusion set is rejected at load.

### 2.2 Backend `app/ml/` — 13 modules, 2533 lines

| Module | Lines | Responsibility |
| --- | --- | --- |
| `schema.py` | 247 | loads/validates the contract; asserts the exclusion set holds |
| `statuses.py` | 44 | one typed definition of the status vocabulary |
| `validation.py` | 169 | accept/reject per row, with stable reason codes |
| `labels.py` | 206 | the operator label registry — the only label source |
| `dataset.py` | 300 | join → resolve labels → validate → split → digest |
| `splitter.py` | 191 | capture-level deterministic split + leakage assertion |
| `preprocessing.py` | 169 | fitted `ColumnTransformer`; missing indicators |
| `baseline.py` | 75 | `RandomForestClassifier(class_weight="balanced")` |
| `metrics.py` | 223 | held-out metrics, calibration, and the small-sample refusal |
| `trainer.py` | 323 | refuse → fit → evaluate → version → write |
| `artifacts.py` | 322 | versioned registry, `joblib` trust boundary, fingerprints |
| `predictor.py` | 230 | compatibility check, inference, abstention, summaries |

Plus `services/ml_service.py` (804), `schemas/ml.py` (262), `endpoints/ml.py`
(354), `models/traffic_prediction.py` (133), and migration
`d5a1b8f3c204` (203).

### 2.3 Frontend

| File | Lines | Purpose |
| --- | --- | --- |
| `pages/traffic-intelligence-page.tsx` | 513 | Traffic Intelligence landing page (`/traffic`) |
| `components/ml-predictions.tsx` | 587 | shared prediction/metric/model/dataset UI |
| `lib/ml.ts` | 147 | pure presentation helpers and status explanations |
| `types/api.ts` | +253 | ML contracts |
| `lib/api-client.ts` | +methods | ML endpoints |
| `hooks/use-api.ts` | +hooks | queries/mutations with invalidation |
| `pages/analysis-detail-page.tsx` | +199 | per-analysis **Predictions** tab |

---

## 3. Design decisions that matter

### 3.1 Labels can only come from outside the capture

A label is a claim about what the traffic *actually was*. Nothing in a PCAP can
prove it. `ML_LABEL_FILE` is the only source; `label_source` must be
`user_provided`; provenance is recorded as `USER_PROVIDED`. The schema
explicitly forbids port heuristics, filename parsing, synthetic PCAPs, model
self-labelling and Phase 3 finding derivation.

The consequence: port 5060 is a *feature*, never a label. Inferring "this is
voice" from a port would produce ~100% accuracy on a dataset whose labels were
derived from the same port — a self-referential number that measures nothing.

### 3.2 The split unit is the capture

Flows within one capture share endpoints, time window, MTU, network stack and
often an application session. A flow-level split produces test scores that look
excellent and measure memorisation of one capture's traffic mix. The failure is
**invisible in the metrics**, which is why `allocate_captures` +
`assert_no_capture_leakage` make it a checked invariant. Splitting uses
`sorted(capture_keys)` + a seeded RNG; Python's per-process-salted `hash()` is
never used.

### 3.3 Small samples produce no numbers

A 2-sample test split yields accuracy 0.0 or 1.0. Below
`min_samples_for_metrics` (20) the artifact records `INSUFFICIENT_DATA` and the
metric block is **absent** — not zero, not `null`, absent. The API returns
`metrics: null` with an explicit note explaining that no metrics are claimed.

### 3.4 Abstention is a first-class outcome

Below `ML_MIN_CONFIDENCE` (0.60): `prediction="UNKNOWN"`, `abstained=true`,
`top_candidate` retained, and `observation_status` **stays `model_predicted`**.
The model ran and produced an observation; it declined to be specific. That is
different from `MODEL_NOT_AVAILABLE`, and the two are never conflated.

### 3.5 `null` is not zero

`null` in the feature store means "not computable for this flow". It is never
coerced to `0.0`, and out-of-range values are **rejected, not clipped** — a
negative duration is a corrupt row, not a duration of zero. Preprocessing adds
one binary missing-indicator column per numeric feature so the model can tell
"not computable" from "genuinely zero".

### 3.6 ML is advisory and structurally separate

`TrafficPrediction` is a different table from `SecurityFinding` with different
authority. ML cannot create a finding, set severity, or affect a risk score.
`TestPhase3Isolation` asserts against the database that finding count and
`analyses.rule_version` are unchanged across a full train → predict cycle, and
the E2E re-verifies it live on PostgreSQL.

### 3.7 Unavailability is not an error

`DISABLED`, `MODEL_NOT_AVAILABLE`, `INSUFFICIENT_DATA` and
`INSUFFICIENT_LABELED_DATA` are all **HTTP 200** with an explicit `status`, so
the UI renders an informative empty state rather than a failure banner. HTTP
errors are reserved for genuine faults: 404 unknown analysis/model, 403 training
while disabled, 400 malformed version.

---

## 4. Files created — backend

```
backend/app/ml/__init__.py                            34
backend/app/ml/artifacts.py                          322
backend/app/ml/baseline.py                            75
backend/app/ml/dataset.py                            300
backend/app/ml/labels.py                             206
backend/app/ml/metrics.py                            223
backend/app/ml/predictor.py                          230
backend/app/ml/preprocessing.py                      169
backend/app/ml/schema.py                             247
backend/app/ml/splitter.py                           191
backend/app/ml/statuses.py                            44
backend/app/ml/trainer.py                            323
backend/app/ml/validation.py                         169
backend/app/services/ml_service.py                   804
backend/app/schemas/ml.py                            261
backend/app/api/v1/endpoints/ml.py                   347
backend/app/models/traffic_prediction.py             133
backend/alembic/versions/d5a1b8f3c204_...py          207
backend/scripts/ml_e2e.py                            265
backend/tests/ml_fixtures.py                         322
backend/tests/test_ml_pipeline.py                   1010
backend/tests/test_ml_api.py                         618
configs/ml_feature_schema.yaml                       181
```

## 5. Files created — frontend & docs

```
frontend/src/pages/traffic-intelligence-page.tsx     513
frontend/src/components/ml-predictions.tsx           587
frontend/src/lib/ml.ts                               147
docs/phase-4-architecture.md
docs/ml-dataset-plan.md
docs/ml-reproducibility.md
docs/ml-security.md
docs/ml-api.md                                       446
docs/phase-4-report.md                               (this file)
```

## 6. Commands run (all PASSED)

```bash
# backend gates
cd backend
ruff check app tests scripts                     -> All checks passed!
ruff format --check app tests scripts            -> 113 files already formatted
mypy app tests                                   -> Success: no issues found in 113 source files
python -m pytest                                 -> 255 tests, 0 failures, 0 errors, 0 skipped
  tests/test_ml_pipeline.py                      -> 84
  tests/test_ml_api.py                           -> 47

# migrations — SQLite
alembic upgrade head && alembic downgrade -1 && alembic upgrade head   -> OK

# migrations — PostgreSQL 5433 (clean database)
alembic upgrade head                             -> d5a1b8f3c204
alembic downgrade -1                             -> type + table removed
alembic upgrade head                             -> d5a1b8f3c204
alembic check                                    -> No new upgrade operations detected.

# Phase 4 E2E against real PostgreSQL 5433
DATABASE_URL=postgresql+psycopg://…@localhost:5433/ipsec_sentinel_p4 \
  python scripts/ml_e2e.py                       -> E2E PASSED (45 checks)

# frontend gates
npm run typecheck                                -> clean
npm run lint                                     -> 0 errors, 2 pre-existing warnings
npm run build                                    -> 1960 modules, built in 387ms
```

The 2 lint warnings are in `components/ui/badge.tsx` and
`components/ui/button.tsx` (shadcn `react-refresh` advisories) — untouched
Phase 1 scaffolding, present before Phase 4.

---

## 7. Live E2E (real PostgreSQL, real Scapy capture)

`scripts/ml_e2e.py` — upload → analyze → Phase 3 assess → ML health → train →
dataset → predict → Phase 3 re-assess → delete. Real Scapy PCAP (3239 bytes,
SHA-256 verified), real PostgreSQL 5433, no fabricated values.

| # | Step | Result |
| --- | --- | --- |
| 1 | Upload Scapy PCAP | 200, SHA-256 `411fef80a46a2ba0…` recorded |
| 2 | Analyze | completed, 4 flow-feature rows persisted |
| 3 | Phase 3 assess | 200, `rule_version=1.0.0`, 10 rules run, 3 findings created |
| 4 | `GET /ml/health` | 200, `any_model_available=false`, `active_model_version=null`, reason + remediation present, 27 features |
| 5 | `POST /ml/train` | 200, `INSUFFICIENT_LABELED_DATA`, `trained=false`, `metrics=null`, **model dir empty** |
| 6 | `GET /ml/dataset` | 200, 4 feature rows visible, 0 labeled, registry `none`, notes explain the zero, no split |
| 7 | `POST .../predict` | 200, `MODEL_NOT_AVAILABLE`, 0 predictions produced, `created=0`, **0 rows written** |
| 8 | Re-assess | 200, `created=0` (idempotent), `rule_version` unchanged `1.0.0`, findings 3 → 3 |
| 9 | Delete capture | 200, analysis 404 after cascade |

Steps 5 and 7 are the important ones: with ML enabled and no ground truth, the
system **declines to produce a model and declines to write predictions**, and
says exactly why.

---

## 8. Two real defects found and fixed during verification

Recording these because "tests passed" was not sufficient to catch either.

### 8.1 PostgreSQL migration was broken — enum created twice

`d5a1b8f3c204` failed on a real PostgreSQL database with
`type "observation_status" already exists`. The migration created the enum
explicitly via `op.execute` *and* let `sa.Enum` emit its own `CREATE TYPE`
inside `create_table`.

**SQLite cannot catch this** — it renders every `Enum` as `VARCHAR` and never
creates a type — so the SQLite round-trip passed while no PostgreSQL deployment
could upgrade at all. The earlier "verified on SQLite" note was a real gap.

Fixed with a dialect-aware column type: `postgresql.ENUM(..., create_type=False)`
on PostgreSQL (the explicit create owns the type), `sa.String(32)` on SQLite.
Upgrade/downgrade/upgrade now verified on both, and `alembic check` is clean.

### 8.2 `/dataset` ignored the request's `label_file`

`run_training` resolves labels as *request `label_file` → `ML_LABEL_FILE`*, but
`dataset_report` only ever read `ML_LABEL_FILE`. So an operator who trained
against an explicit label file was told by `/dataset` that **zero rows were
labeled** — while training had just succeeded on 264 rows. That directly
contradicts the endpoint's own docstring ("read exactly as training would read
it") and is precisely the kind of misleading number this project exists to
avoid.

Fixed by threading `label_file` through `dataset_report` and exposing it as a
bounded query parameter on `GET /ml/dataset`, with a regression test
(`test_dataset_endpoint_audits_an_explicit_label_file`).

### 8.3 One ambiguity documented rather than changed

`PredictionRunResponse.total` counts **candidate flows considered**, not
predictions produced, so it is non-zero (4) on a `MODEL_NOT_AVAILABLE` run
while `summary.count` is 0. That is informative — it tells the operator how much
data is waiting — and the frontend already renders it as "rejected of N flows".
Rather than discard the signal, the field descriptions and
`docs/ml-api.md` §7.0 now state the semantics, and a test pins the behaviour.

---

## 9. Tests (255 passed)

| Suite | Count | Coverage |
| --- | --- | --- |
| `test_ml_pipeline.py` | 84 | schema loading + exclusion assertions, per-row validation and reason codes, label registry (incl. every forbidden source and non-`user_provided` refusal), capture-level splitting + leakage assertion, preprocessing, artifact path traversal / symlink escape / version validation, trainer refusal paths, determinism, metrics incl. the small-sample refusal, predictor abstention + schema-mismatch refusal |
| `test_ml_api.py` | 47 | all 13 endpoints, no-label refusal, training-disabled guard, `/dataset` label-file audit, model list/detail/metrics incl. null-metrics note, idempotent re-run, abstention, 404 paths, `model_predicted` semantics, Phase 3 isolation |
| pre-existing | 124 | Phases 1–3, unchanged and still green |

The ML tests fit real models through the real trainer to exercise mechanics.
They assert **no accuracy**.

---

## 10. Honest limitations

1. **No model ships.** `POST /ml/train` refuses and the Traffic page shows
   `MODEL_NOT_AVAILABLE`. Correct and tested, but it means the classifier has
   never seen real traffic. Producing a defensible accuracy number requires the
   operator-supplied ground truth in `docs/ml-dataset-plan.md` §5.
2. **No real-world accuracy claim exists anywhere.** The perfect scores the
   fixtures produce are an artifact of the generator separating classes by a
   fixed offset; they demonstrate that evaluation, splitting and artifact
   writing work, nothing more.
3. **`joblib.load` executes pickle.** A model file in `ML_MODEL_DIR` is trusted
   by definition. Path traversal, API-supplied paths and symlink escape are all
   closed, but an untrusted pickle cannot be made safe. See
   `docs/ml-security.md` §4.
4. **`analyses.summarization_json` is still empty.** Summarisation needs a
   language model and real content; it is not attempted.
5. **No ONNX/llama.cpp runtime.** The plan named them as candidates; scikit-learn
   is the smallest thing satisfying CPU-only + arm64. A model-format change
   would need artifact-format work.
6. **Confidence is not risk and not a score.** Those are Phase 5.
7. **No browser E2E.** The frontend has no test runner, so UI verification was
   `typecheck` + `lint` + `build` plus API-level contract checks, not a
   click-through. TShark and Docker were unavailable.
8. **No multi-tenant model isolation.** One deployment, one registry.

---

## 11. Recommended next step

Not Phase 5. **Obtain ground truth** and produce one honest model:

1. stand up the controlled testbed described in `docs/ml-dataset-plan.md` §5;
2. collect ≥ 20 captures per class, label from run logs (not ports);
3. write the registry, set `ML_LABEL_FILE`;
4. `GET /api/v1/ml/dataset` to audit coverage;
5. `POST /api/v1/ml/train`, then read the **held-out** metrics and calibration
   error before trusting anything;
6. commit the resulting `metadata.json` (not the binary) so the model is
   reproducible and auditable.

Only after a model with honest metrics exists is a security score (Phase 5)
meaningful — and it must be grounded in Phase 3 findings, never in model output.
