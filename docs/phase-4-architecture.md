# Phase 4 — Architecture (AI/ML-assisted analysis)

**IPsec Sentinel — Problem Statement 26160** · CPU-only · scikit-learn ·
versioned, reproducible artifacts · abstaining classifier · ML never becomes a
security claim.

This document describes how Phase 4 is built and, more importantly, how it is
constrained. Every "refuses to" statement below is enforced in code and covered
by a test.

---

## 1. Where Phase 4 sits

```
Phase 2 (real)                      Phase 3 (deterministic)     Phase 4 (probabilistic)
─────────────────────────────       ───────────────────────     ─────────────────────────
captures ─ SHA-256 verified        analyses.rule_version       configs/ml_feature_schema.yaml
analyses ─ parser/analyzer ver.    SecurityFinding             app/ml/*  (schema → dataset →
flows ─ bidirectional                 IPSEC-* rules              validator → splitter → trainer)
flow_features.feature_json         evidence_digest                │
  (27 approved ML features)                                     ▼
                                                   TrafficPrediction (model_version)
                                                   observation_status=MODEL_PREDICTED
                                                              │
                                                              ▼
                                                   frontend: Traffic Intelligence page
                                                   + analysis detail "Predictions" tab
```

Phase 4 is **read-only** with respect to Phase 2 and Phase 3. It reads persisted
`flow_features` rows and writes only its own table. It never mutates an analysis,
a flow, or a `SecurityFinding`.

### 1.1 Two kinds of claim, two different tables

| | `SecurityFinding` (Phase 3) | `TrafficPrediction` (Phase 4) |
| --- | --- | --- |
| Basis | deterministic rule over parsed evidence | probabilistic model over flow features |
| Authority | authoritative, evidence-backed | advisory, not a security claim |
| Status vocabulary | `OPEN`/`ACKNOWLEDGED`/`RESOLVED` | `MODEL_PREDICTED` |
| Feeds severity / risk / score | yes (severity is rule-declared) | **never** |
| Produced by a rule table | yes | no |

`app/models/traffic_prediction.py` documents this at the class level, and
`backend/tests/test_ml_api.py::TestPhase3Isolation` asserts it against the
database: after a full train → predict cycle, `SecurityFinding` count and
`analyses.rule_version` are byte-for-byte unchanged.

---

## 2. Module map (`backend/app/ml/`)

| Module | Lines | Responsibility |
| --- | --- | --- |
| `schema.py` | 247 | Loads/validates `configs/ml_feature_schema.yaml`; `MLFeatureSchema`, `MLFeatureDefinition`; asserts no feature intersects the exclusion set |
| `statuses.py` | 44 | The single typed definition of `RunStatus` / `TrainStatus` literals, shared by service, predictor and Pydantic schemas |
| `validation.py` | 169 | Per-row acceptance/rejection against the schema; `ValidatedRow`, `Rejection`, stable reason codes |
| `labels.py` | 206 | Reads the operator label registry from `ML_LABEL_FILE`; match by `capture_id` or `capture_sha256`; records `USER_PROVIDED` provenance |
| `dataset.py` | 300 | Joins `flow_features` → `flows` → `analyses` → `captures`, resolves labels, validates rows, assigns splits, computes the dataset digest |
| `splitter.py` | 191 | Capture-level deterministic split; `assert_no_capture_leakage` |
| `preprocessing.py` | 169 | Fitted `ColumnTransformer` (median impute + missing indicators + standard scaler); `rows_to_matrix` |
| `baseline.py` | 75 | `RandomForestClassifier` pipeline; the CPU-first model choice |
| `metrics.py` | 223 | Accuracy / macro P,R,F1 / confusion matrix / log loss / ECE / abstention rate, with the small-sample refusal |
| `trainer.py` | 323 | `train_model`: refuse → fit → evaluate → version → write artifact |
| `artifacts.py` | 322 | Versioned artifact registry, `joblib` load trust boundary, environment fingerprint |
| `predictor.py` | 230 | `load_compatible_artifact`, `predict_rows`, confidence threshold, abstention |
| `__init__.py` | 34 | Docstring-only exports (no eager sklearn import) |

Service and transport layers:

| File | Lines | Responsibility |
| --- | --- | --- |
| `app/services/ml_service.py` | 804 | Orchestration: health, dataset report, training, idempotent inference, listing, deletion |
| `app/api/v1/endpoints/ml.py` | 335 | 13 routes under `/api/v1/ml` |
| `app/schemas/ml.py` | 249 | Request/response models, `ApiResponse[T]` wrapping |
| `app/models/traffic_prediction.py` | 133 | ORM model + `TrafficType` enum |
| `alembic/versions/d5a1b8f3c204_*.py` | 186 | Phase 4 migration |

---

## 3. The data path

### 3.1 Dataset build (`app/ml/dataset.py`)

1. Read persisted `flow_features` rows for analyses whose
   `feature_schema_version` matches `source_feature_schema_version` (`"1.0"`).
   A mismatch is **rejected**, never coerced.
2. Project each row onto the 27 features in **schema order** — never database
   order, never dict order.
3. Resolve a label from the registry (`capture_id` or `capture_sha256`). No
   label → the capture is reported as unlabeled and excluded. The builder
   cannot invent one.
4. `validate_row` → `ValidatedRow` or `Rejection` with a stable reason code.
5. `allocate_captures` assigns whole captures to train/validation/test.
6. `assert_no_capture_leakage` re-checks the allocation and raises if a capture
   appears in two splits.
7. Order rows by (analysis key, flow key) and hash → `dataset_digest`.

The digest plus the seed plus the library fingerprint is what makes two runs over
the same database byte-identical.

### 3.2 Training (`app/ml/trainer.py`)

Refusal comes first, fitting second:

| Condition | Result | Fitted? | Artifact written? |
| --- | --- | --- | --- |
| `ML_TRAINING_ENABLED=false` | `DISABLED` | no | no |
| No label file / empty registry | `INSUFFICIENT_LABELED_DATA` | **no** | **no** |
| Label file unreadable / malformed | `LABEL_FILE_UNREADABLE` | no | no |
| < `min_total_samples` (40) | `INSUFFICIENT_DATA` + shortfall | no | no |
| < `min_samples_per_class` (2) | `INSUFFICIENT_DATA` + shortfall | no | no |
| < `min_captures_per_split` (1) | `INSUFFICIENT_DATA` + shortfall | no | no |
| held-out test split < `min_samples_for_metrics` (20) | artifact written, `metrics.status=INSUFFICIENT_DATA` | yes | yes (no metric numbers) |
| otherwise | `OK` / `TRAINED` | yes | yes |

**A misleading artifact can never exist**, because the first six rows all return
before `build_pipeline` is reached.

### 3.3 Inference (`app/ml/predictor.py`)

1. `load_compatible_artifact` resolves the requested version (or the newest
   schema-compatible one) and checks `feature_schema_version` **before** scoring.
   An incompatible model raises rather than producing a plausible-looking wrong
   class.
2. `rows_to_matrix` applies the artifact's own fitted preprocessor — inference
   cannot diverge from training because the transform is serialised inside the
   model.
3. `predict_proba` → the model's `classes_` label, its probability, and the
   probability vector.
4. If `max(proba) < ML_MIN_CONFIDENCE` (default `0.60`): `prediction="UNKNOWN"`,
   `abstained=true`, `top_candidate` retained, `observation_status` stays
   `MODEL_PREDICTED`.
5. Rows failing validation are rejected with reasons, never repaired.

### 3.4 Persistence (`app/services/ml_service.py`)

Idempotency key: `(flow_id, model_version)`, enforced by a unique index. A
re-run updates rows in place and reports `created` / `updated` separately, so a
client can prove the table did not grow.

---

## 4. Runtime states that are not errors

"No model exists" is a normal state for a system with no ground truth, so it
travels as **HTTP 200** with an explicit status. The UI renders it as
information, never as a failure.

| Status | Meaning | `trained`/rows | `detail.reason` |
| --- | --- | --- | --- |
| `OK` | a model ran / predictions exist | yes | — |
| `MODEL_NOT_AVAILABLE` | ML enabled, no compatible artifact | no | no compatible model |
| `INSUFFICIENT_DATA` | too few labeled flows/captures to train | no | exact shortfall |
| `DISABLED` | `ML_ENABLED=false` | no | ML disabled in config |
| `INSUFFICIENT_LABELED_DATA` | no label file / empty registry | no | no ground truth registered |
| `NO_LABELS_REGISTERED` | label file present but empty | no | — |
| `LABEL_FILE_UNREADABLE` | label file present but invalid | no | parse/validation error |

`UNKNOWN` is deliberately **not** in that table. It is a prediction *outcome*,
not a runtime state: a flow can be `UNKNOWN` while the run status is `OK`.

---

## 5. Configuration

| Setting | Default | Effect |
| --- | --- | --- |
| `ML_ENABLED` | `false` | gates inference |
| `ML_TRAINING_ENABLED` | `false` | gates training; an upload never becomes training data implicitly |
| `ML_MODEL_DIR` | `backend/data/models` | artifact registry root (gitignored) |
| `ML_FEATURE_SCHEMA_PATH` | `configs/ml_feature_schema.yaml` | feature contract |
| `ML_DEFAULT_MODEL_VERSION` | `""` | empty ⇒ resolve newest schema-compatible model |
| `ML_MIN_CONFIDENCE` | `0.60` | the only place the abstention threshold lives |
| `ML_RANDOM_SEED` | `42` | splitter + model seed |
| `ML_DATASET_VERSION` | `"1.0"` | stamped on every artifact |
| `ML_LABEL_FILE` | `""` | operator ground truth; empty ⇒ `INSUFFICIENT_LABELED_DATA` |
| `ML_MAX_TRAINING_FLOWS` | `200000` | memory bound for a single M2 |

Both gates default to **off**. Shipping ML inert is the safe default; an
operator opts in explicitly.

---

## 6. Reproducibility

`metadata.json` on every artifact records: `model_version`, `model_type`,
`dataset_version`, `feature_schema_version`, `class_definition_version`,
`analyzer_version`, `parser_version`, `preprocessing_version`, `random_seed`,
`training_samples`, `capture_count`, `feature_count`, `classes`,
`label_provenance`, `library_versions` (Python / scikit-learn / numpy / pandas /
joblib), and the dataset digest.

`evaluation.json` records the held-out metrics, confusion matrix, class
distribution, calibration error and abstention rate — or `INSUFFICIENT_DATA`
with the metric block absent.

See [`ml-reproducibility.md`](ml-reproducibility.md).

---

## 7. Security posture

The residual risk is stated plainly: `joblib.load` executes pickle, so **a model
file placed in `ML_MODEL_DIR` by an operator is trusted by definition.** The
mitigations are in [`ml-security.md`](ml-security.md); they reduce the blast
radius (no path traversal, no API-supplied paths, containment re-checked after
symlink resolution) but they cannot make an untrusted pickle safe. Loading a
model from an untrusted source requires a separate trust decision.

---

## 8. What Phase 4 deliberately does not do

- No payload decryption, no plaintext, no content inspection — the model reads
  flow *metadata* only.
- No security score, no risk level, no severity, no report generation (Phase 5).
- No summarization into `analyses.summarization_json` (still reserved, still
  empty) — that requires a language model and real content to summarise.
- No ONNX Runtime or llama.cpp model runtime. The plan named them as candidates;
  the implementation uses scikit-learn only, which is the smallest thing that
  satisfies the requirement on CPU/arm64.
- No label inference from ports, filenames, protocol names, Phase 3 findings, or
  model self-labelling.
- No auto-training on upload, no synthetic-data training, no SMOTE/oversampling.
