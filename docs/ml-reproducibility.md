# Phase 4 — Reproducibility & Evaluation

**IPsec Sentinel — Problem Statement 26160** · artifacts are build outputs ·
dataset digest + seed + library fingerprint · small samples publish no numbers.

A model you cannot reproduce is an anecdote. This document specifies what makes
a Phase 4 prediction re-derivable, and what is deliberately *not* claimed.

---

## 1. Artifacts are build outputs, not source

```
$ML_MODEL_DIR/                        # default backend/data/models/ (gitignored)
  traffic-classifier-0.1.0/
    model.joblib        # fitted sklearn Pipeline, preprocessor included
    metadata.json       # reproduction + provenance record
    evaluation.json     # held-out metrics, confusion matrix, class distribution
```

Nothing under `ML_MODEL_DIR` is tracked in git. What *is* tracked is the
registry layout contract, the feature schema, and the code that produces
artifacts. A model is therefore **reproduced by re-running the trainer**, not by
checking in a binary that nobody can audit.

This also means a clone of the repository has no model, and the API correctly
reports `MODEL_NOT_AVAILABLE`.

---

## 2. What `metadata.json` records

| Field | Why it matters |
| --- | --- |
| `model_version` | the artifact identity and the idempotency key component |
| `model_type` | e.g. `sklearn.RandomForestClassifier` — an algorithm swap is visible |
| `dataset_version` | `"1.0"`, the dataset contract this fit consumed |
| `feature_schema_version` | the compatibility gate checked before every inference |
| `class_definition_version` | the class vocabulary at fit time |
| `analyzer_version` | Phase 2 analyzer version of the source captures |
| `parser_version` | Phase 2 parser version of the source captures |
| `preprocessing_version` | transform contract |
| `random_seed` | `ML_RANDOM_SEED`, default 42 |
| `training_samples` / `capture_count` / `feature_count` | dataset size, in the three units that matter |
| `classes` | the fitted label set |
| `label_provenance` | histogram of `USER_PROVIDED` labels consumed |
| `library_versions` | Python, scikit-learn, numpy, pandas, joblib |
| `dataset_digest` | SHA-256 over the ordered, split-assigned dataset |
| `created_at` | ISO-8601 UTC |

## 3. What `evaluation.json` records

Computed on the **held-out test split only** — never on training data:

- `accuracy`
- `precision_macro`, `recall_macro`, `f1_macro`
- per-class precision/recall/F1/support
- `confusion_matrix` + `confusion_matrix_labels`
- `log_loss`
- `expected_calibration_error` (15 equal-width bins on the held-out set)
- `abstention_rate` — the share of held-out flows whose max probability fell
  below `ML_MIN_CONFIDENCE`
- `mean_predicted_confidence`
- `class_distribution` in declared class order, zeros included
- `status`: `OK`, or `INSUFFICIENT_DATA` with the metric block **absent**

### 3.1 Correctness details that are easy to get wrong

- **Calibration is measured against the model's own predictions.** A calibration
  curve answers "when the model says 0.8, is it right 80% of the time" — so it
  must bin by predicted probability and score with `y_pred`, not by true label.
  Binning by `y_true` measures the class prior, not calibration.
- **The reported class is the model's class, and `top_candidate` is the
  probability argmax.** These coincide in normal operation. When a class is
  missing from `classes_`, the predictor reports the model's label and keeps the
  argmax separately rather than silently substituting one for the other.
- **Zero-evaluation samples** yield `INSUFFICIENT_DATA`, never a division by
  zero surfacing as `NaN` in JSON.

---

## 4. Determinism

Two runs over the same database produce byte-identical artifacts. That requires
four things, all implemented:

1. **Feature order is schema order.** The matrix columns follow
   `ml_feature_schema.yaml`, not dict or database order.
2. **Row order is a stable sort key** — analysis key, then flow key — not
   database return order.
3. **Split assignment is seeded and hash-free.** `sorted(capture_keys)` then
   `random.Random(seed)`. Python's `hash()` is salted per process and would make
   splits differ between runs; it is never used.
4. **The model is seeded** with the same `random_seed`.

`dataset_digest` is asserted equal across two training runs in
`test_ml_pipeline.py::TestTrainer::test_same_seed_same_data_gives_same_metrics`.

### 4.1 What is *not* bit-reproducible

Library versions are recorded, not pinned by the artifact. A scikit-learn upgrade
may change a fitted model bit-for-bit. The `library_versions` block exists so a
mismatch is *diagnosable* rather than mysterious: if a re-run differs, compare
fingerprints first. Exact reproduction additionally requires the recorded
library set — a container pinned to it, not a fresh install.

---

## 5. Refusing to report

| Situation | Reported |
| --- | --- |
| No labels registered | `INSUFFICIENT_LABELED_DATA`, no fit, no artifact |
| < 40 total labeled flows | `INSUFFICIENT_DATA` + exact shortfall |
| any class < 2 samples | `INSUFFICIENT_DATA` + exact shortfall |
| a split with 0 captures | `INSUFFICIENT_DATA` + exact shortfall |
| held-out test split < 20 samples | artifact written; `evaluation.status = INSUFFICIENT_DATA`; **no metric numbers** |
| feature schema mismatch | `MLSchemaError`; the model refuses to score |

The first five are asserted in `test_ml_pipeline.py` and `test_ml_api.py`. A
2-sample test split is not a measurement; publishing its accuracy would be a
fabrication with extra steps.

---

## 6. Inference is reproducible too

- The fitted `ColumnTransformer` is serialised **inside** `model.joblib`, so
  inference cannot apply a different transform than training. There is no
  separate preprocessing artifact to drift out of sync.
- `ML_MIN_CONFIDENCE` is recorded on every prediction row
  (`min_confidence_threshold`), so an old prediction can be re-interpreted
  against the threshold that produced it.
- The full `probabilities` vector is stored per row, so a decision can be
  re-derived without re-running the model.
- Predictions are keyed `(flow_id, model_version)`. Re-running updates in place
  and reports `created` / `updated` separately.

---

## 7. The verification commands

```bash
cd backend

# type + lint gates
ruff check app tests
ruff format --check app tests
mypy app tests

# full suite
python -m pytest -q

# focused ML suites
python -m pytest tests/test_ml_pipeline.py -q
python -m pytest tests/test_ml_api.py -q

# migration round-trip (verified on SQLite *and* PostgreSQL)
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
alembic check          # -> No new upgrade operations detected.
```

Determinism, refusal and idempotency are covered by test names that state the
property, e.g. `test_no_labels_refuses_and_writes_no_artifact`,
`test_schema_mismatch_refuses`,
`test_rerun_is_idempotent_and_does_not_grow`.

---

## 8. Limits of the current evidence

**No real-world accuracy claim is made anywhere in this repository, because none
is possible yet.** The test suite fits real models, through the real trainer, on
deterministic fixtures — and asserts *mechanics* (it refuses without labels, it
splits by capture, it is idempotent, it abstains below threshold), never accuracy.
Those fixtures carry injected labels and exist to exercise code paths.

Producing a defensible accuracy number requires the operator-supplied ground
truth described in [`ml-dataset-plan.md`](ml-dataset-plan.md) §5.
