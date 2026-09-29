# Phase 4 — ML API Reference

**IPsec Sentinel — Problem Statement 26160** · 13 routes under `/api/v1/ml` ·
`ApiResponse[T]` envelope · unavailability is HTTP 200 with an explicit status.

All examples below are **real captured responses** from a local run, not
hand-written illustrations. Where a run used the test-only deterministic
fixtures to exercise the mechanics, that is stated inline.

---

## 1. Envelope

Every response uses the project envelope:

```json
{ "success": true, "data": { }, "error": null, "meta": {} }
```

Errors:

```json
{
  "success": false,
  "data": null,
  "error": { "code": "NOT_FOUND", "message": "Model 'nope-1.0.0' is not registered.", "details": null }
}
```

## 2. Status-code policy

**ML unavailability is not an HTTP error.** "No model has been trained" is a
normal state for a system with no ground truth, so it travels as HTTP 200 with
an explicit `status` the frontend renders as information.

| Situation | Code | Body |
| --- | --- | --- |
| ML disabled, no model, no labels, insufficient data | **200** | `status` ∈ `DISABLED` / `MODEL_NOT_AVAILABLE` / `INSUFFICIENT_LABELED_DATA` / `INSUFFICIENT_DATA`, `trained: false` or empty `predictions` |
| unknown analysis or model, unknown flow prediction | 404 | `NOT_FOUND` |
| training while `ML_TRAINING_ENABLED=false` | 403 | `FORBIDDEN` |
| malformed model version, schema conflict | 400 | `BAD_REQUEST` |

---

## 3. Route index

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/ml/health` | readiness, active model, why unavailable |
| `GET` | `/ml/schema` | full feature contract (audit view) |
| `GET` | `/ml/features` | flat feature list + active threshold |
| `GET` | `/ml/models` | registered models |
| `GET` | `/ml/models/{model_version}` | one model's provenance |
| `GET` | `/ml/models/{model_version}/metrics` | held-out metrics (may be `null`) |
| `GET` | `/ml/dataset` | dry-run: label coverage, splits, rejections — no fit |
| `POST` | `/ml/train` | explicit, gated training run |
| `POST` | `/ml/analyses/{analysis_key}/predict` | run inference, persist idempotently |
| `GET` | `/ml/analyses/{analysis_key}/predictions` | stored predictions + summary |
| `DELETE` | `/ml/analyses/{analysis_key}/predictions` | remove stored predictions |
| `GET` | `/ml/predictions` | cross-analysis history, newest first |
| `GET` | `/ml/flows/{flow_uuid}/prediction` | one flow's most recent prediction |

---

## 4. Readiness

### `GET /api/v1/ml/health` — always 200

```json
{
  "success": true,
  "data": {
    "ml_enabled": true,
    "training_enabled": true,
    "any_model_available": false,
    "active_model_version": null,
    "feature_schema_version": "1.0",
    "dataset_version": "1.0",
    "min_confidence": 0.6,
    "class_count": 7,
    "models": [],
    "detail": {
      "reason": "No trained model is available for feature schema 1.0.",
      "required_feature_schema_version": "1.0",
      "configured_model_version": null,
      "registered_model_versions": [],
      "remediation": "Register ground-truth labels and train a model with POST /api/v1/ml/train."
    }
  },
  "error": null,
  "meta": {}
}
```

This is the true state of the repository as shipped: no ground truth, therefore
no model, with a `remediation` that says what to do about it.

---

## 5. Training

### `POST /api/v1/ml/train`

Request (all fields optional):

```json
{
  "model_version": "doc-1.0.0",
  "label_file": "/srv/labels/ground_truth.json",
  "notes": "testbed run 2026-04-02"
}
```

`label_file` is a **server-side path**. There is no label upload endpoint, so a
remote caller cannot make the backend read an arbitrary file. Precedence:
request `label_file` → `ML_LABEL_FILE`.

#### 5.1 The expected result in this repository — no labels

```json
{
  "success": true,
  "data": {
    "status": "INSUFFICIENT_LABELED_DATA",
    "trained": false,
    "message": "No capture in the database has a registered ground-truth label. Phase 4 does not generate labels, so there is nothing legitimate to train on. Register ground truth via ML_LABEL_FILE and re-run training.",
    "model_version": null,
    "feature_schema_version": "1.0",
    "dataset_version": "1.0",
    "training_samples": 0,
    "capture_count": 0,
    "splits": { "train": 0, "validation": 0, "test": 0 },
    "metrics": null,
    "classes": ["VOIP", "MESSAGING", "EMAIL", "WEB", "VIDEO", "ICMP", "UNKNOWN"],
    "label_provenance": { "user_provided": 0 },
    "rejected_rows": 0,
    "rejection_reasons": {},
    "created_at": null
  },
  "error": null,
  "meta": {}
}
```

`trained: false` and no artifact exists. This is a success response, not a
failure: the system correctly declined to fabricate a model.

#### 5.2 A successful run (deterministic test fixtures — mechanics, not accuracy)

```json
{
  "status": "OK",
  "trained": true,
  "model_version": "doc-1.0.0",
  "training_samples": 264,
  "capture_count": 32,
  "splits": { "train": 264, "validation": 48, "test": 72 },
  "classes": ["VOIP", "MESSAGING", "EMAIL", "WEB", "VIDEO", "ICMP", "UNKNOWN"],
  "label_provenance": { "user_provided": 264 },
  "rejected_rows": 0
}
```

> The `accuracy: 1.0` in the metrics block of such a run describes **synthetic
> fixtures with injected labels**, not real-world IPsec traffic. The fixtures
> separate classes by a deliberate offset, so a tree model separates them
> perfectly. It demonstrates that evaluation, splitting and artifact writing
> work — nothing more. See
> [`ml-dataset-plan.md`](ml-dataset-plan.md) §1.

#### 5.3 Refusal table

| `status` | `trained` | Cause |
| --- | --- | --- |
| `DISABLED` | false | `ML_TRAINING_ENABLED=false` (403 if called via API) |
| `INSUFFICIENT_LABELED_DATA` | false | no label file / empty registry |
| `NO_LABELS_REGISTERED` | false | label file present but registers nothing |
| `LABEL_FILE_UNREADABLE` | false | label file present but invalid |
| `INSUFFICIENT_DATA` | false | too few samples/classes/captures; `message` states the shortfall |

---

## 6. Dataset dry-run

### `GET /api/v1/ml/dataset`

Query: `label_file` (optional, ≤ 512 chars) — resolved with the same precedence
as `POST /train`, so this audits the registry you actually intend to train on.

Nothing is fitted and nothing is written.

```json
{
  "status": "INSUFFICIENT_LABELED_DATA",
  "dataset_version": "1.0",
  "feature_schema_version": "1.0",
  "class_definition_version": "1.0",
  "dataset_digest": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
  "feature_count": 27,
  "total_feature_rows": 0,
  "labeled_rows": 0,
  "unlabeled_rows": 0,
  "rejected_rows": 0,
  "rejection_reasons": {},
  "capture_count": 0,
  "labeled_capture_count": 0,
  "class_distribution": {},
  "label_registry_source": "none",
  "label_file": null,
  "notes": [
    "No ground-truth labels are registered (ML_LABEL_FILE is unset or empty). Phase 4 will not invent labels, so no dataset can be labeled."
  ],
  "split": null
}
```

`notes` is a human-readable list of caveats, not decoration: it explains *why* a
number is zero.

---

## 7. Inference

### `POST /api/v1/ml/analyses/{analysis_key}/predict`

Query: `model_version` (optional, ≤ 64). Empty ⇒ the newest schema-compatible
model.

```json
{
  "status": "OK",
  "analysis_id": "ANL-T003",
  "model_version": "doc-1.0.0",
  "total": 12,
  "created": 12,
  "updated": 0,
  "rejected": 0,
  "rejection_reasons": {},
  "observation_status": "model_predicted",
  "summary": {
    "count": 12,
    "model_version": "doc-1.0.0",
    "average_confidence": 0.9797,
    "unknown_count": 0,
    "abstained_count": 0,
    "low_confidence_count": 0,
    "class_distribution": { "VOIP": 12 }
  },
  "detail": null,
  "duration_seconds": 0.085
}
```

**Re-running does not grow the table.** The idempotency key is
`(flow_id, model_version)`; the same call again returns:

```json
{ "status": "OK", "total": 12, "created": 0, "updated": 12, "observation_status": "model_predicted" }
```

`created` and `updated` are reported separately precisely so a client can prove
this.

### 7.0 `total` vs `summary.count`

`total` is the number of **candidate flows considered**, not the number of
predictions produced. When the run did not happen, `total` can be non-zero while
`created` is 0 and `summary.count` is 0 — which is exactly what a real capture
looks like with no model:

```json
{
  "status": "MODEL_NOT_AVAILABLE",
  "total": 4,
  "created": 0,
  "updated": 0,
  "summary": { "count": 0, "class_distribution": {} },
  "detail": { "reason": "No compatible trained model is available.", "remediation": "…" }
}
```

Read **`summary.count` as "predictions produced"**. Rendering `total` as a
prediction count would be wrong, and the frontend renders it as
"rejected of N flows" for that reason.

### `GET /api/v1/ml/analyses/{analysis_key}/predictions`

Query: `model_version`, `min_confidence` (`0.0–1.0`), `prediction` (≤ 32).

One stored row:

```json
{
  "id": "22f2c8f0-1806-441c-b600-f990fffc6655",
  "prediction_id": "PRED-000001",
  "analysis_id": "5f2ff9b7-6a0e-4045-a20b-54d301d122fd",
  "flow_id": "592598d7-966e-42c8-a836-1808bb876d4c",
  "capture_id": "CAP-T003",
  "model_version": "doc-1.0.0",
  "model_type": "sklearn.RandomForestClassifier",
  "dataset_version": "1.0",
  "feature_schema_version": "1.0",
  "prediction": "VOIP",
  "top_candidate": "VOIP",
  "confidence": 1.0,
  "min_confidence_threshold": 0.6,
  "abstained": false,
  "probabilities": { "EMAIL": 0.0, "ICMP": 0.0, "VOIP": 1.0, "WEB": 0.0 },
  "observation_status": "model_predicted"
}
```

`min_confidence_threshold` is stored per row, so an old prediction can be
re-read against the threshold that produced it.

### 7.1 Abstention

When `max(probabilities) < ML_MIN_CONFIDENCE`, the row is
`prediction: "UNKNOWN"`, `abstained: true`, `top_candidate` retained, and
`observation_status` **stays `model_predicted`**. The model ran and produced an
observation; it declined to be specific. That is a different fact from
`MODEL_NOT_AVAILABLE`.

### `DELETE /api/v1/ml/analyses/{analysis_key}/predictions` → `{"deleted": 12}`

---

## 8. Model registry

### `GET /api/v1/ml/models`

```json
{
  "total": 0,
  "active_model_version": null,
  "models": []
}
```

With a model present, each entry carries provenance plus metrics:

```json
{
  "model_version": "doc-1.0.0",
  "model_type": "sklearn.RandomForestClassifier",
  "feature_schema_version": "1.0",
  "dataset_version": "1.0",
  "created_at": "2026-09-29T09:02:05.994243+00:00",
  "classes": ["EMAIL", "ICMP", "VOIP", "WEB"],
  "training_samples": 384,
  "feature_count": 27,
  "metrics": { "accuracy": 1.0, "evaluated_samples": 72, "expected_calibration_error": 0.1 },
  "splits": { },
  "library_versions": { }
}
```

`classes` here is the **fitted** label set — it is a subset of the declared
vocabulary, because only classes present in the labeled data get fitted.

### `GET /api/v1/ml/models/{model_version}/metrics`

```json
{
  "model_version": "doc-1.0.0",
  "metrics": { "accuracy": 1.0, "evaluated_samples": 72 },
  "evaluated": true,
  "note": null,
  "min_confidence": 0.6
}
```

If the model was fitted but the held-out split was below `min_samples_for_metrics`
(20), then `metrics` is `null` and `evaluated` is `false`, with an explicit note:

> "This model was fitted but not evaluated: the held-out test split was smaller
> than the configured minimum. No metrics are claimed."

An explicit `null` — never zeros.

### `GET /api/v1/ml/models/{model_version}` → 404 when unregistered

```json
{
  "success": false,
  "data": null,
  "error": { "code": "NOT_FOUND", "message": "Model 'nope-1.0.0' is not registered.", "details": null }
}
```

A traversal attempt in the version segment (`..%2F..%2Fetc`) does not reach the
handler at all — Starlette returns 404, and the version pattern
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` would reject it regardless. See
[`ml-security.md`](ml-security.md) §2.1.

---

## 9. Flow lookup and history

- `GET /api/v1/ml/flows/{flow_uuid}/prediction` — most recent prediction for one
  flow across models; **404** when none exists:

  ```json
  {
    "success": false,
    "data": null,
    "error": {
      "code": "NOT_FOUND",
      "message": "No prediction exists for flow '00000000-0000-0000-0000-000000000000'.",
      "details": null
    }
  }
  ```

- `GET /api/v1/ml/predictions?capture_id=&flow_id=&limit=50` — cross-analysis
  history, newest first. `limit` is bounded `1–500`.

---

## 10. Frontend mapping

| Endpoint | Hook | Rendered by |
| --- | --- | --- |
| `/ml/health` | `useMLHealthQuery` | `MLUnavailablePanel` on the Traffic page |
| `/ml/models`, `/ml/models/{v}/metrics` | `useMLModelsQuery`, `useMLModelMetricsQuery` | model cards, metric table, confusion matrix |
| `/ml/dataset` | `useMLDatasetQuery` | dataset coverage panel (label coverage, splits, rejections) |
| `/ml/analyses/{k}/predict` | `usePredictMutation` | *Run predictions* button; invalidates predictions + health |
| `/ml/analyses/{k}/predictions` | `usePredictionsQuery` | analysis **Predictions** tab, summary cards, per-flow rows |
| `/ml/features` | `useMLFeaturesQuery` | feature table with units, bounds, nullability |

`UNKNOWN`/`abstained` rows are labelled as such in the UI, never rendered as a
confident class.

---

## 11. Verification

```bash
cd backend
python -m pytest tests/test_ml_api.py -q        # 47 tests
python -m pytest tests/test_ml_pipeline.py -q   # 84 tests
```

Covered: the no-label refusal, the disabled-training guard, schema-mismatch
refusal, idempotent re-run, abstention, `model_predicted` semantics, the
`/dataset` label-file audit, 404 paths, and Phase 3 isolation.
