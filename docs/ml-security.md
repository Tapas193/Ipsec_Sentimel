# Phase 4 — Security Notes

**IPsec Sentinel — Problem Statement 26160** · pickle trust boundary · no
path traversal · no label leakage · ML cannot become a security claim.

This document states the Phase 4 attack surface, the controls against it, and —
in §4 — the one risk that is *not* eliminated.

---

## 1. Threat model

Phase 4 introduces a capability the earlier phases did not have: **loading a
file from disk and deserializing it into an executable object**. Phase 1–3 read
structured data (pcap bytes, JSON) and evaluated their own rule code. Phase 4
evaluates a model *and* unpickles a blob.

Adversaries considered:

| # | Adversary | Capability | Primary risk |
| --- | --- | --- | --- |
| A1 | Untrusted capture uploader | supplies a PCAP, and via its feature rows tries to steer inference | feature manipulation, resource exhaustion |
| A2 | API client | sends arbitrary JSON to `/api/v1/ml/*` | path traversal via `model_version`, training abuse, info disclosure |
| A3 | Network attacker | observes traffic in transit | model/label disclosure (low value: local artifact, not transmitted) |
| A4 | Host-level attacker with write access to `ML_MODEL_DIR` | plants a malicious `model.joblib` | arbitrary code execution on unpickle |
| A5 | Model itself (data poisoning via labels) | influences what the model learns | a wrong-but-confident classifier |

A1–A3 and A5 are controlled. **A4 is not** — see §4.

---

## 2. Controls

### 2.1 Deserialization trust boundary

`joblib.load` is pickle, so loading a model file **executes code**. The controls
in `app/ml/artifacts.py`:

1. **No API-supplied paths, ever.** The API accepts a *version string*, never a
   path. `resolve_model_dir` constructs the directory from `ML_MODEL_DIR` plus a
   validated version.
2. **Version format validation.** `MODEL_VERSION_PATTERN` is
   `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. No `/`, no `\`, no `..`, no absolute
   paths, no null bytes, bounded length.
3. **Containment re-check after resolution.** The resolved path is confirmed to
   be inside the configured root *after* symlink resolution, closing the
   symlink-escape route.
4. **Never derive a path from user input in the service layer.** The service
   passes version strings down; only `artifacts.py` builds paths.

`test_ml_pipeline.py` covers `../` traversal, absolute paths, and a symlink
pointing outside the root.

### 2.2 Label integrity

- Labels are read from one place: the operator file at `ML_LABEL_FILE`.
- `label_source` must be `user_provided`; any other value fails validation.
- Label classes must exist in `class_definition.classes`; `UNKNOWN` is declared
  as an abstention class and is never a training target.
- `feature_schema_version` / `class_definition_version` must match the loaded
  schema, so a stale label file cannot be applied to a different contract.
- `capture_id` / `capture_sha256` are matched against persisted rows only.

**Leakage is the bigger threat than forgery.** A label derived from a port number
or a filename produces a model that looks excellent and knows nothing, and the
accuracy number is a self-referential artifact. The schema's
`target.forbidden_sources` plus `app/ml/labels.py` reject the label registry
outright if it claims a forbidden source.

### 2.3 Capture-level splitting

Flows from one capture are statistically dependent. Splitting by flow inflates
test scores to near-1.0 and makes the model useless on a new capture, with
nothing in the metrics to reveal it. `allocate_captures` +
`assert_no_capture_leakage` make the split a checked invariant rather than a
convention.

### 2.4 Resource bounds

| Bound | Value | Why |
| --- | --- | --- |
| `ML_MAX_TRAINING_FLOWS` | 200,000 | memory ceiling for a single M2 Air |
| `MODEL_VERSION_PATTERN` length | ≤ 64 | bounded filenames |
| `min_samples_for_metrics` | 20 | a 2-sample "metric" is a fabrication |
| `limit` on history endpoints | ≤ 500 | bounded response size |
| Model type | `RandomForestClassifier`, 300 trees, CPU | inference runs inline on a request path |

`ML_ENABLED=false` and `ML_TRAINING_ENABLED=false` are the defaults: an operator
opts in explicitly, and an upload never becomes training data implicitly.

### 2.5 Phase 3 isolation

ML output is advisory. It cannot create a `SecurityFinding`, cannot set severity
or confidence, and cannot influence a risk score (Phase 5). `TestPhase3Isolation`
asserts finding count and `analyses.rule_version` are unchanged after a full
train → predict cycle.

### 2.6 No plaintext, ever

The classifier reads flow *metadata* only. Phase 2 does not extract payload
plaintext and `app/ml/predictor.py` does not look for it. Model input is the 27
approved features; `payload`, `content` and decrypt-related fields are not in the
schema and are in the exclusion set.

### 2.7 Input validation at the boundary

- `min_confidence` query parameters are bounded `0.0 ≤ x ≤ 1.0`.
- `model_version` query/path parameters are length-bounded and pattern-validated.
- `MLTrainingRequest.label_file` is bounded in length and resolved against
  `ML_LABEL_FILE`-style configured paths, not opened as an arbitrary path.
- Response `detail` dicts are validated into `MLUnavailableDetail` in the
  endpoint, so a missing or misspelled key is a construction error rather than a
  silently wrong body.

### 2.8 Errors do not leak internals

- `ModelArtifactError` / `MLSchemaError` surface as a 400 with a message that
  names the *contract* violated ("model trained against feature schema 1.0,
  data is 2.0"), not filesystem internals or a traceback.
- `INSUFFICIENT_LABELED_DATA` is a 200 with a status, not a 500.
- A missing flow prediction is a 404, not a 200 with an empty body.

---

## 3. What is explicitly *not* claimed

- No model accuracy claim. There is no ground truth in this repository.
- No resistance to an attacker who already has code execution on the host. At
  that point the model file is not the interesting target.
- No protection of a model file from a **legitimate operator** who places a
  hostile artifact in the trusted directory. That is §4.
- No multi-tenant isolation of `ML_MODEL_DIR`. A single deployment has one
  registry.
- No authentication on the ML routes beyond whatever `AUTH_ENABLED` already
  provides project-wide. When auth is enabled, `/api/v1/ml/*` inherits it like
  every other route.

---

## 4. Residual risk: `joblib.load` executes pickle

**A model file placed in `ML_MODEL_DIR` by an operator is trusted by
definition.** No amount of path validation changes this: the file's *contents*
are the payload.

Mitigations reduce the blast radius — no traversal, no API-supplied path,
containment re-checked — but they do not make an untrusted pickle safe. If you
need to load a model from a source you do not control, that is a separate trust
decision requiring one of:

- convert the model to a non-executable format (ONNX) and serve it with a
  runtime that does not unpickle;
- deserialize the artifact in an isolated process/sandbox with no credentials
  and no network;
- accept the risk explicitly for a directory only the operator can write.

Phase 4 ships scikit-learn + `joblib` and therefore depends on the operator
trusting their own `ML_MODEL_DIR`. `ML_MODEL_DIR` is gitignored, and artifacts
are build outputs — the intended path is *re-run the trainer*, not *copy a
blob*.

---

## 5. Verification

Security-relevant behaviour is asserted, not documented-and-hoped:

| Property | Test |
| --- | --- |
| `../` and absolute-path traversal refused | `test_ml_pipeline.py::TestArtifacts` |
| symlink outside the model root refused | `test_ml_pipeline.py::TestArtifacts` |
| forbidden label source refused | `test_ml_pipeline.py::TestLabelRegistry` |
| non-`user_provided` `label_source` refused | `test_ml_pipeline.py::TestLabelRegistry` |
| schema mismatch refuses to score | `test_ml_pipeline.py::TestPredictor`, `test_ml_api.py` |
| no labels ⇒ no fit, no artifact | `test_ml_pipeline.py::TestTrainer`, `test_ml_api.py` |
| training disabled ⇒ `DISABLED`, no fit | `test_ml_api.py` |
| capture-level split has no leakage | `test_ml_pipeline.py::TestSplitter` |
| no metrics below sample floor | `test_ml_pipeline.py::TestMetrics` |
| Phase 3 findings untouched by ML | `test_ml_api.py::TestPhase3Isolation` |
| no plaintext/decrypt input | feature schema exclusion set asserted at load |

---

## 6. Operator checklist

Before enabling ML in a real deployment:

1. `ML_TRAINING_ENABLED=true` only in a controlled environment, with a reviewed
   `ML_LABEL_FILE`. Turn it back off afterwards.
2. Confirm `ML_MODEL_DIR` is writable only by the operator account.
3. Confirm the label registry's provenance is real (`user_provided`, from run
   logs — see [`ml-dataset-plan.md`](ml-dataset-plan.md) §5).
4. Read the held-out metrics and the calibration error before trusting the
   model; if `evaluation.status` is `INSUFFICIENT_DATA`, there is no metric to
   trust.
5. Keep `ML_ENABLED=false` until a model with honest metrics exists. The API
   behaves correctly in either state.
