# Phase 4 — ML Dataset Plan

**IPsec Sentinel — Problem Statement 26160** · ground truth is the bottleneck ·
capture-level splitting · small samples produce no numbers.

This document answers one question honestly: **what would it take to train a real
traffic classifier, and why can't this repository do it today?**

The short answer: there is no ground truth. A label is a claim about what the
traffic *actually was*, and a capture cannot prove that claim. Everything below is
the plan for when an operator supplies the missing half.

---

## 1. The honest state of this repository

`ML_LABEL_FILE` is empty, so the label registry is empty, so:

```
POST /api/v1/ml/train  ->  200
{
  "status": "INSUFFICIENT_LABELED_DATA",
  "trained": false,
  "message": "No labels registered. ..."
}
```

No model is fitted. No artifact is written. No metrics exist. This is the
correct outcome, and it is asserted by tests rather than left to inspection.

Every class in `configs/ml_feature_schema.yaml` is therefore `active: false`.
A class is activated by *registering labels and training*, never by editing that
file to make a model look supported.

### 1.1 What is not a label source

The schema lists these under `target.forbidden_sources`, and the loader rejects
a registry that claims them:

| Tempting source | Why it is not a label |
| --- | --- |
| Port number (5060 ⇒ SIP) | A circular guess dressed as ground truth. The model would learn "port 5060", not "voice traffic", and report ~100% accuracy while learning nothing about traffic. |
| Filename / directory | Encodes the curator's assumption, which *is* the label. Also breaks on re-upload under a new name. |
| Protocol name (`IKE`, `ESP`) | Phase 2 tells you the VPN protocol, not the application carried inside the tunnel. |
| Phase 3 `SecurityFinding` | A deterministic rule output, not an observation about traffic class. Feeding findings forward inverts the trust order. |
| Model's own output | Self-labelling reinforces whatever bias the first model had. |
| Synthetic PCAP generation | A generator knows the answer because it wrote it. Useful for mechanics tests, worthless as evidence. |

`backend/tests/synthetic_pcap.py` output therefore **cannot** be labeled. The
test suite injects labels explicitly, scoped to tests, and asserts mechanics —
never accuracy.

---

## 2. What a legitimate ground-truth file looks like

YAML or JSON, referenced by `ML_LABEL_FILE`:

```yaml
label_source: user_provided
feature_schema_version: "1.0"
class_definition_version: "1.0"
labels:
  # Match by the human capture key, or by content hash so the label survives
  # re-upload. A row may carry either or both; anything else is rejected.
  - capture_id: CAP-000142
    traffic_type: VOIP
  - capture_sha256: 3f9a1c7e...
    traffic_type: WEB
    note: "labelled from testbed run 2026-04-02, voice gateway 10.0.0.5"
```

Rules the loader enforces:

- `label_source` must be `user_provided`. Any other value fails validation
  rather than being silently accepted.
- `traffic_type` must be a declared class from `class_definition.classes`.
- `feature_schema_version` must match the loaded schema, so a label file cannot
  outlive the feature contract it was written against.
- A row identifying no known capture is **not** dropped silently; it is counted
  and surfaced in the dataset report.
- Every accepted label is recorded with `provenance_observation_status =
  USER_PROVIDED`, stored in the artifact's `label_provenance` block.

### 2.1 Label provenance is part of the artifact

`metadata.json` carries a `label_provenance` histogram, so any published model
can be traced back to the operator file it came from. This is the difference
between "a model exists" and "this model, from these labels, on this data".

---

## 3. Splitting: by capture, never by flow

**This is the single most important correctness property of the dataset.**

Flows inside one capture share a source, a destination, a time window, an MTU, a
network stack and often an application session. They are statistically
dependent. If flow 1 of capture A trains a model and flow 2 of the same capture
tests it, the test score measures memorisation of that capture's traffic mix —
not generalisation.

A model can score near-perfect on such a split while being useless on a new
capture. **The failure is invisible in the metrics**, which is exactly why the
split must be enforced rather than assumed.

`app/ml/splitter.py` therefore:

1. Groups rows by capture.
2. Sorts the capture keys — `hash()` is salted per process in Python and would
   make splits irreproducible between runs, so it is never used.
3. Shuffles with `random.Random(seed)` seeded from `ML_RANDOM_SEED` (default 42).
4. Allocates whole captures to train (70%) / validation (15%) / test (15%).
5. `assert_no_capture_leakage` re-verifies the result and raises if any capture
   appears in two splits.

The test set is thus a set of *environments the model has never seen* — the only
split that answers "will this work on the next capture?"

---

## 4. Thresholds: what is too small to measure

| Guard | Value | Meaning |
| --- | --- | --- |
| `min_total_samples` | 40 | below this, no fit at all |
| `min_samples_per_class` | 2 | a 1-sample class teaches memorisation, not a class |
| `min_captures_per_split` | 1 | a split with no capture is not a split |
| `min_samples_for_metrics` | 20 | below this on the **held-out** set, metrics are not computed |

The last one deserves emphasis. A 2-sample test split yields accuracy 0.0 or 1.0
and a macro F1 that is either meaningless or undefined. Publishing those as if
they measured something is worse than publishing nothing. Below the threshold
the artifact records `INSUFFICIENT_DATA` and the metric block is **absent** — not
zero, not `null`, absent.

### 4.1 Imbalance is handled, not hidden

`RandomForestClassifier(class_weight="balanced")` reweights classes during the
fit. Nothing is oversampled: no SMOTE, no duplication, no synthetic rows. The
model is never shown a traffic pattern that did not occur in a labeled capture.

---

## 5. Data collection plan (what an operator would actually do)

The 27-feature contract is fixed (`configs/ml_feature_schema.yaml`). Gathering
labeled data is an operational task, not a code task:

1. **Stand up a controlled testbed.** A VLAN with a known voice gateway, a mail
   server, a web server, a video CDN, a messaging server and an ICMP generator.
   Because traffic is encrypted, classification is over metadata, so the
   testbed only needs to *generate* the right pattern.
2. **Run one capture per scenario**, several captures per scenario. Capture-level
   splitting means the count that matters is **captures**, not flows. One
   5000-flow capture contributes exactly as much test evidence as ten 500-flow
   captures do not.
3. **Label from the run log, not from the capture.** The operator knows they
   started a call at 14:02. That knowledge is the ground truth. Nothing in the
   PCAP can supply it.
4. **Record `capture_sha256`**, not just the capture key, so labels survive a
   re-upload of the same bytes.
5. **Aim for ≥ 20 captures per class** and ≥ 5 per split per class. That is a
   real data-collection project — and pretending otherwise is the failure mode
   this document exists to prevent.
6. Write the registry, set `ML_LABEL_FILE`, `POST /api/v1/ml/train`, then read
   the held-out metrics and the calibration error before trusting any of it.

### 5.1 Check label coverage before training

`GET /api/v1/ml/dataset` reports label coverage, splits, class distribution and
rejection reasons **without fitting or writing anything**. It is the intended
first call when assembling a registry.

---

## 6. Feature contract summary

27 features, schema `1.0`, read only from `flow_features.feature_json`:

| Group | Count | Notes |
| --- | --- | --- |
| Volume/rate | 5 | `packet_count`, `byte_count`, `duration_seconds`, `packets_per_second`, `bytes_per_second` |
| Packet size | 7 | mean, median, std, min, max, p25, p75 |
| Inter-arrival | 5 | mean, median, std, min, max |
| Direction | 5 | upstream/downstream packets and bytes, `direction_ratio` |
| Burst | 5 | `burst_count`, `burst_packets_ratio`, `burst_mean_size`, `burst_max_size`, `burst_mean_duration` |

Excluded, with reasons asserted by the builder:

- identifiers and provenance (let the model memorise a capture)
- timestamps (encode capture order and, in curated corpora, the label)
- network identifiers (IP/port/SPI/transport — the classic label-leak path)
- strings with label content (protocol, title, description, filename, path, UA)
- `packet_size_histogram` (buckets already summarised by the `packet_size_*`
  features; not a scalar input at schema 1.0)
- Phase 3 outputs (`severity`, `finding_type`, `rule_id`, `evidence_digest`)

### 6.1 `null` is not zero

`null` in the feature store means "not computable for this flow". It is never
coerced to `0.0` and never clipped into range. A negative duration is a corrupt
row, not a duration of zero.

Preprocessing preserves the distinction with one binary indicator column per
numeric feature, so the model can learn "not computable" separately from
"genuinely zero". See [`phase-4-architecture.md`](phase-4-architecture.md) §3.3
and [`ml-reproducibility.md`](ml-reproducibility.md).

---

## 7. What this means for a reader of the dashboard

If the Traffic Intelligence page shows a model, dataset, or metric: an operator
supplied ground truth for that data. If it shows `MODEL_NOT_AVAILABLE` or
`INSUFFICIENT_LABELED_DATA`: that is the true state of this deployment, not a
broken feature.

No accuracy number in this repository describes real-world IPsec traffic. None
exists yet.
