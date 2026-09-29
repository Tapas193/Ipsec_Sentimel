"""Baseline classifier for Phase 4.

``RandomForestClassifier`` on a 27-column numeric feature vector:

- CPU-only, trains in well under a second on this feature count, and the
  prediction cost per flow is negligible. That matters because inference runs
  inline on a request path.
- No scaling requirement, so the scaler in the preprocessor is harmless rather
  than load-bearing, and adding a distance-based model later needs no artifact
  change.
- ``class_weight="balanced"`` handles imbalance without fabricating samples.
  Nothing is oversampled: no synthetic rows, no SMOTE, no duplication.
- ``predict_proba`` is required, not optional — the confidence threshold and the
  abstention path depend on real probabilities.

It is a **baseline**, not a production classifier. With one sample per class it
would memorise; that is why the trainer refuses to fit below
``min_samples_per_class`` and refuses to publish metrics below
``min_samples_for_metrics``.
"""

from __future__ import annotations

from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from app.ml.preprocessing import build_preprocessor
from app.ml.schema import MLFeatureSchema

MODEL_TYPE = "sklearn.RandomForestClassifier"
N_ESTIMATORS = 300
MAX_DEPTH: int | None = None
MIN_SAMPLES_LEAF = 1
MIN_SAMPLES_SPLIT = 2


def build_pipeline(
    schema: MLFeatureSchema,
    *,
    seed: int,
    use_balanced_class_weights: bool = True,
    n_estimators: int = N_ESTIMATORS,
) -> Pipeline:
    """Build the unfitted pipeline: preprocessor + classifier, in one object."""
    classifier = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=MAX_DEPTH,
        min_samples_leaf=MIN_SAMPLES_LEAF,
        min_samples_split=MIN_SAMPLES_SPLIT,
        class_weight="balanced" if use_balanced_class_weights else None,
        random_state=seed,
        n_jobs=1,
    )
    return Pipeline(
        [
            ("preprocessor", build_preprocessor(schema)),
            ("classifier", classifier),
        ]
    )


def classifier_params(seed: int, use_balanced_class_weights: bool = True) -> dict[str, Any]:
    """Hyperparameters, recorded in the evaluation artifact for reproduction."""
    return {
        "estimator": "RandomForestClassifier",
        "n_estimators": N_ESTIMATORS,
        "max_depth": MAX_DEPTH,
        "min_samples_leaf": MIN_SAMPLES_LEAF,
        "min_samples_split": MIN_SAMPLES_SPLIT,
        "class_weight": "balanced" if use_balanced_class_weights else None,
        "random_state": seed,
        "n_jobs": 1,
    }
