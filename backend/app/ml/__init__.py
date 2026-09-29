"""Phase 4 — AI/ML-assisted encrypted traffic analysis.

ML operates on the numeric flow metadata Phase 2 already extracted from a
capture. It never decrypts IPsec, never touches plaintext application data,
and never attacks a live endpoint. See docs/ml-security.md for the threat
model and docs/ml-dataset-plan.md for the dataset contract.

Honesty note: the repository ships no ground-truth labels, so the trainer
reports ``INSUFFICIENT_LABELED_DATA`` until an operator registers a label file.
That is the designed behaviour, not a missing feature.
"""

from __future__ import annotations

from app.ml.labels import LabelRegistry, load_label_registry
from app.ml.schema import (
    MLFeatureSchema,
    MLSchemaError,
    get_feature_schema,
    load_feature_schema,
)
from app.ml.validation import Rejection, ValidatedRow, validate_row

__all__ = [
    "LabelRegistry",
    "MLFeatureSchema",
    "MLSchemaError",
    "Rejection",
    "ValidatedRow",
    "get_feature_schema",
    "load_feature_schema",
    "load_label_registry",
    "validate_row",
]
