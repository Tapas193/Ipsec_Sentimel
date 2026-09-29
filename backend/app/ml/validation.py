"""Feature quality validation for Phase 4.

The contract with Phase 2 is that persisted features are already clean (see
``backend/tests/test_feature_quality.py``). This module does not trust that:
rows are re-validated on the way into a dataset because the store is a plain
``Text`` JSON column that anything could have written.

Two outcomes, never a third
---------------------------
- **Accepted**: value is a finite number inside the declared bounds, or ``null``
  for a feature the schema marks nullable.
- **Rejected**: anything else. The row is dropped and the reason recorded.

What is deliberately NOT done:

- Invalid values are **not** clipped into range and **not** replaced with zero.
  A negative duration is a corrupt row, not a duration of zero. Replacing it
  would teach the model something the capture never showed.
- ``null`` is **not** turned into zero here either. Missingness is preserved as
  ``None`` through the builder and represented explicitly by the preprocessing
  missing-indicator columns. Only the imputer may fill a value, and it does so
  in a way the model can see.
- Non-finite floats (``NaN``, ``inf``, ``-inf``) are rejected outright. They are
  never a legitimate Phase 2 output.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from app.ml.schema import MLFeatureSchema

# Reasons are stable strings so they can be counted in the dataset audit.
REASON_NOT_A_MAPPING = "row_not_a_mapping"
REASON_SCHEMA_VERSION_MISMATCH = "feature_schema_version_mismatch"
REASON_MISSING_FEATURE = "missing_feature"
REASON_WRONG_TYPE = "wrong_type"
REASON_NOT_FINITE = "not_finite"
REASON_BOOL = "bool_not_numeric"
REASON_OUT_OF_RANGE = "out_of_range"
REASON_NULL_ON_NON_NULLABLE = "null_on_non_nullable"


@dataclass(frozen=True)
class Rejection:
    flow_key: str
    analysis_id: str
    capture_id: str
    reason: str
    feature: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "flow_key": self.flow_key,
            "analysis_id": self.analysis_id,
            "capture_id": self.capture_id,
            "reason": self.reason,
            "feature": self.feature,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ValidatedRow:
    """A single accepted (features, provenance) tuple.

    ``features`` maps schema feature name -> float, preserving ``None`` for
    not-computable nullable features.
    """

    features: dict[str, float | None]
    flow_key: str
    flow_uuid: str
    analysis_id: str
    analysis_key: str
    capture_id: str
    capture_sha256: str | None
    feature_schema_version: str
    analyzer_version: str | None
    parser_version: str | None


def validate_row(
    row: dict[str, Any],
    *,
    schema: MLFeatureSchema,
    source_feature_schema_version: str,
    flow_key: str,
    flow_uuid: str,
    analysis_id: str,
    analysis_key: str,
    capture_id: str,
    capture_sha256: str | None,
    analyzer_version: str | None,
    parser_version: str | None,
) -> tuple[ValidatedRow | None, Rejection | None]:
    """Validate one feature mapping. Returns (accepted_row, rejection)."""

    def reject(
        reason: str, feature: str | None = None, detail: str | None = None
    ) -> tuple[None, Rejection]:
        return None, Rejection(
            flow_key=flow_key,
            analysis_id=analysis_key,
            capture_id=capture_id,
            reason=reason,
            feature=feature,
            detail=detail,
        )

    if source_feature_schema_version != schema.source_feature_schema_version:
        return reject(
            REASON_SCHEMA_VERSION_MISMATCH,
            detail=(
                f"row={source_feature_schema_version!r} "
                f"expected={schema.source_feature_schema_version!r}"
            ),
        )

    values: dict[str, float | None] = {}
    for spec in schema.features:
        present = spec.name in row
        raw = row.get(spec.name)

        if not present or raw is None:
            if spec.nullable:
                values[spec.name] = None
                continue
            return reject(REASON_NULL_ON_NON_NULLABLE, spec.name, "value is null/absent")

        # bool is a subclass of int in Python; treat it as invalid rather than
        # silently accepting True as 1.
        if isinstance(raw, bool):
            return reject(REASON_BOOL, spec.name, repr(raw))

        if isinstance(raw, int):
            value = float(raw)
        elif isinstance(raw, float):
            value = raw
        else:
            return reject(REASON_WRONG_TYPE, spec.name, f"got {type(raw).__name__}")

        if not math.isfinite(value):
            return reject(REASON_NOT_FINITE, spec.name, repr(value))

        if not spec.in_range(value):
            bounds = f"[{spec.minimum}, {spec.maximum}]"
            return reject(REASON_OUT_OF_RANGE, spec.name, f"{value} outside {bounds}")

        values[spec.name] = value

    return (
        ValidatedRow(
            features=values,
            flow_key=flow_key,
            flow_uuid=flow_uuid,
            analysis_id=analysis_id,
            analysis_key=analysis_key,
            capture_id=capture_id,
            capture_sha256=capture_sha256,
            feature_schema_version=source_feature_schema_version,
            analyzer_version=analyzer_version,
            parser_version=parser_version,
        ),
        None,
    )
