"""Inference for Phase 4.

The model is a classifier over flow *metadata*, not a payload reader. It never
sees, and cannot obtain, plaintext: Phase 2 does not extract it and this module
does not look for it.

Abstention
----------
``ML_MIN_CONFIDENCE`` (default 0.60) is the only place the threshold lives —
it is read from settings, never hardcoded here or in the API. When the highest
predicted probability falls below it, the prediction is ``UNKNOWN`` while
``observation_status`` stays ``MODEL_PREDICTED``, because the model *did* run
and produced an observation; it simply declined to be specific. That is a
different fact from "no model was available", which is reported as
``MODEL_NOT_AVAILABLE``.

Schema compatibility
--------------------
A model trained against feature schema 1.0 refuses to score data from another
version. The check happens before prediction, not after, so an incompatible
artifact cannot produce a plausible-looking but meaningless class.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.ml.artifacts import (
    ModelArtifact,
    ModelArtifactError,
    list_artifacts,
    resolve_default_version,
)
from app.ml.preprocessing import rows_to_matrix
from app.ml.schema import MLFeatureSchema
from app.ml.statuses import RunStatus
from app.models.traffic_prediction import TrafficType
from app.security.enums import ObservationStatus

logger = logging.getLogger("ipsec_sentinel.ml")

PREDICTION_UNKNOWN = TrafficType.UNKNOWN.value
OBSERVATION_MODEL_PREDICTED = ObservationStatus.MODEL_PREDICTED.value

STATUS_OK: RunStatus = "OK"
STATUS_MODEL_NOT_AVAILABLE: RunStatus = "MODEL_NOT_AVAILABLE"
STATUS_INSUFFICIENT_DATA: RunStatus = "INSUFFICIENT_DATA"
STATUS_DISABLED: RunStatus = "DISABLED"


class ModelNotAvailableError(RuntimeError):
    """No compatible model artifact exists for the configured feature schema."""

    code = STATUS_MODEL_NOT_AVAILABLE


class FeatureSchemaMismatchError(RuntimeError):
    """The loaded model was trained against a different feature schema."""

    code = "FEATURE_SCHEMA_MISMATCH"


@dataclass(frozen=True)
class Prediction:
    """One scored flow.

    ``observation_status`` is always ``MODEL_PREDICTED`` — the model ran. The
    abstention decision is carried by ``predicted_class`` becoming ``UNKNOWN``
    plus ``abstained=True``, never by downgrading the observation status.
    """

    predicted_class: str
    confidence: float
    probabilities: dict[str, float]
    observation_status: str
    model_version: str
    abstained: bool
    top_candidate: str


def load_compatible_artifact(
    model_dir: str,
    schema: MLFeatureSchema,
    requested_version: str = "",
) -> ModelArtifact:
    """Load the selected model, or explain precisely why it cannot be loaded."""
    version = resolve_default_version(model_dir, requested=requested_version, schema=schema)
    if version is None:
        raise ModelNotAvailableError(
            "No trained model is available for feature schema "
            f"{schema.feature_schema_version}. Train one explicitly with POST /api/v1/ml/train."
        )

    artifacts = {artifact.model_version: artifact for artifact in list_artifacts(model_dir)}
    artifact = artifacts.get(version)
    if artifact is None:
        raise ModelNotAvailableError(f"Model {version!r} is not present in the model registry.")

    if artifact.metadata.feature_schema_version != schema.feature_schema_version:
        raise FeatureSchemaMismatchError(
            f"Model {version!r} was trained against feature schema "
            f"{artifact.metadata.feature_schema_version}, this deployment uses "
            f"{schema.feature_schema_version}. Refusing to predict."
        )

    if artifact.metadata.feature_names != schema.feature_names:
        raise FeatureSchemaMismatchError(
            f"Model {version!r} expects features {artifact.metadata.feature_names}, "
            f"the schema provides {schema.feature_names}."
        )

    return artifact


def predict_rows(
    rows: list[dict[str, float | None]],
    *,
    artifact: ModelArtifact,
    schema: MLFeatureSchema,
    min_confidence: float,
) -> list[Prediction]:
    """Score validated rows, applying the abstention threshold to each."""
    if not rows:
        return []

    pipeline = artifact.load_pipeline()
    classes = [str(name) for name in pipeline.classes_]
    matrix = rows_to_matrix(rows, schema)
    predicted = [str(value) for value in pipeline.predict(matrix)]
    probabilities = pipeline.predict_proba(matrix)

    results: list[Prediction] = []
    # `RandomForestClassifier.predict` is the argmax of the same probability
    # matrix, so `model_class` and the probability argmax `best` agree by
    # construction. The reported label comes from the model's own decision and
    # `best` is kept separately so an abstained row still records the closest
    # candidate the model would otherwise have chosen.
    for model_class, row in zip(predicted, probabilities, strict=True):
        scores = {name: float(value) for name, value in zip(classes, row, strict=True)}
        confidence = max(scores.values())
        best = max(scores, key=lambda name: scores[name])
        abstained = confidence < min_confidence
        results.append(
            Prediction(
                predicted_class=PREDICTION_UNKNOWN if abstained else model_class,
                confidence=round(confidence, 4),
                probabilities={name: round(value, 6) for name, value in sorted(scores.items())},
                observation_status=OBSERVATION_MODEL_PREDICTED,
                model_version=artifact.model_version,
                abstained=abstained,
                top_candidate=best,
            )
        )
    return results


def run_inference(
    rows: list[dict[str, float | None]],
    *,
    model_dir: str,
    schema: MLFeatureSchema,
    requested_version: str = "",
    min_confidence: float = 0.60,
) -> tuple[RunStatus, list[Prediction], str | None]:
    """Convenience wrapper returning (status, predictions, model_version).

    Catches the expected unavailability conditions so callers (API, tests) can
    report them without exception plumbing. Real bugs still propagate.
    """
    try:
        artifact = load_compatible_artifact(model_dir, schema, requested_version)
    except (ModelNotAvailableError, ModelArtifactError, FeatureSchemaMismatchError) as exc:
        logger.warning(
            "ml inference unavailable",
            extra={"reason": type(exc).__name__, "detail": str(exc)},
        )
        return STATUS_MODEL_NOT_AVAILABLE, [], None

    if not rows:
        return STATUS_INSUFFICIENT_DATA, [], artifact.model_version

    return (
        STATUS_OK,
        predict_rows(
            rows,
            artifact=artifact,
            schema=schema,
            min_confidence=min_confidence,
        ),
        artifact.model_version,
    )


def default_min_confidence(configured: float) -> float:
    """Clamp into (0, 1]; a threshold of 0 would defeat abstention entirely."""
    return max(0.0, min(1.0, float(configured)))


def summarize(predictions: list[Prediction]) -> dict[str, Any]:
    """Aggregate view used by the analysis detail summary card."""
    if not predictions:
        return {
            "count": 0,
            "model_version": None,
            "average_confidence": None,
            "unknown_count": 0,
            "low_confidence_count": 0,
            "class_distribution": {},
        }
    confidences = [prediction.confidence for prediction in predictions]
    distribution: dict[str, int] = {}
    for prediction in predictions:
        distribution[prediction.predicted_class] = (
            distribution.get(prediction.predicted_class, 0) + 1
        )
    return {
        "count": len(predictions),
        "model_version": predictions[0].model_version,
        "average_confidence": round(sum(confidences) / len(confidences), 4),
        "unknown_count": sum(
            1 for prediction in predictions if prediction.predicted_class == PREDICTION_UNKNOWN
        ),
        "abstained_count": sum(1 for prediction in predictions if prediction.abstained),
        "low_confidence_count": sum(
            1 for prediction in predictions if prediction.confidence < 0.75
        ),
        "class_distribution": dict(sorted(distribution.items())),
    }
