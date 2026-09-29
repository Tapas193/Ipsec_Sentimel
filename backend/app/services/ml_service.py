"""Phase 4 ML service — inference orchestration and prediction persistence.

Responsibilities
----------------
- Score the persisted Phase 2 features of one analysis with a trained model.
- Persist results as ``TrafficPrediction`` rows, idempotently.
- Report ML availability states honestly, without raising for conditions that
  are normal (no model yet, no labels yet, ML disabled).

Separation of concerns
----------------------
This service knows nothing about security. It never writes a ``SecurityFinding``,
never touches severity, and never contributes to a risk score. A traffic
prediction and a security finding are independent claims about the same
capture and are stored in separate tables for exactly that reason.

Idempotency
-----------
A unique index on ``(flow_id, model_version)`` is the source of truth. Re-running
inference for the same model version updates the existing row in place rather
than appending, so the predictions table stays proportional to flows x models
and never to the number of inference runs. Rows are only inserted for flows
that still exist; a flow deleted with its analysis cascades its predictions.

Abstention
----------
When the top probability is below ``ML_MIN_CONFIDENCE`` the stored
``prediction`` is ``UNKNOWN`` and ``abstained`` is true, but
``observation_status`` remains ``MODEL_PREDICTED`` and ``top_candidate`` keeps
the runner-up. Discarding the runner-up would make the abstention
unauditable — the operator needs to see what the model nearly said.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, get_settings
from app.ml import predictor
from app.ml.artifacts import (
    ModelArtifact,
    ModelArtifactError,
    ModelMetadata,
    list_artifacts,
    list_model_versions,
    read_evaluation,
    read_metadata,
    resolve_default_version,
    resolve_model_dir,
)
from app.ml.dataset import DatasetBuildResult, build_dataset
from app.ml.schema import MLFeatureSchema, MLSchemaError, get_feature_schema
from app.ml.statuses import RunStatus
from app.ml.trainer import STATUS_TRAINED, TrainingResult, train_model
from app.ml.validation import Rejection, ValidatedRow, validate_row
from app.models import Analysis, Capture, Flow, FlowFeatures, TrafficPrediction
from app.security.enums import ObservationStatus

logger = logging.getLogger("ipsec_sentinel.ml")

__all__ = [
    "InferenceResult",
    "MLNotEnabledError",
    "MLTrainingDisabledError",
    "dataset_report",
    "delete_predictions",
    "describe_models",
    "get_health",
    "list_prediction_history",
    "list_predictions",
    "ml_schema_payload",
    "predict_analysis",
    "run_training",
]


class MLNotEnabledError(RuntimeError):
    """Inference was requested while ``ML_ENABLED`` is false."""

    code = "ML_DISABLED"


class MLTrainingDisabledError(RuntimeError):
    """Training was requested while ``ML_TRAINING_ENABLED`` is false."""

    code = "ML_TRAINING_DISABLED"


@dataclass
class InferenceResult:
    """Outcome of an inference run. Never an exception for 'no model'."""

    status: RunStatus
    analysis_id: str
    model_version: str | None = None
    total: int = 0
    created: int = 0
    updated: int = 0
    rejected: int = 0
    rejection_reasons: dict[str, int] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    detail: dict[str, Any] | None = None
    duration_seconds: float = 0.0

    @property
    def observation_status(self) -> str:
        return str(ObservationStatus.MODEL_PREDICTED)


def _settings() -> Settings:
    return get_settings()


def _schema() -> MLFeatureSchema:
    return get_feature_schema()


def _unavailable(
    reason: str,
    *,
    required_version: str | None = None,
    remediation: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "reason": reason,
        "required_feature_schema_version": required_version,
        "registered_model_versions": list_model_versions(_settings().ML_MODEL_DIR),
        "remediation": remediation
        or "Register ground-truth labels and train a model with POST /api/v1/ml/train.",
    }
    detail.update(extra)
    return detail


# --------------------------------------------------------------------------- #
# Health / schema / model registry
# --------------------------------------------------------------------------- #


def get_health() -> dict[str, Any]:
    """Report ML readiness without training or scoring anything."""
    settings = _settings()
    try:
        schema = _schema()
    except MLSchemaError as exc:
        logger.error("ml feature schema is unreadable", extra={"detail": str(exc)})
        return {
            "ml_enabled": settings.ML_ENABLED,
            "training_enabled": settings.ML_TRAINING_ENABLED,
            "any_model_available": False,
            "active_model_version": None,
            "feature_schema_version": "",
            "dataset_version": settings.ML_DATASET_VERSION,
            "min_confidence": settings.ML_MIN_CONFIDENCE,
            "class_count": 0,
            "models": [],
            "detail": _unavailable(f"Feature schema is invalid: {exc}"),
        }

    versions = list_model_versions(settings.ML_MODEL_DIR)
    active = _active_version(schema, settings)

    detail: dict[str, Any] | None = None
    if not settings.ML_ENABLED:
        detail = _unavailable(
            "ML inference is disabled (ML_ENABLED=false).",
            required_version=schema.feature_schema_version,
            remediation="Set ML_ENABLED=true to enable inference.",
        )
    elif active is None:
        detail = _unavailable(
            f"No trained model is available for feature schema {schema.feature_schema_version}.",
            required_version=schema.feature_schema_version,
        )

    return {
        "ml_enabled": settings.ML_ENABLED,
        "training_enabled": settings.ML_TRAINING_ENABLED,
        "any_model_available": active is not None,
        "active_model_version": active,
        "feature_schema_version": schema.feature_schema_version,
        "dataset_version": schema.dataset_version,
        "min_confidence": settings.ML_MIN_CONFIDENCE,
        "class_count": len(schema.declared_classes),
        "models": versions,
        "detail": detail,
    }


def ml_schema_payload() -> dict[str, Any]:
    """The feature contract exposed to clients, for reproducibility auditing."""
    schema = _schema()
    return {
        "feature_schema_version": schema.feature_schema_version,
        "dataset_version": schema.dataset_version,
        "features": [
            {
                "name": spec.name,
                "type": spec.kind,
                "unit": spec.unit,
                "nullable": spec.nullable,
                "minimum": spec.minimum,
                "maximum": spec.maximum,
            }
            for spec in schema.features
        ],
        "excluded_features": sorted(schema.excluded_fields),
        "exclusions": {},
        "classes": list(schema.declared_classes),
        "split": {
            "strategy": "capture_level_holdout",
            "unit": schema.dataset.split_unit,
            "train_ratio": schema.dataset.train_ratio,
            "validation_ratio": schema.dataset.validation_ratio,
            "test_ratio": schema.dataset.test_ratio,
            "min_captures_per_split": schema.dataset.min_captures_per_split,
            "min_total_samples": schema.dataset.min_total_samples,
            "min_samples_per_class": schema.dataset.min_samples_per_class,
            "min_samples_for_metrics": schema.dataset.min_samples_for_metrics,
            "random_seed": schema.dataset.random_seed,
        },
        "preprocessing": {
            "version": schema.preprocessing.version,
            "imputation": schema.preprocessing.imputer_strategy,
            "standardization": schema.preprocessing.scaler,
            "add_missing_indicators": schema.preprocessing.add_missing_indicator,
            "categorical_imputation": schema.preprocessing.categorical_imputer_strategy,
        },
    }


def _active_version(schema: MLFeatureSchema, settings: Settings) -> str | None:
    try:
        return resolve_default_version(
            settings.ML_MODEL_DIR,
            requested=settings.ML_DEFAULT_MODEL_VERSION,
            schema=schema,
        )
    except ModelArtifactError:
        return None


def describe_models() -> dict[str, Any]:
    """List registered models, newest first."""
    settings = _settings()
    schema = _schema()
    artifacts = list_artifacts(settings.ML_MODEL_DIR)
    artifacts.sort(key=lambda a: (a.metadata.training_timestamp, a.model_version), reverse=True)
    return {
        "total": len(artifacts),
        "active_model_version": _active_version(schema, settings),
        "models": [_model_payload(artifact) for artifact in artifacts],
    }


def _model_payload(artifact: ModelArtifact) -> dict[str, Any]:
    metadata = artifact.metadata
    counts = metadata.training_data_counts
    return {
        "model_version": metadata.model_version,
        "model_type": metadata.model_type,
        "feature_schema_version": metadata.feature_schema_version,
        "dataset_version": metadata.dataset_version,
        "created_at": metadata.training_timestamp,
        "classes": list(metadata.classes),
        "training_samples": sum(counts.values()) if counts else 0,
        "feature_count": len(metadata.feature_names),
        "metrics": _public_metrics(artifact.evaluation),
        "splits": dict(counts),
        "library_versions": dict(metadata.ml_library_versions),
    }


def _public_metrics(evaluation: dict[str, Any] | None) -> dict[str, Any] | None:
    """Strip internal bookkeeping and pass through only real measurements.

    Returns ``None`` when the model was fitted but never evaluated (held-out
    sample too small). An empty or zero-filled metrics object would misrepresent
    "not measured" as "measured as zero".
    """
    if not evaluation:
        return None
    if evaluation.get("status") != "OK" or evaluation.get("accuracy") is None:
        return None
    return {
        "accuracy": evaluation.get("accuracy"),
        "precision_macro": evaluation.get("precision_macro"),
        "recall_macro": evaluation.get("recall_macro"),
        "f1_macro": evaluation.get("f1_macro"),
        "per_class": evaluation.get("per_class", {}),
        "confusion_matrix": evaluation.get("confusion_matrix"),
        "confusion_matrix_labels": evaluation.get("confusion_matrix_labels", []),
        "mean_predicted_confidence": evaluation.get("mean_predicted_confidence"),
        "evaluated_samples": evaluation.get("evaluated_samples"),
        "expected_calibration_error": evaluation.get("expected_calibration_error"),
        "abstention_rate": evaluation.get("abstention_rate"),
    }


def read_model_evaluation(model_dir: str, model_version: str) -> dict[str, Any] | None:
    return read_evaluation(resolve_model_dir(model_dir, model_version))


# --------------------------------------------------------------------------- #
# Training
# --------------------------------------------------------------------------- #


def run_training(
    db: Session,
    *,
    model_version: str | None = None,
    label_file: str | None = None,
    schema: MLFeatureSchema | None = None,
) -> dict[str, Any]:
    """Run the explicit training pipeline and return a fully honest report.

    Raises only for genuine errors (training disabled, unreadable label file).
    "Not enough labeled data" is a *successful* call that reports
    ``INSUFFICIENT_LABELED_DATA`` and writes no artifact.
    """
    settings = _settings()
    if not settings.ML_TRAINING_ENABLED:
        raise MLTrainingDisabledError(
            "Model training is disabled (ML_TRAINING_ENABLED=false). "
            "Enable it deliberately, train, then disable it again."
        )

    started = time.monotonic()
    active_schema = schema or _schema()
    version = model_version or _next_model_version(db, active_schema)

    result: TrainingResult = train_model(
        db,
        model_dir=settings.ML_MODEL_DIR,
        model_version=version,
        label_file=label_file or settings.ML_LABEL_FILE or None,
        random_seed=settings.ML_RANDOM_SEED,
        schema=active_schema,
    )
    return _training_payload(result, active_schema, started)


def _next_model_version(db: Session, schema: MLFeatureSchema) -> str:
    """Version models monotonically so the registry order is unambiguous."""
    existing = list_model_versions(_settings().ML_MODEL_DIR)
    highest = 0
    for version in existing:
        tail = version.rsplit("-", 1)[-1]
        if tail.isdigit():
            highest = max(highest, int(tail))
    return f"traffic-classifier-{highest + 1}.0.0"


def _training_payload(
    result: TrainingResult,
    schema: MLFeatureSchema,
    started: float,
) -> dict[str, Any]:
    trained = result.status == STATUS_TRAINED
    payload: dict[str, Any] = {
        "status": "OK" if trained else result.status,
        "trained": trained,
        "message": result.reason or "Model trained and registered.",
        "model_version": result.model_version,
        "feature_schema_version": schema.feature_schema_version,
        "dataset_version": schema.dataset_version,
        "training_samples": result.split_counts.get("train", 0),
        "capture_count": result.dataset.get("labeled_capture_count", 0),
        "splits": result.split_counts,
        "metrics": _public_metrics(result.evaluation),
        "classes": list(schema.declared_classes),
        "excluded_features": sorted(schema.excluded_fields),
        "label_provenance": {"user_provided": result.split_counts.get("train", 0)},
        "duration_seconds": round((time.monotonic() - started) * 1000, 1000),
        "library_versions": (result.metadata or {}).get("ml_library_versions", {}),
        "created_at": (result.metadata or {}).get("training_timestamp"),
    }
    if not trained:
        # Keep the audit detail for an operator who is trying to figure out
        # *why* nothing trained, but never present it as a metric.
        payload["rejected_rows"] = result.dataset.get("rejected_rows", 0)
        payload["rejection_reasons"] = result.dataset.get("rejection_reasons", {})
        payload["notes"] = result.dataset.get("notes", [])
        payload["total_feature_rows"] = result.dataset.get("total_feature_rows", 0)
        payload["unlabeled_rows"] = result.dataset.get("unlabeled_rows", 0)
    return payload


def dataset_report(
    db: Session,
    schema: MLFeatureSchema | None = None,
    label_file: str | None = None,
) -> dict[str, Any]:
    """Dry-run the dataset builder: what training *would* see, without fitting.

    This is the honest way to answer "can we train yet?" without writing an
    artifact. The label registry is read exactly as training would read it, so
    ``label_file`` resolves with the same precedence as ``run_training``:
    the argument, then ``ML_LABEL_FILE``. Without that, an operator who trains
    against an explicit label file would be told here that zero rows are
    labeled -- while training had just succeeded.
    """
    active_schema = schema or _schema()
    result: DatasetBuildResult = build_dataset(
        db,
        schema=active_schema,
        label_file=label_file or _settings().ML_LABEL_FILE or None,
    )
    return result.summary()


# --------------------------------------------------------------------------- #
# Inference
# --------------------------------------------------------------------------- #


def _load_validated_rows(
    db: Session, analysis: Analysis
) -> tuple[list[ValidatedRow], list[Rejection]]:
    """Validate this analysis's flow features against the ML schema."""
    schema = _schema()
    rows: list[ValidatedRow] = []
    rejections: list[Rejection] = []

    query = (
        select(FlowFeatures)
        .join(Flow, FlowFeatures.flow_id == Flow.id)
        .options(selectinload(FlowFeatures.flow))
        .where(Flow.analysis_id == analysis.id)
        .order_by(FlowFeatures.flow_id)
    )

    # `Analysis.capture_id` is the captures *UUID* (the FK); the human-facing
    # capture key is `Capture.capture_id`. Resolve it so stored predictions
    # carry the same key the rest of the API and the label registry use.
    capture_key = _capture_key_for(db, analysis)

    for feature_row in db.scalars(query).all():
        flow = feature_row.flow
        if flow is None:
            rejections.append(
                Rejection(
                    flow_key=feature_row.flow_id,
                    analysis_id=analysis.analysis_id or analysis.id,
                    capture_id=capture_key or "",
                    reason="orphan_flow_feature",
                    detail="FlowFeatures row has no flow",
                )
            )
            continue
        candidate, rejection = validate_row(
            feature_row.features,
            schema=schema,
            source_feature_schema_version=feature_row.feature_schema_version,
            flow_key=flow.flow_id,
            flow_uuid=flow.id,
            analysis_id=analysis.id,
            analysis_key=analysis.analysis_id or analysis.id,
            capture_id=capture_key or "",
            capture_sha256=None,
            analyzer_version=analysis.analyzer_version,
            parser_version=analysis.parser_version,
        )
        if rejection is not None:
            rejections.append(rejection)
            continue
        assert candidate is not None
        rows.append(candidate)

    return rows, rejections


def _capture_key_for(db: Session, analysis: Analysis) -> str | None:
    """Resolve an analysis to its human-facing capture key (``Capture.capture_id``).

    ``Analysis.capture_id`` holds the captures UUID because that is the foreign
    key; the ``CAP-000001`` style key lives in ``Capture.capture_id``. Storing
    the UUID where the API shows a capture key would make predictions
    impossible to join back to a capture by eye or by the label registry.
    """
    return db.scalar(select(Capture.capture_id).where(Capture.id == analysis.capture_id))


def _count_reasons(rejections: list[Rejection]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rejection in rejections:
        counts[rejection.reason] = counts.get(rejection.reason, 0) + 1
    return dict(sorted(counts.items()))


def predict_analysis(
    db: Session,
    analysis: Analysis,
    *,
    model_version: str | None = None,
) -> InferenceResult:
    """Score an analysis's flows and persist predictions idempotently."""
    started = time.monotonic()
    settings = _settings()
    schema = _schema()
    # `Analysis.analysis_id` is nullable (it is assigned when an analysis job
    # completes), so every returned result resolves the human-facing key once
    # here rather than propagating an optional into the response schema.
    analysis_key = analysis.analysis_id or analysis.id

    if not settings.ML_ENABLED:
        return InferenceResult(
            status=predictor.STATUS_DISABLED,
            analysis_id=analysis_key,
            detail=_unavailable(
                "ML inference is disabled (ML_ENABLED=false).",
                required_version=schema.feature_schema_version,
                remediation="Set ML_ENABLED=true to enable inference.",
            ),
            summary=predictor.summarize([]),
        )

    rows, rejections = _load_validated_rows(db, analysis)
    if not rows:
        return InferenceResult(
            status=predictor.STATUS_INSUFFICIENT_DATA,
            analysis_id=analysis_key,
            rejected=len(rejections),
            rejection_reasons=_count_reasons(rejections),
            detail=_unavailable(
                "This analysis has no usable flow features to score.",
                required_version=schema.feature_schema_version,
                remediation="Re-run the capture through packet analysis so flow "
                "features are persisted, then retry.",
                rejected_rows=len(rejections),
            ),
            summary=predictor.summarize([]),
            duration_seconds=round(time.monotonic() - started, 3),
        )

    status, predictions, resolved_version = predictor.run_inference(
        [row.features for row in rows],
        model_dir=settings.ML_MODEL_DIR,
        schema=schema,
        requested_version=model_version or settings.ML_DEFAULT_MODEL_VERSION,
        min_confidence=predictor.default_min_confidence(settings.ML_MIN_CONFIDENCE),
    )

    if status != predictor.STATUS_OK or resolved_version is None:
        return InferenceResult(
            status=status,
            analysis_id=analysis_key,
            total=len(rows),
            rejected=len(rejections),
            rejection_reasons=_count_reasons(rejections),
            detail=_unavailable(
                "No compatible trained model is available.",
                required_version=schema.feature_schema_version,
            ),
            summary=predictor.summarize([]),
            duration_seconds=round(time.monotonic() - started, 3),
        )

    created, updated = _persist_predictions(
        db,
        analysis=analysis,
        rows=rows,
        predictions=predictions,
        model_version=resolved_version,
        threshold=predictor.default_min_confidence(settings.ML_MIN_CONFIDENCE),
    )

    result = InferenceResult(
        status=status,
        analysis_id=analysis_key,
        model_version=resolved_version,
        total=len(predictions),
        created=created,
        updated=updated,
        rejected=len(rejections),
        rejection_reasons=_count_reasons(rejections),
        summary=predictor.summarize(predictions),
        duration_seconds=round(time.monotonic() - started, 3),
    )
    logger.info(
        "ml inference complete",
        extra={
            "analysis_id": analysis.analysis_id,
            "model_version": resolved_version,
            "total": result.total,
            "created": created,
            "updated": updated,
            "rejected": result.rejected,
        },
    )
    return result


def _persist_predictions(
    db: Session,
    *,
    analysis: Analysis,
    rows: list[ValidatedRow],
    predictions: list[Any],
    model_version: str,
    threshold: float,
) -> tuple[int, int]:
    """Upsert predictions keyed on (flow_id, model_version). Returns (created, updated)."""
    metadata = _model_metadata_for(model_version)
    capture_id = _capture_key_for(db, analysis)

    existing = {
        row.flow_id: row
        for row in db.scalars(
            select(TrafficPrediction).where(
                TrafficPrediction.analysis_id == analysis.id,
                TrafficPrediction.model_version == model_version,
            )
        ).all()
    }

    created = 0
    updated = 0
    seen: set[str] = set()

    for row, prediction in zip(rows, predictions, strict=True):
        seen.add(row.flow_uuid)
        record = existing.get(row.flow_uuid)
        if record is None:
            record = TrafficPrediction(
                analysis_id=analysis.id,
                flow_id=row.flow_uuid,
                capture_id=capture_id,
                model_version=model_version,
                model_type=metadata.model_type if metadata else None,
                dataset_version=metadata.dataset_version if metadata else None,
                feature_schema_version=metadata.feature_schema_version
                if metadata
                else get_feature_schema().feature_schema_version,
                prediction=prediction.predicted_class,
                top_candidate=prediction.top_candidate,
                confidence=prediction.confidence,
                min_confidence_threshold=threshold,
                abstained=prediction.abstained,
                probabilities_json=json.dumps(prediction.probabilities, sort_keys=True),
                observation_status=ObservationStatus.MODEL_PREDICTED,
            )
            db.add(record)
            created += 1
        else:
            record.prediction = prediction.predicted_class
            record.top_candidate = prediction.top_candidate
            record.confidence = prediction.confidence
            record.min_confidence_threshold = threshold
            record.abstained = prediction.abstained
            record.probabilities_json = json.dumps(prediction.probabilities, sort_keys=True)
            record.capture_id = capture_id
            updated += 1

    if created:
        # New rows are still pending in the session, and the test session runs
        # with autoflush disabled, so they must be flushed before the id
        # allocator can see them.
        db.flush()
        _assign_prediction_ids(db)
    else:
        db.flush()

    # Flows that disappeared since the last run must not keep stale predictions.
    stale = [uuid for uuid in existing if uuid not in seen]
    if stale:
        db.execute(
            delete(TrafficPrediction).where(
                TrafficPrediction.analysis_id == analysis.id,
                TrafficPrediction.model_version == model_version,
                TrafficPrediction.flow_id.in_(stale),
            )
        )

    db.commit()
    return created, updated


def _assign_prediction_ids(db: Session) -> None:
    """Give un-numbered rows a human-readable PRED-000001 id, once, at flush.

    The start number is read once and then incremented in memory. Asking the
    database for the max on every row would return the same value for each
    uncommitted row and collide on the unique index.
    """
    unnumbered = db.scalars(
        select(TrafficPrediction)
        .where(TrafficPrediction.prediction_id.is_(None))
        .order_by(TrafficPrediction.created_at, TrafficPrediction.id)
    ).all()
    if not unnumbered:
        return
    highest = 0
    for existing in db.scalars(
        select(TrafficPrediction.prediction_id).where(TrafficPrediction.prediction_id.is_not(None))
    ).all():
        text = str(existing)
        suffix = text.split("-")[-1]
        if text.startswith("PRED-") and suffix.isdigit():
            highest = max(highest, int(suffix))
    for offset, row in enumerate(unnumbered, start=1):
        row.prediction_id = f"PRED-{highest + offset:06d}"


def _model_metadata_for(model_version: str) -> ModelMetadata | None:
    """Best-effort metadata lookup; a missing artifact is not fatal here."""
    try:
        return read_metadata(resolve_model_dir(_settings().ML_MODEL_DIR, model_version))
    except (ModelArtifactError, KeyError, ValueError, OSError):
        return None


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #


def list_predictions(
    db: Session,
    analysis: Analysis,
    *,
    model_version: str | None = None,
    min_confidence: float | None = None,
    prediction: str | None = None,
) -> tuple[list[TrafficPrediction], str | None, dict[str, Any]]:
    """Return stored predictions for an analysis plus a summary block."""
    query = (
        select(TrafficPrediction)
        .where(TrafficPrediction.analysis_id == analysis.id)
        .order_by(TrafficPrediction.confidence.desc(), TrafficPrediction.flow_id)
    )
    if model_version:
        query = query.where(TrafficPrediction.model_version == model_version)
    if prediction:
        query = query.where(TrafficPrediction.prediction == prediction.upper())
    if min_confidence is not None:
        query = query.where(TrafficPrediction.confidence >= min_confidence)

    rows = list(db.scalars(query).all())
    if not rows:
        return [], model_version, predictor.summarize([])

    used_version = model_version or rows[0].model_version
    summary = {
        "count": len(rows),
        "model_version": used_version,
        "average_confidence": round(sum(row.confidence for row in rows) / len(rows), 4),
        "unknown_count": sum(1 for row in rows if row.prediction == predictor.PREDICTION_UNKNOWN),
        "abstained_count": sum(1 for row in rows if row.abstained),
        "low_confidence_count": sum(1 for row in rows if row.confidence < 0.75),
        "class_distribution": _distribution(rows),
    }
    return rows, used_version, summary


def _distribution(rows: list[TrafficPrediction]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.prediction] = counts.get(row.prediction, 0) + 1
    return dict(sorted(counts.items()))


def list_prediction_history(
    db: Session,
    *,
    capture_id: str | None = None,
    flow_id: str | None = None,
    limit: int = 50,
) -> list[TrafficPrediction]:
    """Cross-analysis prediction history, newest first."""
    query = select(TrafficPrediction).order_by(
        TrafficPrediction.created_at.desc(), TrafficPrediction.id
    )
    if capture_id:
        query = query.where(TrafficPrediction.capture_id == capture_id)
    if flow_id:
        query = query.where(TrafficPrediction.flow_id == flow_id)
    return list(db.scalars(query.limit(limit)).all())


def delete_predictions(db: Session, analysis: Analysis, *, model_version: str | None = None) -> int:
    """Remove stored predictions for an analysis (used by delete endpoints)."""
    query = delete(TrafficPrediction).where(TrafficPrediction.analysis_id == analysis.id)
    if model_version:
        query = query.where(TrafficPrediction.model_version == model_version)
    result = db.execute(query)
    db.commit()
    # `rowcount` lives on CursorResult, which SQLAlchemy only narrows to at
    # runtime for a DML statement, so it is spelled out here.
    return int(cast("CursorResult[Any]", result).rowcount or 0)


def prediction_counts(db: Session) -> dict[str, int]:
    """Aggregate prediction counts for stats endpoints."""
    total = db.scalar(select(func.count()).select_from(TrafficPrediction)) or 0
    unknown = (
        db.scalar(
            select(func.count())
            .select_from(TrafficPrediction)
            .where(TrafficPrediction.prediction == predictor.PREDICTION_UNKNOWN)
        )
        or 0
    )
    return {"total": int(total), "unknown": int(unknown)}
