"""Phase 4 ML endpoints.

Route surface:

    GET    /api/v1/ml/health                 readiness + active model
    GET    /api/v1/ml/schema                 feature contract
    GET    /api/v1/ml/models                 registered models
    GET    /api/v1/ml/models/{version}       one model's provenance
    GET    /api/v1/ml/models/{version}/metrics  held-out metrics (may be absent)
    POST   /api/v1/ml/train                  explicit, gated training run
    GET    /api/v1/ml/dataset                dry-run of the dataset builder
    POST   /api/v1/ml/analyses/{key}/predict     run inference and persist
    GET    /api/v1/ml/analyses/{key}/predictions list stored predictions
    DELETE /api/v1/ml/analyses/{key}/predictions remove stored predictions
    GET    /api/v1/ml/predictions            cross-analysis history
    GET    /api/v1/ml/flows/{flow_uuid}/prediction  one flow's prediction

Status-code policy
------------------
ML unavailability is *not* an HTTP error. ``ML_NOT_AVAILABLE``,
``INSUFFICIENT_LABELED_DATA`` and friends are returned as HTTP 200 with an
explicit status field so the frontend can render an informative empty state
instead of a generic failure banner. HTTP errors are reserved for genuine
faults: unknown analysis (404), training while disabled (403), a malformed
model version (400).

Security posture
----------------
- Model artifacts are never addressable by path. Only a version token is
  accepted, and it is validated against a strict pattern before use.
- The label file is a *server-side* path. There is no upload endpoint, so a
  remote caller cannot make the backend read an arbitrary file, and label files
  are never echoed back in responses.
- No endpoint writes a SecurityFinding or any security score.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, status
from sqlalchemy.orm import Session

from app.api.v1.common import DbSession
from app.core.exceptions import (
    AnalysisNotFoundError,
    AppError,
    BadRequestError,
    NotFoundError,
)
from app.core.responses import ok
from app.ml.artifacts import ModelArtifactError
from app.ml.schema import MLSchemaError
from app.models import Analysis
from app.schemas.common import ApiResponse
from app.schemas.ml import (
    MLFeatureListResponse,
    MLHealthResponse,
    MLModelListResponse,
    MLModelRead,
    MLSchemaResponse,
    MLTrainingRequest,
    MLTrainingResponse,
    MLUnavailableDetail,
    PredictionListResponse,
    PredictionRead,
    PredictionRunResponse,
    PredictionSummary,
    RunStatus,
)
from app.services import ml_service
from app.services.analysis_service import get_analysis_by_key

logger = logging.getLogger("ipsec_sentinel.ml")


def _analysis_or_404(db: Session, analysis_key: str) -> Analysis:
    analysis = get_analysis_by_key(db, analysis_key)
    if analysis is None:
        raise AnalysisNotFoundError(
            f"Analysis {analysis_key!r} was not found.", details={"analysis_id": analysis_key}
        )
    return analysis


router = APIRouter(prefix="/ml", tags=["ml"])

AnalysisKey = Annotated[
    str, Path(min_length=1, max_length=64, description="Analysis id, e.g. ANA-000001")
]
FlowUuid = Annotated[str, Path(min_length=1, max_length=36, description="Flow UUID")]


def _empty_summary() -> PredictionSummary:
    return PredictionSummary(
        count=0,
        model_version=None,
        average_confidence=None,
        unknown_count=0,
        abstained_count=0,
        low_confidence_count=0,
        class_distribution={},
    )


@router.get("/health", response_model=ApiResponse[MLHealthResponse])
def ml_health() -> ApiResponse[MLHealthResponse]:
    """Readiness of the ML subsystem. Always 200: 'not trained' is a valid state."""
    return ok(MLHealthResponse(**ml_service.get_health()))


@router.get("/schema", response_model=ApiResponse[MLSchemaResponse])
def ml_schema() -> ApiResponse[MLSchemaResponse]:
    """The exact feature contract, for reproducibility auditing."""
    try:
        payload = ml_service.ml_schema_payload()
    except MLSchemaError as exc:
        raise AppError(f"ML feature schema is invalid: {exc}") from exc
    return ok(MLSchemaResponse(**payload))


@router.get("/features", response_model=ApiResponse[MLFeatureListResponse])
def ml_features() -> ApiResponse[MLFeatureListResponse]:
    """Flat feature list with the active confidence threshold."""
    settings = ml_service.get_health()
    schema = ml_service.ml_schema_payload()
    return ok(
        MLFeatureListResponse(
            feature_schema_version=schema["feature_schema_version"],
            dataset_version=schema["dataset_version"],
            feature_count=len(schema["features"]),
            features=schema["features"],
            excluded_features=schema["excluded_features"],
            classes=schema["classes"],
            min_confidence=settings["min_confidence"],
        )
    )


@router.get("/models", response_model=ApiResponse[MLModelListResponse])
def list_models() -> ApiResponse[MLModelListResponse]:
    return ok(MLModelListResponse(**ml_service.describe_models()))


@router.get("/models/{model_version}", response_model=ApiResponse[MLModelRead])
def get_model(
    model_version: Annotated[str, Path(min_length=1, max_length=64)],
) -> ApiResponse[MLModelRead]:
    for model in ml_service.describe_models()["models"]:
        if model["model_version"] == model_version:
            return ok(MLModelRead(**model))
    raise NotFoundError(f"Model {model_version!r} is not registered.")


@router.get("/models/{model_version}/metrics", response_model=ApiResponse[dict[str, Any]])
def get_model_metrics(
    model_version: Annotated[str, Path(min_length=1, max_length=64)],
) -> ApiResponse[dict[str, Any]]:
    """Held-out metrics for one model.

    ``metrics`` is ``null`` when the model was fitted but never evaluated. That
    is reported as an explicit null, never as zeros.
    """
    health = ml_service.get_health()
    evaluation = None
    for model in ml_service.describe_models()["models"]:
        if model["model_version"] == model_version:
            evaluation = model.get("metrics")
            break
    else:
        raise NotFoundError(f"Model {model_version!r} is not registered.")
    return ok(
        {
            "model_version": model_version,
            "metrics": evaluation,
            "evaluated": evaluation is not None,
            "note": None
            if evaluation is not None
            else "This model was fitted but not evaluated: the held-out test split "
            "was smaller than the configured minimum. No metrics are claimed.",
            "min_confidence": health["min_confidence"],
        }
    )


@router.get("/dataset", response_model=ApiResponse[dict[str, Any]])
def dataset_status(
    db: DbSession,
    label_file: Annotated[
        str | None,
        Query(
            max_length=512,
            description=(
                "Optional label registry to audit. Resolves with the same "
                "precedence as POST /ml/train: this value, then ML_LABEL_FILE."
            ),
        ),
    ] = None,
) -> ApiResponse[dict[str, Any]]:
    """Dry-run the dataset builder: what training would see, without fitting.

    This is how an operator checks label coverage without writing an artifact.
    """
    return ok(ml_service.dataset_report(db, label_file=label_file))


@router.post(
    "/train",
    response_model=ApiResponse[MLTrainingResponse],
    status_code=status.HTTP_200_OK,
)
def train(
    db: DbSession,
    body: MLTrainingRequest | None = None,
) -> ApiResponse[MLTrainingResponse]:
    """Explicit training run.

    Returns 200 with ``trained=false`` and ``status=INSUFFICIENT_LABELED_DATA``
    when no ground truth exists. That is the expected result for this repository
    and is *not* an error.
    """
    request = body or MLTrainingRequest()
    try:
        payload = ml_service.run_training(
            db,
            model_version=request.model_version,
            label_file=request.label_file,
        )
    except ml_service.MLTrainingDisabledError as exc:
        raise AppError(str(exc)) from exc
    except (MLSchemaError, ModelArtifactError) as exc:
        raise BadRequestError(f"Training could not start: {exc}") from exc
    return ok(MLTrainingResponse(**payload))


@router.post(
    "/analyses/{analysis_key}/predict",
    response_model=ApiResponse[PredictionRunResponse],
    status_code=status.HTTP_200_OK,
)
def run_prediction(
    db: DbSession,
    analysis_key: AnalysisKey,
    model_version: Annotated[str | None, Query(max_length=64)] = None,
) -> ApiResponse[PredictionRunResponse]:
    """Score an analysis and persist predictions idempotently.

    Re-running for the same model version updates rows in place; the count of
    stored rows never grows.
    """
    analysis = _analysis_or_404(db, analysis_key)
    result = ml_service.predict_analysis(db, analysis, model_version=model_version)
    return ok(
        PredictionRunResponse(
            status=result.status,
            analysis_id=result.analysis_id,
            model_version=result.model_version,
            total=result.total,
            created=result.created,
            updated=result.updated,
            rejected=result.rejected,
            rejection_reasons=result.rejection_reasons,
            observation_status=result.observation_status,
            summary=PredictionSummary(**result.summary),
            detail=MLUnavailableDetail(**result.detail) if result.detail else None,
            duration_seconds=result.duration_seconds,
        )
    )


@router.get(
    "/analyses/{analysis_key}/predictions",
    response_model=ApiResponse[PredictionListResponse],
)
def analysis_predictions(
    db: DbSession,
    analysis_key: AnalysisKey,
    model_version: Annotated[str | None, Query(max_length=64)] = None,
    min_confidence: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    prediction: Annotated[str | None, Query(max_length=32)] = None,
) -> ApiResponse[PredictionListResponse]:
    """Stored predictions for one analysis."""
    analysis = _analysis_or_404(db, analysis_key)
    rows, used_version, summary = ml_service.list_predictions(
        db,
        analysis,
        model_version=model_version,
        min_confidence=min_confidence,
        prediction=prediction,
    )
    health = ml_service.get_health()
    # `detail` is a plain dict inside the service's response-shaped payloads; it
    # is validated into the schema here so a missing or misspelled key is a
    # construction error rather than a silently wrong JSON body.
    raw_detail = health.get("detail") if not rows else None
    detail = MLUnavailableDetail(**raw_detail) if raw_detail else None
    status_value: RunStatus = (
        "OK" if rows else ("DISABLED" if not health["ml_enabled"] else "MODEL_NOT_AVAILABLE")
    )
    return ok(
        PredictionListResponse(
            status=status_value,
            analysis_id=analysis.analysis_id or analysis.id,
            model_version=used_version,
            summary=PredictionSummary(**summary),
            predictions=[PredictionRead.model_validate(row) for row in rows],
            detail=detail,
        )
    )


@router.delete("/analyses/{analysis_key}/predictions", response_model=ApiResponse[dict[str, Any]])
def clear_predictions(db: DbSession, analysis_key: AnalysisKey) -> ApiResponse[dict[str, Any]]:
    removed = ml_service.delete_predictions(db, _analysis_or_404(db, analysis_key))
    return ok({"deleted": removed})


@router.get("/predictions", response_model=ApiResponse[dict[str, Any]])
def prediction_history(
    db: DbSession,
    capture_id: Annotated[str | None, Query(max_length=32)] = None,
    flow_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> ApiResponse[dict[str, Any]]:
    """Cross-analysis prediction history, newest first."""
    rows = ml_service.list_prediction_history(
        db, capture_id=capture_id, flow_id=flow_id, limit=limit
    )
    return ok(
        {
            "total": len(rows),
            "predictions": [PredictionRead.model_validate(row).model_dump() for row in rows],
        }
    )


@router.get("/flows/{flow_uuid}/prediction", response_model=ApiResponse[dict[str, Any]])
def flow_prediction(db: DbSession, flow_uuid: FlowUuid) -> ApiResponse[dict[str, Any]]:
    """The most recent prediction for one flow, across models."""
    rows = ml_service.list_prediction_history(db, flow_id=flow_uuid, limit=1)
    if not rows:
        raise NotFoundError(f"No prediction exists for flow {flow_uuid!r}.")
    return ok(PredictionRead.model_validate(rows[0]).model_dump())


__all__ = ["router"]
