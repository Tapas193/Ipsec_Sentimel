"""Phase 4 ML schemas.

Response shapes only. Every ML response carries an explicit ``status`` so the
frontend can distinguish the honest outcomes from a failure:

- ``OK``                    — a model ran and produced predictions.
- ``MODEL_NOT_AVAILABLE``   — no compatible artifact exists (a valid state, HTTP 200).
- ``INSUFFICIENT_DATA``     — the analysis has no flow features to score.
- ``INSUFFICIENT_LABELED_DATA`` — training was refused for lack of ground truth.
- ``DISABLED``              — ``ML_ENABLED``/``ML_TRAINING_ENABLED`` is off.

ML statuses are never HTTP errors. "No model yet" is a normal, expected
condition of a system that has not been trained, and the UI must render it as
information rather than as a failure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.ml.statuses import RunStatus, TrainStatus
from app.security.enums import ObservationStatus

__all__ = [
    "MLFeatureDefinition",
    "MLFeatureListResponse",
    "MLHealthResponse",
    "MLMetrics",
    "MLModelListResponse",
    "MLModelRead",
    "MLSchemaResponse",
    "MLTrainingRequest",
    "MLTrainingResponse",
    "MLUnavailableDetail",
    "PredictionListResponse",
    "PredictionRead",
    "PredictionRunResponse",
    "PredictionSummary",
    "RunStatus",
    "TrainStatus",
]


class MLFeatureDefinition(BaseModel):
    name: str
    type: str
    unit: str | None = None
    nullable: bool = False
    minimum: float | None = None
    maximum: float | None = None


class MLFeatureListResponse(BaseModel):
    """The exact feature contract a model must have been trained against."""

    feature_schema_version: str
    dataset_version: str
    feature_count: int
    features: list[MLFeatureDefinition]
    excluded_features: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=list)
    min_confidence: float


class MLSchemaResponse(BaseModel):
    feature_schema_version: str
    dataset_version: str
    features: list[MLFeatureDefinition]
    excluded_features: list[str] = Field(default_factory=list)
    exclusions: dict[str, str] = Field(default_factory=dict)
    classes: list[str] = Field(default_factory=list)
    split: dict[str, Any] = Field(default_factory=dict)
    preprocessing: dict[str, Any] = Field(default_factory=dict)


class MLUnavailableDetail(BaseModel):
    """Why no model is available, in a form the UI can display verbatim."""

    reason: str
    required_feature_schema_version: str | None = None
    configured_model_version: str | None = None
    registered_model_versions: list[str] = Field(default_factory=list)
    remediation: str = "Train a model with POST /api/v1/ml/train."


class MLHealthResponse(BaseModel):
    ml_enabled: bool
    training_enabled: bool
    any_model_available: bool
    active_model_version: str | None = None
    feature_schema_version: str
    dataset_version: str
    min_confidence: float
    class_count: int
    models: list[str] = Field(default_factory=list)
    detail: MLUnavailableDetail | None = None


class MLModelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    model_version: str
    model_type: str
    feature_schema_version: str
    dataset_version: str
    created_at: str
    classes: list[str] = Field(default_factory=list)
    training_samples: int
    feature_count: int
    metrics: dict[str, Any] | None = None
    splits: dict[str, Any] = Field(default_factory=dict)
    library_versions: dict[str, str] = Field(default_factory=dict)


class MLModelListResponse(BaseModel):
    total: int
    active_model_version: str | None = None
    models: list[MLModelRead] = Field(default_factory=list)


class MLMetrics(BaseModel):
    """Held-out metrics. Present only when a model was genuinely evaluated.

    ``None`` fields mean *not computed*, never *computed as zero* — reporting
    0.0 for a metric that was never measured would be a fabricated result.
    """

    accuracy: float | None = None
    precision_macro: float | None = None
    recall_macro: float | None = None
    f1_macro: float | None = None
    per_class: dict[str, dict[str, float]] = Field(default_factory=dict)
    confusion_matrix: list[list[int]] | None = None
    confusion_matrix_labels: list[str] = Field(default_factory=list)
    mean_predicted_confidence: float | None = None
    evaluated_samples: int | None = None
    expected_calibration_error: float | None = None
    abstention_rate: float | None = None


class MLTrainingRequest(BaseModel):
    """Body for an explicit training run.

    Deliberately minimal: there is no "generate labels" option, and no way to
    point training at unlabeled captures as if they were labeled data.
    """

    model_version: str | None = Field(
        default=None,
        description="Explicit version string. Auto-generated when omitted.",
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    )
    label_file: str | None = Field(
        default=None,
        description="Server-side path to a ground-truth label file. Must exist on "
        "the backend host; the value is never fetched over HTTP.",
        max_length=1024,
    )
    notes: str | None = Field(default=None, max_length=1024)


class MLTrainingResponse(BaseModel):
    status: TrainStatus
    trained: bool
    message: str
    model_version: str | None = None
    feature_schema_version: str | None = None
    dataset_version: str | None = None
    training_samples: int = 0
    capture_count: int = 0
    splits: dict[str, Any] = Field(default_factory=dict)
    metrics: MLMetrics | None = None
    classes: list[str] = Field(default_factory=list)
    excluded_features: list[str] = Field(default_factory=list)
    label_provenance: dict[str, int] = Field(default_factory=dict)
    rejected_rows: int = 0
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    library_versions: dict[str, str] = Field(default_factory=dict)
    duration_seconds: float | None = None
    created_at: str | None = None


class PredictionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    prediction_id: str | None
    analysis_id: str
    flow_id: str
    capture_id: str | None
    model_version: str
    model_type: str | None
    dataset_version: str | None
    feature_schema_version: str
    prediction: str
    top_candidate: str | None
    confidence: float
    min_confidence_threshold: float | None
    abstained: bool
    probabilities: dict[str, float] = Field(default_factory=dict)
    observation_status: str


class PredictionSummary(BaseModel):
    count: int
    model_version: str | None = None
    average_confidence: float | None = None
    unknown_count: int = 0
    abstained_count: int = 0
    low_confidence_count: int = 0
    class_distribution: dict[str, int] = Field(default_factory=dict)


class PredictionListResponse(BaseModel):
    status: RunStatus
    analysis_id: str
    model_version: str | None = None
    summary: PredictionSummary
    predictions: list[PredictionRead] = Field(default_factory=list)
    observation_status: str = ObservationStatus.MODEL_PREDICTED
    detail: MLUnavailableDetail | None = None
    duration_seconds: float | None = None


class PredictionRunResponse(BaseModel):
    """Result of an explicit inference run.

    ``created`` counts rows actually inserted, ``updated`` counts rows replaced
    by the (flow_id, model_version) idempotency key. Re-running inference for
    the same model must not grow the table.

    ``total`` is the number of candidate flows *considered*, not the number of
    predictions produced. When ``status`` is not ``OK`` the run may not have
    happened at all, so ``total`` can be non-zero while ``created`` is 0 and
    ``summary.count`` is 0. Read ``summary.count`` as "predictions produced".
    """

    status: RunStatus
    analysis_id: str
    model_version: str | None = None
    total: int = Field(
        default=0,
        description="Candidate flows considered. Not the number of predictions; see summary.count.",
    )
    created: int = Field(default=0, description="Prediction rows inserted.")
    updated: int = Field(default=0, description="Prediction rows replaced via the idempotency key.")
    rejected: int = Field(default=0, description="Flows whose features failed schema validation.")
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    observation_status: str = ObservationStatus.MODEL_PREDICTED
    summary: PredictionSummary
    detail: MLUnavailableDetail | None = None
    duration_seconds: float | None = None
    trained_at: datetime | None = None
