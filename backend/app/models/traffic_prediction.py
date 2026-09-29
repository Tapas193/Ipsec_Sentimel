"""Traffic prediction model — one row per (flow, model version) ML observation.

Phase 4 stores model output *beside* Phase 3 findings, never instead of them.
The two are different kinds of claim and stay in different tables:

- ``SecurityFinding``   — deterministic rule output, authoritative, evidence-backed.
- ``TrafficPrediction`` — probabilistic model output, ``MODEL_PREDICTED``, and
  explicitly *not* a security severity. Nothing here feeds a risk score.

Design notes:

- Flow features are **not** duplicated. The row references the source flow and
  stores only what is needed to interpret and reproduce the prediction: the
  model/dataset/schema versions, the class, the confidence, the full
  probability vector, and the observation status.
- ``capture_id`` is denormalized on purpose: a prediction must remain auditable
  against its capture even if the analysis row is inspected later.
- Idempotency is a unique index on ``(flow_id, model_version)``, mirroring the
  Phase 3 evidence-digest approach. Re-running inference for the same model
  version updates the existing row instead of appending a duplicate.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str
from app.security.enums import ObservationStatus

__all__ = ["ObservationStatus", "TrafficPrediction", "TrafficType"]


class TrafficType(StrEnum):
    """Traffic classes the model may report.

    The value set mirrors ``class_definition.classes`` in
    ``configs/ml_feature_schema.yaml``. ``UNKNOWN`` is both a declared class and
    the abstention outcome when confidence falls below ``ML_MIN_CONFIDENCE``.
    """

    VOIP = "VOIP"
    MESSAGING = "MESSAGING"
    EMAIL = "EMAIL"
    WEB = "WEB"
    VIDEO = "VIDEO"
    ICMP = "ICMP"
    UNKNOWN = "UNKNOWN"


class TrafficPrediction(Base, TimestampMixin):
    __tablename__ = "traffic_predictions"
    __table_args__ = (
        # One prediction per (flow, model version). Re-running inference for the
        # same model must not create a second row.
        Index(
            "ix_traffic_predictions_flow_model",
            "flow_id",
            "model_version",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    prediction_id: Mapped[str | None] = mapped_column(
        String(32), unique=True, index=True, nullable=True
    )
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    flow_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("flows.id", ondelete="CASCADE"), index=True
    )
    capture_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)

    model_version: Mapped[str] = mapped_column(String(64), index=True)
    model_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dataset_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    feature_schema_version: Mapped[str] = mapped_column(String(16))

    prediction: Mapped[str] = mapped_column(String(32), index=True)
    top_candidate: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, index=True)
    min_confidence_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    abstained: Mapped[bool] = mapped_column(Boolean, default=False)
    probabilities_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    observation_status: Mapped[ObservationStatus] = mapped_column(
        SAEnum(ObservationStatus, name="observation_status"),
        default=ObservationStatus.MODEL_PREDICTED,
        index=True,
    )
    pipeline_position: Mapped[int | None] = mapped_column(Integer, nullable=True)

    analysis = relationship("Analysis", back_populates="traffic_predictions")
    flow = relationship("Flow", back_populates="traffic_predictions")

    @property
    def probabilities(self) -> dict[str, float]:
        if not self.probabilities_json:
            return {}
        try:
            parsed = json.loads(self.probabilities_json)
        except (TypeError, ValueError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        return {str(key): float(value) for key, value in parsed.items()}

    def as_dict(self) -> dict[str, Any]:
        return {
            "prediction_id": self.prediction_id,
            "flow_id": self.flow_id,
            "analysis_id": self.analysis_id,
            "capture_id": self.capture_id,
            "model_version": self.model_version,
            "model_type": self.model_type,
            "dataset_version": self.dataset_version,
            "feature_schema_version": self.feature_schema_version,
            "prediction": self.prediction,
            "top_candidate": self.top_candidate,
            "confidence": self.confidence,
            "min_confidence_threshold": self.min_confidence_threshold,
            "abstained": self.abstained,
            "probabilities": self.probabilities,
            "observation_status": str(self.observation_status),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
