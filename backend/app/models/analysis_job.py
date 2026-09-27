"""Analysis job model — tracks asynchronous analysis progress."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class JobStage(StrEnum):
    VALIDATION = "validation"
    PACKET_READING = "packet_reading"
    PROTOCOL_DETECTION = "protocol_detection"
    IKE_ANALYSIS = "ike_analysis"
    ESP_ANALYSIS = "esp_analysis"
    FLOW_BUILDING = "flow_building"
    FEATURE_EXTRACTION = "feature_extraction"
    PERSISTENCE = "persistence"
    COMPLETED = "completed"
    # Legacy stages retained for backward-compatible enum values.
    INGESTION = "ingestion"
    AI_ANALYSIS = "ai_analysis"
    SECURITY_ASSESSMENT = "security_assessment"
    REPORT_GENERATION = "report_generation"


class AnalysisJob(Base, TimestampMixin):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    job_id: Mapped[str | None] = mapped_column(String(32), nullable=True, unique=True, index=True)
    capture_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[JobStatus] = mapped_column(
        SAEnum(JobStatus, name="job_status"), default=JobStatus.QUEUED, index=True
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    current_stage: Mapped[JobStage] = mapped_column(SAEnum(JobStage, name="job_stage"))
    stage_message: Mapped[str | None] = mapped_column(String(256), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    capture = relationship("Capture", back_populates="jobs")
