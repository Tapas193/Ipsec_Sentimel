"""Completed analysis record model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str


class AnalysisStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class Analysis(Base, TimestampMixin):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True, unique=True, index=True
    )
    capture_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        SAEnum(AnalysisStatus, name="analysis_status"), default=AnalysisStatus.RUNNING
    )
    protocol: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ike_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    vpn_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    security_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    overall_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Phase 2 — protocol detection summary.
    protocol_detected: Mapped[str | None] = mapped_column(String(64), nullable=True)
    protocol_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ike_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ike_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    esp_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ah_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ipv4_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ipv6_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    packet_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    byte_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    flow_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    summarization_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Versioning for reproducibility (populated by analyzers in later phases).
    analyzer_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dataset_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    capture = relationship("Capture", back_populates="analyses")
    findings = relationship(
        "SecurityFinding", back_populates="analysis", cascade="all, delete-orphan"
    )
    reports = relationship("Report", back_populates="analysis", cascade="all, delete-orphan")
    protocol_observations = relationship(
        "ProtocolObservation",
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    ike_messages = relationship(
        "IkeMessage",
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    esp_packets = relationship(
        "EspPacket",
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    ah_packets = relationship(
        "AhPacket",
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    flows = relationship(
        "Flow",
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
