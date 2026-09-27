"""Security finding model — one row per detected configuration risk.

Phase 3 added the deterministic assessment fields: ``finding_id`` (human
readable like ``SEC-000001``), ``rule_version``, ``observed_value`` /
``expected_value``, ``evidence_digest`` (idempotency key), and upgraded
``confidence`` and ``status`` from free-form columns to explicit enums.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str
from app.security.enums import FindingConfidence, FindingStatus

__all__ = [
    "FindingConfidence",
    "FindingStatus",
    "FindingType",
    "SecurityFinding",
    "Severity",
]


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(StrEnum):
    VULNERABILITY_INDICATOR = "vulnerability_indicator"
    POLICY_DEVIATION = "policy_deviation"
    CONFIGURATION_RISK = "configuration_risk"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class SecurityFinding(Base, TimestampMixin):
    __tablename__ = "security_findings"
    __table_args__ = (
        # Idempotency key for re-assessment: one finding per
        # (analysis, rule, evidence). Declared as a unique Index rather than a
        # UniqueConstraint so the model matches the unique index created by
        # migration b7f0a1e2034a (keeps `alembic check` clean).
        Index(
            "ix_security_findings_analysis_rule_evidence",
            "analysis_id",
            "rule_id",
            "evidence_digest",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    finding_id: Mapped[str | None] = mapped_column(
        String(32), unique=True, index=True, nullable=True
    )
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity, name="severity"), index=True)
    finding_type: Mapped[FindingType] = mapped_column(
        SAEnum(FindingType, name="finding_type"), default=FindingType.CONFIGURATION_RISK
    )
    category: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[FindingConfidence] = mapped_column(
        SAEnum(FindingConfidence, name="finding_confidence"),
        default=FindingConfidence.HIGH,
    )
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, name="finding_status"),
        default=FindingStatus.OPEN,
        index=True,
    )
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="findings")

    @property
    def evidence(self) -> dict[str, Any] | None:
        if not self.evidence_json:
            return None
        try:
            parsed = json.loads(self.evidence_json)
            return parsed if isinstance(parsed, dict) else None
        except (TypeError, ValueError):
            return None
