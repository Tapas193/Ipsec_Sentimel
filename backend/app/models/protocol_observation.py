"""Protocol observation model — per-analysis protocol packet counts."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str


class ProtocolObservation(Base, TimestampMixin):
    __tablename__ = "protocol_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def evidence(self) -> list[str]:
        if not self.evidence_json:
            return []
        import json

        try:
            parsed = json.loads(self.evidence_json)
            return list(parsed) if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return []

    analysis = relationship("Analysis", back_populates="protocol_observations")
