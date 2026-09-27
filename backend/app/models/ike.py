"""IKE message and proposal models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str


class IkeMessage(Base, TimestampMixin):
    __tablename__ = "ike_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    packet_id: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False)
    exchange_type: Mapped[int] = mapped_column(Integer, nullable=False)
    exchange_name: Mapped[str] = mapped_column(String(64), nullable=False)
    flags: Mapped[int] = mapped_column(Integer, nullable=False)
    message_id: Mapped[str] = mapped_column(String(16), nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    next_payload: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_types_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiator_spi: Mapped[str] = mapped_column(String(32), nullable=False)
    responder_spi: Mapped[str] = mapped_column(String(32), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)

    @property
    def payload_types(self) -> list[str]:
        if not self.payload_types_json:
            return []
        import json

        try:
            parsed = json.loads(self.payload_types_json)
            return list(parsed) if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return []

    analysis = relationship("Analysis", back_populates="ike_messages")
    proposals = relationship(
        "IkeProposal",
        back_populates="ike_message",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class IkeProposal(Base, TimestampMixin):
    __tablename__ = "ike_proposals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    ike_message_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("ike_messages.id", ondelete="CASCADE"), nullable=True, index=True
    )
    proposal_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol_id: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol_name: Mapped[str] = mapped_column(String(32), nullable=False)
    encryption: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    key_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    integrity: Mapped[str] = mapped_column(String(64), nullable=False)
    integrity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prf: Mapped[str] = mapped_column(String(64), nullable=False)
    prf_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dh_group: Mapped[int | None] = mapped_column(Integer, nullable=True)
    esn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    transform_confidence: Mapped[str] = mapped_column(String(16), nullable=False)

    analysis = relationship("Analysis")
    ike_message = relationship("IkeMessage", back_populates="proposals")
