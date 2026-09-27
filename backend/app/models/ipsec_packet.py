"""ESP and AH packet observation models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str


class EspPacket(Base, TimestampMixin):
    __tablename__ = "esp_packets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    packet_id: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    spi: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    sequence_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)

    analysis = relationship("Analysis", back_populates="esp_packets")


class AhPacket(Base, TimestampMixin):
    __tablename__ = "ah_packets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    packet_id: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    spi: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    sequence_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    next_header: Mapped[int | None] = mapped_column(Integer, nullable=True)

    analysis = relationship("Analysis", back_populates="ah_packets")
