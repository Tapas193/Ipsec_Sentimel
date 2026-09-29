"""Flow and flow-feature models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, uuid_str


class Flow(Base, TimestampMixin):
    __tablename__ = "flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    # A flow key renders "<src>:<sport>-<proto>/<ipver>-><dst>:<dport>". The
    # previous String(32) truncated any flow with 5-digit ports on both sides
    # (e.g. "10.0.0.1:12345-udp/4->10.0.0.2:8080" is 35 chars) and could not
    # hold IPv6 keys at all. Truncation is unacceptable here because flow_id is
    # the stable identity used to group flows, so two distinct flows could be
    # merged. 255 comfortably covers the longest possible IPv6 key.
    flow_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    transport: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ip_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration: Mapped[float] = mapped_column(Float, nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    upstream_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    downstream_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    upstream_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    downstream_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    spi: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ike_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    esp_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ah_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    analysis = relationship("Analysis", back_populates="flows")
    features = relationship(
        "FlowFeatures",
        back_populates="flow",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    traffic_predictions = relationship(
        "TrafficPrediction",
        back_populates="flow",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class FlowFeatures(Base, TimestampMixin):
    __tablename__ = "flow_features"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    flow_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("flows.id", ondelete="CASCADE"), index=True
    )
    feature_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    feature_json: Mapped[str] = mapped_column(Text, nullable=False)

    @property
    def features(self) -> dict[str, object]:
        import json

        try:
            parsed = json.loads(self.feature_json)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}

    @property
    def flow_key(self) -> str | None:
        """The stable, human-readable flow identity.

        ``FlowFeatures.flow_id`` is only a foreign key to ``flows.id`` (a UUID
        that is regenerated on every analysis), so it cannot identify a flow
        across captures or re-runs. Consumers that need a stable flow identity
        — notably the future ML data contract — must use this value, which is
        the same ``Flow.flow_id`` key reported by the flows endpoint.
        """
        return self.flow.flow_id if self.flow is not None else None

    analysis = relationship("Analysis")
    flow = relationship("Flow", back_populates="features")
