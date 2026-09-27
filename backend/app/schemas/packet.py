"""Packet analysis sub-resource schemas.

These describe the derived data persisted by an analysis:
protocol observations, IKE messages/proposals, ESP/AH packets,
flows and flow features.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProtocolObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    protocol: str
    packet_count: int
    byte_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    confidence: str | None
    evidence: list[str] = []


class IkeProposalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    proposal_number: int | None
    protocol_id: int
    protocol_name: str
    encryption: str
    encryption_id: int | None
    key_length: int | None
    integrity: str
    integrity_id: int | None
    prf: str
    prf_id: int | None
    dh_group: int | None
    esn: int | None
    status: str
    transform_confidence: str


class IkeMessageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    packet_id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    version: str
    exchange_type: int
    exchange_name: str
    flags: int
    message_id: str
    length: int
    next_payload: int
    payload_types: list[str] = []
    initiator_spi: str
    responder_spi: str
    direction: str
    proposals: list[IkeProposalRead] = []


class EspPacketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    packet_id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    spi: str
    sequence_number: int | None
    length: int
    direction: str
    encryption_algorithm: str


class AhPacketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    packet_id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    spi: str
    sequence_number: int | None
    length: int
    direction: str
    next_header: int | None


class FlowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    transport: str | None
    ip_version: int | None
    start_time: datetime
    end_time: datetime
    duration: float
    packet_count: int
    byte_count: int
    upstream_packets: int
    downstream_packets: int
    upstream_bytes: int
    downstream_bytes: int
    direction: str
    spi: str | None
    ike_packets: int
    esp_packets: int
    ah_packets: int


class FlowFeaturesRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    # `flow_id` is the FlowFeatures -> flows foreign key (a per-analysis UUID).
    # It is NOT the human-readable flow identity and is not stable across
    # re-analyses. `flow_key` below carries the stable flow identity.
    flow_id: str
    flow_key: str | None = None
    feature_schema_version: str
    features: dict[str, object] = {}
