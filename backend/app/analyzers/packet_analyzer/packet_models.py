"""Data models shared by the packet analyzer.

These are plain dataclasses (no ORM). They describe a single packet capture
analysis session and are converted to database rows by the analysis service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class IkeLayer:
    """Parsed IKE header + payload chain (bytes level, no decryption)."""

    version: str  # "IKEv1" | "IKEv2" | "unknown"
    initiator_spi: str  # hex
    responder_spi: str  # hex
    next_payload: int
    exchange_type: int
    exchange_name: str
    flags: int
    message_id: str  # hex
    length: int
    payload_types: list[str]
    raw: bytes = b""
    sa_payload: bytes | None = None


@dataclass
class IkeProposalData:
    proposal_number: int
    protocol_id: int
    protocol_name: str
    encryption: str
    encryption_id: int | None = None
    key_length: int | None = None
    integrity: str = "UNKNOWN"
    integrity_id: int | None = None
    prf: str = "UNKNOWN"
    prf_id: int | None = None
    dh_group: int | None = None
    esn: int | None = None
    status: str = "OFFERED"
    transform_confidence: str = "low"


@dataclass
class EspLayer:
    """ESP header observation. Payload is ciphertext and is not inspected."""

    spi: str  # hex
    sequence_number: int | None
    encryption_algorithm: str = "UNKNOWN"
    nat_t: bool = False


@dataclass
class AhLayer:
    """Authentication Header observation."""

    spi: str  # hex
    sequence_number: int | None
    next_header: int | None = None


@dataclass
class ParsedPacket:
    number: int
    timestamp: float
    length: int
    source: str
    destination: str
    ip_version: int | None
    protocol: str  # esp | ah | udp | tcp | icmp | icmpv6 | unknown
    transport: str | None  # udp | tcp | None
    source_port: int | None
    destination_port: int | None
    fragmented: bool = False
    ike: IkeLayer | None = None
    esp: EspLayer | None = None
    ah: AhLayer | None = None
    flow_key: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class IkeMessageRecord:
    packet_id: int
    timestamp: float
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
    payload_types: list[str]
    initiator_spi: str
    responder_spi: str
    direction: str
    proposals: list[IkeProposalData] = field(default_factory=list)


@dataclass
class EspPacketRecord:
    packet_id: int
    timestamp: float
    source_ip: str
    destination_ip: str
    spi: str
    sequence_number: int | None
    length: int
    direction: str
    flow_id: str | None = None
    flow_key: str | None = None
    encryption_algorithm: str = "UNKNOWN"


@dataclass
class AhPacketRecord:
    packet_id: int
    timestamp: float
    source_ip: str
    destination_ip: str
    spi: str
    sequence_number: int | None
    length: int
    direction: str
    flow_id: str | None = None
    flow_key: str | None = None
    next_header: int | None = None


@dataclass
class ProtocolObservation:
    protocol: str
    packet_count: int
    byte_count: int
    first_seen: float
    last_seen: float
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)


@dataclass
class FlowRecord:
    flow_key: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    transport: str | None
    ip_version: int | None
    start_time: float
    end_time: float
    duration: float
    packet_count: int
    byte_count: int
    upstream_packets: int
    downstream_packets: int
    upstream_bytes: int
    downstream_bytes: int
    direction: str  # first_seen | reverse | unknown
    spi: str | None = None
    ike_packets: int = 0
    esp_packets: int = 0
    ah_packets: int = 0
    packet_indices: list[int] = field(default_factory=list)


@dataclass
class FlowFeatures:
    flow_key: str
    feature_schema_version: str
    features: dict[str, object]
