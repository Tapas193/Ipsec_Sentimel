"""Assessment context: the persisted Phase 2 data a rule evaluates.

The assessment engine never re-parses a PCAP; it consumes exactly what was
persisted by the Phase 2 analysis pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models import (
    AhPacket,
    Analysis,
    EspPacket,
    Flow,
    FlowFeatures,
    IkeMessage,
    IkeProposal,
    ProtocolObservation,
)


@dataclass
class AssessmentContext:
    analysis: Analysis
    ike_messages: list[IkeMessage] = field(default_factory=list)
    proposals: list[IkeProposal] = field(default_factory=list)
    esp_packets: list[EspPacket] = field(default_factory=list)
    ah_packets: list[AhPacket] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    features: list[FlowFeatures] = field(default_factory=list)
    protocol_observations: list[ProtocolObservation] = field(default_factory=list)
