"""Abstract analyzer interfaces (Phase 2 clean interfaces).

The concrete engine (``engine.py``) implements all of these; the analysis
service composes them so each stage can be tested in isolation.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from app.analyzers.packet_analyzer.packet_models import (
    AhPacketRecord,
    EspPacketRecord,
    FlowFeatures,
    FlowRecord,
    IkeMessageRecord,
    ParsedPacket,
    ProtocolObservation,
)


@runtime_checkable
class PacketReader(Protocol):
    def iterate(self) -> Iterable[tuple[int, float, bytes]]: ...  # pragma: no cover


@runtime_checkable
class PacketAnalyzer(Protocol):
    """Parses raw frames into normalized packets."""

    def parse(self, frames: Iterable[tuple[int, float, bytes]]) -> list[ParsedPacket]: ...


@runtime_checkable
class ProtocolAnalyzer(Protocol):
    """Detects protocols and produces observations + IKE/ESP/AH records."""

    def detect(
        self, packets: list[ParsedPacket]
    ) -> tuple[
        list[ProtocolObservation],
        list[IkeMessageRecord],
        list[EspPacketRecord],
        list[AhPacketRecord],
    ]: ...


@runtime_checkable
class FlowAnalyzer(Protocol):
    """Reconstructs bidirectional flows from packets."""

    def build(self, packets: list[ParsedPacket]) -> list[FlowRecord]: ...


@runtime_checkable
class FeatureExtractor(Protocol):
    """Computes per-flow feature vectors."""

    def extract(
        self, flows: list[FlowRecord], packets: list[ParsedPacket]
    ) -> list[FlowFeatures]: ...
