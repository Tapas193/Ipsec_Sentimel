"""The packet analysis engine.

Composes packet reading → parsing → protocol detection → IKE/ESP/AH analysis
→ flow building → feature extraction into a single deterministic pipeline with
resource limits (max packets, deadline). The engine is database-agnostic.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field

from app.analyzers.packet_analyzer.feature_extractor import compute_all_flow_features
from app.analyzers.packet_analyzer.flow_builder import build_flow_lookup, build_flows
from app.analyzers.packet_analyzer.packet_models import (
    AhPacketRecord,
    EspPacketRecord,
    FlowFeatures,
    FlowRecord,
    IkeMessageRecord,
    ParsedPacket,
)
from app.analyzers.packet_analyzer.parser import parse_packet
from app.analyzers.packet_analyzer.protocol_detector import DetectionSummary, detect_protocols
from app.analyzers.packet_analyzer.protocols.ike import parse_ike_message
from app.analyzers.packet_analyzer.reader import (
    Frame,
    PacketSource,
    SourceFactory,
    UnsupportedCaptureFormat,
    detect_capture_format,
    reader_factory,
)

ANALYZER_TIMEOUT_CODE = "ANALYSIS_TIMEOUT"
PARSER_ERROR_CODE = "PARSER_ERROR"
UNSUPPORTED_FORMAT_CODE = "UNSUPPORTED_FORMAT"
TOOL_UNAVAILABLE_CODE = "TOOL_UNAVAILABLE"


@dataclass
class AnalysisContext:
    capture_path: str
    max_packets: int
    timeout_seconds: int
    feature_schema_version: str
    burst_window_seconds: float = 0.1


@dataclass
class AnalysisResult:
    reader: str
    capture_format: str | None
    packets: list[ParsedPacket] = field(default_factory=list)
    detection: DetectionSummary | None = None
    ike_messages: list[IkeMessageRecord] = field(default_factory=list)
    esp_packets: list[EspPacketRecord] = field(default_factory=list)
    ah_packets: list[AhPacketRecord] = field(default_factory=list)
    flows: list[FlowRecord] = field(default_factory=list)
    flow_features: list[FlowFeatures] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    reader_errors: list[str] = field(default_factory=list)


class PacketAnalyzerEngine:
    def __init__(self, source_factory: SourceFactory | None = None) -> None:
        self.source_factory = source_factory

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        deadline = time.monotonic() + context.timeout_seconds

        capture_format = detect_capture_format(context.capture_path)
        if capture_format is None:
            return AnalysisResult(
                reader="",
                capture_format=None,
                error_code=UNSUPPORTED_FORMAT_CODE,
                error_message="Unsupported or unrecognized capture format.",
            )

        source = (self.source_factory or self._default_factory())()
        reader_name = source.name
        packet_list: list[ParsedPacket] = []
        reader_errors: list[str] = []

        frames = 0
        try:
            for frame in self._iter_source(source, context.capture_path):
                frame_number, timestamp, data = (
                    frame.number,
                    frame.timestamp,
                    frame.data,
                )
                frames += 1
                if frames > context.max_packets:
                    reader_errors.append(f"Packet limit reached ({context.max_packets})")
                    break
                if time.monotonic() > deadline:
                    reader_errors.append("Analysis deadline exceeded during packet reading")
                    break
                parsed = parse_packet(frame_number, timestamp, data)
                if parsed is not None:
                    packet_list.append(parsed)
        except UnsupportedCaptureFormat as exc:
            return AnalysisResult(
                reader=reader_name,
                capture_format=capture_format,
                error_code=UNSUPPORTED_FORMAT_CODE,
                error_message=str(exc),
            )
        except FileNotFoundError:
            return AnalysisResult(
                reader=reader_name,
                capture_format=capture_format,
                error_code=PARSER_ERROR_CODE,
                error_message="Capture file not found.",
            )
        except OSError as exc:  # pragma: no cover - defensive
            return AnalysisResult(
                reader=reader_name,
                capture_format=capture_format,
                error_code=PARSER_ERROR_CODE,
                error_message=f"Failed to read capture: {exc}",
            )

        reader_errors.extend(source.errors)

        if not packet_list:
            return AnalysisResult(
                reader=reader_name,
                capture_format=capture_format,
                error_code=PARSER_ERROR_CODE,
                error_message="No parseable packets found in the capture.",
                reader_errors=reader_errors,
            )

        if time.monotonic() > deadline:
            return AnalysisResult(
                reader=reader_name,
                capture_format=capture_format,
                packets=packet_list,
                error_code=ANALYZER_TIMEOUT_CODE,
                error_message="Packet reading exceeded the analysis deadline.",
                reader_errors=reader_errors,
            )

        detection = detect_protocols(packet_list)

        ike_messages = [
            msg
            for pkt in packet_list
            if pkt.ike is not None and (msg := parse_ike_message(pkt, pkt.ike)) is not None
        ]

        flows = build_flows(packet_list)
        flow_lookup = build_flow_lookup(flows)
        flows_by_key = {flow.flow_key: flow for flow in flows}
        for index, pkt in enumerate(packet_list):
            flow_index = flow_lookup.get(index)
            if flow_index is not None:
                pkt.flow_key = flows[flow_index].flow_key

        esp_packets = [
            _build_esp_record(pkt, flows_by_key) for pkt in packet_list if pkt.esp is not None
        ]
        ah_packets = [
            _build_ah_record(pkt, flows_by_key) for pkt in packet_list if pkt.ah is not None
        ]

        flow_features = compute_all_flow_features(
            flows,
            packet_list,
            context.feature_schema_version,
            burst_window_seconds=context.burst_window_seconds,
        )

        return AnalysisResult(
            reader=reader_name,
            capture_format=capture_format,
            packets=packet_list,
            detection=detection,
            ike_messages=ike_messages,
            esp_packets=esp_packets,
            ah_packets=ah_packets,
            flows=flows,
            flow_features=flow_features,
            reader_errors=reader_errors,
        )

    def _default_factory(self) -> SourceFactory:
        from app.analyzers.packet_analyzer.reader import available_tools

        factory, _ = reader_factory(available_tools())
        return factory

    def _iter_source(self, source: PacketSource, path: str) -> Iterator[Frame]:
        return source.read(path)


def _is_upstream(pkt: ParsedPacket, flow: FlowRecord) -> bool:
    return (
        pkt.source == flow.source_ip
        and pkt.destination == flow.destination_ip
        and pkt.source_port == flow.source_port
        and pkt.destination_port == flow.destination_port
    )


def _build_esp_record(pkt: ParsedPacket, flows_by_key: dict[str, FlowRecord]) -> EspPacketRecord:
    from app.analyzers.packet_analyzer.packet_models import EspPacketRecord

    flow = flows_by_key.get(pkt.flow_key or "")
    direction = _direction_for(pkt, flow)

    return EspPacketRecord(
        packet_id=pkt.number,
        timestamp=pkt.timestamp,
        source_ip=pkt.source,
        destination_ip=pkt.destination,
        spi=pkt.esp.spi if pkt.esp else "",
        sequence_number=pkt.esp.sequence_number if pkt.esp else None,
        length=pkt.length,
        direction=direction,
        flow_key=pkt.flow_key,
        encryption_algorithm=pkt.esp.encryption_algorithm if pkt.esp else "UNKNOWN",
    )


def _build_ah_record(pkt: ParsedPacket, flows_by_key: dict[str, FlowRecord]) -> AhPacketRecord:
    from app.analyzers.packet_analyzer.packet_models import AhPacketRecord

    flow = flows_by_key.get(pkt.flow_key or "")
    direction = _direction_for(pkt, flow)

    return AhPacketRecord(
        packet_id=pkt.number,
        timestamp=pkt.timestamp,
        source_ip=pkt.source,
        destination_ip=pkt.destination,
        spi=pkt.ah.spi if pkt.ah else "",
        sequence_number=pkt.ah.sequence_number if pkt.ah else None,
        length=pkt.length,
        direction=direction,
        flow_key=pkt.flow_key,
        next_header=pkt.ah.next_header if pkt.ah else None,
    )


def _direction_for(pkt: ParsedPacket, flow: FlowRecord | None) -> str:
    if flow is None:
        return "unknown"
    return "upstream" if _is_upstream(pkt, flow) else "downstream"


__all__ = [
    "AnalysisContext",
    "AnalysisResult",
    "ANALYZER_TIMEOUT_CODE",
    "PARSER_ERROR_CODE",
    "PacketAnalyzerEngine",
    "TOOL_UNAVAILABLE_CODE",
    "UNSUPPORTED_FORMAT_CODE",
]
