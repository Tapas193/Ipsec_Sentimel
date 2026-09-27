"""Protocol detection over parsed packets.

Builds per-protocol observations and an overall IPsec determination
(yes / no / unknown) with evidence. Detection is evidence-based — UDP 500/
4500 traffic without a valid IKE header yields ``unknown``, never a claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analyzers.packet_analyzer.packet_models import (
    Confidence,
    ParsedPacket,
    ProtocolObservation,
)

_PROTOCOL_KEYS = (
    "ipv4",
    "ipv6",
    "udp",
    "tcp",
    "icmp",
    "icmpv6",
    "ike",
    "esp",
    "ah",
    "natt",
    "other",
)


@dataclass
class DetectionSummary:
    ipsec: str  # yes | no | unknown
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)
    observations: list[ProtocolObservation] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0
    duration: float = 0.0
    first_packet_time: float | None = None
    last_packet_time: float | None = None
    port4500_ike_heuristic: int = 0
    port4500_esp_heuristic: int = 0


class _Counter:
    __slots__ = ("protocol", "count", "bytes", "first", "last", "evidence")

    def __init__(self, protocol: str) -> None:
        self.protocol = protocol
        self.count = 0
        self.bytes = 0
        self.first: float | None = None
        self.last: float | None = None
        self.evidence: list[str] = []

    def add(self, timestamp: float, size: int, evidence: str | None = None) -> None:
        self.count += 1
        self.bytes += size
        if self.first is None or timestamp < self.first:
            self.first = timestamp
        if self.last is None or timestamp > self.last:
            self.last = timestamp
        if evidence and len(self.evidence) < 3:
            self.evidence.append(evidence)


def detect_protocols(packets: list[ParsedPacket]) -> DetectionSummary:
    counters = {name: _Counter(name) for name in _PROTOCOL_KEYS}
    counters.pop("other")

    ike_like_ports = 0  # UDP 500/4500 without a valid IKE parse
    first_ts: float | None = None
    last_ts: float | None = None

    for pkt in packets:
        if pkt.ip_version == 4:
            counters["ipv4"].add(pkt.timestamp, pkt.length)
        elif pkt.ip_version == 6:
            counters["ipv6"].add(pkt.timestamp, pkt.length)

        if pkt.protocol in ("udp", "tcp", "icmp", "icmpv6", "esp", "ah"):
            counters[pkt.protocol].add(pkt.timestamp, pkt.length, _first_evidence(pkt))

        if pkt.ike is not None:
            counters["ike"].add(
                pkt.timestamp,
                pkt.length,
                f"{pkt.ike.version} {pkt.ike.exchange_name}",
            )

        is_natt = pkt.source_port == 4500 or pkt.destination_port == 4500
        if is_natt:
            if pkt.ike is not None or pkt.esp is not None:
                counters["natt"].add(
                    pkt.timestamp,
                    pkt.length,
                    "UDP 4500 (NAT-T) carries IPsec",
                )
            elif pkt.protocol == "udp":
                counters["natt"].add(
                    pkt.timestamp,
                    pkt.length,
                    "UDP 4500 — structure not parsed",
                )

        if (pkt.source_port == 500 or pkt.destination_port == 500) and pkt.ike is None:
            ike_like_ports += 1

        if first_ts is None or pkt.timestamp < first_ts:
            first_ts = pkt.timestamp
        if last_ts is None or pkt.timestamp > last_ts:
            last_ts = pkt.timestamp

    observations: list[ProtocolObservation] = []
    for counter in counters.values():
        if counter.count <= 0 or counter.first is None or counter.last is None:
            continue
        observations.append(
            ProtocolObservation(
                protocol=counter.protocol,
                packet_count=counter.count,
                byte_count=counter.bytes,
                first_seen=counter.first,
                last_seen=counter.last,
                confidence=Confidence.HIGH,
                evidence=counter.evidence,
            )
        )

    packet_count = len(packets)
    byte_count = sum(p.length for p in packets)
    duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0

    evidence: list[str] = []
    ipsec, confidence = _ipsec_decision(counters, ike_like_ports, evidence)

    return DetectionSummary(
        ipsec=ipsec,
        confidence=confidence,
        evidence=evidence,
        observations=observations,
        packet_count=packet_count,
        byte_count=byte_count,
        duration=duration,
        first_packet_time=first_ts,
        last_packet_time=last_ts,
    )


def _ipsec_decision(
    counters: dict[str, _Counter], ike_like_ports: int, evidence: list[str]
) -> tuple[str, Confidence]:
    ipsec_packets = counters["ike"].count + counters["esp"].count + counters["ah"].count
    if ipsec_packets > 0:
        detail = [
            f"ike={counters['ike'].count}",
            f"esp={counters['esp'].count}",
            f"ah={counters['ah'].count}",
        ]
        evidence.append("IPsec evidence: " + ", ".join(d for d in detail if not d.startswith("=0")))
        return "yes", Confidence.HIGH
    if ike_like_ports > 0 or counters["natt"].count > 0:
        evidence.append("UDP 500/4500 observed but no valid IKE/ESP/AH header parsed")
        return "unknown", Confidence.LOW
    evidence.append("No IKE, ESP or AH packets observed")
    return "no", Confidence.HIGH


def _first_evidence(pkt: ParsedPacket) -> str | None:
    return pkt.evidence[0] if pkt.evidence else None
