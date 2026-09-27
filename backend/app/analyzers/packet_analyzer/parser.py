"""Frame parser: turns raw capture bytes into :class:`ParsedPacket` records.

Pure Python, no external dependencies, deterministic. Handles Ethernet II
(and VLAN tags), raw IP, IPv4, IPv6 (with extension headers), UDP, TCP,
ICMP/ICMPv6, and IPsec (ESP/AH/IKE). Encrypted payloads are never inspected.
"""

from __future__ import annotations

from app.analyzers.packet_analyzer.packet_models import ParsedPacket
from app.analyzers.packet_analyzer.protocols.ah import parse_ah
from app.analyzers.packet_analyzer.protocols.esp import parse_esp
from app.analyzers.packet_analyzer.protocols.ike import parse_ike_header
from app.analyzers.packet_analyzer.protocols.ip import (
    ETHER_TYPE_IPV4,
    ETHER_TYPE_IPV6,
    ETHER_TYPE_QINQ,
    ETHER_TYPE_VLAN,
    IP_PROTO_AH,
    IP_PROTO_ESP,
    IP_PROTO_ICMP,
    IP_PROTO_ICMPV6,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    ipv6_to_str,
)
from app.analyzers.packet_analyzer.protocols.ipv4 import parse_ipv4, parse_ipv6
from app.analyzers.packet_analyzer.protocols.udp import parse_udp

IKE_PORT = 500
NATT_PORT = 4500
_NON_ESP_MARKER = b"\x00\x00\x00\x00"


def parse_packet(number: int, timestamp: float, frame: bytes) -> ParsedPacket | None:
    """Parse a single captured frame into a normalized packet record."""
    if not frame:
        return None

    layer3: bytes | None = None
    if len(frame) >= 14:
        ethertype = int.from_bytes(frame[12:14], "big")
        if ethertype in (ETHER_TYPE_VLAN, ETHER_TYPE_QINQ) and len(frame) >= 18:
            ethertype = int.from_bytes(frame[16:18], "big")
            layer3 = frame[18:]
        elif ethertype in (ETHER_TYPE_IPV4, ETHER_TYPE_IPV6):
            layer3 = frame[14:]
        elif frame[0] >> 4 in (4, 6):
            layer3 = frame
    if layer3 is None:
        # Raw IP capture (linktype 0/101) or an unhandled encapsulation.
        if len(frame) >= 20 and frame[0] >> 4 in (4, 6):
            layer3 = frame
    if layer3 is None:
        return None
    len(frame) - len(layer3)

    ip_version = layer3[0] >> 4
    if ip_version == 4:
        parsed_v4 = parse_ipv4(layer3)
        if parsed_v4 is None:
            return None
        proto, _ihl, src_bytes, dst, transport_payload, fragmented = parsed_v4
    elif ip_version == 6:
        parsed_v6 = parse_ipv6(layer3)
        if parsed_v6 is None:
            return None
        next_header, src_bytes, dst, transport_payload, fragmented = parsed_v6
        proto = next_header
    else:
        return None

    base = ParsedPacket(
        number=number,
        timestamp=timestamp,
        length=len(frame),
        source="",
        destination="",
        ip_version=ip_version,
        protocol="unknown",
        transport=None,
        source_port=None,
        destination_port=None,
        fragmented=fragmented,
    )

    if ip_version == 4:
        base.source = ".".join(str(b) for b in src_bytes)
        base.destination = dst
    else:
        base.source = ipv6_to_str(src_bytes)
        base.destination = dst

    _dissect_transport(base, proto, transport_payload, fragmented=fragmented)
    return base


def _dissect_transport(
    packet: ParsedPacket, proto: int, payload: bytes, fragmented: bool = False
) -> None:
    if fragmented and proto in (IP_PROTO_UDP, IP_PROTO_TCP):
        packet.protocol = "udp" if proto == IP_PROTO_UDP else "tcp"
        packet.transport = packet.protocol
        packet.evidence.append("IP fragment — transport ports not dissected")
        return
    if proto == IP_PROTO_UDP:
        udp = parse_udp(payload)
        if udp is None:
            if payload:
                packet.protocol = "udp"
            return
        packet.protocol = "udp"
        packet.transport = "udp"
        packet.source_port, packet.destination_port, data = udp
        if packet.source_port == IKE_PORT or packet.destination_port == IKE_PORT:
            ike_layer = parse_ike_header(data)
            if ike_layer is not None:
                packet.ike = ike_layer
                packet.evidence.append(f"IKE header parsed ({ike_layer.version})")
        elif packet.source_port == NATT_PORT or packet.destination_port == NATT_PORT:
            if data.startswith(_NON_ESP_MARKER):
                ike_layer = parse_ike_header(data[len(_NON_ESP_MARKER) :])
                if ike_layer is not None:
                    packet.ike = ike_layer
                    packet.evidence.append("NAT-T IKE (non-ESP marker present)")
            else:
                esp = parse_esp(data, nat_t=True)
                if esp is not None:
                    packet.esp = esp
                    packet.protocol = "esp"
                    packet.evidence.append("ESP over UDP 4500 (NAT-T)")
    elif proto == IP_PROTO_TCP:
        if len(payload) >= 20:
            packet.protocol = "tcp"
            packet.transport = "tcp"
            packet.source_port = int.from_bytes(payload[0:2], "big")
            packet.destination_port = int.from_bytes(payload[2:4], "big")
        elif payload:
            packet.protocol = "tcp"
    elif proto == IP_PROTO_ICMP:
        packet.protocol = "icmp"
    elif proto == IP_PROTO_ICMPV6:
        packet.protocol = "icmpv6"
    elif proto == IP_PROTO_ESP and not fragmented:
        esp = parse_esp(payload)
        if esp is not None:
            packet.esp = esp
            packet.protocol = "esp"
            packet.evidence.append("ESP header parsed (protocol 50)")
    elif proto == IP_PROTO_AH and not fragmented:
        ah = parse_ah(payload)
        if ah is not None:
            packet.ah = ah
            packet.protocol = "ah"
            packet.evidence.append("AH header parsed (protocol 51)")
    elif fragmented:
        packet.protocol = "unknown"
        packet.evidence.append("IP fragment — transport not dissected")
