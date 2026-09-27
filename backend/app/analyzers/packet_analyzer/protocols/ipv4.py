"""IPv4/IPv6 header parsing helpers."""

from __future__ import annotations

from app.analyzers.packet_analyzer.protocols.ip import (
    _IPV6_EXTENSION_HEADERS,
    _IPV6_FRAGMENT_HEADER,
    ipv4_to_str,
    ipv6_to_str,
)


def parse_ipv4(
    frame: bytes,
) -> tuple[int, int, bytes, str, bytes, bool] | None:
    """Parse an IPv4 header.

    Returns (proto, ihl*4, src_bytes, dst_str, transport_payload, fragmented)
    or None when the header is malformed.
    """
    if len(frame) < 20 or frame[0] >> 4 != 4:
        return None
    ihl = (frame[0] & 0x0F) * 4
    total_len = int.from_bytes(frame[2:4], "big")
    if ihl < 20 or ihl > len(frame):
        return None
    proto = frame[9]
    src = frame[12:16]
    dst = frame[16:20]
    frag_field = int.from_bytes(frame[6:8], "big")
    frag_offset = frag_field & 0x1FFF
    mf = frag_field & 0x2000 != 0
    wire_len = min(total_len, len(frame)) if total_len else len(frame)
    payload = frame[ihl:wire_len]
    return proto, ihl, src, ipv4_to_str(dst), payload, frag_offset > 0 or mf


def parse_ipv6(
    frame: bytes,
) -> tuple[int, bytes, str, bytes, bool] | None:
    """Parse an IPv6 header including extension headers.

    Returns (next_header, src_bytes, dst_str, transport_payload, fragmented).
    """
    if len(frame) < 40 or frame[0] >> 4 != 6:
        return None
    next_header = frame[6]
    src = frame[8:24]
    dst = frame[24:40]
    payload_len = int.from_bytes(frame[4:6], "big")
    wire_len = min(40 + payload_len, len(frame)) if payload_len else len(frame)
    offset = 40
    fragmented = False
    while next_header in _IPV6_EXTENSION_HEADERS or next_header == _IPV6_FRAGMENT_HEADER:
        if offset + 2 > wire_len:
            return None
        if next_header == _IPV6_FRAGMENT_HEADER:
            fragmented = True
            next_header = frame[offset]
            offset += 8
            continue
        hdr_len = (frame[offset + 1] + 1) * 8
        if offset + hdr_len > wire_len:
            return None
        next_header = frame[offset]
        offset += hdr_len
    return next_header, src, ipv6_to_str(dst), frame[offset:wire_len], fragmented
