"""IP layer helpers and parsing primitives shared across dissectors."""

from __future__ import annotations

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMPV6 = 58
IP_PROTO_AH = 51
IP_PROTO_ESP = 50

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_IPV6 = 0x86DD
ETHER_TYPE_VLAN = 0x8100
ETHER_TYPE_QINQ = 0x88A8

# IPv6 next-header values that may be encrypted/extension headers.
_IPV6_EXTENSION_HEADERS = frozenset({0, 43, 60, 135})
_IPV6_FRAGMENT_HEADER = 44


def ipv4_to_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def ipv6_to_str(raw: bytes) -> str:
    parts = [raw[i : i + 2] for i in range(0, 16, 2)]
    return ":".join(p.hex() for p in parts)


def parse_ipv4_payload(ip_payload: bytes) -> tuple[int, bytes]:
    """Return (protocol, payload_bytes) from an IPv4 packet body."""
    if len(ip_payload) < 1:
        return 0, b""
    return ip_payload[0], ip_payload[1:]


def apply_esp_header_fixup(protocol: int, fragmented: bool) -> bool:
    """ESP fields are only meaningful for non-fragmented first fragments."""
    return protocol == 50 and not fragmented
