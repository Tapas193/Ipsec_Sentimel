"""UDP dissector."""

from __future__ import annotations


def parse_udp(payload: bytes) -> tuple[int, int, bytes] | None:
    """Return (source_port, destination_port, udp_data) or None."""
    if len(payload) < 8:
        return None
    source_port = int.from_bytes(payload[0:2], "big")
    destination_port = int.from_bytes(payload[2:4], "big")
    return source_port, destination_port, payload[8:]
