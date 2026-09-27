"""IPv6 header parsing (thin wrapper over the ipv4 module's shared helpers)."""

from __future__ import annotations

from app.analyzers.packet_analyzer.protocols.ipv4 import parse_ipv6  # noqa: F401
