"""AH (Authentication Header) observation.

AH integrity validation would require shared keys and part of the original
IP packet; neither is available from a capture alone. Only the SPI, sequence
number and next header are reported.
"""

from __future__ import annotations

from app.analyzers.packet_analyzer.packet_models import AhLayer


def parse_ah(payload: bytes) -> AhLayer | None:
    """Read the AH header fields (SPI + sequence number)."""
    if len(payload) < 12:
        return None
    next_header = payload[0]
    spi = payload[4:8].hex()
    sequence_number = int.from_bytes(payload[8:12], "big")
    return AhLayer(spi=spi, sequence_number=sequence_number, next_header=next_header)
