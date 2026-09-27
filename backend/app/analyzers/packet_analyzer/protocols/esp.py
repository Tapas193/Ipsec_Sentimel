"""ESP (Encapsulating Security Payload) observation.

Only the ESP header is examined (SPI + sequence number). The payload is
ciphertext — it is deliberately never inspected or decrypted.
"""

from __future__ import annotations

from app.analyzers.packet_analyzer.packet_models import EspLayer


def parse_esp(payload: bytes, nat_t: bool = False) -> EspLayer | None:
    """Read the ESP SPI and sequence number."""
    if len(payload) < 8:
        return None
    spi = payload[0:4].hex()
    sequence_number = int.from_bytes(payload[4:8], "big")
    return EspLayer(
        spi=spi,
        sequence_number=sequence_number,
        encryption_algorithm="UNKNOWN",
        nat_t=nat_t,
    )
