"""Synthetic PCAP generation for tests and fixtures.

.. warning::

   **TEST FIXTURE — NOT REAL NETWORK TRAFFIC.**

   Every byte produced by this module is synthesised in Python. It exists only
   to make the analyzer and the security rule engine deterministically
   testable and demoable. Nothing here was recorded from a production or real
   VPN network, and no result derived from these files may be presented as a
   finding about real traffic.

Pure-Python; no Scapy dependency. Produces a classic libpcap (microsecond
timestamps) file whose frames are built byte-by-byte so the pure-Python
parser can be exercised deterministically.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class SyntheticFrame:
    data: bytes
    timestamp: float


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (
        b"\x00\x11\x22\x33\x44\x55"
        + b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(">H", ethertype)
        + payload
    )


def ipv4(
    payload: bytes,
    src: str,
    dst: str,
    protocol: int,
    ttl: int = 64,
    fragment: int = 0,
) -> bytes:
    src_bytes = bytes(int(p) for p in src.split("."))
    dst_bytes = bytes(int(p) for p in dst.split("."))
    total = 20 + len(payload)
    return (
        b"\x45\x00"
        + struct.pack(">H", total)
        + b"\x00\x00"
        + struct.pack(">H", fragment)
        + bytes([ttl, protocol])
        + b"\x00\x00"
        + src_bytes
        + dst_bytes
        + payload
    )


def udp(payload: bytes, sport: int, dport: int) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def ikev2_sa_init_payload() -> bytes:
    def transform(ttype: int, tid: int, attrs: bytes = b"") -> bytes:
        total = 8 + len(attrs)
        return (
            bytes([0, 0])
            + struct.pack(">H", total)
            + bytes([ttype, 0])
            + struct.pack(">H", tid)
            + attrs
        )

    enc = transform(1, 18, bytes([0x80 | 14, 0, 0x01, 0x00]))  # AES_GCM_16, key 256
    integ = transform(3, 5)  # HMAC_SHA2_256_128
    prf = transform(2, 5)  # HMAC_SHA2_256
    dh = transform(4, 19)  # group 19 (ECP 256)
    proposal_body = bytes([1, 3, 0, 4])
    proposal = (
        bytes([0, 0])
        + struct.pack(">H", 4 + len(proposal_body) + len(enc) + len(integ) + len(prf) + len(dh))
        + proposal_body
        + enc
        + integ
        + prf
        + dh
    )
    sa_payload = bytes([0, 0]) + struct.pack(">H", 4 + len(proposal)) + proposal
    return sa_payload


def ikev2_sa_init_message() -> bytes:
    sa = ikev2_sa_init_payload()
    ike_len = 28 + len(sa)
    ike = (
        b"\x11" * 8
        + b"\x00" * 8
        + bytes([33, 0x20, 34, 0x01])  # next=SA, v2, IKE_SA_INIT, initiator
        + struct.pack(">I", 0)
        + struct.pack(">I", ike_len)
        + sa
    )
    return ike


def ikev1_aggressive_message() -> bytes:
    t_attrs = (
        struct.pack(">HHI", 0x0005, 4, 3)  # auth RSA_SIG
        + struct.pack(">HHI", 0x0006, 4, 2)  # hash SHA1
        + struct.pack(">HHI", 0x0003, 4, 2)  # group modp1024
    )
    transform = (
        bytes([2, 0])
        + struct.pack(">H", 4 + 1 + 1 + 2 + len(t_attrs))
        + bytes([1, 5])  # 3DES_CBC
        + b"\x00\x00"
        + t_attrs
    )
    proposal = (
        bytes([1, 0]) + struct.pack(">H", 4 + 4 + len(transform)) + bytes([1, 1, 0, 1]) + transform
    )
    sa_payload = bytes([0, 0]) + struct.pack(">H", 4 + len(proposal)) + proposal
    ike_len = 28 + len(sa_payload)
    ike = (
        b"\x22" * 8
        + b"\x00" * 8
        + bytes([1, 0x10, 4, 0])  # next=SA, v1, aggressive, no flags
        + struct.pack(">I", 0)
        + struct.pack(">I", ike_len)
        + sa_payload
    )
    return ike


def esp_payload(spi: int, seq: int, body: bytes, nat_t: bool = False) -> bytes:
    if nat_t:
        return struct.pack(">HHHH", 4500, 4500, 8 + len(body), 0) + b"\x00" * 4 + body
    return struct.pack(">I", spi) + struct.pack(">I", seq) + body


def ah_payload(spi: int, seq: int, body: bytes) -> bytes:
    return (
        bytes([4, 0, 0, 0])  # next header, payload len
        + struct.pack(">I", spi)
        + struct.pack(">I", seq)
        + body
    )


class PcapWriter:
    def __init__(self) -> None:
        self.frames: list[SyntheticFrame] = []

    def add(self, frame: SyntheticFrame) -> None:
        self.frames.append(frame)

    def add_many(self, frames: list[SyntheticFrame]) -> None:
        self.frames.extend(frames)

    def write(self, path: str) -> int:
        payload = b"".join(self._to_bytes(f) for f in self.frames)
        packet_count = len(self.frames)
        with open(path, "wb") as fh:
            fh.write(
                b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
            )
            fh.write(payload)
        return packet_count

    def _to_bytes(self, frame: SyntheticFrame) -> bytes:
        ts_sec = int(frame.timestamp)
        ts_usec = int((frame.timestamp - ts_sec) * 1_000_000)
        return struct.pack("<IIII", ts_sec, ts_usec, len(frame.data), len(frame.data)) + frame.data


def build_ipsec_pcap(
    start_time: float = 1_000_000.0,
    ike_count: int = 4,
    esp_count: int = 12,
    include_ah: bool = True,
    include_plain: bool = True,
) -> PcapWriter:
    writer = PcapWriter()
    t = start_time
    src, dst = "10.0.0.1", "10.0.0.2"

    for _ in range(ike_count):
        frame = ethernet(ipv4(udp(ikev2_sa_init_message(), 500, 500), src, dst, 17))
        writer.add(SyntheticFrame(frame, t))
        t += 0.05

    if include_ah:
        for _ in range(3):
            frame = ethernet(ipv4(ah_payload(0x10101010, _ + 1, b"\x00" * 24), src, dst, 51))
            writer.add(SyntheticFrame(frame, t))
            t += 0.02

    for n in range(esp_count):
        body = bytes(range(32)) * 4
        frame = ethernet(ipv4(esp_payload(0xDEADBEEF, n + 1, body), src, dst, 50))
        writer.add(SyntheticFrame(frame, t))
        t += 0.01

    if include_plain:
        for _ in range(3):
            frame = ethernet(ipv4(udp(b"hello", 53, 53), src, "8.8.8.8", 17))
            writer.add(SyntheticFrame(frame, t))
            t += 0.1

    return writer


def build_ikev1_pcap(start_time: float = 2_000_000.0) -> PcapWriter:
    writer = PcapWriter()
    t = start_time
    for _ in range(2):
        frame = ethernet(
            ipv4(udp(ikev1_aggressive_message(), 500, 500), "10.0.0.3", "10.0.0.4", 17)
        )
        writer.add(SyntheticFrame(frame, t))
        t += 0.1
    return writer


def build_plaintext_pcap(start_time: float = 3_000_000.0) -> PcapWriter:
    """DNS + HTTP-style UDP traffic only — no IPsec at all (negative test)."""
    writer = PcapWriter()
    t = start_time
    for _ in range(6):
        frame = ethernet(ipv4(udp(b"hello", 53, 53), "10.0.0.1", "8.8.8.8", 17))
        writer.add(SyntheticFrame(frame, t))
        t += 0.1
        frame = ethernet(ipv4(udp(b"gimme", 12345, 8080), "10.0.0.1", "10.0.0.2", 17))
        writer.add(SyntheticFrame(frame, t))
        t += 0.1
    return writer


__all__ = [
    "PcapWriter",
    "SyntheticFrame",
    "build_ikev1_pcap",
    "build_ipsec_pcap",
    "build_plaintext_pcap",
    "ethernet",
    "ipv4",
    "udp",
]
