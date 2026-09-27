"""Capture readers: turn PCAP/PCAPNG files into raw frames.

Reader preference (best-effort, reported to the user):
  1. TShark  — most reliable dissector, used when installed.
  2. Scapy   — pure-Python fallback.
  3. Builtin — dependency-free pcap/pcapng parser (always available).

No reader shells out with ``shell=True``; all subprocess calls use argument
arrays and a bounded timeout.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Literal, Protocol

PCAP_MAGIC_LITTLE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BIG = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NANO_LITTLE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NANO_BIG = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass
class Frame:
    number: int
    timestamp: float
    data: bytes


@dataclass
class ToolAvailability:
    tshark: bool
    tshark_version: str | None
    tcpdump: bool
    scapy: bool
    scapy_version: str | None
    active_reader: str = "builtin"


def detect_capture_format(path: str) -> str | None:
    """Return ``pcap`` or ``pcapng`` based on the file magic, else None."""
    try:
        with open(path, "rb") as f:
            header = f.read(4)
    except OSError:
        return None
    if header in (PCAP_MAGIC_LITTLE, PCAP_MAGIC_BIG, PCAP_MAGIC_NANO_LITTLE, PCAP_MAGIC_NANO_BIG):
        return "pcap"
    if header == PCAPNG_MAGIC:
        return "pcapng"
    return None


class BuiltinPacketSource:
    name = "builtin"

    def __init__(self) -> None:
        self.errors: list[str] = []
        self._frame_count = 0
        self._linktype = 1

    def read(self, path: str) -> Iterator[Frame]:
        fmt = detect_capture_format(path)
        if fmt == "pcap":
            yield from self._read_pcap(path)
        elif fmt == "pcapng":
            yield from self._read_pcapng(path)
        else:
            raise UnsupportedCaptureFormat(f"Unsupported capture format for {path}")

    def _read_pcap(self, path: str) -> Iterator[Frame]:
        with open(path, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return
            magic = header[0:4]
            endian: Literal["little", "big"]
            if magic == PCAP_MAGIC_LITTLE or magic == PCAP_MAGIC_NANO_LITTLE:
                endian = "little"
            elif magic == PCAP_MAGIC_BIG or magic == PCAP_MAGIC_NANO_BIG:
                endian = "big"
            else:
                return
            if magic in (PCAP_MAGIC_NANO_LITTLE, PCAP_MAGIC_NANO_BIG):
                ts_multiplier = 1e-9
            else:
                ts_multiplier = 1e-6
            number = 0
            while True:
                rec = f.read(16)
                if len(rec) < 16:
                    break
                ts_sec = int.from_bytes(rec[0:4], endian)
                ts_frac = int.from_bytes(rec[4:8], endian)
                incl_len = int.from_bytes(rec[8:12], endian)
                if incl_len > 16_000_000:  # sanity: >16MB frame
                    self.errors.append(f"implausible packet length {incl_len} at #{number}")
                    return
                data = f.read(incl_len)
                if len(data) < incl_len:
                    break
                number += 1
                yield Frame(
                    number=number,
                    timestamp=float(ts_sec) + float(ts_frac) * ts_multiplier,
                    data=data,
                )

    def _read_pcapng(self, path: str) -> Iterator[Frame]:
        endian: Literal["little", "big"] = "little"
        ts_resol = 1e-6
        with open(path, "rb") as f:
            header = f.read(12)
            if len(header) < 12 or header[0:4] != PCAPNG_MAGIC:
                return
            bom = header[4:8]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = "little"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "big"
            else:
                return
            while True:
                block_header = f.read(8)
                if len(block_header) < 8:
                    break
                block_type = int.from_bytes(block_header[0:4], endian)
                total_len = int.from_bytes(block_header[4:8], endian)
                if total_len < 12 or total_len > 64_000_000:
                    self.errors.append(f"implausible pcapng block length {total_len}")
                    return
                body = f.read(total_len - 12)
                trailing = f.read(4)
                if len(body) + 8 < total_len or len(trailing) < 4:
                    break
                if block_type == 0x00000001:  # Interface Description Block
                    self._linktype = int.from_bytes(body[0:4], endian)
                    ts_resol = _pcapng_ts_resolution(body[8:], endian)
                elif block_type == 0x00000006:  # Enhanced Packet Block
                    if len(body) >= 20:
                        ts_high = int.from_bytes(body[4:8], endian)
                        ts_low = int.from_bytes(body[8:12], endian)
                        caplen = int.from_bytes(body[12:16], endian)
                        packet_data = body[16 : 16 + caplen]
                        timestamp = ((ts_high << 32) | ts_low) * ts_resol
                        self._frame_count += 1
                        if self._linktype == 1:
                            yield Frame(
                                number=self._frame_count,
                                timestamp=float(timestamp),
                                data=packet_data,
                            )


def _pcapng_ts_resolution(options: bytes, endian: Literal["little", "big"]) -> float:
    offset = 0
    while offset + 4 <= len(options):
        code = int.from_bytes(options[offset : offset + 2], endian)
        opt_len = int.from_bytes(options[offset + 2 : offset + 4], endian)
        offset += 4
        if offset + opt_len > len(options):
            break
        value = options[offset : offset + opt_len]
        if code == 9 and len(value) >= 1:  # if_tsresol
            b = value[0]
            if b >> 7:
                return float(2 ** -(b & 0x7F))
            return 10.0 ** (-b)
        offset += opt_len + (opt_len % 4)
    return 1e-6


class UnsupportedCaptureFormat(Exception):
    pass


class ScapyPacketSource:
    name = "scapy"

    def __init__(self) -> None:
        self.errors: list[str] = []

    def read(self, path: str) -> Iterator[Frame]:
        from scapy.utils import RawPcapNgReader, RawPcapReader

        fmt = detect_capture_format(path)
        items: Iterator[object] | Iterator[tuple[bytes, object]] | None = None
        if fmt == "pcap":
            items = RawPcapReader(path)
        elif fmt == "pcapng":
            items = RawPcapNgReader(path)
        else:
            raise UnsupportedCaptureFormat(f"Unsupported capture format for {path}")
        assert items is not None
        for number, item in enumerate(items, start=1):
            data, timestamp = _extract_scapy_item(item)
            if data is None:
                continue
            yield Frame(number=number, timestamp=timestamp, data=data)


def _extract_scapy_item(item: object) -> tuple[bytes | None, float]:
    """Normalize scapy reader yields.

    RawPcapReader yields ``(bytes, PacketMetadata)`` in scapy >= 2.5; older
    versions yield ``(bytes, float)``. RawPcapNgReader yields raw bytes only.
    ``PacketMetadata`` is ``namedtuple(sec, usec, wirelen, caplen)``.
    """
    if isinstance(item, tuple) and len(item) == 2:
        data, metadata = item
        if isinstance(metadata, (int, float)):
            return bytes(data), float(metadata)
        sec = getattr(metadata, "sec", 0)
        usec = getattr(metadata, "usec", 0)
        return bytes(data), float(sec) + float(usec) * 1e-6
    if isinstance(item, bytes):
        return item, 0.0
    return None, 0.0


class TSharkPacketSource:
    name = "tshark"

    def __init__(self) -> None:
        self.errors: list[str] = []

    def read(self, path: str) -> Iterator[Frame]:
        try:
            result = subprocess.run(
                ["tshark", "-r", str(path), "-T", "json", "-x"],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.SubprocessError as exc:  # noqa: BLE001
            self.errors.append(f"tshark failed: {exc}")
            return
        try:
            docs = json.loads(result.stdout)
        except json.JSONDecodeError:
            self.errors.append("tshark produced unparseable output")
            return
        for number, doc in enumerate(docs, start=1):
            layers = doc.get("_source", {}).get("layers", {})
            raw = _extract_tshark_raw(layers)
            if raw is None:
                continue
            timestamp = _extract_tshark_timestamp(layers)
            yield Frame(number=number, timestamp=timestamp, data=raw)


def _extract_tshark_raw(layers: dict[str, object]) -> bytes | None:
    frame_raw: object = layers.get("frame_raw")
    if not frame_raw:
        frame_container = layers.get("frame")
        frame_raw = frame_container.get("frame_raw") if isinstance(frame_container, dict) else None
    if not frame_raw:
        return None
    hex_parts: list[str] = []
    if isinstance(frame_raw, list):
        for line in frame_raw:
            parts = _tshark_hex_line(str(line))
            hex_parts.extend(parts)
    elif isinstance(frame_raw, str):
        hex_parts.extend(_tshark_hex_line(frame_raw))
    if not hex_parts:
        return None
    try:
        return bytes.fromhex("".join(hex_parts))
    except ValueError:
        return None


def _tshark_hex_line(line: str) -> list[str]:
    """Extract hex byte tokens from a `tshark -x` dump line.

    Format: `0000  12 34 56 ... 78 9a  ...ascii...`
    """
    line = line.strip()
    if "  " in line:
        # Everything before the ASCII column is hex pairs.
        before, _ = line.split("  ", 1)
        tokens = before.split()
        normalized = []
        for tok in tokens:
            tok = tok.lower()
            if len(tok) == 4 and all(c in "0123456789abcdef" for c in tok):
                normalized.append(tok[0:2])
                normalized.append(tok[2:4])
            elif len(tok) == 2 and all(c in "0123456789abcdef" for c in tok):
                normalized.append(tok)
        return normalized
    tokens = line.split()
    return [t for t in tokens if len(t) == 2 and all(c in "0123456789abcdef" for c in t.lower())]


def _extract_tshark_timestamp(layers: dict[str, object]) -> float:
    frame = layers.get("frame", {})
    if isinstance(frame, dict) and "frame.frame_time_epoch" in frame:
        try:
            return float(frame["frame.frame_time_epoch"])
        except (TypeError, ValueError):
            pass
    if isinstance(frame, dict) and "frame.time_epoch" in frame:
        try:
            return float(frame["frame.time_epoch"])
        except (TypeError, ValueError):
            pass
    return 0.0


def detect_tools() -> ToolAvailability:
    tshark_path = shutil.which("tshark")
    tcpdump_path = shutil.which("tcpdump")
    tshark_version: str | None = None
    if tshark_path:
        try:
            out = subprocess.run(
                [tshark_path, "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
            tshark_version = out.splitlines()[0].strip() if out else None
        except (subprocess.SubprocessError, FileNotFoundError):  # noqa: BLE001
            tshark_version = None

    scapy_version: str | None = None
    try:
        import scapy  # noqa: F401

        scapy_version = getattr(scapy, "__version__", None)
    except ImportError:
        scapy_version = None

    return ToolAvailability(
        tshark=tshark_path is not None,
        tshark_version=tshark_version,
        tcpdump=tcpdump_path is not None,
        scapy=scapy_version is not None,
        scapy_version=scapy_version,
    )


class PacketSource(Protocol):
    name: str
    errors: list[str]

    def read(self, path: str) -> Iterator[Frame]: ...


SourceFactory = Callable[[], PacketSource]


def reader_factory(availability: ToolAvailability) -> tuple[SourceFactory, str]:
    if availability.tshark:
        return (lambda: TSharkPacketSource(), "tshark")
    if availability.scapy:
        return (lambda: ScapyPacketSource(), "scapy")
    return (lambda: BuiltinPacketSource(), "builtin")


_CACHED_TOOLS: ToolAvailability | None = None


def available_tools() -> ToolAvailability:
    """Cached tool detection (refreshed by the caller when needed)."""
    global _CACHED_TOOLS
    if _CACHED_TOOLS is None:
        _CACHED_TOOLS = detect_tools()
    return _CACHED_TOOLS


def refresh_tools() -> ToolAvailability:
    global _CACHED_TOOLS
    _CACHED_TOOLS = detect_tools()
    return _CACHED_TOOLS


__all__ = [
    "BuiltinPacketSource",
    "Frame",
    "ScapyPacketSource",
    "SourceFactory",
    "TSharkPacketSource",
    "ToolAvailability",
    "UnsupportedCaptureFormat",
    "available_tools",
    "detect_capture_format",
    "detect_tools",
    "reader_factory",
    "refresh_tools",
]
