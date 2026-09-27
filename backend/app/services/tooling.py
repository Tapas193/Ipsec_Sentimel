"""Tooling detection service."""

from __future__ import annotations

from app.analyzers.packet_analyzer.reader import (
    ToolAvailability,
    available_tools,
    reader_factory,
)
from app.schemas.tools import ToolsData, ToolStatus

_TSHARK_INSTALL_HINTS = {
    "darwin": "brew install wireshark",
    "linux": "sudo apt-get install tshark",
}
_PLATFORM_HINT = "See your platform package manager for install instructions."


def build_tools_data() -> ToolsData:
    tools = available_tools()
    platform = _platform_name()
    hint = _TSHARK_INSTALL_HINTS.get(platform, _PLATFORM_HINT)
    return ToolsData(
        active_reader=_active_reader(tools),
        tools=[
            ToolStatus(
                name="tshark",
                installed=tools.tshark,
                version=tools.tshark_version,
                detail=None if tools.tshark else hint,
            ),
            ToolStatus(
                name="tcpdump",
                installed=tools.tcpdump,
                detail=None,
            ),
            ToolStatus(
                name="scapy",
                installed=tools.scapy,
                version=tools.scapy_version,
                detail="Pure-Python fallback packet reader" if tools.scapy else None,
            ),
            ToolStatus(
                name="builtin",
                installed=True,
                detail="Dependency-free pcap/pcapng reader (always available)",
            ),
        ],
    )


def _active_reader(tools: ToolAvailability) -> str:
    factory, name = reader_factory(tools)
    del factory
    return name


def _platform_name() -> str:
    import platform as _platform

    system = _platform.system().lower()
    if system.startswith("darwin"):
        return "darwin"
    if system.startswith("linux"):
        return "linux"
    return system or "unknown"
