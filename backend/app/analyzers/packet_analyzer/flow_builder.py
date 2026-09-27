"""Flow reconstruction from parsed packets.

Flows are bidirectional aggregates keyed by the endpoint pair, transport
protocol and IP version. The first packet's direction becomes the upstream
direction; the reverse direction is tracked separately so direction features
can be computed downstream.
"""

from __future__ import annotations

from app.analyzers.packet_analyzer.packet_models import FlowRecord, ParsedPacket


def flow_key_for(
    source: str,
    destination: str,
    source_port: int | None,
    destination_port: int | None,
    protocol: str,
    ip_version: int | None,
) -> str:
    # `is not None` rather than a truthiness check: port 0 is a real (if unusual)
    # transport port and must not collapse onto the same key as a protocol that
    # carries no ports at all. Two distinct flows sharing a flow_key would break
    # flow-level grouping for the future ML data contract.
    def render(port: int | None) -> str:
        return "x" if port is None else str(port)

    return (
        f"{source}:{render(source_port)}-{protocol}/{ip_version}"
        f"->{destination}:{render(destination_port)}"
    )


def _canonical_key(
    source: str,
    destination: str,
    source_port: int | None,
    destination_port: int | None,
    protocol: str,
    ip_version: int | None,
) -> tuple[str, int | None, frozenset[tuple[str, int | None]]]:
    left = (source, source_port)
    right = (destination, destination_port)
    pair = frozenset((left, right))
    return (protocol, ip_version, pair)


def build_flows(packets: list[ParsedPacket]) -> list[FlowRecord]:
    flows_by_key: dict[tuple[str, int | None, frozenset[tuple[str, int | None]]], FlowRecord] = {}
    spi_counts: dict[tuple[str, int | None, frozenset[tuple[str, int | None]]], dict[str, int]] = {}

    for index, pkt in enumerate(packets):
        if pkt.protocol == "unknown" or not pkt.source or not pkt.destination:
            continue
        protocol = pkt.protocol
        key = _canonical_key(
            pkt.source,
            pkt.destination,
            pkt.source_port,
            pkt.destination_port,
            protocol,
            pkt.ip_version,
        )
        flow = flows_by_key.get(key)
        if flow is None:
            flow = FlowRecord(
                flow_key=flow_key_for(
                    pkt.source,
                    pkt.destination,
                    pkt.source_port,
                    pkt.destination_port,
                    protocol,
                    pkt.ip_version,
                ),
                source_ip=pkt.source,
                destination_ip=pkt.destination,
                source_port=pkt.source_port,
                destination_port=pkt.destination_port,
                protocol=protocol,
                transport=pkt.transport,
                ip_version=pkt.ip_version,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                duration=0.0,
                packet_count=0,
                byte_count=0,
                upstream_packets=0,
                downstream_packets=0,
                upstream_bytes=0,
                downstream_bytes=0,
                direction="first_seen",
            )
            flows_by_key[key] = flow

        upstream = (
            pkt.source == flow.source_ip
            and pkt.destination == flow.destination_ip
            and pkt.source_port == flow.source_port
            and pkt.destination_port == flow.destination_port
        )
        flow.packet_count += 1
        flow.byte_count += pkt.length
        flow.packet_indices.append(index)
        if upstream:
            flow.upstream_packets += 1
            flow.upstream_bytes += pkt.length
        else:
            flow.downstream_packets += 1
            flow.downstream_bytes += pkt.length
        flow.start_time = min(flow.start_time, pkt.timestamp)
        flow.end_time = max(flow.end_time, pkt.timestamp)
        flow.duration = max(flow.end_time - flow.start_time, 0.0)

        if pkt.ike is not None:
            flow.ike_packets += 1
        if pkt.esp is not None:
            flow.esp_packets += 1
            if pkt.esp.spi:
                counts = spi_counts.setdefault(key, {})
                counts[pkt.esp.spi] = counts.get(pkt.esp.spi, 0) + 1
        if pkt.ah is not None:
            flow.ah_packets += 1
            if pkt.ah.spi:
                counts = spi_counts.setdefault(key, {})
                counts[pkt.ah.spi] = counts.get(pkt.ah.spi, 0) + 1

    flows = list(flows_by_key.values())
    for flow in flows:
        counts = spi_counts.get(
            _canonical_key(
                flow.source_ip,
                flow.destination_ip,
                flow.source_port,
                flow.destination_port,
                flow.protocol,
                flow.ip_version,
            ),
            {},
        )
        if counts:
            flow.spi = max(counts, key=counts.__getitem__)
        if flow.downstream_packets > flow.upstream_packets:
            flow.direction = "reverse"
        elif flow.downstream_packets == flow.upstream_packets:
            flow.direction = "unknown"

    flows.sort(key=lambda f: (f.start_time, -f.packet_count))
    return flows


def build_flow_lookup(flows: list[FlowRecord]) -> dict[int, int]:
    """Map a packet index to its flow index based on endpoint+protocol match."""
    lookup: dict[int, int] = {}
    for flow_idx, flow in enumerate(flows):
        for pkt_idx in flow.packet_indices:
            lookup[pkt_idx] = flow_idx
    return lookup
