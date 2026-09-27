"""Flow feature extraction.

Computes descriptive statistics (mean/median/std/min/max/quartiles, timing,
direction, bursts, and a packet-size histogram) for every reconstructed flow.

Each feature value is stored in ``flow_features.feature_json`` and conforms to
``configs/feature_schema.yaml`` (version ``FEATURE_SCHEMA_VERSION``).
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence

from app.analyzers.packet_analyzer.packet_models import (
    FlowFeatures,
    FlowRecord,
    ParsedPacket,
)

_HISTOGRAM_EDGES = [0, 64, 256, 1024, 4096, 65536]


def _percentile(sorted_values: Sequence[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = (len(sorted_values) - 1) * p
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return float(sorted_values[int(index)])
    frac = index - lower
    return float(sorted_values[lower] * (1 - frac) + sorted_values[upper] * frac)


def _histogram(sizes: list[int], edges: list[int]) -> list[dict[str, object]]:
    boundaries = edges + [10**9]
    buckets = [0] * (len(boundaries) - 1)
    for size in sizes:
        for i in range(len(buckets) - 1, -1, -1):
            if size >= boundaries[i]:
                buckets[i] += 1
                break
        else:  # pragma: no cover - defensive
            buckets[0] += 1
    total = len(sizes)
    result: list[dict[str, object]] = []
    for i, count in enumerate(buckets):
        if i == len(buckets) - 1:
            label = f">{boundaries[i]}"
        else:
            label = f"{boundaries[i] + 1}-{boundaries[i + 1]}"
        result.append(
            {
                "range": label,
                "count": count,
                "share": round(count / total, 4) if total else 0.0,
            }
        )
    return result


def compute_flow_features(
    flow: FlowRecord,
    packets: list[ParsedPacket],
    feature_schema_version: str,
    burst_window_seconds: float = 0.1,
) -> FlowFeatures:
    members: list[ParsedPacket] = [packets[i] for i in flow.packet_indices]
    sizes = [p.length for p in members]
    timestamps = [p.timestamp for p in members]

    interarrivals: list[float] = []
    if len(timestamps) > 1:
        for prev, cur in zip(timestamps, timestamps[1:], strict=False):
            interarrivals.append(max(cur - prev, 0.0))

    sorted_sizes = sorted(sizes)
    count = flow.packet_count
    duration = flow.duration

    burst_stats = _burst_stats(timestamps, burst_window_seconds)

    features: dict[str, object] = {
        "packet_count": count,
        "byte_count": flow.byte_count,
        "duration_seconds": round(duration, 6),
        "packets_per_second": round(count / duration, 4) if duration > 0 else None,
        "bytes_per_second": round(flow.byte_count / duration, 2) if duration > 0 else None,
        "packet_size_mean": round(statistics.mean(sizes), 2) if sizes else None,
        "packet_size_median": round(_percentile(sorted_sizes, 0.5), 2) if sizes else None,
        "packet_size_std": round(statistics.stdev(sizes), 2) if len(sizes) > 1 else None,
        "packet_size_min": min(sizes) if sizes else None,
        "packet_size_max": max(sizes) if sizes else None,
        "packet_size_p25": round(_percentile(sorted_sizes, 0.25), 2) if sizes else None,
        "packet_size_p75": round(_percentile(sorted_sizes, 0.75), 2) if sizes else None,
        "interarrival_mean": round(statistics.mean(interarrivals), 6) if interarrivals else None,
        "interarrival_median": round(_percentile(sorted(interarrivals), 0.5), 6)
        if interarrivals
        else None,
        "interarrival_std": round(statistics.stdev(interarrivals), 6)
        if len(interarrivals) > 1
        else None,
        "interarrival_min": min(interarrivals) if interarrivals else None,
        "interarrival_max": max(interarrivals) if interarrivals else None,
        "upstream_packets": flow.upstream_packets,
        "downstream_packets": flow.downstream_packets,
        "upstream_bytes": flow.upstream_bytes,
        "downstream_bytes": flow.downstream_bytes,
        "direction_ratio": round(flow.upstream_packets / count, 4) if count else None,
        "burst_count": burst_stats["count"],
        "burst_packets_ratio": burst_stats["packets_ratio"],
        "burst_mean_size": burst_stats["mean_size"],
        "burst_max_size": burst_stats["max_size"],
        "burst_mean_duration": burst_stats["mean_duration"],
        "packet_size_histogram": _histogram(sizes, _HISTOGRAM_EDGES),
    }

    return FlowFeatures(
        flow_key=flow.flow_key,
        feature_schema_version=feature_schema_version,
        features=features,
    )


def _burst_stats(timestamps: list[float], window: float) -> dict[str, float]:
    if len(timestamps) < 2:
        return {
            "count": 0.0,
            "packets_ratio": 0.0,
            "mean_size": 0.0,
            "max_size": 0.0,
            "mean_duration": 0.0,
        }
    bursts: list[list[float]] = []
    current = [timestamps[0]]
    for prev, cur in zip(timestamps, timestamps[1:], strict=False):
        if cur - prev <= window:
            current.append(cur)
        else:
            bursts.append(current)
            current = [cur]
    bursts.append(current)
    burst_sizes = [len(b) for b in bursts if len(b) > 1]
    if not burst_sizes:
        return {
            "count": 0.0,
            "packets_ratio": 0.0,
            "mean_size": 0.0,
            "max_size": 0.0,
            "mean_duration": 0.0,
        }
    burst_durations = [max(b[-1] - b[0], 0.0) for b in bursts if len(b) > 1]
    packets_in_burst = sum(burst_sizes)
    total = len(timestamps)
    return {
        "count": float(len(burst_sizes)),
        "packets_ratio": round(packets_in_burst / total, 4),
        "mean_size": round(statistics.mean(burst_sizes), 2),
        "max_size": float(max(burst_sizes)),
        "mean_duration": round(statistics.mean(burst_durations), 6),
    }


def compute_all_flow_features(
    flows: list[FlowRecord],
    packets: list[ParsedPacket],
    feature_schema_version: str,
    burst_window_seconds: float = 0.1,
) -> list[FlowFeatures]:
    return [
        compute_flow_features(flow, packets, feature_schema_version, burst_window_seconds)
        for flow in flows
    ]
