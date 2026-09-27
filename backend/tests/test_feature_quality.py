"""Phase 4 readiness: feature-quality guarantees.

Every persisted feature must be safe to hand to a model: no NaN, no infinity,
no negative durations or ratios, no division by zero, and no fabricated value
where the data cannot support one. These tests pin those guarantees down
against degenerate inputs that real captures do produce (single-packet flows,
zero-length captures, identical timestamps, out-of-order timestamps).
"""

from __future__ import annotations

import math

import pytest

from app.analyzers.packet_analyzer.feature_extractor import compute_flow_features
from app.analyzers.packet_analyzer.flow_builder import build_flows, flow_key_for
from app.analyzers.packet_analyzer.packet_models import FlowRecord, ParsedPacket

SCHEMA_VERSION = "1.0"


def _packet(
    number: int,
    timestamp: float,
    length: int = 100,
    source: str = "10.0.0.1",
    destination: str = "10.0.0.2",
    source_port: int | None = 500,
    destination_port: int | None = 500,
    protocol: str = "udp",
) -> ParsedPacket:
    return ParsedPacket(
        number=number,
        timestamp=timestamp,
        length=length,
        source=source,
        destination=destination,
        ip_version=4,
        protocol=protocol,
        transport="udp" if protocol == "udp" else None,
        source_port=source_port,
        destination_port=destination_port,
        fragmented=False,
        ike=None,
        esp=None,
        ah=None,
        flow_key=None,
        evidence=[],
    )


def _features_for(packets: list[ParsedPacket]) -> dict[str, object]:
    flows = build_flows(packets)
    assert len(flows) == 1
    return compute_flow_features(flows[0], packets, SCHEMA_VERSION).features


def _num(features: dict[str, object], key: str) -> float:
    """Narrow a feature to a real number for arithmetic assertions."""
    value = features[key]
    assert isinstance(value, (int, float)), f"{key} is not numeric: {value!r}"
    return float(value)


def _buckets(features: dict[str, object]) -> list[dict[str, object]]:
    value = features["packet_size_histogram"]
    assert isinstance(value, list)
    return [b for b in value if isinstance(b, dict)]


def _assert_clean(features: dict[str, object]) -> None:
    """No NaN, no infinity, and no negative value for any rate/duration/count."""
    for key, value in features.items():
        if isinstance(value, list):
            for bucket in value:
                assert isinstance(bucket, dict)
                for sub_key, sub_value in bucket.items():
                    if isinstance(sub_value, float):
                        assert not math.isnan(sub_value), f"{key}.{sub_key} is NaN"
                        assert not math.isinf(sub_value), f"{key}.{sub_key} is infinite"
                        assert sub_value >= 0, f"{key}.{sub_key} is negative"
            continue
        if isinstance(value, float):
            assert not math.isnan(value), f"{key} is NaN"
            assert not math.isinf(value), f"{key} is infinite"
            assert value >= 0, f"{key} is negative"


class TestDegenerateFlows:
    def test_single_packet_flow_is_safe(self) -> None:
        features = _features_for([_packet(1, 100.0)])
        _assert_clean(features)
        assert features["packet_count"] == 1
        # Duration is zero, so rates must be absent rather than infinite/ZeroDivision.
        assert features["duration_seconds"] == 0.0
        assert features["packets_per_second"] is None
        assert features["bytes_per_second"] is None
        # A single sample has no standard deviation and no interarrival gap.
        assert features["packet_size_std"] is None
        assert features["interarrival_mean"] is None
        assert features["interarrival_std"] is None
        # Direction is fully determined, so the ratio is not undefined.
        assert features["direction_ratio"] == 1.0
        # A burst needs at least two packets.
        assert features["burst_count"] == 0.0
        assert features["burst_packets_ratio"] == 0.0

    def test_all_packets_at_identical_timestamps_is_safe(self) -> None:
        features = _features_for([_packet(i, 100.0, length=100) for i in range(1, 6)])
        _assert_clean(features)
        assert features["duration_seconds"] == 0.0
        assert features["packets_per_second"] is None
        assert features["bytes_per_second"] is None
        # Interarrival gaps are 0, not negative, and must not be NaN.
        assert features["interarrival_mean"] == 0.0
        assert features["interarrival_max"] == 0.0

    def test_out_of_order_timestamps_do_not_produce_negative_interarrivals(self) -> None:
        features = _features_for(
            [
                _packet(1, 100.0),
                _packet(2, 90.0),  # arrives earlier than its predecessor
                _packet(3, 110.0),
            ]
        )
        _assert_clean(features)
        assert features["interarrival_min"] == 0.0
        # Duration is derived from min/max timestamps, so it stays non-negative.
        assert features["duration_seconds"] == pytest.approx(20.0)
        # A burst spanning an out-of-order pair must not report a negative span.
        assert _num(features, "burst_mean_duration") >= 0.0

    def test_zero_length_capture_produces_no_flows_and_no_features(self) -> None:
        packets: list[ParsedPacket] = []
        assert build_flows(packets) == []

    def test_unknown_protocol_packets_are_not_turned_into_flows(self) -> None:
        packets = [_packet(1, 100.0, protocol="unknown")]
        assert build_flows(packets) == []

    def test_two_packets_with_different_sizes_reports_population_stats(self) -> None:
        features = _features_for([_packet(1, 100.0, length=100), _packet(2, 101.0, length=300)])
        _assert_clean(features)
        assert features["packet_size_min"] == 100
        assert features["packet_size_max"] == 300
        assert features["packet_size_mean"] == 200.0
        assert features["packet_size_median"] == 200.0
        assert features["packet_size_std"] == pytest.approx(141.42, abs=0.01)
        # Percentiles use linear interpolation between the two samples.
        assert features["packet_size_p25"] == 150.0
        assert features["packet_size_p75"] == 250.0


class TestFeatureInvariants:
    @pytest.mark.parametrize(
        ("lengths", "timestamps"),
        [
            ([100] * 10, [100.0 + 0.01 * i for i in range(10)]),
            ([64, 65, 255, 256, 1023, 1024, 4095, 4096, 65535, 65536], list(range(10))),
            ([1], [5.0]),
            ([1500] * 3, [0.0, 0.0, 0.0]),
        ],
    )
    def test_no_nan_inf_or_negative_values(
        self, lengths: list[int], timestamps: list[float]
    ) -> None:
        packets = [
            _packet(i + 1, ts, length=length)
            for i, (length, ts) in enumerate(zip(lengths, timestamps, strict=True))
        ]
        _assert_clean(_features_for(packets))

    def test_direction_counts_sum_to_packet_count(self) -> None:
        features = _features_for(
            [
                _packet(1, 100.0),
                _packet(
                    2,
                    101.0,
                    source="10.0.0.2",
                    destination="10.0.0.1",
                    source_port=500,
                    destination_port=500,
                ),
                _packet(3, 102.0),
            ]
        )
        assert _num(features, "upstream_packets") + _num(features, "downstream_packets") == _num(
            features, "packet_count"
        )
        assert _num(features, "upstream_bytes") + _num(features, "downstream_bytes") == _num(
            features, "byte_count"
        )
        assert features["direction_ratio"] == pytest.approx(2 / 3, abs=1e-4)

    def test_histogram_shares_sum_to_one(self) -> None:
        features = _features_for(
            [_packet(i, 100.0 + i, length=(i + 1) * 100) for i in range(1, 12)]
        )
        buckets = _buckets(features)
        assert len(buckets) == 6
        assert sum(_num(b, "count") for b in buckets) == _num(features, "packet_count")
        assert sum(_num(b, "share") for b in buckets) == pytest.approx(1.0, abs=0.01)

    def test_histogram_handles_empty_size_list_without_dividing_by_zero(self) -> None:
        features = compute_flow_features(
            FlowRecord(
                flow_key="empty",
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
                source_port=1,
                destination_port=2,
                protocol="udp",
                transport="udp",
                ip_version=4,
                start_time=0.0,
                end_time=0.0,
                duration=0.0,
                packet_count=0,
                byte_count=0,
                upstream_packets=0,
                downstream_packets=0,
                upstream_bytes=0,
                downstream_bytes=0,
                direction="unknown",
                packet_indices=[],
            ),
            [],
            SCHEMA_VERSION,
        ).features
        buckets = _buckets(features)
        assert len(buckets) == 6
        assert all(_num(b, "count") == 0 and _num(b, "share") == 0.0 for b in buckets)
        assert not any(math.isnan(_num(b, "share")) for b in buckets)

    def test_burst_features_reflect_a_tight_cluster(self) -> None:
        # Three packets 10ms apart (inside the 100ms window) then a long gap.
        features = _features_for(
            [
                _packet(1, 0.00),
                _packet(2, 0.01),
                _packet(3, 0.02),
                _packet(4, 50.0),
            ]
        )
        assert features["burst_count"] == 1.0
        assert features["burst_max_size"] == 3.0
        assert features["burst_mean_size"] == 3.0
        assert features["burst_packets_ratio"] == 0.75
        assert features["burst_mean_duration"] == pytest.approx(0.02, abs=1e-6)

    def test_isolated_packets_produce_no_bursts(self) -> None:
        features = _features_for([_packet(1, 0.0), _packet(2, 10.0), _packet(3, 20.0)])
        assert features["burst_count"] == 0.0
        assert features["burst_packets_ratio"] == 0.0
        assert features["burst_mean_size"] == 0.0


class TestFlowKeyStability:
    def test_port_zero_does_not_collide_with_missing_port(self) -> None:
        """Port 0 is falsy; it must not render the same key as a portless protocol."""
        with_port_zero = flow_key_for("10.0.0.1", "10.0.0.2", 0, 0, "udp", 4)
        without_ports = flow_key_for("10.0.0.1", "10.0.0.2", None, None, "udp", 4)
        assert with_port_zero != without_ports
        assert with_port_zero == "10.0.0.1:0-udp/4->10.0.0.2:0"
        assert without_ports == "10.0.0.1:x-udp/4->10.0.0.2:x"

    def test_flow_keys_are_unique_within_a_capture(self) -> None:
        """The ML data contract groups by flow_key, so keys must never collide."""
        packets = [
            _packet(1, 100.0, source_port=0, destination_port=0),
            _packet(2, 101.0, source_port=None, destination_port=None),
            _packet(3, 102.0, source_port=500, destination_port=500),
            _packet(4, 103.0, source_port=500, destination_port=500),
            _packet(5, 104.0, protocol="esp", source_port=None, destination_port=None),
            _packet(6, 105.0, protocol="esp", source_port=None, destination_port=None),
        ]
        flows = build_flows(packets)
        keys = [f.flow_key for f in flows]
        assert len(keys) == len(set(keys)), f"duplicate flow keys: {keys}"

    def test_bidirectional_packets_merge_into_one_flow(self) -> None:
        flows = build_flows(
            [
                _packet(1, 100.0),
                _packet(
                    2,
                    101.0,
                    source="10.0.0.2",
                    destination="10.0.0.1",
                    source_port=500,
                    destination_port=500,
                ),
            ]
        )
        assert len(flows) == 1
        assert flows[0].upstream_packets == 1
        assert flows[0].downstream_packets == 1
        assert flows[0].direction == "unknown"
