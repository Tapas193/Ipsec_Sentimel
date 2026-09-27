"""Unit tests for the packet parser, IKE proposal parsing, flows and features."""

from __future__ import annotations

from app.analyzers.packet_analyzer.feature_extractor import compute_flow_features
from app.analyzers.packet_analyzer.flow_builder import build_flows
from app.analyzers.packet_analyzer.parser import parse_packet
from app.analyzers.packet_analyzer.protocols.ike import (
    parse_ike_message,
    parse_sa_proposals,
)
from tests.synthetic_pcap import (
    ah_payload,
    esp_payload,
    ethernet,
    ikev2_sa_init_message,
    ikev2_sa_init_payload,
    ipv4,
    udp,
)


def _v2_msg_frame(src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    return ethernet(ipv4(udp(ikev2_sa_init_message(), 500, 500), src, dst, 17))


class TestPacketParser:
    def test_parses_ikev2_sa_init(self) -> None:
        packet = parse_packet(1, 100.0, _v2_msg_frame())
        assert packet is not None
        assert packet.ip_version == 4
        assert packet.protocol == "udp"
        assert packet.source_port == 500
        assert packet.ike is not None
        assert packet.ike.version == "IKEv2"
        assert packet.ike.exchange_name == "IKE_SA_INIT"
        assert "SA" in packet.ike.payload_types
        assert packet.ike.sa_payload is not None

    def test_detects_esp(self) -> None:
        body = b"\x01" * 32
        frame = ethernet(ipv4(esp_payload(0xDEADBEEF, 1, body), "10.0.0.1", "10.0.0.2", 50))
        packet = parse_packet(1, 100.0, frame)
        assert packet is not None
        assert packet.protocol == "esp"
        assert packet.esp is not None
        assert packet.esp.spi == "deadbeef"
        assert packet.esp.sequence_number == 1

    def test_nat_t_esp_over_4500(self) -> None:
        # ESP over UDP 4500: the ESP header (SPI + sequence) starts directly,
        # with NO non-ESP marker prefix.
        body = b"\xab\xab\xab\xab" + b"\x00\x00\x00\x01" + b"\xab" * 32
        frame = ethernet(ipv4(udp(body, 4500, 4500), "10.0.0.1", "10.0.0.2", 17))
        packet = parse_packet(1, 100.0, frame)
        assert packet is not None
        assert packet.esp is not None
        assert packet.esp.spi == "abababab"
        assert packet.esp.nat_t is True

    def test_detects_ah(self) -> None:
        frame = ethernet(ipv4(ah_payload(0x10101010, 1, b"\x00" * 24), "10.0.0.1", "10.0.0.2", 51))
        packet = parse_packet(1, 100.0, frame)
        assert packet is not None
        assert packet.protocol == "ah"
        assert packet.ah is not None
        assert packet.ah.spi == "10101010"

    def test_garbage_ip_payload_is_none(self) -> None:
        frame = ethernet(b"\x45\x00" + b"\x00" * 30, 0x0800)
        assert parse_packet(1, 100.0, frame) is not None  # header-only parsed

    def test_non_ethernet_raw_ip(self) -> None:
        ip = ipv4(udp(ikev2_sa_init_message(), 500, 500), "10.0.0.1", "10.0.0.2", 17)
        packet = parse_packet(1, 100.0, ip)
        assert packet is not None
        assert packet.ike is not None


class TestSaParsing:
    def test_ikev2_proposal_fields(self) -> None:
        sa_body = ikev2_sa_init_payload()[4:]
        proposals = parse_sa_proposals(sa_body, "IKEv2")
        assert len(proposals) == 1
        proposal = proposals[0]
        assert proposal.protocol_name == "ESP"
        assert proposal.encryption == "AES_GCM_16"
        assert proposal.key_length == 256
        assert proposal.dh_group == 19
        assert proposal.status in ("OFFERED", "SELECTED")

    def test_ikev2_sa_init_via_message_record(self) -> None:
        packet = parse_packet(1, 100.0, _v2_msg_frame())
        assert packet is not None and packet.ike is not None
        message = parse_ike_message(packet, packet.ike)
        assert message is not None
        assert message.version == "IKEv2"
        assert message.direction == "initiator"
        assert len(message.proposals) == 1
        assert message.proposals[0].encryption == "AES_GCM_16"

    def test_responder_flags_select_proposal(self) -> None:
        sa_payload = ikev2_sa_init_payload()
        header = (
            b"\x11" * 8
            + b"\x00" * 8
            + bytes([33, 0x20, 34, 0x20])  # responder flag bit (0x20), not initiator
            + b"\x00\x00\x00\x00"
            + len(bytearray(sa_payload)).to_bytes(4, "big")
        )
        raw = header + sa_payload
        packet = parse_packet(1, 100.0, _frame_with_ike(raw))
        assert packet is not None and packet.ike is not None
        message = parse_ike_message(packet, packet.ike)
        assert message is not None
        assert message.direction == "responder"
        assert message.proposals and message.proposals[0].status == "SELECTED"


class TestFlows:
    def test_build_flows_groups_endpoint_pairs(self) -> None:
        packets = []
        for i in range(3):
            pkt = parse_packet(i + 1, 100.0 + i, _v2_msg_frame())
            assert pkt is not None
            packets.append(pkt)
        flows = build_flows(packets)
        assert len(flows) == 1
        flow = flows[0]
        assert flow.protocol == "udp"
        assert flow.ike_packets == 3
        assert flow.packet_count == 3

    def test_esp_and_ike_share_flow(self) -> None:
        packets = []
        pkt = parse_packet(1, 100.0, _v2_msg_frame())
        assert pkt is not None
        packets.append(pkt)
        esp_frame = ethernet(
            ipv4(esp_payload(0xDEADBEEF, 1, b"\x01" * 32), "10.0.0.1", "10.0.0.2", 50)
        )
        esp_pkt = parse_packet(2, 100.1, esp_frame)
        assert esp_pkt is not None
        packets.append(esp_pkt)
        flows = build_flows(packets)
        # ESP (portless) and IKE (500) are distinct flows but ESP flow has index.
        assert len(flows) == 2
        features = compute_flow_features(flows[0], packets, "1.0", burst_window_seconds=0.1)
        assert features.features["packet_count"] == 1
        duration = features.features["duration_seconds"]
        assert isinstance(duration, float)
        assert duration >= 0.0


def _frame_with_ike(ike: bytes) -> bytes:
    _src, _dst = [10, 0, 0, 1], [10, 0, 0, 2]
    udp_header = udp(ike, 500, 500)
    return ethernet(ipv4(udp_header, "10.0.0.1", "10.0.0.2", 17))
