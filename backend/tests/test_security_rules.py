"""Unit tests for the deterministic security rules.

Rules are pure functions of an :class:`AssessmentContext`. We build contexts
from plain model instances (no engine/session needed) so every positive and
negative branch is exercised deterministically.
"""

from __future__ import annotations

from typing import cast

import pytest

from app.models import (
    AhPacket,
    Analysis,
    EspPacket,
    Flow,
    FlowFeatures,
    IkeMessage,
    IkeProposal,
    ProtocolObservation,
    Severity,
)
from app.security.base import FindingDraft, Rule
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence
from app.security.evidence import EvidenceItem, FindingEvidence, evidence_digest
from app.security.registry import RULES, RULES_VERSION, RegistryError, get_rule, rule_ids
from app.security.rules.crypto import UnknownEncryptionRule, WeakEncryptionRule
from app.security.rules.esp import (
    CompositeEspAhRule,
    ReplayAnomalyRule,
    SequenceObs,
    _find_anomalies,
)
from app.security.rules.ike import ConflictingSaParametersRule, IncompleteIkeNegotiationRule
from app.security.rules.kex import PfsNotObservedRule, WeakDhGroupRule
from app.security.rules.meta import (
    IkeInitiationFrequencyRule,
    PlaintextAlongsideIpsecRule,
)


def make_analysis(**kwargs: object) -> Analysis:
    analysis = Analysis()
    for key, value in kwargs.items():
        setattr(analysis, key, value)
    return analysis


def make_message(**kwargs: object) -> IkeMessage:
    message = IkeMessage()
    for key, value in kwargs.items():
        setattr(message, key, value)
    return message


def make_proposal(**kwargs: object) -> IkeProposal:
    proposal = IkeProposal()
    for key, value in kwargs.items():
        setattr(proposal, key, value)
    return proposal


def make_esp(**kwargs: object) -> EspPacket:
    packet = EspPacket()
    for key, value in kwargs.items():
        setattr(packet, key, value)
    return packet


def make_ah(**kwargs: object) -> AhPacket:
    packet = AhPacket()
    for key, value in kwargs.items():
        setattr(packet, key, value)
    return packet


def make_observation(**kwargs: object) -> ProtocolObservation:
    observation = ProtocolObservation()
    for key, value in kwargs.items():
        setattr(observation, key, value)
    return observation


def build_ctx(**kwargs: object) -> AssessmentContext:
    """Build an AssessmentContext from loosely typed keyword arguments.

    Rule tests only need a handful of collections, so the kwargs are unpacked
    positionally-by-name rather than through ``**kwargs`` (which mypy cannot
    check against the dataclass signature).
    """
    kwargs.setdefault("analysis", make_analysis())
    return AssessmentContext(
        analysis=cast(Analysis, kwargs.get("analysis")),
        ike_messages=cast("list[IkeMessage]", kwargs.get("ike_messages", [])),
        proposals=cast("list[IkeProposal]", kwargs.get("proposals", [])),
        esp_packets=cast("list[EspPacket]", kwargs.get("esp_packets", [])),
        ah_packets=cast("list[AhPacket]", kwargs.get("ah_packets", [])),
        flows=cast("list[Flow]", kwargs.get("flows", [])),
        features=cast("list[FlowFeatures]", kwargs.get("features", [])),
        protocol_observations=cast(
            "list[ProtocolObservation]", kwargs.get("protocol_observations", [])
        ),
    )


def rule_drafts(rule: object, ctx: AssessmentContext) -> list[FindingDraft]:
    assert isinstance(rule, Rule)
    return rule.evaluate(ctx)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    EXPECTED = {
        "IPSEC-CRYPTO-001",
        "IPSEC-CRYPTO-002",
        "IPSEC-DH-001",
        "IPSEC-PFS-001",
        "IPSEC-IKE-001",
        "IPSEC-SA-001",
        "IPSEC-REPLAY-001",
        "IPSEC-COMPOSITE-001",
        "IPSEC-META-001",
        "IPSEC-META-002",
    }

    def test_all_rules_registered(self) -> None:
        assert set(rule_ids()) == self.EXPECTED
        assert len(RULES) == len(self.EXPECTED)

    def test_version_is_semver(self) -> None:
        assert RULES_VERSION.count(".") == 2
        assert all(part.isdigit() for part in RULES_VERSION.split("."))

    def test_get_rule_unknown(self) -> None:
        with pytest.raises(RegistryError):
            get_rule("IPSEC-UNKNOWN-001")

    def test_every_rule_is_instantiable(self) -> None:
        for rule in RULES:
            assert rule.rule_id and rule.title and rule.description


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_digest_is_deterministic(self) -> None:
        evidence = FindingEvidence(
            items=[EvidenceItem(source="esp_packets", field="spi", observed_value="X")],
            packet_ids=[1, 2],
        )
        assert evidence_digest(evidence) == evidence_digest(evidence)
        assert len(evidence_digest(evidence)) == 64

    def test_digest_ignores_item_order_and_notes(self) -> None:
        evidence_a = FindingEvidence(
            items=[
                EvidenceItem(source="a", field="f", observed_value=1),
                EvidenceItem(source="b", field="g", observed_value=2),
            ]
        )
        evidence_b = FindingEvidence(
            items=[
                EvidenceItem(source="b", field="g", observed_value=2),
                EvidenceItem(source="a", field="f", observed_value=1),
            ],
            notes=["unused note"],
        )
        assert evidence_digest(evidence_a) == evidence_digest(evidence_b)

    def test_digest_changes_with_evidence(self) -> None:
        a = FindingEvidence(
            items=[EvidenceItem(source="esp_packets", field="spi", observed_value="X")]
        )
        b = FindingEvidence(
            items=[EvidenceItem(source="esp_packets", field="spi", observed_value="Y")]
        )
        assert evidence_digest(a) != evidence_digest(b)

    def test_evidence_to_json_is_serializable(self) -> None:
        evidence = FindingEvidence(
            items=[EvidenceItem(source="s", field="f", observed_value=5)],
            packet_ids=[3],
        )
        assert '"""' not in evidence.to_json()
        assert evidence.to_dict()["packet_ids"] == [3]


# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------


class TestUnknownEncryptionRule:
    def test_unknown_esp_encryption_triggers(self) -> None:
        ctx = build_ctx(esp_packets=[make_esp(encryption_algorithm="UNKNOWN")])
        drafts = rule_drafts(UnknownEncryptionRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].rule_id == "IPSEC-CRYPTO-001"
        assert drafts[0].confidence is FindingConfidence.HIGH

    def test_encr_prefix_esp_triggers(self) -> None:
        ctx = build_ctx(esp_packets=[make_esp(encryption_algorithm="ENCR_12")])
        assert len(rule_drafts(UnknownEncryptionRule(), ctx)) == 1

    def test_known_esp_does_not_trigger(self) -> None:
        ctx = build_ctx(esp_packets=[make_esp(encryption_algorithm="AES_GCM_16")])
        assert rule_drafts(UnknownEncryptionRule(), ctx) == []

    def test_unknown_ike_proposal_triggers(self) -> None:
        ctx = build_ctx(proposals=[make_proposal(encryption="ENCR_7")])
        drafts = rule_drafts(UnknownEncryptionRule(), ctx)
        assert len(drafts) == 1

    def test_empty_context_no_findings(self) -> None:
        assert UnknownEncryptionRule().evaluate(build_ctx()) == []


class TestWeakEncryptionRule:
    def test_null_is_critical(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="NULL", key_length=None, transform_confidence="high")
            ]
        )
        drafts = rule_drafts(WeakEncryptionRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.CRITICAL

    def test_des_family_is_high(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="DES_CBC", key_length=56, transform_confidence="high")
            ]
        )
        drafts = rule_drafts(WeakEncryptionRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.HIGH

    def test_3des_is_medium(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="3DES", key_length=168, transform_confidence="high")
            ]
        )
        assert rule_drafts(WeakEncryptionRule(), ctx)[0].severity is Severity.MEDIUM

    def test_weak_aes_key_length_is_high(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="AES_CBC", key_length=96, transform_confidence="high")
            ]
        )
        drafts = rule_drafts(WeakEncryptionRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.HIGH

    def test_strong_aes_not_reported(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="AES_CBC", key_length=256, transform_confidence="high")
            ]
        )
        assert rule_drafts(WeakEncryptionRule(), ctx) == []

    def test_unknown_never_reported_as_weak(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="UNKNOWN", key_length=None, transform_confidence="low")
            ]
        )
        assert rule_drafts(WeakEncryptionRule(), ctx) == []

    def test_low_transform_confidence_downgrades_confidence(self) -> None:
        ctx = build_ctx(
            proposals=[make_proposal(encryption="DES", key_length=56, transform_confidence="low")]
        )
        drafts = rule_drafts(WeakEncryptionRule(), ctx)
        assert drafts[0].confidence is FindingConfidence.MEDIUM

    def test_groups_per_encryption(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(encryption="DES_CBC", key_length=56, transform_confidence="high"),
                make_proposal(encryption="DES_CBC", key_length=56, transform_confidence="high"),
                make_proposal(encryption="NULL", key_length=None, transform_confidence="high"),
            ]
        )
        assert len(rule_drafts(WeakEncryptionRule(), ctx)) == 2


# ---------------------------------------------------------------------------
# Key exchange
# ---------------------------------------------------------------------------


class TestWeakDhGroupRule:
    @pytest.mark.parametrize(
        ("group", "expected_severity"),
        [(1, Severity.HIGH), (2, Severity.HIGH), (3, Severity.MEDIUM), (22, Severity.HIGH)],
    )
    def test_weak_groups_reported(self, group: int, expected_severity: Severity) -> None:
        ctx = build_ctx(proposals=[make_proposal(dh_group=group, transform_confidence="high")])
        drafts = rule_drafts(WeakDhGroupRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is expected_severity
        assert drafts[0].confidence is FindingConfidence.HIGH

    def test_strong_or_absent_group_not_reported(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(dh_group=19, transform_confidence="high"),
                make_proposal(dh_group=None, transform_confidence="high"),
                make_proposal(dh_group=5, transform_confidence="high"),
            ]
        )
        assert rule_drafts(WeakDhGroupRule(), ctx) == []


class TestPfsNotObservedRule:
    def test_child_sa_without_dh_reported(self) -> None:
        message = make_message(
            id="m1",
            packet_id=10,
            exchange_name="CREATE_CHILD_SA",
            payload_types_json='["SA"]',
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
        )
        ctx = build_ctx(
            ike_messages=[message],
            proposals=[make_proposal(dh_group=None, ike_message_id="m1")],
        )
        drafts = rule_drafts(PfsNotObservedRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.MEDIUM
        assert drafts[0].confidence is FindingConfidence.HIGH

    def test_child_sa_with_ke_not_report(self) -> None:
        message = make_message(
            id="m1",
            packet_id=10,
            exchange_name="CREATE_CHILD_SA",
            payload_types_json='["SA", "KE"]',
        )
        ctx = build_ctx(ike_messages=[message], proposals=[make_proposal(dh_group=None)])
        assert rule_drafts(PfsNotObservedRule(), ctx) == []

    def test_child_sa_with_dh_group_not_reported(self) -> None:
        message = make_message(
            id="m1",
            packet_id=10,
            exchange_name="QUICK_MODE",
            payload_types_json='["SA"]',
        )
        ctx = build_ctx(
            ike_messages=[message],
            proposals=[make_proposal(dh_group=19, ike_message_id="m1")],
        )
        assert rule_drafts(PfsNotObservedRule(), ctx) == []

    def test_no_child_exchange_is_unknown_not_finding(self) -> None:
        ctx = build_ctx(
            ike_messages=[
                make_message(
                    id="m1", packet_id=1, exchange_name="IKE_SA_INIT", payload_types_json='["SA"]'
                )
            ]
        )
        assert rule_drafts(PfsNotObservedRule(), ctx) == []


# ---------------------------------------------------------------------------
# IKE
# ---------------------------------------------------------------------------


class TestIncompleteIkeNegotiationRule:
    def test_sa_init_only_with_tunnel_reported(self) -> None:
        ctx = build_ctx(
            analysis=make_analysis(status="completed"),
            ike_messages=[
                make_message(
                    id="m1", packet_id=1, exchange_name="IKE_SA_INIT", payload_types_json='["SA"]'
                )
            ],
            esp_packets=[make_esp(encryption_algorithm="AES_GCM_16")],
        )
        drafts = rule_drafts(IncompleteIkeNegotiationRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.LOW
        assert drafts[0].confidence is FindingConfidence.MEDIUM

    def test_progress_exchange_suppresses(self) -> None:
        ctx = build_ctx(
            ike_messages=[
                make_message(
                    id="m1", packet_id=1, exchange_name="IKE_SA_INIT", payload_types_json='["SA"]'
                ),
                make_message(
                    id="m2", packet_id=2, exchange_name="IKE_AUTH", payload_types_json='["SA"]'
                ),
            ],
            esp_packets=[make_esp(encryption_algorithm="AES_GCM_16")],
        )
        assert rule_drafts(IncompleteIkeNegotiationRule(), ctx) == []

    def test_no_tunnel_traffic_suppresses(self) -> None:
        ctx = build_ctx(
            ike_messages=[
                make_message(
                    id="m1", packet_id=1, exchange_name="IKE_SA_INIT", payload_types_json='["SA"]'
                )
            ]
        )
        assert rule_drafts(IncompleteIkeNegotiationRule(), ctx) == []

    def test_no_setup_messages(self) -> None:
        ctx = build_ctx(ike_messages=[make_message(exchange_name="INFORMATIONAL")])
        assert rule_drafts(IncompleteIkeNegotiationRule(), ctx) == []


class TestConflictingSaParametersRule:
    def test_unresolved_integrity_on_selected_reported(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(
                    id="p1",
                    status="SELECTED",
                    protocol_name="IKEv2",
                    integrity="INTEG_5",
                    prf="HMAC_SHA2_256",
                )
            ]
        )
        drafts = rule_drafts(ConflictingSaParametersRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.MEDIUM
        assert drafts[0].confidence is FindingConfidence.MEDIUM

    def test_unresolved_prf_reported(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(
                    id="p1",
                    status="SELECTED",
                    protocol_name="IKEv2",
                    integrity="HMAC_SHA2_256",
                    prf="UNKNOWN",
                )
            ]
        )
        assert len(rule_drafts(ConflictingSaParametersRule(), ctx)) == 1

    def test_multiple_selected_conflicts_reported(self) -> None:
        message = make_message(
            id="m1",
            packet_id=1,
            exchange_name="IKE_SA_INIT",
            payload_types_json='["SA"]',
            initiator_spi="1111111111111111",
            responder_spi="0000000000000000",
        )
        proposals = [
            make_proposal(
                id=f"p{i}",
                status="SELECTED",
                protocol_name="IKEv2",
                integrity="HMAC_SHA2_256",
                prf="HMAC_SHA2_256",
                ike_message_id="m1",
            )
            for i in range(2)
        ]
        for proposal in proposals:
            proposal.ike_message = message
        ctx = build_ctx(ike_messages=[message], proposals=proposals)
        drafts = rule_drafts(ConflictingSaParametersRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.HIGH
        assert drafts[0].confidence is FindingConfidence.LOW

    def test_clean_selected_no_finding(self) -> None:
        ctx = build_ctx(
            proposals=[
                make_proposal(
                    id="p1",
                    status="SELECTED",
                    protocol_name="IKEv2",
                    integrity="HMAC_SHA2_256_128",
                    prf="HMAC_SHA2_256",
                    transform_confidence="high",
                )
            ]
        )
        assert rule_drafts(ConflictingSaParametersRule(), ctx) == []

    def test_no_selected_no_finding(self) -> None:
        ctx = build_ctx(proposals=[make_proposal(id="p1", status="OFFERED")])
        assert rule_drafts(ConflictingSaParametersRule(), ctx) == []


# ---------------------------------------------------------------------------
# ESP / AH
# ---------------------------------------------------------------------------


class TestReplayAnomalyRule:
    def test_non_increasing_sequence_reported(self) -> None:
        ctx = build_ctx(
            esp_packets=[
                make_esp(packet_id=1, spi="aa", direction="forward", sequence_number=1),
                make_esp(packet_id=2, spi="aa", direction="forward", sequence_number=2),
                make_esp(packet_id=3, spi="aa", direction="forward", sequence_number=2),
                make_esp(packet_id=4, spi="aa", direction="forward", sequence_number=4),
            ]
        )
        drafts = rule_drafts(ReplayAnomalyRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.MEDIUM
        assert drafts[0].evidence.packet_ids == [3]

    def test_ah_anomaly_reported_separately(self) -> None:
        ctx = build_ctx(
            ah_packets=[
                make_ah(packet_id=1, spi="bb", direction="reverse", sequence_number=5),
                make_ah(packet_id=2, spi="bb", direction="reverse", sequence_number=5),
            ]
        )
        drafts = rule_drafts(ReplayAnomalyRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].evidence.packet_ids == [2]

    def test_increasing_sequence_not_reported(self) -> None:
        ctx = build_ctx(
            esp_packets=[
                make_esp(packet_id=i, spi="aa", direction="forward", sequence_number=i)
                for i in range(1, 6)
            ]
        )
        assert rule_drafts(ReplayAnomalyRule(), ctx) == []

    def test_wrap_handled(self) -> None:
        obs = [
            SequenceObs(packet_id=1, spi="aa", direction="f", sequence_number=4_000_000_000),
            SequenceObs(packet_id=2, spi="aa", direction="f", sequence_number=100),
        ]
        assert _find_anomalies(obs) == []

    def test_large_decrease_is_anomaly_not_wrap(self) -> None:
        obs = [
            SequenceObs(packet_id=1, spi="aa", direction="f", sequence_number=2_000_000_000),
            SequenceObs(packet_id=2, spi="aa", direction="f", sequence_number=100),
        ]
        assert _find_anomalies(obs)

    def test_capped_at_25(self) -> None:
        obs = [
            SequenceObs(packet_id=i, spi="aa", direction="f", sequence_number=1) for i in range(30)
        ]
        anomalies = _find_anomalies(obs)
        assert len(anomalies) == 25


class TestCompositeEspAhRule:
    def test_same_spi_direction_reported(self) -> None:
        ctx = build_ctx(
            esp_packets=[
                make_esp(
                    packet_id=1, spi="aa", direction="forward", encryption_algorithm="AES_GCM_16"
                )
            ],
            ah_packets=[make_ah(packet_id=2, spi="aa", direction="forward", sequence_number=1)],
        )
        drafts = rule_drafts(CompositeEspAhRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.INFO
        assert drafts[0].confidence is FindingConfidence.HIGH

    def test_distinct_spi_not_reported(self) -> None:
        ctx = build_ctx(
            esp_packets=[make_esp(packet_id=1, spi="aa", direction="forward")],
            ah_packets=[make_ah(packet_id=2, spi="bb", direction="forward")],
        )
        assert rule_drafts(CompositeEspAhRule(), ctx) == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestPlaintextAlongsideIpsecRule:
    def test_plaintext_alongside_ipsec_reported(self) -> None:
        ctx = build_ctx(
            analysis=make_analysis(protocol_detected="yes"),
            protocol_observations=[make_observation(protocol="DNS", packet_count=3)],
        )
        drafts = rule_drafts(PlaintextAlongsideIpsecRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.INFO
        assert drafts[0].confidence is FindingConfidence.HIGH

    def test_ipsec_only_not_reported(self) -> None:
        ctx = build_ctx(
            analysis=make_analysis(protocol_detected="yes"),
            protocol_observations=[
                make_observation(protocol="ike", packet_count=4),
                make_observation(protocol="esp", packet_count=1),
                make_observation(protocol="ipv4", packet_count=10),  # structural, ignored
            ],
        )
        assert rule_drafts(PlaintextAlongsideIpsecRule(), ctx) == []

    def test_ipsec_not_detected_not_reported(self) -> None:
        ctx = build_ctx(
            analysis=make_analysis(protocol_detected="no"),
            protocol_observations=[make_observation(protocol="DNS", packet_count=3)],
        )
        assert rule_drafts(PlaintextAlongsideIpsecRule(), ctx) == []


class TestIkeInitiationFrequencyRule:
    def test_high_frequency_reported(self) -> None:
        messages = [
            make_message(
                id=f"m{i}",
                packet_id=i,
                exchange_name="IKE_SA_INIT",
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
            )
            for i in range(20)
        ]
        ctx = build_ctx(ike_messages=messages)
        drafts = rule_drafts(IkeInitiationFrequencyRule(), ctx)
        assert len(drafts) == 1
        assert drafts[0].severity is Severity.INFO
        assert drafts[0].confidence is FindingConfidence.MEDIUM

    def test_below_threshold_not_reported(self) -> None:
        messages = [
            make_message(
                id=f"m{i}",
                packet_id=i,
                exchange_name="IKE_SA_INIT",
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
            )
            for i in range(19)
        ]
        ctx = build_ctx(ike_messages=messages)
        assert rule_drafts(IkeInitiationFrequencyRule(), ctx) == []

    def test_spread_across_endpoints_not_reported(self) -> None:
        messages = [
            make_message(
                id=f"m{i}",
                packet_id=i,
                exchange_name="IKE_SA_INIT",
                source_ip=f"10.0.0.{i % 2}",
                destination_ip="10.0.0.9",
            )
            for i in range(20)
        ]
        assert rule_drafts(IkeInitiationFrequencyRule(), build_ctx(ike_messages=messages)) == []
