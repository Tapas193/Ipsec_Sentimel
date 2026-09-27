"""Key-exchange rules.

- ``IPSEC-DH-001`` — use of a documented weak Diffie-Hellman group
- ``IPSEC-PFS-001`` — perfect forward secrecy not observed for rekeys

PFS is only ever reported when a child-SA rekey is actually visible in the
capture; when no evidence exists the status remains ``UNKNOWN`` and no
finding is raised.
"""

from __future__ import annotations

from app.models import FindingType, IkeProposal, Severity
from app.security.base import FindingDraft, Rule
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence, ObservationStatus
from app.security.evidence import EvidenceItem, FindingEvidence

# Documented weak DH groups: group -> (severity, human-readable name).
WEAK_DH_GROUPS: dict[int, tuple[Severity, str]] = {
    1: (Severity.HIGH, "MODP_768"),
    2: (Severity.HIGH, "MODP_1024"),
    3: (Severity.MEDIUM, "MODP_1536"),
    22: (Severity.HIGH, "MODP_1024_S160"),
}

_CHILD_EXCHANGES: frozenset[str] = frozenset({"CREATE_CHILD_SA", "QUICK_MODE"})
_INIT_EXCHANGES: frozenset[str] = frozenset({"IKE_SA_INIT"})
_STRONG_DH_EXAMPLE = "MODP_2048 (5/14), MODP_3072 (15), ECP_256 (19) or higher"


class WeakDhGroupRule(Rule):
    """Use of a documented weak Diffie-Hellman group."""

    rule_id = "IPSEC-DH-001"
    name = "Weak Diffie-Hellman group"
    category = "KEY_EXCHANGE"
    finding_type = FindingType.VULNERABILITY_INDICATOR
    default_severity = Severity.MEDIUM
    title = "Weak Diffie-Hellman group in use"
    description = (
        "An IKE proposal negotiates (or offers) a Diffie-Hellman group from the "
        "documented weak set: MODP_768, MODP_1024, MODP_1536, or MODP_1024_S160. "
        "Groups below 2048 bits are deprecated for key exchange. Absent or "
        "unrecognized groups are never reported here."
    )
    impact = (
        "Deprecated DH groups allow relatively cheap precomputation attacks on "
        "the negotiated key exchange and weaken forward secrecy."
    )
    recommendation = (
        f"Configure the gateway to use {_STRONG_DH_EXAMPLE}, and remove legacy "
        "groups from proposals."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        per_group: dict[int, list[IkeProposal]] = {}
        for proposal in ctx.proposals:
            if proposal.dh_group in WEAK_DH_GROUPS:
                per_group.setdefault(proposal.dh_group, []).append(proposal)

        drafts: list[FindingDraft] = []
        for dh_group, proposals in sorted(per_group.items()):
            severity, group_name = WEAK_DH_GROUPS[dh_group]
            observed = f"DH group {dh_group} ({group_name})"
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="ike_proposals",
                        field="dh_group",
                        observed_value=dh_group,
                        expected_value=_STRONG_DH_EXAMPLE,
                        observation_status=ObservationStatus.OBSERVED,
                    )
                ],
                message_ids=[p.ike_message_id for p in proposals if p.ike_message_id],
                notes=[f"{len(proposals)} proposal(s) affected."],
            )
            drafts.append(
                FindingDraft(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=severity,
                    finding_type=self.finding_type,
                    category=self.category,
                    description=self.description,
                    impact=self.impact,
                    recommendation=self.recommendation,
                    confidence=FindingConfidence.HIGH,
                    evidence=evidence,
                    observed_value=observed,
                    expected_value=_STRONG_DH_EXAMPLE,
                )
            )
        return drafts


class PfsNotObservedRule(Rule):
    """Perfect forward secrecy not used for a visible child-SA rekey."""

    rule_id = "IPSEC-PFS-001"
    name = "PFS not used for child security associations"
    category = "PFS"
    finding_type = FindingType.POLICY_DEVIATION
    default_severity = Severity.MEDIUM
    title = "Perfect forward secrecy not observed for child SAs"
    description = (
        "IKE child-SA negotiations (CREATE_CHILD_SA / QUICK_MODE) were observed "
        "without a fresh Diffie-Hellman exchange, so rekeyed child SAs do not "
        "derive fresh keys from a new DH contribution. This claim is made only "
        "because the rekey exchange is directly visible in the capture; when PFS "
        "posture cannot be observed it is left unknown instead."
    )
    impact = (
        "Without PFS, compromise of a long-term key would allow the session keys "
        "of all rekeyed child SAs to be recovered."
    )
    recommendation = (
        "Enable perfect forward secrecy (a new KE/DH exchange on every child-SA "
        "rekey) on the VPN gateway."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        child_messages = [m for m in ctx.ike_messages if m.exchange_name in _CHILD_EXCHANGES]
        if not child_messages:
            # PFS posture cannot be determined -> stays UNKNOWN -> no finding.
            return []

        child_message_ids = {m.id for m in child_messages}
        child_proposals = [p for p in ctx.proposals if p.ike_message_id in child_message_ids]
        has_dh_exchange = any("KE" in m.payload_types for m in child_messages) or any(
            p.dh_group is not None for p in child_proposals
        )
        if has_dh_exchange:
            return []

        evidence = FindingEvidence(
            items=[
                EvidenceItem(
                    source="ike_messages",
                    field="payload_types",
                    observed_value="SA (no KE)",
                    expected_value="SA + KE (fresh DH on rekey)",
                    observation_status=ObservationStatus.OBSERVED,
                )
            ],
            message_ids=sorted(child_message_ids),
            packet_ids=[m.packet_id for m in child_messages],
            notes=[f"{len(child_messages)} child-SA exchange(s) without a DH/KE payload."],
        )
        return [
            FindingDraft(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.default_severity,
                finding_type=self.finding_type,
                category=self.category,
                description=self.description,
                impact=self.impact,
                recommendation=self.recommendation,
                confidence=FindingConfidence.HIGH,
                evidence=evidence,
                observed_value="no KE / new DH on child rekey",
                expected_value="KE / new DH on child rekey",
            )
        ]
