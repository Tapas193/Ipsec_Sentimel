"""IKE protocol rules.

- ``IPSEC-IKE-001`` — incomplete IKE negotiation
- ``IPSEC-SA-001`` — inconsistent or partially unverifiable selected SA
"""

from __future__ import annotations

from app.models import FindingType, IkeProposal, Severity
from app.security.base import FindingDraft, Rule
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence, ObservationStatus
from app.security.evidence import EvidenceItem, FindingEvidence
from app.security.helpers import is_unresolved_transform

_SETUP_EXCHANGES: frozenset[str] = frozenset(
    {"IKE_SA_INIT", "BASE", "IDENTITY_PROTECTION", "AGGRESSIVE"}
)

# Exchanges that indicate a given IKE SA progressed beyond the first exchange.
_PROGRESS_EXCHANGES: frozenset[str] = frozenset(
    {
        "IKE_AUTH",
        "CREATE_CHILD_SA",
        "INFORMATIONAL",
        "IKE_SESSION_RESUME",
        "QUICK_MODE",
        "AUTHENTICATION_ONLY",
    }
)


class IncompleteIkeNegotiationRule(Rule):
    """IKE negotiation started but never completed within the capture."""

    rule_id = "IPSEC-IKE-001"
    name = "Incomplete IKE negotiation"
    category = "PROTOCOL"
    finding_type = FindingType.CONFIGURATION_RISK
    default_severity = Severity.LOW
    title = "IKE negotiation may be incomplete"
    description = (
        "IKE setup exchanges (IKE_SA_INIT or IKEv1 equivalents) were observed, but "
        "no message in the capture shows the negotiation advancing to a later "
        "stage, while ESP/AH traffic is also present. The capture may simply be "
        "partial; the finding is raised only because the evidence is directly "
        "visible."
    )
    impact = (
        "An IKE SA that never completes cannot carry traffic; combined with "
        "observed ESP/AH traffic this may indicate a partial capture or an "
        "interrupted negotiation."
    )
    recommendation = (
        "Re-capture the full negotiation (or confirm the capture covers both the "
        "IKE_SA_INIT and IKE_AUTH exchanges) before relying on the result."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        setup_messages = [m for m in ctx.ike_messages if m.exchange_name in _SETUP_EXCHANGES]
        if not setup_messages:
            return []
        if any(m.exchange_name in _PROGRESS_EXCHANGES for m in ctx.ike_messages):
            return []
        has_tunnel_traffic = bool(ctx.esp_packets or ctx.ah_packets)
        if not has_tunnel_traffic:
            return []

        evidence = FindingEvidence(
            items=[
                EvidenceItem(
                    source="ike_messages",
                    field="exchange_name",
                    observed_value="IKE_SA_INIT only",
                    expected_value="IKE_SA_INIT then IKE_AUTH / CREATE_CHILD_SA",
                    observation_status=ObservationStatus.INFERRED,
                )
            ],
            message_ids=[m.id for m in setup_messages],
            packet_ids=[m.packet_id for m in setup_messages],
            notes=[
                f"{len(setup_messages)} setup exchange(s) without a later-stage "
                "message; ESP/AH traffic present in the same capture."
            ],
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
                confidence=FindingConfidence.MEDIUM,
                evidence=evidence,
                observed_value="IKE_SA_INIT only (+ ESP/AH)",
                expected_value="IKE_SA_INIT + IKE_AUTH",
            )
        ]


class ConflictingSaParametersRule(Rule):
    """Selected SA carries partially unverifiable or conflicting parameters."""

    rule_id = "IPSEC-SA-001"
    name = "Inconsistent or unverifiable selected SA"
    category = "SECURITY_ASSOCIATION"
    finding_type = FindingType.CONFIGURATION_RISK
    default_severity = Severity.MEDIUM
    title = "Selected security association could not be fully verified"
    description = (
        "An IKE proposal marked as SELECTED still carries transform attributes "
        "(integrity/PRF/authentication) that could not be resolved to a known "
        "value, or multiple proposals are marked SELECTED for the same SA. The "
        "effective parameters of the negotiated SA are therefore uncertain."
    )
    impact = (
        "If a selected SA uses an integrity or PRF algorithm the analyzer cannot "
        "resolve, its true protection level is unverified and should be checked "
        "out-of-band."
    )
    recommendation = (
        "Confirm the negotiated integrity/PRF algorithms on the gateway and ensure "
        "the IKE proposal list contains only resolvable transforms."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        selected = [p for p in ctx.proposals if p.status == "SELECTED"]
        if not selected:
            return []

        drafts: list[FindingDraft] = []
        unresolved = [p for p in selected if _proposal_unresolved(p)]
        if unresolved:
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="ike_proposals",
                        field="transform_confidence",
                        observed_value="unresolved integrity/PRF",
                        expected_value="resolved transform values",
                        observation_status=ObservationStatus.OBSERVED,
                    )
                ],
                message_ids=[p.ike_message_id for p in unresolved if p.ike_message_id],
                notes=[
                    f"{len(unresolved)} selected proposal(s) contain unresolved "
                    "transform attributes."
                ],
            )
            drafts.append(
                FindingDraft(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.default_severity,
                    finding_type=self.finding_type,
                    category=self.category,
                    description=self.description,
                    impact=self.impact,
                    recommendation=self.recommendation,
                    confidence=FindingConfidence.MEDIUM,
                    evidence=evidence,
                    observed_value=f"{len(unresolved)} unresolved selected proposal(s)",
                    expected_value="all selected transforms resolved",
                )
            )

        conflicts = _conflicting_selections(selected)
        if conflicts:
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="ike_proposals",
                        field="status",
                        observed_value="multiple SELECTED proposals per SA",
                        expected_value="exactly one SELECTED proposal per SA",
                        observation_status=ObservationStatus.INFERRED,
                    )
                ],
                message_ids=[m for group in conflicts for m in group],
                notes=[f"{len(conflicts)} SA(s) with conflicting selections."],
            )
            drafts.append(
                FindingDraft(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    finding_type=FindingType.VULNERABILITY_INDICATOR,
                    category=self.category,
                    description=(
                        "Multiple IKE proposals are marked SELECTED for the same "
                        "security association, which conflicts with normal IKE "
                        "negotiation semantics."
                    ),
                    impact=self.impact,
                    recommendation=self.recommendation,
                    confidence=FindingConfidence.LOW,
                    evidence=evidence,
                    observed_value="conflicting SELECTED proposals",
                    expected_value="single SELECTED proposal per SA",
                )
            )
        return drafts


def _proposal_unresolved(proposal: IkeProposal) -> bool:
    return is_unresolved_transform(proposal.integrity) or is_unresolved_transform(proposal.prf)


def _conflicting_selections(proposals: list[IkeProposal]) -> list[list[str]]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for proposal in proposals:
        message = proposal.ike_message
        key = (
            proposal.protocol_name,
            f"{message.initiator_spi}:{message.responder_spi}" if message else "",
        )
        grouped.setdefault(key, []).append(proposal.id)
    return [ids for ids in grouped.values() if len(ids) > 1]
