"""Metadata / visibility rules.

- ``IPSEC-META-001`` — plaintext traffic coexisting with IPsec traffic
- ``IPSEC-META-002`` — elevated IKE initiation frequency
"""

from __future__ import annotations

from app.models import FindingType, Severity
from app.security.base import FindingDraft, Rule
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence, ObservationStatus
from app.security.evidence import EvidenceItem, FindingEvidence

_IPSEC_PROTOCOLS: frozenset[str] = frozenset({"ike", "esp", "ah", "natt", "isakmp", "ipsec"})
_NON_TRAFFIC_PROTOCOLS: frozenset[str] = frozenset({"ipv4", "ipv6", "arp"})

_INIT_FREQUENCY_THRESHOLD = 20
_INIT_EXCHANGES: frozenset[str] = frozenset(
    {"IKE_SA_INIT", "AGGRESSIVE", "BASE", "IDENTITY_PROTECTION"}
)


class PlaintextAlongsideIpsecRule(Rule):
    """Non-IPsec traffic observed in the same capture as IPsec."""

    rule_id = "IPSEC-META-001"
    name = "Non-IPsec traffic alongside IPsec"
    category = "METADATA"
    finding_type = FindingType.INFORMATIONAL
    default_severity = Severity.INFO
    title = "Non-IPsec traffic observed alongside IPsec"
    description = (
        "The capture contains both IPsec traffic and plaintext/non-IPsec "
        "protocols. This is informational: it may indicate split tunnelling, or "
        "unrelated traffic present on the same segment."
    )
    impact = (
        "Information about surrounding traffic (protocols, sizes, timing, "
        "endpoints, flow duration and direction) is observable to anyone with "
        "access to the capture."
    )
    recommendation = (
        "If expose of this metadata is a concern, filter the capture to IPsec "
        "traffic only, or keep the capture itself confidential."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        if ctx.analysis.protocol_detected not in ("yes",):
            return []
        others = [
            (o.protocol, o.packet_count)
            for o in ctx.protocol_observations
            if o.protocol not in _IPSEC_PROTOCOLS and o.protocol not in _NON_TRAFFIC_PROTOCOLS
        ]
        if not others:
            return []

        observed = {name for name, _ in others}
        counts = {name: count for name, count in others}
        evidence = FindingEvidence(
            items=[
                EvidenceItem(
                    source="protocol_observations",
                    field="protocol",
                    observed_value=", ".join(sorted(counts)),
                    expected_value="IPsec protocols only",
                    observation_status=ObservationStatus.OBSERVED,
                )
            ],
            notes=[
                "Plaintext protocols with packet counts: "
                + ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
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
                confidence=FindingConfidence.HIGH,
                evidence=evidence,
                observed_value=", ".join(sorted(observed)),
                expected_value="IPsec protocols only",
            )
        ]


class IkeInitiationFrequencyRule(Rule):
    """High volume of IKE setup requests towards the same peer."""

    rule_id = "IPSEC-META-002"
    name = "Elevated IKE initiation frequency"
    category = "METADATA"
    finding_type = FindingType.INFORMATIONAL
    default_severity = Severity.INFO
    title = "Elevated IKE initiation frequency observed"
    description = (
        "A large number of IKE setup requests originate from the same endpoint "
        "towards a peer. This can indicate rekey churn, a misconfigured client, "
        "or probing/scanning; it is reported as informational metadata, not as a "
        "confirmed attack."
    )
    impact = (
        "Repeated initiations are visible metadata that may reveal client "
        "behaviour or attract attention on the wire."
    )
    recommendation = (
        "Inspect the initiating endpoint for a misconfigured client or IKE "
        "scanning before assuming malice."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        per_endpoint: dict[tuple[str, str], list[str]] = {}
        for message in ctx.ike_messages:
            if message.exchange_name not in _INIT_EXCHANGES:
                continue
            key = (message.source_ip, message.destination_ip)
            per_endpoint.setdefault(key, []).append(message.id)

        offending: list[tuple[tuple[str, str], list[str]]] = []
        for (source, destination), message_ids in per_endpoint.items():
            if len(message_ids) >= _INIT_FREQUENCY_THRESHOLD:
                offending.append(((source, destination), message_ids))

        if not offending:
            return []

        drafts: list[FindingDraft] = []
        for (source, destination), message_ids in sorted(
            offending, key=lambda kv: (kv[0][0], kv[0][1])
        ):
            observed = f"{len(message_ids)} initiations from {source} to {destination}"
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="ike_messages",
                        field="exchange_name",
                        observed_value=f"{len(message_ids)} setup requests",
                        expected_value=f"< {_INIT_FREQUENCY_THRESHOLD} setup requests",
                        observation_status=ObservationStatus.INFERRED,
                    )
                ],
                message_ids=message_ids,
                notes=[
                    f"{observed}; threshold is {_INIT_FREQUENCY_THRESHOLD} "
                    "setup requests from one endpoint."
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
                    observed_value=observed,
                    expected_value=(f"< {_INIT_FREQUENCY_THRESHOLD} initiations per endpoint"),
                )
            )
        return drafts
