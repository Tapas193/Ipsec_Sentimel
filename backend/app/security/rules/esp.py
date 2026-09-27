"""ESP/AH packet rules.

- ``IPSEC-REPLAY-001`` — non-increasing ESP/AH sequence numbers
- ``IPSEC-COMPOSITE-001`` — ESP and AH both used on the same SA
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models import FindingType, Severity
from app.security.base import FindingDraft, Rule
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence, ObservationStatus
from app.security.evidence import EvidenceItem, FindingEvidence

_MAX_SEQUENCE_ANOMALIES = 25
_SEQUENCE_WRAP = 1 << 31


@dataclass
class SequenceObs:
    packet_id: int
    spi: str
    direction: str
    sequence_number: int


class ReplayAnomalyRule(Rule):
    """ESP/AH sequence numbers that do not strictly increase per SA."""

    rule_id = "IPSEC-REPLAY-001"
    name = "Possible replay / sequence anomaly"
    category = "REPLAY_PROTECTION"
    finding_type = FindingType.VULNERABILITY_INDICATOR
    default_severity = Severity.MEDIUM
    title = "Non-increasing ESP/AH sequence numbers observed"
    description = (
        "For at least one (SPI, direction), ESP or AH packet sequence numbers do "
        "not strictly increase over the capture. Duplicated or out-of-order "
        "sequence numbers are what replay protection exists to detect; out-of-order "
        "network delivery is also consistent with this observation, so the claim "
        "is intentionally conservative."
    )
    impact = (
        "A non-monotonic sequence stream may indicate replayed or duplicated "
        "packets, or merely reordering under normal transport."
    )
    recommendation = (
        "Confirm the IPsec peer's anti-replay window and inspect the affected "
        "packets; correlate with peer-side receive-window counters before "
        "concluding a replay attack."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        drafts: list[FindingDraft] = []

        esp_anomalies = _find_anomalies(
            [
                SequenceObs(p.packet_id, p.spi, p.direction, p.sequence_number)
                for p in ctx.esp_packets
                if p.sequence_number is not None
            ]
        )
        if esp_anomalies:
            drafts.append(self._draft("esp_packets", esp_anomalies))

        ah_anomalies = _find_anomalies(
            [
                SequenceObs(p.packet_id, p.spi, p.direction, p.sequence_number)
                for p in ctx.ah_packets
                if p.sequence_number is not None
            ]
        )
        if ah_anomalies:
            drafts.append(self._draft("ah_packets", ah_anomalies))

        return drafts

    def _draft(self, source: str, anomalies: list[SequenceObs]) -> FindingDraft:
        packet_ids = [a.packet_id for a in anomalies]
        evidence = FindingEvidence(
            items=[
                EvidenceItem(
                    source=source,
                    field="sequence_number",
                    observed_value=", ".join(str(a.sequence_number) for a in anomalies[:5]),
                    expected_value="strictly increasing per (SPI, direction)",
                    observation_status=ObservationStatus.INFERRED,
                )
            ],
            packet_ids=packet_ids,
            notes=[
                f"{len(anomalies)} non-increasing sequence observation(s); "
                "out-of-order delivery cannot be excluded."
            ],
        )
        return FindingDraft(
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
            observed_value=f"{len(anomalies)} non-increasing sequence(s)",
            expected_value="strictly increasing sequence numbers",
        )


def _find_anomalies(observations: list[SequenceObs]) -> list[SequenceObs]:
    per_sa: dict[tuple[str, str], list[SequenceObs]] = {}
    for obs in observations:
        per_sa.setdefault((obs.spi, obs.direction), []).append(obs)

    anomalies: list[SequenceObs] = []
    for records in per_sa.values():
        ordered = sorted(records, key=lambda r: r.packet_id)
        max_seen: int | None = None
        for record in ordered:
            seq = record.sequence_number
            if max_seen is None:
                max_seen = seq
                continue
            if max_seen - seq > _SEQUENCE_WRAP:
                # 32-bit counter wrapped.
                max_seen = seq
                continue
            if seq <= max_seen:
                anomalies.append(record)
                if len(anomalies) >= _MAX_SEQUENCE_ANOMALIES:
                    return anomalies
            else:
                max_seen = seq
    return anomalies


class CompositeEspAhRule(Rule):
    """ESP and AH applied to the same (SPI, direction) security association.

    Informational only: dual-use (both confidentiality+integrity and a separate
    integrity layer) is a valid deployment, not a vulnerability.
    """

    rule_id = "IPSEC-COMPOSITE-001"
    name = "ESP and AH both applied to the same SA"
    category = "SECURITY_ASSOCIATION"
    finding_type = FindingType.INFORMATIONAL
    default_severity = Severity.INFO
    title = "ESP and AH both applied to the same security association"
    description = (
        "The same SPI and direction carries both ESP and AH packets, so the "
        "security association combines ESP (confidentiality + integrity) with an "
        "additional AH integrity layer. This is an informational observation; it "
        "is not itself a vulnerability."
    )
    impact = (
        "Dual ESP+AH usage increases per-packet overhead; whether that is "
        "appropriate depends on the deployment policy."
    )
    recommendation = (
        "Verify the dual-protection configuration matches the organization's IPsec policy."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        esp_keys = {(p.spi, p.direction) for p in ctx.esp_packets}
        ah_keys = {(p.spi, p.direction) for p in ctx.ah_packets}
        overlap = sorted(esp_keys & ah_keys)
        if not overlap:
            return []

        evidence = FindingEvidence(
            items=[
                EvidenceItem(
                    source="ah_packets",
                    field="spi",
                    observed_value=", ".join(f"{spi}/{direction}" for spi, direction in overlap),
                    expected_value="no SPI shared with ESP",
                    observation_status=ObservationStatus.OBSERVED,
                )
            ],
            packet_ids=[p.packet_id for p in ctx.esp_packets if (p.spi, p.direction) in overlap],
            notes=[f"{len(overlap)} SA(s) carry both ESP and AH."],
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
                observed_value=f"{len(overlap)} SA(s) with ESP + AH",
                expected_value="single protection layer per SA",
            )
        ]
