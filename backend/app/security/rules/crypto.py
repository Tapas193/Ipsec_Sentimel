"""Cryptography rules.

- ``IPSEC-CRYPTO-001`` — encryption that could not be verified
- ``IPSEC-CRYPTO-002`` — use of a documented weak encryption algorithm

The weak-encryption table is a static, documented mapping; an algorithm is
never marked weak just because it is unknown.
"""

from __future__ import annotations

from app.models import FindingType, IkeProposal, Severity
from app.security.base import FindingDraft, Rule
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence, ObservationStatus
from app.security.evidence import EvidenceItem, FindingEvidence
from app.security.helpers import is_unknown_encryption

# Documented weak algorithms -> severity. NULL (no confidentiality) is worst.
WEAK_ENCRYPTION: dict[str, Severity] = {
    "NULL": Severity.CRITICAL,
    "DES": Severity.HIGH,
    "DES_CBC": Severity.HIGH,
    "DES_IV64": Severity.HIGH,
    "DES_IV32": Severity.HIGH,
    "RC5": Severity.HIGH,
    "RC5_R16": Severity.HIGH,
    "IDEA": Severity.HIGH,
    "IDEA_CBC": Severity.HIGH,
    "3IDEA": Severity.HIGH,
    "CAST": Severity.HIGH,
    "CAST_CBC": Severity.HIGH,
    "BLOWFISH": Severity.HIGH,
    "BLOWFISH_CBC": Severity.HIGH,
    "3DES": Severity.MEDIUM,
    "3DES_CBC": Severity.MEDIUM,
}

# AES with an effective key length below 128 bits is treated as weak.
MIN_AES_KEY_BITS = 128

_VERIFIABLE_ENCRYPTION = "A recognized algorithm such as AES_CBC or AES_GCM_16"


class UnknownEncryptionRule(Rule):
    """Encryption that cannot be verified from the capture."""

    rule_id = "IPSEC-CRYPTO-001"
    name = "Encryption could not be verified"
    category = "VISIBILITY"
    finding_type = FindingType.INFORMATIONAL
    default_severity = Severity.LOW
    title = "Encryption could not be verified from the capture"
    description = (
        "One or more security associations carry an encryption algorithm the "
        "analyzer could not verify. ESP payloads are end-to-end encrypted and are "
        "never decrypted; where the transform is not visible in IKE, the algorithm "
        "remains unknown. This is a verification/visibility limitation, not an "
        "indication the algorithm is weak."
    )
    impact = (
        "The confidentiality strength of the affected flows cannot be confirmed "
        "from the capture alone."
    )
    recommendation = (
        "Verify the IKE/ESP configuration out-of-band on the VPN gateway. If IKE "
        "proposals are present, encrypt them (IKEv2) or use a modern transform. "
        "For ESP payloads, confirm the negotiated algorithm using gateway logs."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        drafts: list[FindingDraft] = []

        esp_packets = [p for p in ctx.esp_packets if is_unknown_encryption(p.encryption_algorithm)]
        if esp_packets:
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="esp_packets",
                        field="encryption_algorithm",
                        observed_value="UNKNOWN",
                        expected_value=_VERIFIABLE_ENCRYPTION,
                        observation_status=ObservationStatus.OBSERVED,
                    )
                ],
                packet_ids=[p.packet_id for p in esp_packets],
                notes=[
                    f"{len(esp_packets)} ESP packet(s) recorded without a verifiable "
                    "encryption algorithm (payloads are not decrypted)."
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
                    confidence=FindingConfidence.HIGH,
                    evidence=evidence,
                    observed_value="UNKNOWN",
                    expected_value=_VERIFIABLE_ENCRYPTION,
                )
            )

        proposals = [p for p in ctx.proposals if is_unknown_encryption(p.encryption)]
        if proposals:
            message_ids = [p.ike_message_id for p in proposals if p.ike_message_id]
            observed = {p.encryption for p in proposals}
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="ike_proposals",
                        field="encryption",
                        observed_value=", ".join(sorted(observed)),
                        expected_value=_VERIFIABLE_ENCRYPTION,
                        observation_status=ObservationStatus.OBSERVED,
                    )
                ],
                message_ids=message_ids,
                notes=[
                    f"{len(proposals)} IKE proposal(s) reference an unrecognized "
                    "encryption transform id."
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
                    confidence=FindingConfidence.HIGH,
                    evidence=evidence,
                    observed_value=", ".join(sorted(observed)),
                    expected_value=_VERIFIABLE_ENCRYPTION,
                )
            )

        return drafts


def _weak_severity(encryption: str, key_length: int | None) -> Severity | None:
    if encryption in ("AES_CBC", "AES_CTR", "AES_GCM_16", "AES_GCM_12", "AES_GCM_8"):
        if key_length is not None and key_length < MIN_AES_KEY_BITS:
            return Severity.HIGH
        return None
    return WEAK_ENCRYPTION.get(encryption)


class WeakEncryptionRule(Rule):
    """Use of a documented weak encryption algorithm."""

    rule_id = "IPSEC-CRYPTO-002"
    name = "Weak encryption algorithm"
    category = "CRYPTOGRAPHY"
    finding_type = FindingType.VULNERABILITY_INDICATOR
    default_severity = Severity.MEDIUM
    title = "Weak encryption algorithm in use"
    description = (
        "An IKE proposal negotiates (or offers) an encryption algorithm from the "
        "documented weak set (DES family, 3DES, RC5, IDEA, CAST, Blowfish, or NULL). "
        "These ciphers are deprecated for VPN use. 'Unknown' algorithms are never "
        "reported here — only explicit matches from the fixed table are."
    )
    impact = (
        "Weak ciphers provide insufficient confidentiality against modern "
        "cryptanalysis; NULL encryption provides none at all."
    )
    recommendation = (
        "Configure the VPN gateway to use AES-CBC (128/192/256) or an AEAD mode "
        "such as AES-GCM, and retire the legacy cipher from all proposals."
    )

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        per_group: dict[tuple[str, int | None], list[IkeProposal]] = {}
        for proposal in ctx.proposals:
            severity = _weak_severity(proposal.encryption, proposal.key_length)
            if severity is None:
                continue
            key = (proposal.encryption, proposal.key_length)
            per_group.setdefault(key, []).append(proposal)

        drafts: list[FindingDraft] = []
        for (encryption, key_length), proposals in sorted(per_group.items(), key=lambda kv: kv[0]):
            severity = _weak_severity(encryption, key_length)
            if severity is None:
                continue
            has_high_confidence = any(p.transform_confidence == "high" for p in proposals)
            message_ids = [p.ike_message_id for p in proposals if p.ike_message_id]
            observed = encryption if key_length is None else f"{encryption}/{key_length}"
            expected = "AES_CBC, AES_CTR or AES_GCM_*"
            evidence = FindingEvidence(
                items=[
                    EvidenceItem(
                        source="ike_proposals",
                        field="encryption",
                        observed_value=observed,
                        expected_value=expected,
                        observation_status=ObservationStatus.OBSERVED,
                    )
                ],
                message_ids=message_ids,
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
                    confidence=(
                        FindingConfidence.HIGH if has_high_confidence else FindingConfidence.MEDIUM
                    ),
                    evidence=evidence,
                    observed_value=observed,
                    expected_value=expected,
                )
            )
        return drafts
