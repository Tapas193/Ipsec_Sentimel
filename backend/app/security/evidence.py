"""Machine-readable evidence model and canonical digest.

Every finding must carry evidence so a reviewer can see exactly which
fields led to the conclusion. ``evidence_digest`` is a deterministic
SHA-256 over the canonical evidence JSON and is used together with
``(analysis_id, rule_id)`` for idempotent re-assessment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from app.security.enums import ObservationStatus

EVIDENCE_SCHEMA_VERSION = "1"


@dataclass
class EvidenceItem:
    source: str
    field: str
    observed_value: Any = None
    expected_value: Any = None
    observation_status: ObservationStatus = ObservationStatus.OBSERVED


@dataclass
class FindingEvidence:
    items: list[EvidenceItem] = field(default_factory=list)
    packet_ids: list[int] = field(default_factory=list)
    message_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": EVIDENCE_SCHEMA_VERSION,
            "items": [_item_to_dict(item) for item in self.items],
            "packet_ids": sorted(set(self.packet_ids)),
            "message_ids": sorted(set(self.message_ids)),
            "notes": list(self.notes),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _item_to_dict(item: EvidenceItem) -> dict[str, Any]:
    return {
        "source": item.source,
        "field": item.field,
        "observed_value": item.observed_value,
        "expected_value": item.expected_value,
        "observation_status": item.observation_status.value,
    }


def evidence_digest(evidence: FindingEvidence) -> str:
    """Canonical digest used for idempotency across re-assessment runs.

    Rules run with identical evidence produce the identical digest, so the
    same analysis + rule + evidence never produces a duplicate finding.
    """
    payload: dict[str, Any] = {
        "items": sorted(
            (_item_to_dict(item) for item in evidence.items),
            key=lambda d: (
                str(d["source"]),
                str(d["field"]),
                json.dumps(d["observed_value"], sort_keys=True, default=_json_default),
                str(d["observation_status"]),
            ),
        ),
        "packet_ids": sorted(set(evidence.packet_ids)),
        "message_ids": sorted(set(evidence.message_ids)),
    }
    canonical = json.dumps(payload, sort_keys=True, default=_json_default)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if (len(digest)) != 64:
        raise RuntimeError("unexpected SHA-256 digest length")
    return digest


def _json_default(value: object) -> str:
    if value is None:
        return "null"
    return str(value)
