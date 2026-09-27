"""Security finding schemas.

``SecurityFindingRead`` exposes the Phase 3 assessment fields together with
the legacy Phase 1 fields so existing consumers keep working.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingEvidenceItemRead(BaseModel):
    source: str
    field: str
    observed_value: Any = None
    expected_value: Any = None
    observation_status: str


class FindingEvidenceRead(BaseModel):
    version: str | None = None
    items: list[FindingEvidenceItemRead] = Field(default_factory=list)
    packet_ids: list[int] = Field(default_factory=list)
    message_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SecurityFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str | None
    analysis_id: str
    rule_id: str
    rule_version: str | None
    title: str
    severity: str
    finding_type: str
    category: str
    description: str | None
    impact: str | None
    recommendation: str | None
    confidence: str
    status: str
    source: str | None
    observed_value: str | None
    expected_value: str | None
    evidence: FindingEvidenceRead | None
    created_at: datetime
