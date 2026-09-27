"""Schema for the deterministic assessment run summary."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RuleAssessmentRead(BaseModel):
    rule_id: str
    created: int = 0
    skipped: int = 0


class AssessmentResultRead(BaseModel):
    """Idempotent summary returned by ``POST /analyses/{key}/assess``."""

    analysis_id: str | None
    rule_version: str
    rules_run: int
    created: int
    skipped: int
    total_findings: int
    duration_ms: float
    rules: list[RuleAssessmentRead] = Field(default_factory=list)
    completed_at: datetime
