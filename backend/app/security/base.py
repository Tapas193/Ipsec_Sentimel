"""Base class for deterministic security rules and the finding draft model.

A rule is a pure function of an :class:`AssessmentContext`. It never touches
the database and never executes code; it returns zero or more
:class:`FindingDraft` objects. Whether a draft becomes a persisted finding is
decided by the assessment service (dedupe happens there).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models import FindingType, Severity
from app.security.context import AssessmentContext
from app.security.enums import FindingConfidence
from app.security.evidence import FindingEvidence

DEFAULT_SOURCE = "assessment_engine"


@dataclass
class FindingDraft:
    """A rule result that may become a persisted ``SecurityFinding``."""

    rule_id: str
    title: str
    severity: Severity
    finding_type: FindingType
    category: str
    description: str
    impact: str
    recommendation: str
    confidence: FindingConfidence
    evidence: FindingEvidence = field(default_factory=FindingEvidence)
    observed_value: str | None = None
    expected_value: str | None = None
    source: str = DEFAULT_SOURCE


class Rule:
    """Declarative rule metadata + deterministic evaluation."""

    rule_id: str = ""
    name: str = ""
    category: str = ""
    finding_type: FindingType = FindingType.INFORMATIONAL
    default_severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""

    def evaluate(self, ctx: AssessmentContext) -> list[FindingDraft]:
        raise NotImplementedError(f"{self.rule_id} does not implement evaluate()")
