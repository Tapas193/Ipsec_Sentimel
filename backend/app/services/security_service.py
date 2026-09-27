"""Deterministic security assessment service.

Runs the rule registry against the persisted Phase 2 data of a completed
analysis and persists evidence-backed ``SecurityFinding`` rows. Assessment is
idempotent: identical evidence for the same (analysis, rule) is skipped.

Logging includes ``analysis_id``, ``rule_version``, duration and per-rule
counts so every run is auditable.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import AnalysisNotAssessableError
from app.models import (
    AhPacket,
    Analysis,
    AnalysisStatus,
    EspPacket,
    FindingStatus,
    Flow,
    FlowFeatures,
    IkeMessage,
    IkeProposal,
    ProtocolObservation,
    SecurityFinding,
)
from app.security.base import FindingDraft
from app.security.context import AssessmentContext
from app.security.evidence import evidence_digest
from app.security.registry import RULES, RULES_VERSION
from app.services import next_sequence_id

logger = logging.getLogger("ipsec_sentinel.security")

DEFAULT_FINDING_SOURCE = "assessment_engine"


def assess_analysis(db: Session, analysis: Analysis) -> dict[str, Any]:
    """Evaluate all rules for a completed analysis and persist findings.

    Returns an idempotent summary consumed by the API layer.
    """
    if analysis.status is not AnalysisStatus.COMPLETED:
        raise AnalysisNotAssessableError(
            "Analysis must be completed before it can be assessed.",
            details={"analysis_id": analysis.analysis_id, "status": analysis.status.value},
        )

    started = time.monotonic()
    ctx = _load_context(db, analysis)

    rules_run = 0
    created = 0
    skipped = 0
    per_rule: dict[str, dict[str, int]] = {}

    for rule in RULES:
        rule_started = time.monotonic()
        drafts: list[FindingDraft] = []
        try:
            drafts = rule.evaluate(ctx)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "security rule failed",
                extra={
                    "analysis_id": analysis.analysis_id,
                    "rule_id": rule.rule_id,
                },
            )
            raise RuntimeError(
                f"Rule {rule.rule_id} failed with an unexpected error: {exc}"
            ) from exc

        stats = per_rule.setdefault(rule.rule_id, {"created": 0, "skipped": 0})
        for draft in drafts:
            digest = evidence_digest(draft.evidence)
            exists = db.scalar(
                select(SecurityFinding.id).where(
                    SecurityFinding.analysis_id == analysis.id,
                    SecurityFinding.rule_id == draft.rule_id,
                    SecurityFinding.evidence_digest == digest,
                )
            )
            if exists is not None:
                stats["skipped"] += 1
                skipped += 1
                continue
            _persist_finding(db, analysis, digest, draft)
            stats["created"] += 1
            created += 1
        rules_run += 1
        logger.debug(
            "security rule run",
            extra={
                "analysis_id": analysis.analysis_id,
                "rule_id": rule.rule_id,
                "created": stats["created"],
                "skipped": stats["skipped"],
                "duration_ms": (time.monotonic() - rule_started) * 1000,
            },
        )

    analysis.rule_version = RULES_VERSION
    db.commit()

    duration_ms = (time.monotonic() - started) * 1000
    total = (
        db.scalar(
            select(func.count())
            .select_from(SecurityFinding)
            .where(SecurityFinding.analysis_id == analysis.id)
        )
        or 0
    )

    logger.info(
        "security assessment complete",
        extra={
            "analysis_id": analysis.analysis_id,
            "rule_version": RULES_VERSION,
            "rules_run": rules_run,
            "created": created,
            "skipped": skipped,
            "total_findings": total,
            "duration_ms": duration_ms,
        },
    )

    return {
        "analysis_id": analysis.analysis_id,
        "rule_version": RULES_VERSION,
        "rules_run": rules_run,
        "created": created,
        "skipped": skipped,
        "total_findings": total,
        "duration_ms": duration_ms,
        "rules": [{"rule_id": rule_id, **stats} for rule_id, stats in sorted(per_rule.items())],
        "completed_at": datetime.now(UTC),
    }


def _load_context(db: Session, analysis: Analysis) -> AssessmentContext:
    messages = list(
        db.scalars(
            select(IkeMessage)
            .where(IkeMessage.analysis_id == analysis.id)
            .order_by(IkeMessage.packet_id)
        ).all()
    )
    proposals = list(
        db.scalars(
            select(IkeProposal)
            .where(IkeProposal.analysis_id == analysis.id)
            .options(selectinload(IkeProposal.ike_message))
            .order_by(IkeProposal.created_at)
        ).all()
    )
    esp_packets = list(
        db.scalars(
            select(EspPacket)
            .where(EspPacket.analysis_id == analysis.id)
            .order_by(EspPacket.packet_id)
        ).all()
    )
    ah_packets = list(
        db.scalars(
            select(AhPacket).where(AhPacket.analysis_id == analysis.id).order_by(AhPacket.packet_id)
        ).all()
    )
    flows = list(
        db.scalars(
            select(Flow).where(Flow.analysis_id == analysis.id).order_by(Flow.created_at)
        ).all()
    )
    features = list(
        db.scalars(
            select(FlowFeatures)
            .where(FlowFeatures.analysis_id == analysis.id)
            .order_by(FlowFeatures.created_at)
        ).all()
    )
    observations = list(
        db.scalars(
            select(ProtocolObservation)
            .where(ProtocolObservation.analysis_id == analysis.id)
            .order_by(ProtocolObservation.created_at)
        ).all()
    )
    return AssessmentContext(
        analysis=analysis,
        ike_messages=messages,
        proposals=proposals,
        esp_packets=esp_packets,
        ah_packets=ah_packets,
        flows=flows,
        features=features,
        protocol_observations=observations,
    )


def _persist_finding(db: Session, analysis: Analysis, digest: str, draft: FindingDraft) -> None:
    finding_id = next_sequence_id(db, SecurityFinding, SecurityFinding.finding_id, "SEC", 6)
    finding = SecurityFinding(
        finding_id=finding_id,
        analysis_id=analysis.id,
        rule_id=draft.rule_id,
        rule_version=RULES_VERSION,
        title=draft.title,
        severity=draft.severity,
        finding_type=draft.finding_type,
        category=draft.category,
        description=draft.description,
        evidence_json=draft.evidence.to_json(),
        evidence_digest=digest,
        impact=draft.impact,
        recommendation=draft.recommendation,
        confidence=draft.confidence,
        status=FindingStatus.OPEN,
        source=draft.source,
        observed_value=draft.observed_value,
        expected_value=draft.expected_value,
    )
    db.add(finding)
    # Flush immediately so the next finding's human id (derived from
    # max(finding_id)) is unique even on sessions that disable autoflush.
    db.flush()
