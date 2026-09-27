"""Database connection tests."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    Analysis,
    AnalysisStatus,
    FindingConfidence,
    FindingStatus,
    SecurityFinding,
    Severity,
)


def test_database_engine_connects(db_session: Session) -> None:
    result = db_session.execute(text("SELECT 1"))
    assert result.scalar_one() == 1


def test_database_contains_expected_tables(db_session: Session) -> None:
    tables = {
        row[0]
        for row in db_session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).all()
    }
    expected = {
        "captures",
        "analysis_jobs",
        "analyses",
        "security_findings",
        "reports",
        "ike_messages",
        "ike_proposals",
        "esp_packets",
        "ah_packets",
        "flows",
        "flow_features",
        "protocol_observations",
    }
    assert expected.issubset(tables)


def test_security_finding_enum_round_trip(db_session: Session) -> None:
    analysis = Analysis(status=AnalysisStatus.COMPLETED, capture_id="capture-fake-1")
    analysis.analysis_id = "ANL-ENUM-000001"
    db_session.add(analysis)
    db_session.flush()

    finding = SecurityFinding(
        finding_id="SEC-000001",
        analysis_id=analysis.id,
        rule_id="IPSEC-TEST-001",
        title="round trip",
        severity=Severity.HIGH,
        category="PROTOCOL",
        confidence=FindingConfidence.MEDIUM,
        status=FindingStatus.ACKNOWLEDGED,
        evidence_json="{}",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.expire_all()

    reloaded = db_session.get(SecurityFinding, finding.id)
    assert reloaded is not None
    assert reloaded.confidence is FindingConfidence.MEDIUM
    assert reloaded.confidence.value == "medium"
    assert reloaded.status is FindingStatus.ACKNOWLEDGED
    assert reloaded.severity is Severity.HIGH


def test_security_finding_unique_analysis_rule_evidence(db_session: Session) -> None:
    analysis = Analysis(status=AnalysisStatus.COMPLETED, capture_id="capture-fake-1")
    analysis.analysis_id = "ANL-UNIQUE-000001"
    db_session.add(analysis)
    db_session.flush()

    kwargs = {
        "analysis_id": analysis.id,
        "rule_id": "IPSEC-TEST-002",
        "title": "duplicate",
        "severity": Severity.LOW,
        "category": "PROTOCOL",
        "evidence_digest": "d" * 64,
    }
    db_session.add(SecurityFinding(finding_id="SEC-000001", **kwargs))
    db_session.commit()

    db_session.add(SecurityFinding(finding_id="SEC-000002", **kwargs))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_security_finding_finding_id_unique(db_session: Session) -> None:
    analysis = Analysis(status=AnalysisStatus.COMPLETED, capture_id="capture-fake-1")
    analysis.analysis_id = "ANL-UNIQUE-000002"
    db_session.add(analysis)
    db_session.flush()

    db_session.add(
        SecurityFinding(
            finding_id="SEC-000001",
            analysis_id=analysis.id,
            rule_id="IPSEC-TEST-003",
            title="one",
            severity=Severity.INFO,
            category="PROTOCOL",
            evidence_json="{}",
        )
    )
    db_session.commit()
    db_session.add(
        SecurityFinding(
            finding_id="SEC-000001",
            analysis_id=analysis.id,
            rule_id="IPSEC-TEST-004",
            title="two",
            severity=Severity.INFO,
            category="PROTOCOL",
            evidence_json="{}",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
