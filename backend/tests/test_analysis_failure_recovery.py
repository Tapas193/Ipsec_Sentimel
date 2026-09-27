"""Regression tests for analysis failure handling and flow-key storage width.

Two defects are pinned here:

1. ``flows.flow_id`` was ``VARCHAR(32)``, too narrow for a flow key such as
   ``10.0.0.1:12345-udp/4->10.0.0.2:8080`` (35 chars). The resulting
   ``StringDataRightTruncation`` aborted the persistence transaction.
2. The failure path did not roll the session back, so the FAILED status could
   not be written and the analysis stayed ``running`` forever - and because the
   capture stayed ``analyzing``, ``POST /captures/{id}/analyze`` then rejected
   every retry with 409, permanently bricking the capture.

Together these meant one persistence error made a capture unrecoverable.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.analyzers.packet_analyzer.flow_builder import flow_key_for
from app.models import Analysis, AnalysisStatus, Capture, CaptureStatus, Flow
from app.models.flow import Flow as FlowModel
from app.services.analysis_service import _fail

# Longest key the renderer can produce for IPv6 endpoints with 5-digit ports.
WORST_CASE_IPV6_KEY = flow_key_for(
    "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
    "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
    65535,
    65535,
    "udp",
    6,
)


def _make_capture(db: Session, capture_id: str, reference: str) -> Capture:
    """A minimally valid Capture row for the tables' NOT NULL constraints."""
    capture = Capture(
        id=capture_id,
        capture_reference=reference,
        filename=f"{reference}.pcap",
        original_filename=f"{reference}.pcap",
        stored_filename=f"{capture_id}.pcap",
        capture_format="pcap",
        storage_path=f"/tmp/{capture_id}.pcap",
        file_size=10,
        sha256="0" * 64,
        status=CaptureStatus.ANALYZING,
        uploaded_at=datetime.now(UTC),
    )
    db.add(capture)
    db.commit()
    return capture


def _declared_length() -> int | None:
    """The declared VARCHAR length of flows.flow_id, or None if unconstrained."""
    column_type = FlowModel.__table__.c.flow_id.type
    return getattr(column_type, "length", None)


class TestFlowKeyWidth:
    def test_typical_5_digit_port_key_exceeds_the_old_32_char_column(self) -> None:
        key = flow_key_for("10.0.0.1", "10.0.0.2", 12345, 8080, "udp", 4)
        assert len(key) == 35
        assert len(key) > 32, "this is the value that used to overflow the column"

    def test_column_is_wide_enough_for_the_worst_case_key(self) -> None:
        declared = _declared_length()
        assert declared is not None
        assert declared >= len(WORST_CASE_IPV6_KEY), (
            f"flow_id column is VARCHAR({declared}) but the longest possible key is "
            f"{len(WORST_CASE_IPV6_KEY)}: {WORST_CASE_IPV6_KEY}"
        )

    def test_worst_case_key_fits(self) -> None:
        assert len(WORST_CASE_IPV6_KEY) < 255
        assert (_declared_length() or 0) >= len(WORST_CASE_IPV6_KEY)


class TestFailurePathRecovers:
    def test_fail_writes_failed_status_after_a_flush_error(self, db_session: Session) -> None:
        """A persistence error must still leave the analysis in a terminal state."""
        capture = _make_capture(db_session, "cap-1", "CAP-000001")

        analysis = Analysis(
            id="an-1",
            analysis_id="ANL-000001",
            capture_id=capture.id,
            status=AnalysisStatus.RUNNING,
        )
        db_session.add(analysis)
        db_session.commit()

        # Simulate the aborted transaction left behind by a failed flush. SQLite
        # does not enforce VARCHAR length, so a NOT NULL violation is used to
        # reach the same session state a StringDataRightTruncation would cause.
        db_session.add(
            Flow(
                id="flow-1",
                analysis_id=analysis.id,
                flow_id="k" * 64,
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                protocol=None,  # deliberate NOT NULL violation
                start_time=analysis.started_at or analysis.created_at,
                end_time=analysis.started_at or analysis.created_at,
                duration=0.0,
                packet_count=1,
                byte_count=1,
                upstream_packets=1,
                downstream_packets=0,
                upstream_bytes=1,
                downstream_bytes=0,
                direction="first_seen",
            )
        )
        # Deliberately do NOT roll back here: `_fail` must be able to recover from
        # a session that is still in the aborted state, which is exactly what
        # run_analysis hands it when _persist raises.
        with pytest.raises(IntegrityError):
            db_session.commit()

        _fail(db_session, analysis, None, "PARSER_ERROR", "synthetic persistence failure")

        reloaded = db_session.get(Analysis, analysis.id)
        assert reloaded is not None
        assert reloaded.status is AnalysisStatus.FAILED
        assert reloaded.error_message is not None
        assert "PARSER_ERROR" in reloaded.error_message

        reloaded_capture = db_session.get(Capture, capture.id)
        assert reloaded_capture is not None
        assert reloaded_capture.status is CaptureStatus.FAILED

    def test_failed_analysis_does_not_stay_running(self, db_session: Session) -> None:
        """End-to-end: the count of RUNNING analyses must be zero after a failure."""
        capture = _make_capture(db_session, "cap-2", "CAP-000002")
        analysis = Analysis(
            id="an-2",
            analysis_id="ANL-000002",
            capture_id=capture.id,
            status=AnalysisStatus.RUNNING,
        )
        db_session.add(analysis)
        db_session.commit()

        _fail(db_session, analysis, None, "PARSER_ERROR", "boom")

        running = db_session.scalars(
            select(Analysis).where(Analysis.status == AnalysisStatus.RUNNING)
        ).all()
        assert running == [], "a failed analysis must never be left in RUNNING"
        analyzing = db_session.scalars(
            select(Capture).where(Capture.status == CaptureStatus.ANALYZING)
        ).all()
        assert analyzing == [], "a failed capture must never be left in ANALYZING"
