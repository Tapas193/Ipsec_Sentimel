"""Analysis orchestration: job tracking + engine run + persistence.

The analysis service runs the packet analyzer engine for a stored capture,
tracks progress against an AnalysisJob, and persists all derived records
(protocol observations, IKE messages/proposals, ESP/AH packets, flows and
flow features) onto the completed Analysis row. Runs synchronously in a
background task; the job row is polled by the frontend.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.analyzers.packet_analyzer.engine import (
    AnalysisContext,
    AnalysisResult,
    PacketAnalyzerEngine,
)
from app.analyzers.packet_analyzer.packet_models import (
    ProtocolObservation,
)
from app.core.config import Settings, get_settings
from app.models import (
    AhPacket,
    Analysis,
    AnalysisJob,
    AnalysisStatus,
    Capture,
    CaptureStatus,
    EspPacket,
    Flow,
    IkeMessage,
    IkeProposal,
    JobStage,
    JobStatus,
)
from app.models import (
    FlowFeatures as FlowFeaturesModel,
)
from app.models import (
    ProtocolObservation as ProtocolObservationModel,
)
from app.services import next_sequence_id

logger = logging.getLogger(__name__)


def create_analysis(db: Session, capture: Capture, settings: Settings | None = None) -> Analysis:
    """Create the Analysis row (status=running) plus its job."""
    settings = settings or get_settings()
    analysis_ref = next_sequence_id(db, Analysis, Analysis.analysis_id, "ANL", 6)
    analysis = Analysis(
        analysis_id=analysis_ref,
        capture_id=capture.id,
        status=AnalysisStatus.RUNNING,
        started_at=datetime.now(UTC),
        analyzer_version=settings.ANALYZER_VERSION,
        parser_version=settings.PARSER_VERSION,
    )
    db.add(analysis)
    db.flush()

    job = AnalysisJob(
        job_id=next_sequence_id(db, AnalysisJob, AnalysisJob.job_id, "JOB", 6),
        capture_id=capture.id,
        status=JobStatus.RUNNING,
        progress=0.0,
        current_stage=JobStage.PACKET_READING,
        stage_message="Starting analysis",
        started_at=datetime.now(UTC),
    )
    db.add(job)
    db.commit()
    db.refresh(analysis)
    return analysis


def run_analysis(db: Session, analysis: Analysis) -> Analysis:
    """Run the engine and persist results onto the given analysis row."""
    capture = db.get(Capture, analysis.capture_id)
    settings = get_settings()

    job = db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.capture_id == analysis.capture_id)
        .order_by(AnalysisJob.created_at.desc())
    )
    try:
        if capture is None:
            _fail(db, analysis, job, "PARSER_ERROR", "Capture record missing.")
            return analysis
        engine = PacketAnalyzerEngine()
        context = AnalysisContext(
            capture_path=capture.storage_path,
            max_packets=settings.ANALYZER_MAX_PACKETS,
            timeout_seconds=settings.ANALYSIS_TIMEOUT_SECONDS,
            feature_schema_version=settings.FEATURE_SCHEMA_VERSION,
            burst_window_seconds=settings.FLOW_BURST_WINDOW_SECONDS,
        )
        result = engine.analyze(context)
        _set_stage(db, job, JobStage.PERSISTENCE, 0.95, "Persisting results")

        if result.error_code:
            _fail(db, analysis, job, result.error_code, result.error_message or "Analysis failed.")
            return analysis

        _persist(db, analysis, capture, result, settings)
    except Exception as exc:  # noqa: BLE001
        _fail(db, analysis, job, "PARSER_ERROR", f"Analysis failed: {exc}")
        return analysis

    analysis.status = AnalysisStatus.COMPLETED
    analysis.completed_at = datetime.now(UTC)
    capture.status = CaptureStatus.ANALYZED
    capture.analysis_status = "completed"
    if job is not None:
        job.progress = 1.0
        job.current_stage = JobStage.COMPLETED
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(UTC)
        job.stage_message = "Analysis completed"
    db.commit()
    db.refresh(analysis)
    return analysis


def get_analysis_by_key(db: Session, analysis_key: str) -> Analysis | None:
    if analysis_key.startswith("ANL-"):
        return db.scalar(select(Analysis).where(Analysis.analysis_id == analysis_key))
    return db.scalar(select(Analysis).where(Analysis.id == analysis_key))


def get_job_by_key(db: Session, job_key: str) -> AnalysisJob | None:
    if job_key.startswith("JOB-"):
        return db.scalar(select(AnalysisJob).where(AnalysisJob.job_id == job_key))
    return db.scalar(select(AnalysisJob).where(AnalysisJob.id == job_key))


def _set_stage(
    db: Session, job: AnalysisJob | None, stage: JobStage, progress: float, message: str
) -> None:
    if job is None:
        return
    job.current_stage = stage
    job.progress = progress
    job.stage_message = message
    db.commit()


def _fail(
    db: Session,
    analysis: Analysis,
    job: AnalysisJob | None,
    code: str,
    message: str,
) -> None:
    # `_fail` is reached from the `except` branch of `run_analysis`, so the
    # session is usually already in a failed state: a flush error (for example
    # a value that does not fit its column) leaves the transaction aborted and
    # every later statement raises PendingRollbackError. Without this rollback
    # the FAILED status could never be written and the analysis stayed
    # "running" forever. Roll back first, then re-apply the state on clean
    # objects. Re-query so we are not mutating instances detached by rollback.
    db.rollback()
    analysis = db.get(Analysis, analysis.id) or analysis
    analysis.status = AnalysisStatus.FAILED
    analysis.error_message = f"{code}: {message}"
    analysis.completed_at = datetime.now(UTC)
    capture = db.get(Capture, analysis.capture_id)
    if capture:
        capture.status = CaptureStatus.FAILED
        capture.analysis_status = "failed"
    if job is not None:
        job = db.get(AnalysisJob, job.id) or job
        job.status = JobStatus.FAILED
        job.error_message = message
        job.completed_at = datetime.now(UTC)
    try:
        db.commit()
    except SQLAlchemyError:  # pragma: no cover - defensive
        db.rollback()
        logger.exception("failed to persist FAILED status for analysis %s", analysis.id)


def _persist(
    db: Session,
    analysis: Analysis,
    capture: Capture,
    result: AnalysisResult,
    settings: Settings,
) -> None:
    detection = result.detection
    if detection is not None:
        analysis.protocol_detected = detection.ipsec
        analysis.protocol_confidence = detection.confidence.value
        analysis.ike_detected = any(o.protocol == "ike" for o in detection.observations)
        analysis.ike_confidence = _confidence_for(detection.observations, "ike") or _confidence_for(
            detection.observations, "natt"
        )
        analysis.esp_detected = any(o.protocol == "esp" for o in detection.observations)
        analysis.ah_detected = any(o.protocol == "ah" for o in detection.observations)
        analysis.ipv4_detected = any(o.protocol == "ipv4" for o in detection.observations)
        analysis.ipv6_detected = any(o.protocol == "ipv6" for o in detection.observations)
        analysis.packet_count = detection.packet_count
        analysis.byte_count = detection.byte_count
        analysis.duration = detection.duration
        analysis.protocol = detection.ipsec

        for obs in detection.observations:
            db.add(
                ProtocolObservationModel(
                    analysis_id=analysis.id,
                    protocol=obs.protocol,
                    packet_count=obs.packet_count,
                    byte_count=obs.byte_count,
                    first_seen=_ts_to_dt(obs.first_seen),
                    last_seen=_ts_to_dt(obs.last_seen),
                    confidence=obs.confidence.value,
                    evidence_json=json.dumps(obs.evidence),
                )
            )

    for message in result.ike_messages:
        ike = IkeMessage(
            analysis_id=analysis.id,
            packet_id=message.packet_id,
            timestamp=_ts_to_dt(message.timestamp),
            source_ip=message.source_ip,
            destination_ip=message.destination_ip,
            source_port=message.source_port,
            destination_port=message.destination_port,
            version=message.version,
            exchange_type=message.exchange_type,
            exchange_name=message.exchange_name,
            flags=message.flags,
            message_id=message.message_id,
            length=message.length,
            next_payload=message.next_payload,
            payload_types_json=json.dumps(message.payload_types),
            initiator_spi=message.initiator_spi,
            responder_spi=message.responder_spi,
            direction=message.direction,
        )
        db.add(ike)
        db.flush()
        for proposal in message.proposals:
            db.add(
                IkeProposal(
                    analysis_id=analysis.id,
                    ike_message_id=ike.id,
                    proposal_number=proposal.proposal_number,
                    protocol_id=proposal.protocol_id,
                    protocol_name=proposal.protocol_name,
                    encryption=proposal.encryption,
                    encryption_id=proposal.encryption_id,
                    key_length=proposal.key_length,
                    integrity=proposal.integrity,
                    integrity_id=proposal.integrity_id,
                    prf=proposal.prf,
                    prf_id=proposal.prf_id,
                    dh_group=proposal.dh_group,
                    esn=proposal.esn,
                    status=proposal.status,
                    transform_confidence=proposal.transform_confidence,
                )
            )

    for esp in result.esp_packets:
        db.add(
            EspPacket(
                analysis_id=analysis.id,
                packet_id=esp.packet_id,
                timestamp=_ts_to_dt(esp.timestamp),
                source_ip=esp.source_ip,
                destination_ip=esp.destination_ip,
                spi=esp.spi,
                sequence_number=esp.sequence_number,
                length=esp.length,
                direction=esp.direction,
                encryption_algorithm=esp.encryption_algorithm or "UNKNOWN",
            )
        )

    for ah in result.ah_packets:
        db.add(
            AhPacket(
                analysis_id=analysis.id,
                packet_id=ah.packet_id,
                timestamp=_ts_to_dt(ah.timestamp),
                source_ip=ah.source_ip,
                destination_ip=ah.destination_ip,
                spi=ah.spi,
                sequence_number=ah.sequence_number,
                length=ah.length,
                direction=ah.direction,
                next_header=ah.next_header,
            )
        )

    flow_model_by_key: dict[str, Flow] = {}
    for flow in result.flows:
        model = Flow(
            analysis_id=analysis.id,
            flow_id=flow.flow_key,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            source_port=flow.source_port,
            destination_port=flow.destination_port,
            protocol=flow.protocol,
            transport=flow.transport,
            ip_version=flow.ip_version,
            start_time=_ts_to_dt(flow.start_time),
            end_time=_ts_to_dt(flow.end_time),
            duration=flow.duration,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            upstream_packets=flow.upstream_packets,
            downstream_packets=flow.downstream_packets,
            upstream_bytes=flow.upstream_bytes,
            downstream_bytes=flow.downstream_bytes,
            direction=flow.direction,
            spi=flow.spi,
            ike_packets=flow.ike_packets,
            esp_packets=flow.esp_packets,
            ah_packets=flow.ah_packets,
        )
        db.add(model)
        db.flush()
        flow_model_by_key[flow.flow_key] = model

    for features in result.flow_features:
        target = flow_model_by_key.get(features.flow_key)
        if target is None:
            continue
        db.add(
            FlowFeaturesModel(
                analysis_id=analysis.id,
                flow_id=target.id,
                feature_schema_version=features.feature_schema_version,
                feature_json=json.dumps(features.features),
            )
        )

    capture.packet_count = len(result.packets)
    capture.duration = detection.duration if detection else None
    capture.first_packet_time = _ts_to_dt(detection.first_packet_time) if detection else None
    capture.last_packet_time = _ts_to_dt(detection.last_packet_time) if detection else None
    analysis.flow_count = len(result.flows)
    db.commit()


def _confidence_for(observations: list[ProtocolObservation], protocol: str) -> str | None:
    for obs in observations:
        if obs.protocol == protocol:
            return obs.confidence.value
    return None


def _ts_to_dt(ts: float | None) -> datetime | None:
    if ts is None:
        return None
    from datetime import datetime

    return datetime.fromtimestamp(ts, tz=UTC)
