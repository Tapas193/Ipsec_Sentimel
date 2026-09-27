"""Analysis job and analysis endpoints, including packet-analysis
sub-resources (protocol observations, IKE, ESP/AH, flows, features)
and exports.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from datetime import date, datetime
from typing import TypeVar

from fastapi import APIRouter
from fastapi import Response as FastApiResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import DeclarativeBase, Session, selectinload
from sqlalchemy.sql import Select

from app.api.v1.common import DbSession, PageQuery, paginate
from app.core.exceptions import (
    AnalysisNotFoundError,
    BadRequestError,
    FindingNotFoundError,
)
from app.core.responses import ok
from app.models import (
    AhPacket,
    Analysis,
    AnalysisJob,
    EspPacket,
    Flow,
    FlowFeatures,
    IkeMessage,
    ProtocolObservation,
    SecurityFinding,
)
from app.schemas.analysis import AnalysisJobRead, AnalysisRead, AnalysisSummary
from app.schemas.common import ApiResponse, PaginatedData, PaginationMeta
from app.schemas.finding import SecurityFindingRead
from app.schemas.packet import (
    AhPacketRead,
    EspPacketRead,
    FlowFeaturesRead,
    FlowRead,
    IkeMessageRead,
    ProtocolObservationRead,
)
from app.schemas.security import AssessmentResultRead, RuleAssessmentRead
from app.services.analysis_service import get_analysis_by_key, get_job_by_key
from app.services.security_service import assess_analysis

router = APIRouter(tags=["analysis"])


# --- Jobs ---------------------------------------------------------------


@router.get("/analysis-jobs", response_model=ApiResponse[PaginatedData[AnalysisJobRead]])
def list_analysis_jobs(
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[AnalysisJobRead]]:
    return ok(paginate(db, AnalysisJob, params, AnalysisJobRead))


@router.get("/analysis-jobs/{job_key}", response_model=ApiResponse[AnalysisJobRead])
def get_analysis_job(job_key: str, db: DbSession) -> ApiResponse[AnalysisJobRead]:
    job = get_job_by_key(db, job_key)
    if job is None:
        raise AnalysisNotFoundError(
            "Analysis job not found.",
            details={"job_key": job_key},
        )
    return ok(AnalysisJobRead.model_validate(job))


# --- Analyses -----------------------------------------------------------


@router.get("/analyses", response_model=ApiResponse[PaginatedData[AnalysisRead]])
def list_analyses(
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[AnalysisRead]]:
    return ok(paginate(db, Analysis, params, AnalysisRead))


@router.get("/analyses/{analysis_key}", response_model=ApiResponse[AnalysisSummary])
def get_analysis(analysis_key: str, db: DbSession) -> ApiResponse[AnalysisSummary]:
    analysis = _require_analysis(db, analysis_key)
    job = db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.capture_id == analysis.capture_id)
        .order_by(AnalysisJob.created_at.desc())
    )
    obs = db.scalars(
        select(ProtocolObservation)
        .where(ProtocolObservation.analysis_id == analysis.id)
        .order_by(ProtocolObservation.packet_count.desc())
    ).all()
    counts = {
        "ike": db.scalar(
            select(func.count())
            .select_from(IkeMessage)
            .where(IkeMessage.analysis_id == analysis.id)
        )
        or 0,
        "esp": db.scalar(
            select(func.count()).select_from(EspPacket).where(EspPacket.analysis_id == analysis.id)
        )
        or 0,
        "ah": db.scalar(
            select(func.count()).select_from(AhPacket).where(AhPacket.analysis_id == analysis.id)
        )
        or 0,
        "flow": db.scalar(
            select(func.count()).select_from(Flow).where(Flow.analysis_id == analysis.id)
        )
        or 0,
    }
    return ok(
        AnalysisSummary(
            analysis=AnalysisRead.model_validate(analysis),
            job=AnalysisJobRead.model_validate(job) if job else None,
            protocol_observations=[o.protocol for o in obs],
            ike_message_count=counts["ike"],
            esp_packet_count=counts["esp"],
            ah_packet_count=counts["ah"],
            flow_count=counts["flow"],
        )
    )


# --- Sub-resources ------------------------------------------------------


@router.get(
    "/analyses/{analysis_key}/protocol-observations",
    response_model=ApiResponse[PaginatedData[ProtocolObservationRead]],
)
def list_protocol_observations(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[ProtocolObservationRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = select(ProtocolObservation).where(ProtocolObservation.analysis_id == analysis.id)
    return ok(_paginate_query(db, q, params, ProtocolObservationRead))


@router.get(
    "/analyses/{analysis_key}/ike-messages",
    response_model=ApiResponse[PaginatedData[IkeMessageRead]],
)
def list_ike_messages(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[IkeMessageRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = (
        select(IkeMessage)
        .where(IkeMessage.analysis_id == analysis.id)
        .options(selectinload(IkeMessage.proposals))
    )
    return ok(_paginate_query(db, q, params, IkeMessageRead))


@router.get(
    "/analyses/{analysis_key}/esp-packets",
    response_model=ApiResponse[PaginatedData[EspPacketRead]],
)
def list_esp_packets(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[EspPacketRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = select(EspPacket).where(EspPacket.analysis_id == analysis.id)
    return ok(_paginate_query(db, q, params, EspPacketRead))


@router.get(
    "/analyses/{analysis_key}/ah-packets",
    response_model=ApiResponse[PaginatedData[AhPacketRead]],
)
def list_ah_packets(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[AhPacketRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = select(AhPacket).where(AhPacket.analysis_id == analysis.id)
    return ok(_paginate_query(db, q, params, AhPacketRead))


@router.get("/analyses/{analysis_key}/flows", response_model=ApiResponse[PaginatedData[FlowRead]])
def list_flows(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[FlowRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = select(Flow).where(Flow.analysis_id == analysis.id)
    return ok(_paginate_query(db, q, params, FlowRead))


@router.get(
    "/analyses/{analysis_key}/features",
    response_model=ApiResponse[PaginatedData[FlowFeaturesRead]],
)
def list_flow_features(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[FlowFeaturesRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = (
        select(FlowFeatures)
        .where(FlowFeatures.analysis_id == analysis.id)
        .options(selectinload(FlowFeatures.flow))
    )
    return ok(_paginate_query(db, q, params, FlowFeaturesRead))


# --- Findings & assessment ------------------------------------------------


@router.get(
    "/analyses/{analysis_key}/findings",
    response_model=ApiResponse[PaginatedData[SecurityFindingRead]],
)
def list_analysis_findings(
    analysis_key: str,
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[SecurityFindingRead]]:
    analysis = _require_analysis(db, analysis_key)
    q = select(SecurityFinding).where(SecurityFinding.analysis_id == analysis.id)
    return ok(_paginate_findings(db, q, params))


@router.get(
    "/analyses/{analysis_key}/findings/{finding_key}",
    response_model=ApiResponse[SecurityFindingRead],
)
def get_analysis_finding(
    analysis_key: str,
    finding_key: str,
    db: DbSession,
) -> ApiResponse[SecurityFindingRead]:
    analysis = _require_analysis(db, analysis_key)
    if finding_key.startswith("SEC-"):
        finding = db.scalar(
            select(SecurityFinding).where(
                SecurityFinding.analysis_id == analysis.id,
                SecurityFinding.finding_id == finding_key,
            )
        )
    else:
        finding = db.scalar(
            select(SecurityFinding).where(
                SecurityFinding.analysis_id == analysis.id,
                SecurityFinding.id == finding_key,
            )
        )
    if finding is None:
        raise FindingNotFoundError(
            "Security finding not found.",
            details={"analysis_key": analysis_key, "finding_key": finding_key},
        )
    return ok(SecurityFindingRead.model_validate(finding))


@router.post(
    "/analyses/{analysis_key}/assess",
    response_model=ApiResponse[AssessmentResultRead],
)
def assess_security(
    analysis_key: str,
    db: DbSession,
) -> ApiResponse[AssessmentResultRead]:
    analysis = _require_analysis(db, analysis_key)
    result = assess_analysis(db, analysis)
    return ok(
        AssessmentResultRead(
            analysis_id=result["analysis_id"],
            rule_version=result["rule_version"],
            rules_run=result["rules_run"],
            created=result["created"],
            skipped=result["skipped"],
            total_findings=result["total_findings"],
            duration_ms=result["duration_ms"],
            rules=[
                RuleAssessmentRead(rule_id=r["rule_id"], created=r["created"], skipped=r["skipped"])
                for r in result["rules"]
            ],
            completed_at=result["completed_at"],
        )
    )


# --- Exports ------------------------------------------------------------


@router.get("/analyses/{analysis_key}/export/{resource}")
def export_analysis(
    analysis_key: str,
    resource: str,
    db: DbSession,
) -> FastApiResponse:
    analysis = _require_analysis(db, analysis_key)
    if resource == "flows":
        rows = _export_rows(
            list(db.scalars(select(Flow).where(Flow.analysis_id == analysis.id)).all())
        )
        filename = f"{analysis.analysis_id or analysis.id}-flows.csv"
    elif resource == "ike":
        rows = _export_rows(
            list(db.scalars(select(IkeMessage).where(IkeMessage.analysis_id == analysis.id)).all())
        )
        filename = f"{analysis.analysis_id or analysis.id}-ike.csv"
    elif resource == "esp":
        rows = _export_rows(
            list(db.scalars(select(EspPacket).where(EspPacket.analysis_id == analysis.id)).all())
        )
        filename = f"{analysis.analysis_id or analysis.id}-esp.csv"
    elif resource == "features":
        payload = _export_features_json(db, analysis)
        filename = f"{analysis.analysis_id or analysis.id}-features.json"
        disposition = f'attachment; filename="{filename}"'
        return FastApiResponse(
            payload,
            media_type="application/json",
            headers={"Content-Disposition": disposition},
        )
    else:
        raise BadRequestError(
            "Unknown export resource.",
            details={"resource": resource, "allowed": ["flows", "ike", "esp", "features"]},
        )

    csv_payload = _to_csv(rows)
    return FastApiResponse(
        csv_payload,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# --- Helpers ------------------------------------------------------------


def _require_analysis(db: Session, analysis_key: str) -> Analysis:
    analysis = get_analysis_by_key(db, analysis_key)
    if analysis is None:
        raise AnalysisNotFoundError(
            "Analysis not found.",
            details={"analysis_key": analysis_key},
        )
    return analysis


TSchemaT = TypeVar("TSchemaT", bound=BaseModel)
TModelT = TypeVar("TModelT", bound=DeclarativeBase)


def _paginate_findings(
    db: Session,
    query: Select[tuple[SecurityFinding]],
    params: PageQuery,
) -> PaginatedData[SecurityFindingRead]:
    """Paginate security findings newest-first (by created_at, then by human id)."""
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    total_pages = (total + params.page_size - 1) // params.page_size or 1
    rows = db.scalars(
        query.order_by(SecurityFinding.created_at.desc())
        .offset((params.page - 1) * params.page_size)
        .limit(params.page_size)
    ).all()
    return PaginatedData[SecurityFindingRead](
        items=[SecurityFindingRead.model_validate(row) for row in rows],
        pagination=PaginationMeta(
            page=params.page,
            page_size=params.page_size,
            total=total,
            total_pages=total_pages,
        ),
    )


def _paginate_query(
    db: Session,
    query: Select[tuple[TModelT]],
    params: PageQuery,
    schema: type[TSchemaT],
) -> PaginatedData[TSchemaT]:
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    total_pages = (total + params.page_size - 1) // params.page_size or 1
    rows = db.scalars(
        query.order_by("created_at")
        .offset((params.page - 1) * params.page_size)
        .limit(params.page_size)
    ).all()
    return PaginatedData[TSchemaT](
        items=[schema.model_validate(row) for row in rows],
        pagination=PaginationMeta(
            page=params.page,
            page_size=params.page_size,
            total=total,
            total_pages=total_pages,
        ),
    )


TModel = TypeVar("TModel", bound=DeclarativeBase)


def _export_rows(rows: Sequence[TModel]) -> list[dict[str, object]]:
    export: list[dict[str, object]] = []
    for row in rows:
        data: dict[str, object] = dict(row.__dict__)
        data.pop("_sa_instance_state", None)
        export.append(data)
    return export


def _to_csv(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    fieldnames: list[str] = [str(k) for k in rows[0].keys()]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _csv_value(v) for k, v in row.items()})
    return buffer.getvalue()


def _csv_value(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _export_features_json(db: Session, analysis: Analysis) -> str:
    features = db.scalars(select(FlowFeatures).where(FlowFeatures.analysis_id == analysis.id)).all()
    # Report the schema version that was actually stamped on the persisted
    # features rather than a hardcoded literal, so the export stays truthful if
    # FEATURE_SCHEMA_VERSION is ever bumped and old analyses are re-exported.
    schema_versions = sorted({f.feature_schema_version for f in features})
    payload = {
        "analysis_id": analysis.analysis_id,
        "analyzer_version": analysis.analyzer_version,
        "parser_version": analysis.parser_version,
        "feature_schema_version": schema_versions[0] if len(schema_versions) == 1 else None,
        "feature_schema_versions": schema_versions,
        "features": [
            {
                "flow_key": f.flow.flow_id if f.flow else None,
                "feature_schema_version": f.feature_schema_version,
                "features": f.features,
            }
            for f in features
        ],
    }
    return json.dumps(payload, indent=2)
