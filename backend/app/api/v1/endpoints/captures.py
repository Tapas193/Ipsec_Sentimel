"""Capture upload, retrieval, analysis trigger and deletion endpoints."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, File, UploadFile
from sqlalchemy.orm import Session

from app.api.v1.common import DbSession, PageQuery, paginate
from app.core.config import get_settings
from app.core.exceptions import CaptureNotFoundError, ConflictError
from app.core.responses import ok
from app.db.session import SessionLocal as SessionLocal
from app.models import Analysis, Capture, CaptureStatus
from app.schemas.capture import CaptureRead
from app.schemas.common import ApiResponse, PaginatedData
from app.services.analysis_service import create_analysis, run_analysis
from app.services.capture_store import (
    delete_capture_file,
    get_capture_by_key,
    store_capture_file,
    validate_upload_file,
)

router = APIRouter(prefix="/captures", tags=["captures"])


@router.get("", response_model=ApiResponse[PaginatedData[CaptureRead]])
def list_captures(
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[CaptureRead]]:
    return ok(paginate(db, Capture, params, CaptureRead))


@router.post("", response_model=ApiResponse[CaptureRead])
async def upload_capture(
    db: DbSession,
    file: UploadFile = File(...),  # noqa: B008 (FastAPI dependency)
) -> ApiResponse[CaptureRead]:
    settings = get_settings()
    content = await file.read()
    validated = validate_upload_file(file.filename or "capture.pcap", content, settings)
    capture = store_capture_file(db, content, validated, settings)
    return ok(CaptureRead.model_validate(capture))


@router.get("/{capture_key}", response_model=ApiResponse[CaptureRead])
def get_capture(capture_key: str, db: DbSession) -> ApiResponse[CaptureRead]:
    capture = _require_capture(db, capture_key)
    return ok(CaptureRead.model_validate(capture))


@router.delete("/{capture_key}", response_model=ApiResponse[dict[str, str]])
def delete_capture(capture_key: str, db: DbSession) -> ApiResponse[dict[str, str]]:
    capture = _require_capture(db, capture_key)
    delete_capture_file(db, capture)
    return ok({"deleted": capture_key, "id": capture.id})


@router.post("/{capture_key}/analyze", response_model=ApiResponse[dict[str, str]])
def analyze_capture(
    capture_key: str,
    db: DbSession,
    background: BackgroundTasks,  # noqa: B008 (FastAPI dependency)
) -> ApiResponse[dict[str, str]]:
    capture = _require_capture(db, capture_key)
    if capture.status == CaptureStatus.ANALYZING:
        raise ConflictError("Analysis already in progress for this capture.")

    analysis = create_analysis(db, capture)
    capture.status = CaptureStatus.ANALYZING
    capture.analysis_status = "running"
    db.commit()

    background.add_task(_run_analysis_background, analysis.id)
    return ok(
        {"analysis_id": analysis.id, "analysis_reference": analysis.analysis_id},
        meta={"status": "started"},
    )


def _run_analysis_background(analysis_uuid: str) -> None:
    session = SessionLocal()
    try:
        analysis = session.get(Analysis, analysis_uuid)
        if analysis is not None:
            run_analysis(session, analysis)
    finally:
        session.close()


def _require_capture(db: Session, capture_key: str) -> Capture:
    capture = get_capture_by_key(db, capture_key)
    if capture is None:
        raise CaptureNotFoundError(
            "Capture not found.",
            details={"capture_key": capture_key},
        )
    return capture
