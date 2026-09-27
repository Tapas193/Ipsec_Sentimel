"""Report listing endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.common import DbSession, PageQuery, paginate
from app.core.responses import ok
from app.models import Report
from app.schemas.common import ApiResponse, PaginatedData
from app.schemas.report import ReportRead

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=ApiResponse[PaginatedData[ReportRead]])
def list_reports(
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[ReportRead]]:
    return ok(paginate(db, Report, params, ReportRead))
