"""Security finding listing endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.common import DbSession, PageQuery, paginate
from app.core.responses import ok
from app.models import SecurityFinding
from app.schemas.common import ApiResponse, PaginatedData
from app.schemas.finding import SecurityFindingRead

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=ApiResponse[PaginatedData[SecurityFindingRead]])
def list_findings(
    params: PageQuery,
    db: DbSession,
) -> ApiResponse[PaginatedData[SecurityFindingRead]]:
    return ok(paginate(db, SecurityFinding, params, SecurityFindingRead))
