"""Dashboard statistics endpoint.

Counts are computed from the live database. No forecasts, estimations, or
placeholder values are produced.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import func, or_, select

from app.api.v1.common import DbSession
from app.core.responses import ok
from app.models import (
    Analysis,
    AnalysisJob,
    Capture,
    JobStatus,
    Report,
    SecurityFinding,
)
from app.schemas.common import ApiResponse
from app.schemas.stats import DashboardStats

router = APIRouter(tags=["stats"])


@router.get("/stats/dashboard", response_model=ApiResponse[DashboardStats])
def dashboard_stats(db: DbSession) -> ApiResponse[DashboardStats]:
    def count(model: type[Any]) -> int:
        return db.scalar(select(func.count()).select_from(model)) or 0

    pending_jobs = (
        db.scalar(
            select(func.count())
            .select_from(AnalysisJob)
            .where(
                or_(
                    AnalysisJob.status == JobStatus.QUEUED,
                    AnalysisJob.status == JobStatus.RUNNING,
                )
            )
        )
        or 0
    )

    return ok(
        DashboardStats(
            captures=count(Capture),
            analysis_jobs=count(AnalysisJob),
            pending_jobs=pending_jobs,
            analyses=count(Analysis),
            security_findings=count(SecurityFinding),
            reports=count(Report),
        )
    )
