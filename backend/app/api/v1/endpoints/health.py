"""Health endpoint — requires database connectivity."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app import __version__
from app.api.v1.common import DbSession
from app.core.responses import ok
from app.schemas.common import ApiResponse
from app.schemas.health import HealthData

router = APIRouter(tags=["system"])


@router.get("/health", response_model=ApiResponse[HealthData])
def health_check(db: DbSession) -> ApiResponse[HealthData]:
    """Report service health, verifying database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:  # pragma: no cover - exercised via db failure path
        db_status = "error"

    return ok(
        HealthData(
            status="healthy" if db_status == "connected" else "degraded",
            version=__version__,
            database=db_status,
        )
    )
