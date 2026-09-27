"""System information endpoint (non-sensitive)."""

from __future__ import annotations

import platform

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings
from app.core.responses import ok
from app.schemas.common import ApiResponse
from app.schemas.health import SystemComponent, SystemInfoData
from app.schemas.tools import ToolsData
from app.services.tooling import build_tools_data

router = APIRouter(tags=["system"])


@router.get("/system/info", response_model=ApiResponse[SystemInfoData])
def system_info() -> ApiResponse[SystemInfoData]:
    settings = get_settings()
    return ok(
        SystemInfoData(
            application=settings.APP_NAME,
            version=__version__,
            environment=settings.ENVIRONMENT,
            python_version=platform.python_version(),
            components=[
                SystemComponent(
                    name="api",
                    status="available",
                    detail=f"Python {platform.python_version()} on {platform.system()}",
                ),
                SystemComponent(
                    name="database",
                    status="configured",
                    detail=_db_label(settings.DATABASE_URL),
                ),
            ],
        )
    )


@router.get("/system/tools", response_model=ApiResponse[ToolsData])
def system_tools() -> ApiResponse[ToolsData]:
    return ok(build_tools_data())


def _db_label(url: str) -> str:
    if url.startswith("sqlite"):
        return "SQLite (local development)"
    return "PostgreSQL"
