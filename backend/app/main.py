"""IPsec Sentinel — FastAPI application entrypoint.

Exposes the v1 API under ``/api/v1``, wires CORS, exception handlers, and
serves an auto-generated OpenAPI schema under ``/docs`` and ``/redoc``.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework. "
        "Phase 1 foundation: infrastructure, database models, and health/lifecycle endpoints."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

register_exception_handlers(app)

app.include_router(api_router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"name": settings.APP_NAME, "version": settings.APP_VERSION}
