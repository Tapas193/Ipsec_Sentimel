"""Version 1 API router — aggregates all endpoint modules."""

from fastapi import APIRouter

from app.api.v1.endpoints import analyses, captures, findings, health, reports, stats, system

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(system.router)
api_router.include_router(stats.router)
api_router.include_router(captures.router)
api_router.include_router(analyses.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
