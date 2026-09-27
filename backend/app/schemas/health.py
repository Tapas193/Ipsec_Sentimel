"""Health and system info schemas."""

from __future__ import annotations

from pydantic import BaseModel


class HealthData(BaseModel):
    status: str
    version: str
    database: str


class SystemComponent(BaseModel):
    name: str
    status: str
    detail: str | None = None


class SystemInfoData(BaseModel):
    application: str
    version: str
    environment: str
    python_version: str
    components: list[SystemComponent]
