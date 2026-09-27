"""Dashboard statistics schema.

Values are computed directly from the database. With an empty database every
counter is zero; nothing is estimated or fabricated.
"""

from __future__ import annotations

from pydantic import BaseModel


class DashboardStats(BaseModel):
    captures: int
    analysis_jobs: int
    pending_jobs: int
    analyses: int
    security_findings: int
    reports: int
