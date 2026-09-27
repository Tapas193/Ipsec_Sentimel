"""Report schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    report_type: str
    status: str
    storage_path: str | None
    generated_at: datetime | None
    created_at: datetime
