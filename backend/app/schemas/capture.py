"""Capture schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CaptureRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_reference: str
    capture_id: str | None
    filename: str
    original_filename: str
    stored_filename: str | None
    file_size: int
    sha256: str
    capture_format: str | None
    packet_count: int | None
    duration: float | None
    first_packet_time: datetime | None
    last_packet_time: datetime | None
    status: str
    analysis_status: str | None
    uploaded_at: datetime


class CaptureAnalyzeRequest(BaseModel):
    """Request body for triggering analysis on an existing capture."""

    retry: bool = False
