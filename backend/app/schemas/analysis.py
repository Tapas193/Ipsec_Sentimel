"""Analysis, analysis-job and packet-analysis schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AnalysisJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str | None
    capture_id: str
    status: str
    progress: float
    current_stage: str | None
    stage_message: str | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str | None
    capture_id: str
    status: str
    protocol: str | None
    protocol_detected: str | None
    protocol_confidence: str | None
    ike_detected: bool | None
    ike_confidence: str | None
    esp_detected: bool | None
    ah_detected: bool | None
    ipv4_detected: bool | None
    ipv6_detected: bool | None
    ike_version: str | None
    vpn_mode: str | None
    security_score: int | None
    risk_level: str | None
    overall_confidence: float | None
    packet_count: int | None
    byte_count: int | None
    flow_count: int | None
    duration: float | None
    error_message: str | None
    analyzer_version: str | None
    parser_version: str | None
    rule_version: str | None
    model_version: str | None
    dataset_version: str | None
    started_at: datetime | None
    completed_at: datetime | None


class AnalysisSummary(BaseModel):
    """Compact summary for an analysis, used on the analyzer page."""

    analysis: AnalysisRead
    job: AnalysisJobRead | None = None
    protocol_observations: list[str] = Field(default_factory=list)
    ike_message_count: int = 0
    esp_packet_count: int = 0
    ah_packet_count: int = 0
    flow_count: int = 0
