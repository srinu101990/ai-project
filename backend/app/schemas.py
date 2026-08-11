"""Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ThreatEventOut(BaseModel):
    id: int
    source: str
    source_ip: str
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    raw_payload: str
    threat_type: str
    severity: str
    confidence: float
    indicators: Optional[str] = None
    status: str
    is_simulated: bool
    created_at: datetime

    class Config:
        from_attributes = True


class IngestRequest(BaseModel):
    source: str = Field(..., min_length=2, max_length=120)
    source_ip: str = Field(..., min_length=3, max_length=64)
    destination_ip: Optional[str] = None
    protocol: Optional[str] = "UNKNOWN"
    raw_payload: str = Field(..., min_length=5)


class ClassifyRequest(BaseModel):
    text: str = Field(..., min_length=3)


class ClassifyResponse(BaseModel):
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]


class CollectRequest(BaseModel):
    batch_size: int = Field(default=8, ge=1, le=50)
    mode: Optional[str] = Field(
        default=None,
        description="Collection mode override: 'network' (live LAN scan) or 'simulated'.",
        pattern="^(network|simulated)$",
    )


class CollectResponse(BaseModel):
    job_id: int
    status: str
    sources_scanned: int
    events_collected: int
    message: str
    mode: str = "network"
    subnet: Optional[str] = None
    local_ip: Optional[str] = None
    hosts_alive: Optional[int] = None
    open_ports: Optional[int] = None
    events: list[ThreatEventOut]


class StatsResponse(BaseModel):
    total_threats: int
    open_threats: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_source: dict[str, int]
    timeline: list[dict]
    recent_confidence_avg: float


class StatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|investigating|contained|resolved)$")


class ReportSummary(BaseModel):
    generated_at: datetime
    total_threats: int
    open_threats: int
    critical_count: int
    high_count: int
    top_threat_type: str
    recommendations: list[str]
    by_type: dict[str, int]
    by_severity: dict[str, int]


class MonitorStatus(BaseModel):
    enabled: bool
    scanning: bool
    interval_seconds: int
    batch_size: int
    cycles_completed: int
    last_started_at: Optional[datetime] = None
    last_finished_at: Optional[datetime] = None
    last_events_collected: int = 0
    last_message: Optional[str] = None
    last_error: Optional[str] = None
    last_mode: Optional[str] = None
    last_subnet: Optional[str] = None
    last_local_ip: Optional[str] = None
    collection_mode: str


class MonitorControlRequest(BaseModel):
    interval_seconds: Optional[int] = Field(default=None, ge=15, le=3600)


class DemoFeedStatus(BaseModel):
    enabled: bool
    injecting: bool
    interval_seconds: int
    cycles_completed: int
    last_started_at: Optional[datetime] = None
    last_finished_at: Optional[datetime] = None
    last_events_collected: int = 0
    last_message: Optional[str] = None
    last_error: Optional[str] = None
    last_types: list[str] = []
    supported_types: list[str] = []
    mode: Optional[str] = None
    current_type: Optional[str] = None
    next_type: Optional[str] = None
    events: Optional[list[dict]] = None


class DemoFeedControlRequest(BaseModel):
    interval_seconds: Optional[int] = Field(default=None, ge=10, le=600)
