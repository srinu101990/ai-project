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
    batch_size: int = Field(default=1, ge=1, le=50)
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
    live_sources: Optional[list[str]] = None
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


class ReportLatestEvent(BaseModel):
    id: int
    created_at: Optional[datetime] = None
    threat_type: str
    severity: str
    source: str
    source_ip: str
    status: str
    confidence: float = 0.0


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
    by_source: dict[str, int] = Field(default_factory=dict)
    by_device: dict[str, int] = Field(default_factory=dict)
    latest_events: list[ReportLatestEvent] = Field(default_factory=list)
    filter_label: str = "Total / All Reports"
    match_count: int = 0
    empty_message: Optional[str] = None


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


class LiveSourceOut(BaseModel):
    id: str
    name: str
    channel: str
    description: str
    online: bool
    sweeping: bool = False
    observed: int = 0
    last_findings: int = 0
    events_stored: int = 0
    last_threat_type: Optional[str] = None
    last_at: Optional[datetime] = None
    message: Optional[str] = None


class MultiSourceStatus(BaseModel):
    live_source_count: int
    source_count: int
    cycles_completed: int
    sweeping: bool = False
    last_cycle_at: Optional[datetime] = None
    last_message: Optional[str] = None
    sources: list[LiveSourceOut]


class ProjectionBurstResponse(BaseModel):
    status: str
    mode: str
    subnet: Optional[str] = None
    local_ip: Optional[str] = None
    live_events: int = 0
    burst_events: int = 0
    events_collected: int = 0
    sources_scanned: int = 0
    live_sources: list[str] = []
    message: str
    events: list[ThreatEventOut]


class AgentFindingIn(BaseModel):
    protocol: Optional[str] = "AGENT"
    raw_payload: str = Field(..., min_length=5)
    indicators: Optional[list[str]] = None


class AgentHeartbeatRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=80)
    source_ip: str = Field(..., min_length=3, max_length=64)
    os_name: Optional[str] = "unknown"
    username: Optional[str] = "unknown"
    findings: list[AgentFindingIn] = Field(default_factory=list)


class RemoteAgentOut(BaseModel):
    hostname: str
    source_ip: str
    os_name: Optional[str] = None
    username: Optional[str] = None
    online: bool
    reports: int = 0
    last_events: int = 0
    last_threat_type: Optional[str] = None
    last_seen: Optional[datetime] = None
    first_seen: Optional[datetime] = None


class RemoteAgentStatus(BaseModel):
    connected: int
    total_seen: int
    agents: list[RemoteAgentOut]
    join_command: Optional[str] = None
    inject_command: Optional[str] = None
    inject_all_command: Optional[str] = None
    agent_download: str = "/agent/sentinel_agent.py"
    agent_launcher: str = "/agent/start-agent.bat"
    lan_ip: Optional[str] = None
    lan_url: Optional[str] = None


class AgentHeartbeatResponse(BaseModel):
    status: str
    hostname: str
    source_ip: str
    events_collected: int
    message: str
    events: list[ThreatEventOut]


class MailCheckRequest(BaseModel):
    sender: Optional[str] = ""
    subject: Optional[str] = ""
    body: str = Field(..., min_length=3)


class MailCheckResponse(BaseModel):
    phishing: bool
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]
    verdict: str
    sender: Optional[str] = ""
    subject: Optional[str] = ""
    event: Optional[ThreatEventOut] = None


class MailDropScanResponse(BaseModel):
    scanned: int = 0
    new_events: int = 0
    skipped: int = 0
    drop_dir: str
    message: str
    last: Optional[MailCheckResponse] = None


class MailImapConnectRequest(BaseModel):
    host: str = Field(..., min_length=3)
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=3)
    mailbox: Optional[str] = "INBOX"
    interval_seconds: Optional[int] = Field(default=20, ge=8, le=600)


class MailImapStatus(BaseModel):
    enabled: bool
    polling: bool = False
    host: str = ""
    username: str = ""
    mailbox: str = "INBOX"
    interval_seconds: int = 20
    cycles_completed: int = 0
    last_message: Optional[str] = None
    last_error: Optional[str] = None
    last_at: Optional[datetime] = None
    last_events: int = 0
    last_phishing: int = 0
    total_phishing: int = 0
    drop_dir: str
    new_events: Optional[int] = None
    message: Optional[str] = None
    channel: str = "off"
    outlook_installed: bool = False


class FileCheckResponse(BaseModel):
    malicious: bool
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]
    verdict: str
    path: str
    filename: str
    event: Optional[ThreatEventOut] = None


class FileWatchStatus(BaseModel):
    enabled: bool
    scanning: bool = False
    interval_seconds: int = 8
    cycles_completed: int = 0
    folders: list[str] = []
    usb_drives: list[str] = []
    usb_message: Optional[str] = None
    last_message: Optional[str] = None
    last_error: Optional[str] = None
    last_at: Optional[datetime] = None
    last_events: int = 0
    last_malicious: int = 0
    total_malicious: int = 0
    drop_dir: str
    new_events: Optional[int] = None
    message: Optional[str] = None


class FileScanResponse(BaseModel):
    scanned: int = 0
    new_events: int = 0
    skipped: int = 0
    folders: list[str] = []
    drop_dir: str
    message: str
    last: Optional[FileCheckResponse] = None


class FileTestSampleResponse(BaseModel):
    created: list[str]
    new_events: int = 0
    message: str
    last: Optional[FileCheckResponse] = None


class SetupStepOut(BaseModel):
    id: str
    title: str
    done: bool
    optional: bool = False
    detail: str = ""
    tab: Optional[str] = None


class SetupStatus(BaseModel):
    ready: bool
    completed: int
    required: int
    steps: list[SetupStepOut]


class MalwareFamilyStatus(BaseModel):
    id: str
    title: str
    channel: str
    watching: bool = True
    hits: int = 0
    last_message: Optional[str] = None


class EndpointGuardStatus(BaseModel):
    enabled: bool
    scanning: bool = False
    interval_seconds: int = 12
    cycles_completed: int = 0
    last_message: Optional[str] = None
    last_error: Optional[str] = None
    last_at: Optional[datetime] = None
    last_events: int = 0
    total_hits: int = 0
    families: list[MalwareFamilyStatus] = []
    new_events: Optional[int] = None
    message: Optional[str] = None
