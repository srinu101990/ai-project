"""FastAPI application for the AI Cyber Threat Intelligence Dashboard.

Fully offline-capable: local SQLite, local AI model, local fonts in the UI,
bundled Swagger assets, and optional serving of the built React frontend.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from .classifier import classifier
from .collector import collect_from_network, ingest_event, projection_burst
from .config import BIND_HOST, BIND_PORT, COLLECTION_MODE, SCAN_SUBNET
from .database import Base, engine, get_db
from .demo_feed import autostart_demo_feed, demo_feed
from .endpoint_guard import autostart_endpoint_watch, endpoint_monitor
from .file_guard import (
    autostart_file_watch,
    check_and_store as check_file_and_store,
    create_test_samples,
    file_monitor,
    mark_seen,
    scan_folders,
)
from .mail_guard import autostart_mail_watch, check_and_store, mail_monitor, parse_eml_bytes, scan_drop_folder
from .models import ThreatEvent
from .monitor import autostart_monitor, monitor
from .multi_source import source_hub
from .network_scanner import resolve_scan_network
from .remote_agents import agent_registry, ingest_agent_heartbeat
from .schemas import (
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    ClassifyRequest,
    ClassifyResponse,
    CollectRequest,
    CollectResponse,
    DemoFeedControlRequest,
    DemoFeedStatus,
    EndpointGuardStatus,
    FileCheckResponse,
    FileScanResponse,
    FileTestSampleResponse,
    FileWatchStatus,
    IngestRequest,
    MailCheckRequest,
    MailCheckResponse,
    MailDropScanResponse,
    MailImapConnectRequest,
    MailImapStatus,
    MonitorControlRequest,
    MonitorStatus,
    MultiSourceStatus,
    ProjectionBurstResponse,
    RemoteAgentStatus,
    ReportSummary,
    SetupStatus,
    SetupStepOut,
    StatsResponse,
    StatusUpdate,
    ThreatEventOut,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
STATIC_DIR = BACKEND_ROOT / "static"
SWAGGER_DIR = STATIC_DIR / "swagger"
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


def seed_if_empty(db: Session) -> None:
    count = db.query(ThreatEvent).count()
    if count == 0:
        collect_from_network(db, batch_size=14)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    # Ensure classifier model is warm (trained/loaded locally).
    _ = classifier.classify("warmup benign traffic sample")
    from .database import SessionLocal

    db = SessionLocal()
    try:
        seed_if_empty(db)
    finally:
        db.close()
    # Start continuous LAN monitoring in the background.
    autostart_monitor()
    autostart_demo_feed()
    autostart_mail_watch()
    autostart_file_watch()
    autostart_endpoint_watch()
    try:
        yield
    finally:
        demo_feed.stop()
        mail_monitor.stop()
        file_monitor.stop()
        endpoint_monitor.stop()
        monitor.stop()


app = FastAPI(
    title="AI Cyber Threat Intelligence Dashboard",
    description=(
        "Collects cyber threat intelligence from multiple live sources at the same time "
        "(Network IDS, Endpoint, Firewall, DNS, Email, Auth), watches this laptop inbox, "
        "folders, processes, persistence, and ports, classifies phishing/malware/"
        "ransomware with AI, visualizes real-time stats, "
        "and generates decision-support reports. Runs fully offline after dependencies are installed."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if SWAGGER_DIR.exists():
    app.mount("/static/swagger", StaticFiles(directory=str(SWAGGER_DIR)), name="swagger")


@app.get("/docs", include_in_schema=False)
def offline_swagger_ui():
    """Swagger UI served from local static files (no CDN)."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} — Docs (Offline)",
        swagger_js_url="/static/swagger/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger/swagger-ui.css",
        swagger_favicon_url="/favicon.svg",
    )


@app.get("/api/health")
def health():
    subnet = SCAN_SUBNET or None
    local_ip = None
    try:
        local_ip, network = resolve_scan_network()
        subnet = str(network)
    except Exception:
        pass
    mon = monitor.status()
    demo = demo_feed.status()
    hub = source_hub.status()
    return {
        "status": "ok",
        "service": "cyber-threat-intel",
        "collection_mode": COLLECTION_MODE,
        "network_detection": COLLECTION_MODE == "network",
        "continuous_monitoring": mon.get("enabled", False),
        "monitor_scanning": mon.get("scanning", False),
        "monitor_interval_seconds": mon.get("interval_seconds"),
        "monitor_last_message": mon.get("last_message"),
        "demo_feed_enabled": demo.get("enabled", False),
        "demo_feed_interval_seconds": demo.get("interval_seconds"),
        "live_source_count": hub.get("live_source_count", 0),
        "connected_agents": agent_registry.status().get("connected", 0),
        "offline_capable": True,
        "bind_host": BIND_HOST,
        "bind_port": BIND_PORT,
        "local_ip": local_ip,
        "scan_subnet": subnet,
        "frontend_bundled": FRONTEND_DIST.exists(),
    }


@app.get("/api/monitor", response_model=MonitorStatus)
def monitor_status():
    return monitor.status()


@app.post("/api/monitor/start", response_model=MonitorStatus)
def monitor_start(payload: MonitorControlRequest = MonitorControlRequest()):
    return monitor.start(interval_seconds=payload.interval_seconds)


@app.post("/api/monitor/stop", response_model=MonitorStatus)
def monitor_stop():
    return monitor.stop()


@app.get("/api/demo-feed", response_model=DemoFeedStatus)
def demo_feed_status():
    return demo_feed.status()


@app.post("/api/demo-feed/inject-all", response_model=DemoFeedStatus)
def demo_feed_inject_all():
    """One-click inject of all supported threat types for Demo Lab."""
    return demo_feed.inject_once()


@app.post("/api/demo-feed/start", response_model=DemoFeedStatus)
def demo_feed_start(payload: DemoFeedControlRequest = DemoFeedControlRequest()):
    return demo_feed.start(interval_seconds=payload.interval_seconds or 30)


@app.post("/api/demo-feed/stop", response_model=DemoFeedStatus)
def demo_feed_stop():
    return demo_feed.stop()


def _source_counts(db: Session) -> dict[str, int]:
    rows = (
        db.query(ThreatEvent.source, func.count(ThreatEvent.id))
        .group_by(ThreatEvent.source)
        .all()
    )
    return {name: int(count) for name, count in rows}


@app.get("/api/sources", response_model=MultiSourceStatus)
def list_live_sources(db: Session = Depends(get_db)):
    """Status of the six collectors that run in parallel on every sweep."""
    return source_hub.status(_source_counts(db))


@app.post("/api/sources/sweep", response_model=CollectResponse)
def sweep_live_sources(db: Session = Depends(get_db)):
    """Run Network IDS, Endpoint, Firewall, DNS, Email, and Auth at the same time."""
    return collect_from_network(db, batch_size=18, mode="network")


@app.post("/api/sources/burst", response_model=ProjectionBurstResponse)
def projection_multi_source_burst(db: Session = Depends(get_db)):
    """Projector demo: live sweep plus one classified event from every source at once."""
    return projection_burst(db)


def _join_command() -> str:
    local_ip = "127.0.0.1"
    try:
        local_ip, _network = resolve_scan_network()
    except Exception:
        pass
    return f"python sentinel_agent.py --server http://{local_ip}:{BIND_PORT}"


@app.get("/api/agents", response_model=RemoteAgentStatus)
def list_remote_agents():
    """PCs on the LAN that are running the remote agent."""
    payload = agent_registry.status()
    payload["join_command"] = _join_command()
    payload["agent_download"] = "/agent/sentinel_agent.py"
    return payload


@app.post("/api/agents/heartbeat", response_model=AgentHeartbeatResponse)
def remote_agent_heartbeat(
    payload: AgentHeartbeatRequest, db: Session = Depends(get_db)
):
    """Receive hostname/IP/process/port findings from another PC."""
    result = ingest_agent_heartbeat(
        db,
        hostname=payload.hostname,
        source_ip=payload.source_ip,
        os_name=payload.os_name or "unknown",
        username=payload.username or "unknown",
        findings=[item.model_dump() for item in payload.findings],
    )
    return result


@app.get("/agent/sentinel_agent.py", include_in_schema=False)
def download_remote_agent():
    path = PROJECT_ROOT / "agent" / "sentinel_agent.py"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Agent script not found")
    return FileResponse(
        path,
        media_type="text/x-python",
        filename="sentinel_agent.py",
    )


@app.post("/api/mail/check", response_model=MailCheckResponse)
def mail_check(payload: MailCheckRequest, db: Session = Depends(get_db)):
    """Classify a pasted laptop email as phishing or safe."""
    return check_and_store(
        db,
        sender=payload.sender or "",
        subject=payload.subject or "",
        body=payload.body,
        origin="paste",
    )


@app.post("/api/mail/upload-eml", response_model=MailCheckResponse)
async def mail_upload_eml(
    file: UploadFile = File(...), db: Session = Depends(get_db)
):
    """Classify a saved .eml email from Outlook/Gmail."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")
    name = (file.filename or "message.eml").lower()
    if name.endswith(".eml"):
        sender, subject, body = parse_eml_bytes(raw)
    else:
        sender, subject, body = "", file.filename or "upload.txt", raw.decode(errors="replace")
    if not body.strip():
        body = subject or "empty email body"
    return check_and_store(
        db,
        sender=sender,
        subject=subject,
        body=body,
        origin=f"upload:{file.filename}",
    )


@app.post("/api/mail/scan-drop", response_model=MailDropScanResponse)
def mail_scan_drop(db: Session = Depends(get_db)):
    """Scan inbox_drop/ for new .eml or .txt emails saved from the mail app."""
    return scan_drop_folder(db)


@app.get("/api/mail/status", response_model=MailImapStatus)
def mail_status():
    return mail_monitor.status()


@app.post("/api/mail/imap/connect", response_model=MailImapStatus)
def mail_imap_connect(payload: MailImapConnectRequest):
    """Connect to Gmail/Outlook and start watching new inbox mail."""
    try:
        return mail_monitor.connect(
            host=payload.host,
            username=payload.username,
            password=payload.password,
            mailbox=payload.mailbox or "INBOX",
            interval_seconds=payload.interval_seconds or 20,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/mail/imap/poll", response_model=MailImapStatus)
def mail_imap_poll():
    try:
        return mail_monitor.poll_once()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/mail/imap/stop", response_model=MailImapStatus)
def mail_imap_stop():
    return mail_monitor.stop()


@app.get("/api/files/status", response_model=FileWatchStatus)
def files_status():
    return file_monitor.status()


@app.post("/api/files/start", response_model=FileWatchStatus)
def files_start():
    """Start watching Downloads, Desktop, Documents, and file_drop/."""
    return file_monitor.start(interval_seconds=8, persist=True)


@app.post("/api/files/scan", response_model=FileWatchStatus)
def files_scan():
    try:
        return file_monitor.scan_once()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/files/stop", response_model=FileWatchStatus)
def files_stop():
    return file_monitor.stop(forget=True)


@app.post("/api/files/upload", response_model=FileCheckResponse)
async def files_upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Classify a file dropped onto the dashboard (saved into file_drop/)."""
    from .file_guard import DROP_DIR

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")
    name = Path(file.filename or "upload.bin").name
    dest = DROP_DIR / name
    dest.write_bytes(raw)
    return check_file_and_store(db, dest, origin=f"upload:{name}")


@app.post("/api/files/scan-drop", response_model=FileScanResponse)
def files_scan_drop(db: Session = Depends(get_db)):
    from .file_guard import default_watch_folders

    return scan_folders(db, default_watch_folders())


@app.post("/api/files/test-sample", response_model=FileTestSampleResponse)
def files_test_sample(db: Session = Depends(get_db)):
    """Write harmless ransomware/malware test files, then classify them."""
    created = create_test_samples()
    last = None
    for path in created:
        last = check_file_and_store(db, Path(path), origin="test-sample")
    mark_seen(created)
    if not file_monitor.status().get("enabled"):
        file_monitor.start(interval_seconds=8, persist=True)
    return {
        "created": created,
        "new_events": len(created),
        "message": (
            f"Wrote {len(created)} test file(s) and classified them. "
            "Delete the CYBER_SENTINEL_TEST_* and invoice_payment_overdue_*.pdf.exe files after your demo."
        ),
        "last": last,
    }


@app.get("/api/endpoint/status", response_model=EndpointGuardStatus)
def endpoint_status():
    return endpoint_monitor.status()


@app.post("/api/endpoint/start", response_model=EndpointGuardStatus)
def endpoint_start():
    return endpoint_monitor.start(interval_seconds=12, persist=True)


@app.post("/api/endpoint/scan", response_model=EndpointGuardStatus)
def endpoint_scan():
    try:
        return endpoint_monitor.scan_once()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/endpoint/stop", response_model=EndpointGuardStatus)
def endpoint_stop():
    return endpoint_monitor.stop(forget=True)


@app.get("/api/setup", response_model=SetupStatus)
def setup_status():
    """First-run checklist for the laptop demo."""
    mail = mail_monitor.status()
    files = file_monitor.status()
    endpoint = endpoint_monitor.status()
    agents = agent_registry.status()
    steps = [
        SetupStepOut(
            id="app",
            title="Dashboard is running on this laptop",
            done=True,
            detail="Open http://127.0.0.1:8000",
            tab="dashboard",
        ),
        SetupStepOut(
            id="files",
            title="Watch Downloads / Desktop / Documents",
            done=bool(files.get("enabled")),
            detail=files.get("last_message") or "Starts automatically with the app",
            tab="files",
        ),
        SetupStepOut(
            id="endpoint",
            title="Watch this laptop for virus / worm / trojan / RAT / miner / …",
            done=bool(endpoint.get("enabled")),
            detail=endpoint.get("last_message") or "Live process, port, and persistence sweep",
            tab="files",
        ),
        SetupStepOut(
            id="mail",
            title="Connect Gmail or Outlook inbox",
            done=bool(mail.get("enabled")),
            detail=(
                f"Watching {mail.get('username')}"
                if mail.get("enabled")
                else "Open My Mail and start inbox watch with an app password"
            ),
            tab="mail",
        ),
        SetupStepOut(
            id="network",
            title="LAN multi-source monitoring",
            done=bool(monitor.status().get("enabled")),
            detail="Network IDS, endpoint, firewall, DNS, email, and auth sensors",
            tab="sources",
        ),
        SetupStepOut(
            id="agents",
            title="Other PCs (optional)",
            done=int(agents.get("connected") or 0) > 0,
            optional=True,
            detail=(
                f"{agents.get('connected', 0)} PC(s) connected"
                if agents.get("connected")
                else "Run sentinel_agent.py on another PC if you want inside-host data"
            ),
            tab="sources",
        ),
    ]
    required = [step for step in steps if not step.optional]
    completed = sum(1 for step in required if step.done)
    return SetupStatus(
        ready=completed == len(required),
        completed=completed,
        required=len(required),
        steps=steps,
    )


@app.get("/api/threats", response_model=list[ThreatEventOut])
def list_threats(
    threat_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(ThreatEvent).order_by(ThreatEvent.created_at.desc())
    if threat_type:
        query = query.filter(ThreatEvent.threat_type == threat_type)
    if severity:
        query = query.filter(ThreatEvent.severity == severity)
    if status:
        query = query.filter(ThreatEvent.status == status)
    return query.limit(limit).all()


@app.get("/api/threats/{threat_id}", response_model=ThreatEventOut)
def get_threat(threat_id: int, db: Session = Depends(get_db)):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == threat_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return event


@app.patch("/api/threats/{threat_id}", response_model=ThreatEventOut)
def update_threat_status(
    threat_id: int, payload: StatusUpdate, db: Session = Depends(get_db)
):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == threat_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")
    event.status = payload.status
    db.commit()
    db.refresh(event)
    return event


@app.post("/api/collect", response_model=CollectResponse)
def collect_threats(payload: CollectRequest, db: Session = Depends(get_db)):
    result = collect_from_network(
        db,
        batch_size=payload.batch_size,
        mode=payload.mode,
    )
    return result


@app.post("/api/ingest", response_model=ThreatEventOut)
def ingest(payload: IngestRequest, db: Session = Depends(get_db)):
    return ingest_event(
        db,
        source=payload.source,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        protocol=payload.protocol,
        raw_payload=payload.raw_payload,
    )


@app.post("/api/classify", response_model=ClassifyResponse)
def classify_text(payload: ClassifyRequest):
    result = classifier.classify(payload.text)
    return ClassifyResponse(
        threat_type=result.threat_type,
        severity=result.severity,
        confidence=result.confidence,
        indicators=result.indicators,
    )


@app.get("/api/stats", response_model=StatsResponse)
def stats(db: Session = Depends(get_db)):
    return get_stats(db)


@app.get("/api/reports/summary", response_model=ReportSummary)
def report_summary(db: Session = Depends(get_db)):
    return build_report_summary(db)


@app.get("/api/reports/pdf")
def report_pdf(db: Session = Depends(get_db)):
    pdf_bytes, filename = generate_pdf_report(db)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _mount_frontend() -> None:
    """Serve the built React app from FastAPI for single-process offline use."""
    if not FRONTEND_DIST.exists():
        return

    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    fonts_dir = FRONTEND_DIST / "fonts"
    if fonts_dir.exists():
        app.mount("/fonts", StaticFiles(directory=str(fonts_dir)), name="fonts")

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon():
        path = FRONTEND_DIST / "favicon.svg"
        if path.exists():
            return FileResponse(path)
        raise HTTPException(status_code=404, detail="favicon not found")

    @app.get("/", include_in_schema=False)
    def spa_index():
        index = FRONTEND_DIST / "index.html"
        return FileResponse(index)

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        # Never hijack API, docs, or static swagger routes.
        blocked = (
            "api/",
            "static/",
            "agent/",
            "docs",
            "openapi.json",
            "redoc",
        )
        if full_path.startswith(blocked) or full_path in {"docs", "openapi.json", "redoc"}:
            raise HTTPException(status_code=404, detail="Not found")
        candidate = FRONTEND_DIST / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        index = FRONTEND_DIST / "index.html"
        if index.exists():
            return FileResponse(index)
        return HTMLResponse(
            "<h1>Frontend build missing</h1><p>Run <code>npm run build</code> in frontend/.</p>",
            status_code=404,
        )


_mount_frontend()
