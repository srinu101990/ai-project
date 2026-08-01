"""FastAPI application for the AI Cyber Threat Intelligence Dashboard."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .classifier import classifier
from .collector import collect_from_network, ingest_event
from .database import Base, engine, get_db
from .models import ThreatEvent
from .report import build_report_summary, generate_pdf_report, get_stats
from .schemas import (
    ClassifyRequest,
    ClassifyResponse,
    CollectRequest,
    CollectResponse,
    IngestRequest,
    ReportSummary,
    StatsResponse,
    StatusUpdate,
    ThreatEventOut,
)


def seed_if_empty(db: Session) -> None:
    count = db.query(ThreatEvent).count()
    if count == 0:
        collect_from_network(db, batch_size=14)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    # Ensure classifier model is warm.
    _ = classifier.classify("warmup benign traffic sample")
    from .database import SessionLocal

    db = SessionLocal()
    try:
        seed_if_empty(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="AI Cyber Threat Intelligence Dashboard",
    description=(
        "Collects network cyber threat data, classifies phishing/malware/ransomware "
        "with AI, visualizes real-time stats, and generates decision-support reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "cyber-threat-intel"}


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
    result = collect_from_network(db, batch_size=payload.batch_size)
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
