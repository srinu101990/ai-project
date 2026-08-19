"""SQLAlchemy ORM models for threat intelligence."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text

from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(120), nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    destination_ip = Column(String(64), nullable=True)
    protocol = Column(String(32), nullable=True)
    raw_payload = Column(Text, nullable=False)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    indicators = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="open", index=True)
    is_simulated = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


class CollectionJob(Base):
    __tablename__ = "collection_jobs"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(32), nullable=False, default="running")
    sources_scanned = Column(Integer, nullable=False, default=0)
    events_collected = Column(Integer, nullable=False, default=0)
    message = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    mode = Column(String(32), nullable=True)
    subnet = Column(String(64), nullable=True)
    local_ip = Column(String(64), nullable=True)
    started_at = Column(DateTime, nullable=False, default=utcnow)
    finished_at = Column(DateTime, nullable=True)
