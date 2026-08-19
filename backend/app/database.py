"""SQLite database setup and session management."""

from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATA_DIR / 'threats.db'}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

_JOB_COLUMNS = {
    "details": "details TEXT",
    "mode": "mode VARCHAR(32)",
    "subnet": "subnet VARCHAR(64)",
    "local_ip": "local_ip VARCHAR(64)",
}


def ensure_schema() -> None:
    """Add new columns to existing SQLite databases created before this revision."""
    with engine.begin() as conn:
        existing = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(collection_jobs)")).fetchall()
        }
        if not existing:
            return
        for name, ddl in _JOB_COLUMNS.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE collection_jobs ADD COLUMN {ddl}"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
