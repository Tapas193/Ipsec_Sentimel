"""Database engine and session management.

Phase 1 uses a synchronous engine so the same code path works for both
SQLite (local development) and PostgreSQL (Docker / production). Async I/O
can be introduced later without changing the rest of the application.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    # Allow the file-based DB to be shared within the process/threads.
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables from ORM metadata.

    Local development convenience only. Production uses Alembic migrations.
    """
    from app.db import base  # noqa: F401  (import models into metadata)

    base.Base.metadata.create_all(bind=engine)
