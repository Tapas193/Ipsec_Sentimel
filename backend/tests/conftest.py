"""Shared pytest fixtures.

Tests run against an isolated in-memory SQLite database so no external
PostgreSQL instance is required to run the suite.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.api.v1.endpoints.captures as captures_module
from app.core.config import get_settings
from app.db import base
from app.db.session import get_db
from app.main import app

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="session", autouse=True)
def _migrate() -> None:
    base.Base.metadata.create_all(bind=engine)
    get_settings().UPLOAD_DIR = "/tmp/ipsec_sentinel_test_uploads"


@pytest.fixture(autouse=True)
def _clean_tables(db_session: Session) -> Generator[None, None, None]:
    """Isolate tests by deleting all rows before each test."""
    for table in reversed(base.Base.metadata.sorted_tables):
        db_session.execute(table.delete())
    db_session.commit()
    yield


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    original_factory = captures_module.SessionLocal
    captures_module.SessionLocal = TestingSessionLocal
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    captures_module.SessionLocal = original_factory
