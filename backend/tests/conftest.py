"""Shared pytest fixtures.

Tests run against an isolated in-memory SQLite database so no external
PostgreSQL instance is required to run the suite.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.api.v1.endpoints.captures as captures_module
from app.core.config import get_settings
from app.db import base
from app.db.session import get_db
from app.main import app
from tests import ml_fixtures

# Re-exported as pytest fixtures. The `as` alias keeps the binding explicit so
# the fixture names stay importable from conftest without shadowing the fixture
# parameters below, which must use the same names for pytest to inject them.
ml_model_dir = ml_fixtures.ml_model_dir
ml_schema = ml_fixtures.ml_schema

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


@pytest.fixture()
def ml_settings(monkeypatch: pytest.MonkeyPatch, ml_model_dir: Path) -> Iterator[None]:
    """Enable ML for a test and point the model registry at a temp directory.

    Restores the previous values afterwards so ML stays disabled by default for
    every other test — the shipped configuration is ML-off and tests must not
    silently depend on it being on.
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "ML_ENABLED", True)
    monkeypatch.setattr(settings, "ML_TRAINING_ENABLED", True)
    monkeypatch.setattr(settings, "ML_MODEL_DIR", str(ml_model_dir))
    yield


@pytest.fixture()
def enforce_foreign_keys(db_session: Session) -> Iterator[None]:
    """Turn on SQLite's FK enforcement for the duration of one test.

    SQLite ignores ``ON DELETE CASCADE`` unless foreign keys are enabled per
    connection, so cascade behaviour is invisible by default. This is opt-in
    rather than global: several long-standing Phase 1-3 fixtures insert rows
    with placeholder parent ids, and enabling enforcement suite-wide would
    change their behaviour. Tests that actually assert on referential
    integrity ask for this fixture explicitly.
    """
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    yield
    db_session.execute(text("PRAGMA foreign_keys=OFF"))
