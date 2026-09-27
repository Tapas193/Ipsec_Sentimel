"""Application settings loaded from environment variables.

Secrets are never stored in source code. All configuration is overridable
via environment variables (see ``.env.example``).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=f"{BASE_DIR}/.env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "IPsec Sentinel"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"  # development | test | demo | production
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Database. Prefer PostgreSQL (DATABASE_URL=postgresql+psycopg://...).
    # SQLite is supported for local development without Docker.
    DATABASE_URL: str = "sqlite:///./ipsec_sentinel.db"

    # Frontend origin(s) allowed for CORS, comma separated.
    CORS_ORIGINS: str = "http://localhost:2456,http://127.0.0.1:2456"

    # Uploads
    UPLOAD_DIR: str = str((BASE_DIR / "data" / "uploads").resolve())
    MAX_UPLOAD_SIZE_MB: int = 500

    # Packet analyzer (Phase 2)
    ANALYZER_VERSION: str = "1.0.0"
    PARSER_VERSION: str = "1.0.0"
    FEATURE_SCHEMA_VERSION: str = "1.0"
    ANALYSIS_TIMEOUT_SECONDS: int = 300
    ANALYZER_MAX_PACKETS: int = 200_000
    FLOW_BURST_WINDOW_SECONDS: float = 0.1

    # Security
    AUTH_ENABLED: bool = False
    JWT_SECRET: str = "change-this-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    @field_validator("UPLOAD_DIR", mode="before")
    @classmethod
    def _expand_upload_dir(cls, v: str) -> str:
        return os.path.expanduser(v)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def synchronous_driver(self) -> bool:
        """True when using a driver without async support (e.g. SQLite)."""
        return self.DATABASE_URL.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
