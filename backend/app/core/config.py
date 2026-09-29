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

    # Machine learning (Phase 4)
    # ML_ENABLED gates inference. ML_TRAINING_ENABLED gates training, and is
    # off by default: an uploaded capture must never become training data
    # implicitly, and labels only ever come from ML_LABEL_FILE.
    ML_ENABLED: bool = False
    ML_TRAINING_ENABLED: bool = False
    ML_MODEL_DIR: str = str((BASE_DIR / "data" / "models").resolve())
    ML_FEATURE_SCHEMA_PATH: str = str(BASE_DIR.parent / "configs" / "ml_feature_schema.yaml")
    # Empty means "resolve the newest model compatible with the feature
    # schema" at inference time.
    ML_DEFAULT_MODEL_VERSION: str = ""
    # Maximum predicted probability required to report a class. Below this the
    # prediction is UNKNOWN with observation_status=MODEL_PREDICTED.
    ML_MIN_CONFIDENCE: float = 0.60
    ML_RANDOM_SEED: int = 42
    ML_DATASET_VERSION: str = "1.0"
    # Operator-supplied ground-truth file. Empty means "no labeled data", which
    # makes training report INSUFFICIENT_LABELED_DATA.
    ML_LABEL_FILE: str = ""
    ML_MAX_TRAINING_FLOWS: int = 200_000

    @field_validator("UPLOAD_DIR", "ML_MODEL_DIR", mode="before")
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
