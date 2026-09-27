"""Enumerations used by the deterministic security assessment engine.

Semantics follow the Phase 3 rules:

- ``severity`` comes from explicit rule definitions (never a computed score).
- ``confidence`` reflects observation strength, NOT severity. A high
  severity finding can carry low confidence.
- ``observation_status`` describes how each evidence item was obtained.
  Items whose status resolves to ``UNKNOWN`` are never allowed to raise a
  finding; an unresolved observation stays unresolved.
"""

from __future__ import annotations

from enum import StrEnum


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class FindingConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ObservationStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    MODEL_PREDICTED = "model_predicted"
    NOT_OBSERVABLE = "not_observable"
    USER_PROVIDED = "user_provided"
    UNKNOWN = "unknown"


# Allowed finding categories (the DB column is a free string but the engine
# only ever emits values from this fixed set).
CATEGORIES: frozenset[str] = frozenset(
    {
        "CRYPTOGRAPHY",
        "KEY_EXCHANGE",
        "PFS",
        "SECURITY_ASSOCIATION",
        "REPLAY_PROTECTION",
        "PROTOCOL",
        "METADATA",
        "CONFIGURATION",
        "VISIBILITY",
    }
)
