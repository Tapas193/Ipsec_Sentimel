"""Shared predicates for rule implementations.

``UNKNOWN`` values are treated honestly: a value we could not resolve is
reported as unverifiable (never as weak or as strong), and observation status
``UNKNOWN`` never raises a finding by itself.
"""

from __future__ import annotations

UNKNOWN_MARKERS: frozenset[str] = frozenset({"UNKNOWN", "unknown", ""})


def is_unknown_value(value: str | None) -> bool:
    return value is None or value in UNKNOWN_MARKERS


def is_unknown_encryption(value: str | None) -> bool:
    return is_unknown_value(value) or (value or "").startswith("ENCR_")


def is_unresolved_transform(value: str | None) -> bool:
    """True when an integrity/PRF value could not be resolved to a known enum."""
    if is_unknown_value(value):
        return True
    prefixes = ("INTEG_", "PRF_", "HASH_", "AUTH_", "ALG_")
    return (value or "").startswith(prefixes)
