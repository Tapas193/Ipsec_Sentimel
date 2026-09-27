"""Shared service-layer helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def next_sequence_id(
    db: Session, model: type[Any], column: Any, prefix: str, digits: int = 6
) -> str:
    """Generate a durable human-readable id such as CAP-000001.

    The next number is derived from the highest existing suffix for the given
    prefix, so ids remain stable across restarts.
    """
    max_value = db.scalar(select(func.max(column)).select_from(model))
    highest = 0
    if max_value:
        text = str(max_value)
        suffix = text.split("-")[-1]
        if text.startswith(f"{prefix}-") and suffix.isdigit():
            highest = int(suffix)
    return f"{prefix}-{highest + 1:0{digits}d}"
