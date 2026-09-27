"""Shared helpers for v1 API endpoints."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any, TypeVar

from fastapi import Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.common import PaginatedData, PaginationMeta

DbSession = Annotated[Session, Depends(get_db)]

T = TypeVar("T", bound=BaseModel)


@dataclass
class PageParams:
    page: int
    page_size: int


def page_params(
    page: int = Query(1, ge=1, description="Page number, 1-based"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
) -> PageParams:
    return PageParams(page=page, page_size=page_size)


PageQuery = Annotated[PageParams, Depends(page_params)]


def paginate(
    db: Session,
    model: type[Any],
    params: PageParams,
    schema: type[T],
) -> PaginatedData[T]:
    """Fetch a page of ``model`` rows ordered newest-first and return the
    standard paginated envelope."""
    total = db.scalar(select(func.count()).select_from(model)) or 0
    total_pages = (total + params.page_size - 1) // params.page_size or 1
    rows: Sequence[Any] = db.scalars(
        select(model)
        .order_by(model.created_at.desc())
        .offset((params.page - 1) * params.page_size)
        .limit(params.page_size)
    ).all()
    return PaginatedData[T](
        items=[schema.model_validate(row) for row in rows],
        pagination=PaginationMeta(
            page=params.page,
            page_size=params.page_size,
            total=total,
            total_pages=total_pages,
        ),
    )
