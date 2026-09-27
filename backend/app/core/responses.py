"""Standard API response envelope helpers.

Every successful response:

    {"success": true, "data": {...}, "error": null, "meta": {}}

Every error response:

    {"success": false, "data": null, "error": {"code", "message", "details"}}
"""

from __future__ import annotations

from typing import Any

from app.schemas.common import ApiResponse


def ok(data: Any = None, meta: dict[str, Any] | None = None) -> ApiResponse[Any]:
    return ApiResponse(success=True, data=data, error=None, meta=meta or {})
