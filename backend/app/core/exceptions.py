"""Application exception classes with stable error codes."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base error carrying a stable machine-readable code."""

    status_code: int = 500
    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class NotFoundError(AppError):
    status_code = 404
    code = "NOT_FOUND"


class CaptureNotFoundError(NotFoundError):
    code = "CAPTURE_NOT_FOUND"


class AnalysisNotFoundError(NotFoundError):
    code = "ANALYSIS_NOT_FOUND"


class FindingNotFoundError(NotFoundError):
    code = "FINDING_NOT_FOUND"


class BadRequestError(AppError):
    status_code = 400
    code = "BAD_REQUEST"


class ConflictError(AppError):
    status_code = 409
    code = "CONFLICT"


class AnalysisNotAssessableError(ConflictError):
    code = "ANALYSIS_NOT_ASSESSABLE"


class CaptureValidationError(AppError):
    status_code = 400
    code = "INVALID_CAPTURE"


class UnsupportedFormatError(AppError):
    status_code = 400
    code = "UNSUPPORTED_FORMAT"


class StorageError(AppError):
    status_code = 500
    code = "STORAGE_ERROR"


class ParserError(AppError):
    status_code = 500
    code = "PARSER_ERROR"


class AnalysisTimeoutError(AppError):
    status_code = 504
    code = "ANALYSIS_TIMEOUT"


class ToolUnavailableError(AppError):
    status_code = 503
    code = "TOOL_UNAVAILABLE"
