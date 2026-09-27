"""Exception handlers mapping application errors to the API envelope."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.exceptions import AppError
from app.schemas.common import ErrorDetail


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "data": None,
                "error": ErrorDetail(
                    code=exc.code, message=exc.message, details=exc.details
                ).model_dump(),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "success": False,
                "data": None,
                "error": ErrorDetail(
                    code="VALIDATION_ERROR",
                    message="Request validation failed.",
                    details={"errors": exc.errors()},
                ).model_dump(),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "data": None,
                "error": ErrorDetail(
                    code="INTERNAL_ERROR", message="An unexpected error occurred.", details={}
                ).model_dump(),
            },
        )
