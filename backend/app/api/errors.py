"""Uniform JSON error responses: {"error": {"code", "message", "request_id", ...}}."""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas import ErrorBody, ErrorResponse
from app.services import DomainError, InvalidInputError, NotFoundError
from app.utils.logging import get_logger

log = get_logger(__name__)

_DOMAIN_STATUS = {NotFoundError: 404, InvalidInputError: 422}


def _response(
    request: Request,
    status: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorBody(
            code=code,
            message=message,
            request_id=getattr(request.state, "request_id", None),
            details=details,
        )
    )
    return JSONResponse(status_code=status, content=body.model_dump(exclude_none=True))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return _response(request, _DOMAIN_STATUS.get(type(exc), 400), exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Report only where and why validation failed; never echo the submitted input back.
        details = [{"loc": list(e["loc"]), "message": e["msg"]} for e in exc.errors()]
        return _response(request, 422, "validation_error", "Request validation failed.", details)

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _response(request, exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_exception", path=request.url.path)
        return _response(request, 500, "internal_error", "An unexpected error occurred.")
