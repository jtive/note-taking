"""Error types and their RFC 9457 `application/problem+json` representations.

A single error shape across every failure mode means clients write one error
handler instead of guessing per endpoint:

    {
      "type": "urn:notes:error:not-found",
      "title": "Not Found",
      "status": 404,
      "detail": "No note with that id exists in your team.",
      "instance": "/notes/01M3Z4HMB1VS68PXB1QS3EA6GT"
    }
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_CONTENT_TYPE = "application/problem+json"


class ApiError(Exception):
    """Base class for every failure this service reports deliberately."""

    status_code: int = 500
    title: str = "Internal Server Error"
    code: str = "internal-error"

    def __init__(
        self,
        detail: str,
        *,
        headers: dict[str, str] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.headers = headers or {}
        self.extra = extra

    @property
    def type_uri(self) -> str:
        return f"urn:notes:error:{self.code}"

    def to_problem(self, instance: str) -> dict[str, Any]:
        return {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
            "instance": instance,
            **self.extra,
        }


class AuthenticationError(ApiError):
    status_code = 401
    title = "Unauthorized"
    code = "unauthenticated"

    def __init__(self, detail: str = "Authentication is required.", **kwargs: Any) -> None:
        headers = {"WWW-Authenticate": 'Bearer realm="notes"'}
        headers.update(kwargs.pop("headers", {}))
        super().__init__(detail, headers=headers, **kwargs)


class InvalidCredentialsError(AuthenticationError):
    code = "invalid-credentials"

    def __init__(self) -> None:
        # Deliberately indistinguishable between "no such user" and "wrong
        # password" so the endpoint cannot be used to enumerate accounts.
        super().__init__("Email or password is incorrect.")


class PermissionDeniedError(ApiError):
    status_code = 403
    title = "Forbidden"
    code = "permission-denied"


class NotFoundError(ApiError):
    status_code = 404
    title = "Not Found"
    code = "not-found"


class ConflictError(ApiError):
    status_code = 409
    title = "Conflict"
    code = "conflict"


class PreconditionFailedError(ApiError):
    status_code = 412
    title = "Precondition Failed"
    code = "precondition-failed"


class ValidationError(ApiError):
    status_code = 422
    title = "Unprocessable Content"
    code = "validation-failed"


class RateLimitExceededError(ApiError):
    status_code = 429
    title = "Too Many Requests"
    code = "rate-limit-exceeded"


def _problem_response(error: ApiError, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content=error.to_problem(instance=request.url.path),
        headers=error.headers,
        media_type=PROBLEM_CONTENT_TYPE,
    )


async def handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
    return _problem_response(exc, request)


async def handle_request_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
    error = ValidationError(
        "The request body or parameters failed validation.",
        errors=jsonable_encoder(exc.errors()),
    )
    return _problem_response(error, request)


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Render the responses Starlette raises for us, chiefly 404 and 405."""
    error = ApiError(str(exc.detail), headers=dict(exc.headers or {}))
    error.status_code = exc.status_code
    error.title = "Error"
    error.code = "http-error"
    return _problem_response(error, request)


async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    # Log the cause; return nothing that describes our internals.
    logger.exception("Unhandled error serving %s %s", request.method, request.url.path)
    return _problem_response(ApiError("An unexpected error occurred."), request)


def register_exception_handlers(app: FastAPI) -> None:
    # Starlette types handlers as accepting the base Exception, so a handler
    # narrowed to the type it is registered for does not satisfy the signature.
    app.add_exception_handler(ApiError, handle_api_error)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, handle_request_validation)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, handle_unexpected)
