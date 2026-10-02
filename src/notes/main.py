"""The FastAPI application.

One Lambda serves every route rather than one function per endpoint. That means
a single deployment artifact, a single execution role to reason about, and one
warm container serving any path a client hits. The cost is that all routes
share a memory size and timeout, which at this scope they are happy to do.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, Response
from ulid import ULID

from notes import __version__
from notes.config import get_settings
from notes.errors import register_exception_handlers
from notes.logging_config import configure_logging, request_id_var
from notes.routes import auth, health, notes

logger = logging.getLogger(__name__)

DESCRIPTION = """
A note-taking API for small teams.

Every note belongs to a team. Any member of that team can read its notes; only
the author can edit or delete one. Authenticate with `POST /auth/token` and
send the result as `Authorization: Bearer <token>`; the token carries both your
user id and your team, and the team is what scopes every query.

Errors are [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem
documents. Rate limit state is reported on every response via the
`X-RateLimit-*` headers.
"""


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Notes API",
        version=__version__,
        description=DESCRIPTION,
        summary="Team-scoped notes, on Lambda and DynamoDB.",
    )

    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(notes.router)

    @app.middleware("http")
    async def attach_request_id(request: Request, call_next: object) -> Response:
        """Tag the request so every log line from it can be correlated.

        An inbound X-Request-Id is honoured, which lets a caller trace a
        request through their own logs and ours.
        """
        request_id = request.headers.get("x-request-id") or str(ULID())
        token = request_id_var.set(request_id)
        try:
            response: Response = await call_next(request)  # type: ignore[operator]
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-Id"] = request_id
        return response

    logger.info("Application initialised against table %s", settings.table_name)
    return app


app = create_app()
