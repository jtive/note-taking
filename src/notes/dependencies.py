"""Dependency wiring.

Everything the routes need arrives through FastAPI's dependency system, which
gives tests a seam: a test overrides `get_repository` or `get_clock` and the
whole graph below it follows, with no module-level patching.

The DynamoDB resource is cached per execution environment. Building a boto3
client involves loading service JSON and is slow enough that doing it per
request would show up in the latency numbers.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import boto3
from fastapi import Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from notes.auth.signing_key import get_signing_key
from notes.auth.tokens import Principal, decode_token
from notes.clock import Clock, get_clock
from notes.config import Settings, get_settings
from notes.errors import AuthenticationError, RateLimitExceededError
from notes.ratelimit import RateLimiter
from notes.repository import Repository


@lru_cache(maxsize=1)
def get_table() -> Any:
    settings = get_settings()
    resource = boto3.resource("dynamodb", endpoint_url=settings.dynamodb_endpoint_url)
    return resource.Table(settings.table_name)


def get_repository(clock: Clock = Depends(get_clock)) -> Repository:
    return Repository(get_table(), clock)


def get_rate_limiter(clock: Clock = Depends(get_clock)) -> RateLimiter:
    return RateLimiter(get_table(), clock)


bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerToken",
    description="A JWT from POST /auth/token.",
)


def get_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if credentials is None:
        raise AuthenticationError("Provide a bearer token in the Authorization header.")
    return decode_token(
        credentials.credentials,
        signing_key=get_signing_key(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )


def get_client_ip(request: Request) -> str:
    """The caller's address, for limiting routes where no user is known yet.

    API Gateway reports the real source address in
    requestContext.http.sourceIp, which Mangum maps onto the ASGI client scope,
    and which a caller cannot influence. X-Forwarded-For is only consulted as a
    fallback for local runs: preferring it would let a caller send a fresh
    value per request and walk straight through the limit.
    """
    if request.client is not None:
        return request.client.host
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"


def _apply(decision_headers: dict[str, str], response: Response) -> None:
    for name, value in decision_headers.items():
        response.headers[name] = value


def enforce_team_rate_limit(
    response: Response,
    principal: Principal = Depends(get_principal),
    limiter: RateLimiter = Depends(get_rate_limiter),
    settings: Settings = Depends(get_settings),
) -> None:
    """Per-team limit on the authenticated surface.

    Keyed on the team rather than the member, because the team is the only
    thing the credential actually proves. A member name is declared by the
    caller at token-exchange time, so limiting per member would be trivially
    escaped by exchanging a new token under a different name. Keying on the
    source address would be just as wrong in the other direction: a whole
    office behind one NAT would share a single allowance.

    The cost is that one busy member consumes their team's allowance. Fixing
    that properly needs per-member credentials, not a different limit key.
    """
    decision = limiter.check(
        subject=f"team:{principal.team_id}",
        limit=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    _apply(decision.headers(), response)
    if not decision.allowed:
        raise RateLimitExceededError(
            f"Exceeded {decision.limit} requests per {settings.rate_limit_window_seconds} seconds.",
            headers=decision.headers(),
        )


def enforce_auth_rate_limit(
    response: Response,
    client_ip: str = Depends(get_client_ip),
    limiter: RateLimiter = Depends(get_rate_limiter),
    settings: Settings = Depends(get_settings),
) -> None:
    """Tighter per-IP limit on token exchange.

    This route is reachable without a session token, so the threat is someone
    guessing an API token. There is no verified identity to key on yet, which
    leaves the source address. The limit is deliberately much lower than the
    authenticated one.
    """
    decision = limiter.check(
        subject=f"ip:{client_ip}",
        limit=settings.auth_rate_limit_requests,
        window_seconds=settings.auth_rate_limit_window_seconds,
    )
    _apply(decision.headers(), response)
    if not decision.allowed:
        raise RateLimitExceededError(
            f"Exceeded {decision.limit} token exchanges per "
            f"{settings.auth_rate_limit_window_seconds} seconds.",
            headers=decision.headers(),
        )
