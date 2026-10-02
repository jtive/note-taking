"""The Lambda entry point, driven with real API Gateway HTTP API events.

Every other test talks to the ASGI app directly, which skips the adapter. This
file is what catches a handler path that is wrong, an event shape Mangum does
not map as expected, or a rate limiter that cannot see the caller's address -
all failures that would otherwise only appear after a deploy.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from notes.handler import lambda_handler

SOURCE_IP = "203.0.113.17"


def api_gateway_event(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    source_ip: str = SOURCE_IP,
) -> dict[str, Any]:
    """A payload-format 2.0 event, as an HTTP API sends it."""
    return {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {
            "host": "notes.example.com",
            "content-type": "application/json",
        },
        "requestContext": {
            "accountId": "486151888818",
            "apiId": "abc123",
            "domainName": "notes.example.com",
            "http": {
                "method": method,
                "path": path,
                "protocol": "HTTP/1.1",
                "sourceIp": source_ip,
                "userAgent": "pytest",
            },
            "requestId": "test-request-id",
            "stage": "$default",
            "time": "02/Oct/2026:20:00:00 +0000",
            "timeEpoch": 1_790_000_000_000,
        },
        "body": json.dumps(body) if body is not None else None,
        "isBase64Encoded": False,
    }


@pytest.fixture
def context() -> SimpleNamespace:
    return SimpleNamespace(
        function_name="notes-api",
        memory_limit_in_mb=512,
        invoked_function_arn="arn:aws:lambda:us-east-2:486151888818:function:notes-api",
        aws_request_id="test-request-id",
    )


def test_healthz_responds_through_the_adapter(table: Any, context: SimpleNamespace) -> None:
    response = lambda_handler(api_gateway_event("GET", "/healthz"), context)

    assert response["statusCode"] == 200
    assert json.loads(response["body"])["status"] == "ok"


def test_an_unrouted_path_returns_a_problem_document(table: Any, context: SimpleNamespace) -> None:
    response = lambda_handler(api_gateway_event("GET", "/nope"), context)

    assert response["statusCode"] == 404
    assert response["headers"]["content-type"].startswith("application/problem+json")


def test_a_full_round_trip_works_end_to_end(table: Any, context: SimpleNamespace) -> None:
    """Register, get a token, write a note, read it back - all through Lambda."""
    registered = lambda_handler(
        api_gateway_event(
            "POST",
            "/auth/register",
            body={
                "email": "alice@acme.example",
                "password": "correct-horse-battery-staple",
                "team": "acme",
            },
        ),
        context,
    )
    assert registered["statusCode"] == 201

    issued = lambda_handler(
        api_gateway_event(
            "POST",
            "/auth/token",
            body={"email": "alice@acme.example", "password": "correct-horse-battery-staple"},
        ),
        context,
    )
    assert issued["statusCode"] == 200
    token = json.loads(issued["body"])["access_token"]

    create = api_gateway_event("POST", "/notes", body={"note": "written via Lambda"})
    create["headers"]["authorization"] = f"Bearer {token}"
    created = lambda_handler(create, context)
    assert created["statusCode"] == 201
    note_id = json.loads(created["body"])["id"]

    read = api_gateway_event("GET", f"/notes/{note_id}")
    read["headers"]["authorization"] = f"Bearer {token}"
    fetched = lambda_handler(read, context)

    assert fetched["statusCode"] == 200
    assert json.loads(fetched["body"])["note"] == "written via Lambda"


def test_the_rate_limiter_sees_the_api_gateway_source_address(
    table: Any,
    context: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirms sourceIp reaches `request.client.host` through Mangum.

    The per-IP limit on the auth routes depends on this. If the address did not
    survive the adapter, every caller would share one bucket keyed on
    "unknown" and the limit would be useless.
    """
    from notes.config import get_settings

    monkeypatch.setenv("NOTES_AUTH_RATE_LIMIT_REQUESTS", "1")
    get_settings.cache_clear()

    credentials = {"email": "nobody@acme.example", "password": "correct-horse-battery-staple"}

    first = lambda_handler(
        api_gateway_event("POST", "/auth/token", body=credentials, source_ip="198.51.100.1"),
        context,
    )
    second = lambda_handler(
        api_gateway_event("POST", "/auth/token", body=credentials, source_ip="198.51.100.1"),
        context,
    )
    # A different address starts with a fresh allowance, which is what proves
    # the counter is keyed on the address rather than on a shared constant.
    other_caller = lambda_handler(
        api_gateway_event("POST", "/auth/token", body=credentials, source_ip="198.51.100.99"),
        context,
    )

    assert first["statusCode"] == 401
    assert second["statusCode"] == 429
    assert other_caller["statusCode"] == 401
