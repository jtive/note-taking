"""The API token must never appear in a response, on any path.

Pydantic reports the offending `input` alongside each validation error, and for
a *missing field* error that input is the whole parent object - which on this
endpoint contains the caller's API token. These tests pin that it does not get
reflected back.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import TEAM_TOKENS

SECRET = TEAM_TOKENS["acme"]


def test_token_not_echoed_when_another_field_is_invalid(client: TestClient) -> None:
    response = client.post("/auth/token", json={"api_token": SECRET, "member": "bad/name"})

    assert response.status_code == 422
    assert SECRET not in response.text


def test_token_not_echoed_when_a_field_is_missing(client: TestClient) -> None:
    """The case pydantic reports with the entire body as `input`."""
    response = client.post("/auth/token", json={"api_token": SECRET})

    assert response.status_code == 422
    assert SECRET not in response.text


def test_token_not_echoed_when_an_extra_field_is_sent(client: TestClient) -> None:
    response = client.post(
        "/auth/token", json={"api_token": SECRET, "member": "alice", "team": "globex"}
    )

    assert response.status_code == 422
    assert SECRET not in response.text


def test_token_not_echoed_on_success_or_refusal(client: TestClient) -> None:
    issued = client.post("/auth/token", json={"api_token": SECRET, "member": "alice"})
    refused = client.post("/auth/token", json={"api_token": "nt_" + "x" * 40, "member": "alice"})

    assert issued.status_code == 200
    assert SECRET not in issued.text
    assert refused.status_code == 401
    assert "x" * 40 not in refused.text
