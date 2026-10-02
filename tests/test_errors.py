"""Error representation.

The service promises one error shape everywhere. These tests hold it to that,
including on the path nobody plans for.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from notes.dependencies import get_repository
from tests.conftest import Actor


def test_errors_use_the_problem_json_content_type(client: TestClient) -> None:
    response = client.get("/auth/me")

    assert response.headers["content-type"].startswith("application/problem+json")


def test_problem_documents_carry_every_required_member(client: TestClient, alice: Actor) -> None:
    response = client.get("/notes/01M3Z4HMB1VS68PXB1QS3EA6GT", headers=alice.headers)

    body = response.json()
    assert body["type"] == "urn:notes:error:not-found"
    assert body["title"] == "Not Found"
    assert body["status"] == 404
    assert body["detail"]
    assert body["instance"] == "/notes/01M3Z4HMB1VS68PXB1QS3EA6GT"


def test_validation_failures_list_the_offending_fields(client: TestClient) -> None:
    response = client.post("/auth/token", json={})

    assert response.status_code == 422
    fields = {tuple(error["loc"]) for error in response.json()["errors"]}
    assert ("body", "api_token") in fields
    assert ("body", "member") in fields


def test_a_wrong_method_is_reported_as_a_problem(client: TestClient) -> None:
    response = client.put("/healthz")

    assert response.status_code == 405
    assert response.json()["status"] == 405


def test_an_unexpected_failure_does_not_leak_internals(client: TestClient, alice: Actor) -> None:
    class ExplodingRepository:
        def list_notes(self, **kwargs: Any) -> None:
            raise RuntimeError("connection string: super-secret-value")

    client.app.dependency_overrides[get_repository] = ExplodingRepository  # type: ignore[attr-defined]

    response = client.get("/notes", headers=alice.headers)

    assert response.status_code == 500
    assert response.json()["detail"] == "An unexpected error occurred."
    assert "super-secret-value" not in response.text
