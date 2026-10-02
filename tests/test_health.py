from __future__ import annotations

from fastapi.testclient import TestClient


def test_healthz_needs_no_credentials(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_unknown_path_returns_a_problem_document(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["status"] == 404


def test_every_response_carries_a_request_id(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Request-Id": "abc-123"})

    assert response.headers["X-Request-Id"] == "abc-123"
