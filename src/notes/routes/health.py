"""Liveness probe."""

from __future__ import annotations

from fastapi import APIRouter

from notes import __version__
from notes.models import HealthResponse

router = APIRouter(tags=["meta"])


@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
def healthz() -> HealthResponse:
    """Report that the service is running.

    Deliberately touches no dependencies and requires no auth. It answers "did
    this Lambda start and can it route a request", which is the question a
    deploy gate should ask. Reaching into DynamoDB here would make an outage in
    a downstream service look like an outage in this one, and would make the
    probe itself a source of cost and throttling.
    """
    return HealthResponse(version=__version__)
