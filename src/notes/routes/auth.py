"""Exchanging a team's API token for a short-lived session token.

There is no registration endpoint and no password store. Each team holds one
long-lived API token, provisioned out of band by scripts/bootstrap.py, and
trades it here for a JWT that expires within the hour. The long-lived secret
therefore travels once per session instead of on every request, and the
credential on the wire for ordinary calls is one that expires on its own.

The member name in the exchange is attribution, not authentication: the token
proves which team is calling, not which person. See notes/auth/team_tokens.py.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from notes.auth.signing_key import get_signing_key
from notes.auth.team_tokens import resolve_team
from notes.auth.tokens import Principal, issue_token
from notes.clock import Clock, get_clock
from notes.config import Settings, get_settings
from notes.dependencies import (
    enforce_auth_rate_limit,
    enforce_team_rate_limit,
    get_principal,
)
from notes.models import IdentityResponse, TokenRequest, TokenResponse
from notes.routes import PROBLEM_RESPONSES

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange a team API token for a session token",
    dependencies=[Depends(enforce_auth_rate_limit)],
    responses=PROBLEM_RESPONSES,
)
def create_token(
    payload: TokenRequest,
    settings: Settings = Depends(get_settings),
    clock: Clock = Depends(get_clock),
) -> TokenResponse:
    """Issue a short-lived JWT carrying the caller's team and member name.

    An unrecognised API token returns the same 401 as any other failure, with
    no indication of whether a prefix or a team happened to be right.
    """
    team_id = resolve_team(payload.api_token.get_secret_value())

    token = issue_token(
        principal=Principal(member=payload.member, team_id=team_id),
        signing_key=get_signing_key(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=settings.jwt_ttl_seconds,
        now=clock.now(),
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_ttl_seconds,
        team=team_id,
        member=payload.member,
    )


@router.get(
    "/me",
    response_model=IdentityResponse,
    summary="Describe the presented session token",
    dependencies=[Depends(enforce_team_rate_limit)],
    responses=PROBLEM_RESPONSES,
)
def read_identity(principal: Principal = Depends(get_principal)) -> IdentityResponse:
    """Echo the identity the session token asserts, for debugging a client."""
    return IdentityResponse(member=principal.member, team=principal.team_id)
