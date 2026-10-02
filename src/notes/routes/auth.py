"""Registration and token issuance.

Registration is open: anyone may claim membership of any team by naming it.
That is a deliberate scope boundary for this exercise, not an oversight - a
real deployment needs invitations or a directory, and the README says so. It
keeps the auth story reviewable without an email-delivery dependency.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from notes.auth.passwords import hash_password, spend_verification_time, verify_password
from notes.auth.signing_key import get_signing_key
from notes.auth.tokens import Principal, issue_token
from notes.clock import Clock, get_clock
from notes.config import Settings, get_settings
from notes.dependencies import (
    enforce_auth_rate_limit,
    enforce_user_rate_limit,
    get_principal,
    get_repository,
)
from notes.errors import InvalidCredentialsError
from notes.models import (
    IdentityResponse,
    RegisterRequest,
    RegisterResponse,
    TokenRequest,
    TokenResponse,
)
from notes.repository import Repository
from notes.routes import PROBLEM_RESPONSES

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse,
    summary="Create an account and join a team",
    dependencies=[Depends(enforce_auth_rate_limit)],
    responses={
        409: {"description": "An account with that email already exists."},
        **PROBLEM_RESPONSES,
    },
)
def register(
    payload: RegisterRequest,
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> RegisterResponse:
    """Register a user. The team is created if this is its first member."""
    password_hash = hash_password(
        payload.password.get_secret_value(), rounds=settings.bcrypt_rounds
    )
    user = repository.create_user(
        email=payload.email,
        password_hash=password_hash,
        team_id=payload.team,
    )
    return RegisterResponse(user_id=user.user_id, email=user.email, team=user.team_id)


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange credentials for a bearer token",
    dependencies=[Depends(enforce_auth_rate_limit)],
    responses=PROBLEM_RESPONSES,
)
def create_token(
    payload: TokenRequest,
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
    clock: Clock = Depends(get_clock),
) -> TokenResponse:
    """Issue a short-lived JWT carrying the caller's user id and team."""
    user = repository.get_user(payload.email)

    if user is None:
        # Hash anyway. Returning early here would make an unknown address
        # answer in microseconds and a known one in hundreds of milliseconds,
        # which is enough to enumerate accounts by timing alone.
        spend_verification_time(rounds=settings.bcrypt_rounds)
        raise InvalidCredentialsError

    if not verify_password(payload.password.get_secret_value(), user.password_hash):
        raise InvalidCredentialsError

    token = issue_token(
        principal=Principal(user_id=user.user_id, email=user.email, team_id=user.team_id),
        signing_key=get_signing_key(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=settings.jwt_ttl_seconds,
        now=clock.now(),
    )
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_seconds)


@router.get(
    "/me",
    response_model=IdentityResponse,
    summary="Describe the presented token",
    dependencies=[Depends(enforce_user_rate_limit)],
    responses=PROBLEM_RESPONSES,
)
def read_identity(principal: Principal = Depends(get_principal)) -> IdentityResponse:
    """Echo the identity the token asserts, for debugging a client."""
    return IdentityResponse(
        user_id=principal.user_id,
        email=principal.email,
        team=principal.team_id,
    )
