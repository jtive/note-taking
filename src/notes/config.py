"""Runtime configuration, read from the environment.

Everything is prefixed NOTES_ so that application settings can never be
confused with, or shadowed by, the AWS_* variables the Lambda runtime injects.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NOTES_", env_file=".env", extra="ignore")

    table_name: str = Field(description="DynamoDB table holding users, teams, notes and counters.")

    # Exactly one of these supplies the JWT signing key. In AWS the Lambda reads
    # jwt_secret_param from SSM at cold start; jwt_secret is the escape hatch for
    # local development and tests, which must not depend on network calls.
    jwt_secret_param: str | None = None
    jwt_secret: str | None = None

    # Likewise for the team token registry: an SSM parameter in AWS, inline
    # JSON locally. See notes/auth/team_tokens.py for the document shape.
    team_tokens_param: str | None = None
    team_tokens: str | None = None

    jwt_issuer: str = "note-taking-api"
    jwt_audience: str = "note-taking-clients"
    # One hour: long enough that clients are not re-authenticating constantly,
    # short enough to bound the damage from a leaked session token, since a
    # stateless JWT cannot be revoked before it expires.
    jwt_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)

    # Per-team limit on the authenticated API surface.
    rate_limit_requests: int = Field(default=100, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)

    # Tighter per-IP limit on token exchange, where the threat is someone
    # guessing an API token rather than a runaway client.
    auth_rate_limit_requests: int = Field(default=10, ge=1)
    auth_rate_limit_window_seconds: int = Field(default=60, ge=1)

    max_note_length: int = Field(default=20_000, ge=1)
    max_member_name_length: int = Field(default=64, ge=1)
    default_page_size: int = Field(default=25, ge=1)
    max_page_size: int = Field(default=100, ge=1)

    # Points boto3 at DynamoDB Local. Unset in AWS.
    dynamodb_endpoint_url: str | None = None

    log_level: str = "INFO"

    @model_validator(mode="after")
    def _require_every_secret_source(self) -> Settings:
        # Fail at startup rather than on the first request that needs them.
        if not self.jwt_secret and not self.jwt_secret_param:
            raise ValueError(
                "Set NOTES_JWT_SECRET (local/test) or NOTES_JWT_SECRET_PARAM (SSM parameter name)."
            )
        if not self.team_tokens and not self.team_tokens_param:
            raise ValueError(
                "Set NOTES_TEAM_TOKENS (local/test) or NOTES_TEAM_TOKENS_PARAM "
                "(SSM parameter name)."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Settings are read once per execution environment and reused across invocations."""
    return Settings()  # type: ignore[call-arg]  # values come from the environment
