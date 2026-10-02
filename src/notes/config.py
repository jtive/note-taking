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

    jwt_issuer: str = "note-taking-api"
    jwt_audience: str = "note-taking-clients"
    jwt_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)

    # 12 rounds costs roughly a quarter second of Lambda time per login. That is
    # a deliberate trade of latency for resistance to offline cracking, and it
    # applies only to the two auth endpoints.
    bcrypt_rounds: int = Field(default=12, ge=4, le=16)

    # Per-user limit on the authenticated API surface.
    rate_limit_requests: int = Field(default=100, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)

    # Tighter per-IP limit on registration and token issuance, where the threat
    # is credential stuffing rather than runaway clients.
    auth_rate_limit_requests: int = Field(default=10, ge=1)
    auth_rate_limit_window_seconds: int = Field(default=60, ge=1)

    max_note_length: int = Field(default=20_000, ge=1)
    max_team_name_length: int = Field(default=64, ge=1)
    min_password_length: int = Field(default=12, ge=8)
    default_page_size: int = Field(default=25, ge=1)
    max_page_size: int = Field(default=100, ge=1)

    # Points boto3 at DynamoDB Local. Unset in AWS.
    dynamodb_endpoint_url: str | None = None

    log_level: str = "INFO"

    @model_validator(mode="after")
    def _require_a_signing_key_source(self) -> Settings:
        if not self.jwt_secret and not self.jwt_secret_param:
            raise ValueError(
                "Set NOTES_JWT_SECRET (local/test) or NOTES_JWT_SECRET_PARAM (SSM parameter name)."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Settings are read once per execution environment and reused across invocations."""
    return Settings()  # type: ignore[call-arg]  # values come from the environment
