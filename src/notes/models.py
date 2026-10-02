"""Request and response schemas.

The note representation uses the field names from the brief - user, team, date,
note - rather than renaming them to internal vocabulary, plus the two things
any REST resource needs: a stable `id` and an `updated_at` to tell a read-back
from a modification.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

from notes.config import get_settings

TEAM_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

TeamId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        description="Lowercase slug identifying the team, for example 'acme-research'.",
        examples=["acme-research"],
    ),
]


def _normalise_team_id(value: str) -> str:
    candidate = value.strip().lower()
    if not TEAM_ID_PATTERN.match(candidate):
        raise ValueError(
            "Team must contain only lowercase letters, digits and hyphens, "
            "and may not start or end with a hyphen."
        )
    return candidate


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(_Base):
    email: EmailStr = Field(examples=["alice@acme.example"])
    password: SecretStr = Field(examples=["correct-horse-battery"])
    team: TeamId

    @field_validator("email")
    @classmethod
    def _lowercase_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("team")
    @classmethod
    def _check_team(cls, value: str) -> str:
        return _normalise_team_id(value)

    @field_validator("password")
    @classmethod
    def _check_password_length(cls, value: SecretStr) -> SecretStr:
        minimum = get_settings().min_password_length
        if len(value.get_secret_value()) < minimum:
            raise ValueError(f"Password must be at least {minimum} characters.")
        return value


class TokenRequest(_Base):
    email: EmailStr = Field(examples=["alice@acme.example"])
    password: SecretStr

    @field_validator("email")
    @classmethod
    def _lowercase_email(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(_Base):
    access_token: str
    token_type: str = "bearer"  # noqa: S105  # OAuth 2.0 token type, not a credential
    expires_in: int = Field(description="Seconds until the token expires.")


class IdentityResponse(_Base):
    """Who the presented token says you are. Useful for debugging a client."""

    user_id: str
    email: EmailStr
    team: TeamId


class RegisterResponse(IdentityResponse):
    pass


def _validate_note_body(value: str) -> str:
    body = value.strip()
    if not body:
        raise ValueError("Note text cannot be empty or whitespace only.")
    limit = get_settings().max_note_length
    if len(body) > limit:
        raise ValueError(f"Note text cannot exceed {limit} characters.")
    return body


class NoteCreateRequest(_Base):
    note: str = Field(examples=["Ship the rate limiter before the demo."])

    @field_validator("note")
    @classmethod
    def _check_note(cls, value: str) -> str:
        return _validate_note_body(value)


class NoteUpdateRequest(_Base):
    note: str = Field(examples=["Ship the rate limiter after the demo."])

    @field_validator("note")
    @classmethod
    def _check_note(cls, value: str) -> str:
        return _validate_note_body(value)


class NoteResponse(_Base):
    id: str = Field(
        description="ULID; sorts chronologically.",
        examples=["01M3Z4HMB1VS68PXB1QS3EA6GT"],
    )
    user: EmailStr = Field(description="Email of the author.", examples=["alice@acme.example"])
    team: TeamId
    date: str = Field(
        description="ISO 8601 creation time, UTC.",
        examples=["2026-10-02T20:23:00.193Z"],
    )
    note: str
    updated_at: str = Field(description="ISO 8601 last-modification time, UTC.")
    version: int = Field(description="Increments on every edit; the value behind the ETag.")


class NoteListResponse(_Base):
    items: list[NoteResponse]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor. Pass as ?cursor= for the next page; null on the last page.",
    )


class HealthResponse(_Base):
    status: str = "ok"
    version: str


class ProblemResponse(BaseModel):
    """RFC 9457 problem document. Declared so it appears in the OpenAPI schema."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "urn:notes:error:not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "No note with that id exists in your team.",
                "instance": "/notes/01M3Z4HMB1VS68PXB1QS3EA6GT",
            }
        }
    )

    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None
