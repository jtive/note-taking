"""Request and response schemas.

The note representation keeps the field names from the brief - user, team,
date, note - rather than renaming them to internal vocabulary, plus the two
things any REST resource needs: a stable `id` and an `updated_at` to tell a
read-back from a modification.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from notes.config import get_settings

#: Deliberately permissive: a member name is a label for attribution, so an
#: email address, a handle and a display name are all reasonable. Control
#: characters and leading punctuation are not.
MEMBER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+\- ]*$")

TEAM_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

TeamId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        description="Slug identifying the team the credential belongs to.",
        examples=["acme"],
    ),
]

MemberName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        description="Who to attribute notes to. Not independently authenticated; "
        "the team's API token is the credential.",
        examples=["alice"],
    ),
]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_member(value: str) -> str:
    member = " ".join(value.split())
    limit = get_settings().max_member_name_length
    if not member:
        raise ValueError("Member name cannot be empty or whitespace only.")
    if len(member) > limit:
        raise ValueError(f"Member name cannot exceed {limit} characters.")
    if not MEMBER_PATTERN.match(member):
        raise ValueError(
            "Member name must start with a letter or digit and may contain only "
            "letters, digits, spaces and the characters . _ @ + -"
        )
    return member


class TokenRequest(_Base):
    """Exchange a team's long-lived API token for a short-lived session token."""

    api_token: SecretStr = Field(
        description="The team's API token, as issued by scripts/bootstrap.py.",
        examples=["nt_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
    )
    member: MemberName

    @field_validator("member")
    @classmethod
    def _check_member(cls, value: str) -> str:
        return _validate_member(value)


class TokenResponse(_Base):
    access_token: str
    token_type: str = "bearer"  # noqa: S105  # OAuth 2.0 token type, not a credential
    expires_in: int = Field(description="Seconds until the token expires.")
    team: TeamId
    member: MemberName


class IdentityResponse(_Base):
    """Who the presented session token says you are. Useful for debugging a client."""

    member: MemberName
    team: TeamId


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
    user: MemberName = Field(description="Member the note is attributed to.")
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
