"""Note CRUD.

Authorization model: a note belongs to a team, every member of that team can
read it, and only its author can change or delete it. Reads are scoped by
building the DynamoDB partition key from the token's team claim, so a note
belonging to another team is not merely forbidden - it is unaddressable, and
the API reports 404 rather than 403 so it never confirms that an id exists
somewhere else.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Path, Query, Response, status

from notes.auth.tokens import Principal
from notes.config import Settings, get_settings
from notes.dependencies import enforce_user_rate_limit, get_principal, get_repository
from notes.errors import NotFoundError, ValidationError
from notes.models import (
    NoteCreateRequest,
    NoteListResponse,
    NoteResponse,
    NoteUpdateRequest,
)
from notes.repository import Note, Repository
from notes.routes import PROBLEM_RESPONSES

# Crockford base32, the ULID alphabet: digits plus uppercase letters without
# I, L, O or U. Rejecting anything else turns a malformed id into a 422 instead
# of a pointless DynamoDB round trip.
ULID_PATTERN = r"^[0-9A-HJKMNP-TV-Z]{26}$"

NoteId = Path(
    description="ULID of the note.",
    pattern=ULID_PATTERN,
    examples=["01M3Z4HMB1VS68PXB1QS3EA6GT"],
)

router = APIRouter(
    prefix="/notes",
    tags=["notes"],
    # Applied to every route below, which also makes authentication mandatory:
    # the limiter is keyed on the authenticated user id.
    dependencies=[Depends(enforce_user_rate_limit)],
    responses=PROBLEM_RESPONSES,
)


def _to_response(note: Note) -> NoteResponse:
    return NoteResponse(
        id=note.note_id,
        user=note.author_email,
        team=note.team_id,
        date=note.created_at,
        note=note.text,
        updated_at=note.updated_at,
        version=note.version,
    )


def _parse_if_match(value: str | None) -> int | None:
    """Read an If-Match header as the note version it refers to.

    `*` means "any existing version", which the conditional write already
    enforces by requiring the item to exist, so it maps to no version
    constraint.
    """
    if value is None:
        return None

    candidate = value.strip()
    if candidate == "*":
        return None
    if candidate.startswith("W/"):
        candidate = candidate[2:].strip()
    candidate = candidate.strip('"')

    try:
        return int(candidate)
    except ValueError as exc:
        raise ValidationError('If-Match must be a version ETag such as "3", or *.') from exc


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=NoteResponse,
    summary="Create a note in your team",
)
def create_note(
    payload: NoteCreateRequest,
    response: Response,
    principal: Principal = Depends(get_principal),
    repository: Repository = Depends(get_repository),
) -> NoteResponse:
    note = repository.create_note(
        team_id=principal.team_id,
        author_user_id=principal.user_id,
        author_email=principal.email,
        text=payload.note,
    )
    response.headers["Location"] = f"/notes/{note.note_id}"
    response.headers["ETag"] = f'"{note.version}"'
    return _to_response(note)


@router.get(
    "",
    response_model=NoteListResponse,
    summary="List your team's notes, newest first",
)
def list_notes(
    principal: Principal = Depends(get_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
    limit: int | None = Query(
        default=None,
        ge=1,
        description="Page size. Defaults to NOTES_DEFAULT_PAGE_SIZE and is capped at the maximum.",
    ),
    cursor: str | None = Query(default=None, description="next_cursor from a previous page."),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=256,
        description="Case-insensitive substring match on note text.",
    ),
) -> NoteListResponse:
    """Page through the team's notes.

    When `q` is supplied DynamoDB applies the page size before the filter, so a
    page may contain fewer matches than requested while more exist further
    back. Follow `next_cursor` until it is null rather than stopping at the
    first short page.
    """
    page_size = settings.default_page_size if limit is None else min(limit, settings.max_page_size)

    notes, next_cursor = repository.list_notes(
        team_id=principal.team_id,
        limit=page_size,
        cursor=cursor,
        query=q,
    )
    return NoteListResponse(
        items=[_to_response(note) for note in notes],
        next_cursor=next_cursor,
    )


@router.get(
    "/{note_id}",
    response_model=NoteResponse,
    summary="Read one note",
)
def read_note(
    response: Response,
    note_id: str = NoteId,
    principal: Principal = Depends(get_principal),
    repository: Repository = Depends(get_repository),
) -> NoteResponse:
    note = repository.get_note(team_id=principal.team_id, note_id=note_id)
    if note is None:
        raise NotFoundError("No note with that id exists in your team.")
    response.headers["ETag"] = f'"{note.version}"'
    return _to_response(note)


@router.patch(
    "/{note_id}",
    response_model=NoteResponse,
    summary="Edit a note you authored",
    responses={
        412: {"description": "If-Match did not match the current version."},
        **PROBLEM_RESPONSES,
    },
)
def update_note(
    payload: NoteUpdateRequest,
    response: Response,
    note_id: str = NoteId,
    if_match: str | None = Header(
        default=None,
        alias="If-Match",
        description='Version ETag from a previous read, for example "3". '
        "Omit to overwrite unconditionally.",
    ),
    principal: Principal = Depends(get_principal),
    repository: Repository = Depends(get_repository),
) -> NoteResponse:
    """Replace a note's text.

    Supplying If-Match makes the write conditional on the version you read, so
    two people editing the same note cannot silently overwrite each other; the
    second writer gets a 412 and can re-read. Omitting it means last write
    wins, which is the right default for a single-client editor.
    """
    note = repository.update_note(
        team_id=principal.team_id,
        note_id=note_id,
        author_user_id=principal.user_id,
        text=payload.note,
        expected_version=_parse_if_match(if_match),
    )
    response.headers["ETag"] = f'"{note.version}"'
    return _to_response(note)


@router.delete(
    "/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a note you authored",
)
def delete_note(
    note_id: str = NoteId,
    principal: Principal = Depends(get_principal),
    repository: Repository = Depends(get_repository),
) -> None:
    repository.delete_note(
        team_id=principal.team_id,
        note_id=note_id,
        author_user_id=principal.user_id,
    )
