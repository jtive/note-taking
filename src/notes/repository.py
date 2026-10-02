"""All DynamoDB access for notes.

Every method takes the caller's team as an argument and builds keys from it, so
there is no code path that can read or write outside the caller's partition.
See notes/table_schema.py for the layout and why it is shaped this way.

Expressions are written as literal strings with explicit attribute name and
value maps rather than built with boto3's `Key`/`Attr` helpers. The helpers
generate their own placeholder maps, which cannot be combined with
hand-written ones in the same call; keeping everything explicit avoids that
trap and makes each condition readable as the DynamoDB expression it becomes.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError
from ulid import ULID

from notes import table_schema as schema
from notes.clock import Clock, to_iso8601
from notes.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    PreconditionFailedError,
    ValidationError,
)

CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"


@dataclass(frozen=True, slots=True)
class Note:
    note_id: str
    team_id: str
    author: str
    text: str
    created_at: str
    updated_at: str
    version: int


def encode_cursor(last_evaluated_key: dict[str, Any]) -> str:
    payload = json.dumps(
        {
            schema.PARTITION_KEY: last_evaluated_key[schema.PARTITION_KEY],
            schema.SORT_KEY: last_evaluated_key[schema.SORT_KEY],
        },
        separators=(",", ":"),
    )
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_cursor(cursor: str, expected_partition: str) -> dict[str, str]:
    """Turn an opaque cursor back into an ExclusiveStartKey.

    The partition is re-checked against the caller's own partition. A cursor is
    client-visible state, so a caller could otherwise hand back an edited one
    and try to resume paging inside another team.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        partition = payload[schema.PARTITION_KEY]
        sort = payload[schema.SORT_KEY]
    except (KeyError, ValueError, TypeError) as exc:
        raise ValidationError("Cursor is malformed.") from exc

    if not isinstance(partition, str) or not isinstance(sort, str):
        raise ValidationError("Cursor is malformed.")
    if partition != expected_partition:
        raise ValidationError("Cursor does not belong to this collection.")

    return {schema.PARTITION_KEY: partition, schema.SORT_KEY: sort}


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


class Repository:
    def __init__(self, table: Any, clock: Clock) -> None:
        self._table = table
        self._clock = clock

    def create_note(self, *, team_id: str, author: str, text: str) -> Note:
        now = to_iso8601(self._clock.now())
        note = Note(
            note_id=str(ULID()),
            team_id=team_id,
            author=author,
            text=text,
            created_at=now,
            updated_at=now,
            version=1,
        )

        self._table.put_item(
            Item={
                **schema.note_key(team_id, note.note_id),
                "entity_type": "note",
                "note_id": note.note_id,
                "team_id": team_id,
                "author": author,
                "note": text,
                # Lowercase shadow copy so ?q= can match case-insensitively.
                # DynamoDB's contains() has no case-folding option, so the
                # alternative is a case-sensitive search. Storing the text
                # twice costs space; for notes capped at 20k characters that
                # is a better trade than surprising search results.
                "note_lower": text.lower(),
                "created_at": now,
                "updated_at": now,
                "version": 1,
            },
            # Guards against a ULID collision overwriting an existing note.
            ConditionExpression="attribute_not_exists(#sk)",
            ExpressionAttributeNames={"#sk": schema.SORT_KEY},
        )
        return note

    def get_note(self, *, team_id: str, note_id: str) -> Note | None:
        response: dict[str, Any] = self._table.get_item(Key=schema.note_key(team_id, note_id))
        item = response.get("Item")
        return None if item is None else self._to_note(item)

    def list_notes(
        self,
        *,
        team_id: str,
        limit: int,
        cursor: str | None = None,
        query: str | None = None,
    ) -> tuple[list[Note], str | None]:
        """Newest-first page of the team's notes.

        Ordering comes free from the ULID sort key read in reverse. When `query`
        is set, DynamoDB applies `Limit` before the filter, so a page can hold
        fewer than `limit` matches while further matches remain; keep following
        `next_cursor` until it is null rather than stopping on a short page.
        """
        partition = schema.team_partition(team_id)

        names = {"#pk": schema.PARTITION_KEY, "#sk": schema.SORT_KEY}
        values: dict[str, Any] = {":pk": partition, ":prefix": schema.NOTE_SK_PREFIX}

        request: dict[str, Any] = {
            "KeyConditionExpression": "#pk = :pk AND begins_with(#sk, :prefix)",
            "ScanIndexForward": False,
            "Limit": limit,
        }

        if query:
            names["#search"] = "note_lower"
            values[":query"] = query.strip().lower()
            request["FilterExpression"] = "contains(#search, :query)"

        request["ExpressionAttributeNames"] = names
        request["ExpressionAttributeValues"] = values

        if cursor:
            request["ExclusiveStartKey"] = decode_cursor(cursor, partition)

        response: dict[str, Any] = self._table.query(**request)
        notes = [self._to_note(item) for item in response.get("Items", [])]

        last_key = response.get("LastEvaluatedKey")
        return notes, encode_cursor(last_key) if last_key else None

    def update_note(
        self,
        *,
        team_id: str,
        note_id: str,
        author: str,
        text: str,
        expected_version: int | None = None,
    ) -> Note:
        """Replace a note's text. Only its author may do so.

        Authorship and the optional If-Match version are enforced inside the
        conditional write, so there is no window between checking and writing.
        """
        condition = "attribute_exists(#sk) AND #author = :author"
        values: dict[str, Any] = {
            ":author": author,
            ":note": text,
            ":lower": text.lower(),
            ":now": to_iso8601(self._clock.now()),
            ":one": 1,
        }
        if expected_version is not None:
            condition += " AND #version = :expected_version"
            values[":expected_version"] = expected_version

        try:
            response: dict[str, Any] = self._table.update_item(
                Key=schema.note_key(team_id, note_id),
                UpdateExpression=(
                    "SET #note = :note, #lower = :lower, #updated = :now ADD #version :one"
                ),
                ConditionExpression=condition,
                ExpressionAttributeNames={
                    "#sk": schema.SORT_KEY,
                    "#author": "author",
                    "#note": "note",
                    "#lower": "note_lower",
                    "#updated": "updated_at",
                    "#version": "version",
                },
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            if _error_code(exc) == CONDITIONAL_CHECK_FAILED:
                self._raise_for_failed_write(
                    team_id=team_id,
                    note_id=note_id,
                    author=author,
                    expected_version=expected_version,
                )
            raise

        return self._to_note(response["Attributes"])

    def delete_note(self, *, team_id: str, note_id: str, author: str) -> None:
        try:
            self._table.delete_item(
                Key=schema.note_key(team_id, note_id),
                ConditionExpression="attribute_exists(#sk) AND #author = :author",
                ExpressionAttributeNames={
                    "#sk": schema.SORT_KEY,
                    "#author": "author",
                },
                ExpressionAttributeValues={":author": author},
            )
        except ClientError as exc:
            if _error_code(exc) == CONDITIONAL_CHECK_FAILED:
                self._raise_for_failed_write(
                    team_id=team_id,
                    note_id=note_id,
                    author=author,
                    expected_version=None,
                )
            raise

    def _raise_for_failed_write(
        self,
        *,
        team_id: str,
        note_id: str,
        author: str,
        expected_version: int | None,
    ) -> None:
        """Turn a failed condition into the right status code.

        DynamoDB reports only that the condition failed, not which clause. The
        extra read happens on the error path only, so the success path still
        costs a single write.
        """
        existing = self.get_note(team_id=team_id, note_id=note_id)

        if existing is None:
            raise NotFoundError("No note with that id exists in your team.")
        if existing.author != author:
            raise PermissionDeniedError("Only the author of a note can modify or delete it.")
        if expected_version is not None and existing.version != expected_version:
            raise PreconditionFailedError(
                "The note changed since you read it. Re-read it and retry.",
                headers={"ETag": f'"{existing.version}"'},
            )
        # The note exists, is ours, and matches the expected version, so a
        # concurrent write must have raced us between the failure and the read.
        raise ConflictError("The note was modified concurrently. Retry the request.")

    @staticmethod
    def _to_note(item: dict[str, Any]) -> Note:
        return Note(
            note_id=str(item["note_id"]),
            team_id=str(item["team_id"]),
            author=str(item["author"]),
            text=str(item["note"]),
            created_at=str(item["created_at"]),
            updated_at=str(item["updated_at"]),
            version=int(item["version"]),
        )
