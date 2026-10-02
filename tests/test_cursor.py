"""Pagination cursors.

A cursor is a DynamoDB ExclusiveStartKey handed to the client, which makes it
attacker-controlled input on the way back in. These tests pin down what
happens when it is not what we issued.
"""

from __future__ import annotations

import base64
import json

import pytest

from notes.errors import ValidationError
from notes.repository import decode_cursor, encode_cursor

PARTITION = "TEAM#acme"


def test_round_trips_a_key() -> None:
    key = {"PK": PARTITION, "SK": "NOTE#01M3Z4HMB1VS68PXB1QS3EA6GT"}

    assert decode_cursor(encode_cursor(key), PARTITION) == key


def test_is_url_safe_and_unpadded() -> None:
    """It travels in a query string, so it must survive one unescaped."""
    cursor = encode_cursor({"PK": PARTITION, "SK": "NOTE#01M3Z4HMB1VS68PXB1QS3EA6GT"})

    assert "=" not in cursor
    assert "+" not in cursor
    assert "/" not in cursor


def test_a_cursor_for_another_partition_is_refused() -> None:
    """The check that stops a cursor being edited to page another team."""
    foreign = encode_cursor({"PK": "TEAM#globex", "SK": "NOTE#01M3Z4HMB1VS68PXB1QS3EA6GT"})

    with pytest.raises(ValidationError, match="does not belong"):
        decode_cursor(foreign, PARTITION)


@pytest.mark.parametrize(
    "cursor",
    [
        "!!!not-base64!!!",
        "",
        base64.urlsafe_b64encode(b"not json").decode().rstrip("="),
        base64.urlsafe_b64encode(json.dumps({"PK": PARTITION}).encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(json.dumps({"PK": 1, "SK": 2}).encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(json.dumps([PARTITION, "SK"]).encode()).decode().rstrip("="),
    ],
)
def test_a_malformed_cursor_is_refused(cursor: str) -> None:
    with pytest.raises(ValidationError):
        decode_cursor(cursor, PARTITION)
