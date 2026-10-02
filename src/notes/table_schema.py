"""The physical DynamoDB layout: one table, two item types, no secondary indexes.

Items share the table and are distinguished by their key prefixes:

    Note        PK=TEAM#{team}    SK=NOTE#{ulid}
    Rate limit  PK=RL#{subject}   SK=W#{window_start}

There is no user or team item. Teams and their credentials live in the token
registry (see notes/auth/team_tokens.py), so the table holds only what the
application actually generates.

Two properties of this layout carry most of the design weight.

First, a note's partition key is derived from the team, and the team always
comes from a verified token claim. A caller therefore cannot build a key that
addresses another team's data, so tenant isolation is a property of the key
schema rather than a permission check someone can forget to write.

Second, note identifiers are ULIDs, which sort lexicographically by creation
time. That makes SK=NOTE#{ulid} serve as both a unique identifier for point
reads and a chronological sort key for listing, so paginated newest-first
queries need no secondary index. The tradeoff is that the natural ordering is
by creation time; ordering by last update would require a GSI.

template.yaml is the authoritative definition for deployed environments. The
spec below exists so tests and local development build a byte-identical table
instead of approximating it.
"""

from __future__ import annotations

from typing import Any

PARTITION_KEY = "PK"
SORT_KEY = "SK"

TEAM_PK_PREFIX = "TEAM#"
NOTE_SK_PREFIX = "NOTE#"

RATE_LIMIT_PK_PREFIX = "RL#"
RATE_LIMIT_SK_PREFIX = "W#"

TTL_ATTRIBUTE = "expires_at"


def team_partition(team_id: str) -> str:
    return f"{TEAM_PK_PREFIX}{team_id}"


def note_sort_key(note_id: str) -> str:
    return f"{NOTE_SK_PREFIX}{note_id}"


def note_key(team_id: str, note_id: str) -> dict[str, str]:
    return {PARTITION_KEY: team_partition(team_id), SORT_KEY: note_sort_key(note_id)}


def rate_limit_key(subject: str, window_start: int) -> dict[str, str]:
    return {
        PARTITION_KEY: f"{RATE_LIMIT_PK_PREFIX}{subject}",
        SORT_KEY: f"{RATE_LIMIT_SK_PREFIX}{window_start}",
    }


def create_table_args(table_name: str) -> dict[str, Any]:
    """CreateTable arguments mirroring the table in template.yaml."""
    return {
        "TableName": table_name,
        "KeySchema": [
            {"AttributeName": PARTITION_KEY, "KeyType": "HASH"},
            {"AttributeName": SORT_KEY, "KeyType": "RANGE"},
        ],
        "AttributeDefinitions": [
            {"AttributeName": PARTITION_KEY, "AttributeType": "S"},
            {"AttributeName": SORT_KEY, "AttributeType": "S"},
        ],
        "BillingMode": "PAY_PER_REQUEST",
    }
