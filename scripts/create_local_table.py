#!/usr/bin/env python
"""Create the notes table in DynamoDB Local.

    docker compose up -d
    python scripts/create_local_table.py

Safe to re-run; an existing table is left untouched.
"""

from __future__ import annotations

import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from notes.table_schema import TTL_ATTRIBUTE, create_table_args

ENDPOINT_URL = os.environ.get("NOTES_DYNAMODB_ENDPOINT_URL", "http://localhost:8000")
TABLE_NAME = os.environ.get("NOTES_TABLE_NAME", "note-taking-local")


def main() -> int:
    client = boto3.client(
        "dynamodb",
        endpoint_url=ENDPOINT_URL,
        region_name=os.environ.get("AWS_REGION", "us-east-2"),
        # DynamoDB Local requires credentials to be present but ignores them.
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "local"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "local"),
    )

    try:
        client.create_table(**create_table_args(TABLE_NAME))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
        print(f"Table {TABLE_NAME!r} already exists at {ENDPOINT_URL}.")
        return 0

    client.get_waiter("table_exists").wait(TableName=TABLE_NAME)

    # DynamoDB Local accepts the TTL call but never actually expires items, so
    # rate-limit windows accumulate locally. Harmless: reads are keyed by the
    # current window, and -inMemory discards everything on restart.
    client.update_time_to_live(
        TableName=TABLE_NAME,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": TTL_ATTRIBUTE},
    )

    print(f"Created table {TABLE_NAME!r} at {ENDPOINT_URL}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
