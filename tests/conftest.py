"""Test fixtures.

Tests run against moto's in-process DynamoDB rather than a stub repository, and
the table is built from notes.table_schema.create_table_args - the same
function local development uses and a mirror of template.yaml. That means the
conditional writes, the ULID sort ordering and the rate-limit counter are all
exercised as real DynamoDB operations, which is where the interesting bugs in
this design would be.

Environment variables are set at import time because notes.main builds the
application at module scope, so configuration has to exist before the first
import of anything under notes.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

TABLE_NAME = "note-taking-test"
JWT_SECRET = "test-signing-key-long-enough-to-satisfy-validation"
REGION = "us-east-2"

#: Stand-ins for the tokens scripts/bootstrap.py mints into SSM. Supplying the
#: plaintext form of the registry exercises the same parsing path that a local
#: .env would use; the deployed service is handed digests instead.
TEAM_TOKENS = {
    "acme": "nt_test-token-for-acme-team-0000000000",
    "globex": "nt_test-token-for-globex-team-000000000",
    "initech": "nt_test-token-for-initech-team-00000000",
    "umbrella": "nt_test-token-for-umbrella-team-0000000",
}

os.environ.update(
    {
        "NOTES_TABLE_NAME": TABLE_NAME,
        "NOTES_JWT_SECRET": JWT_SECRET,
        "NOTES_TEAM_TOKENS": json.dumps(
            [{"team_id": team, "token": token} for team, token in TEAM_TOKENS.items()]
        ),
        # Generous by default so no test trips a limit by accident. The rate
        # limit tests ask for small limits explicitly.
        "NOTES_RATE_LIMIT_REQUESTS": "10000",
        "NOTES_AUTH_RATE_LIMIT_REQUESTS": "10000",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
    }
)

import boto3  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from moto import mock_aws  # noqa: E402

from notes.auth.signing_key import get_signing_key  # noqa: E402
from notes.auth.team_tokens import get_team_credentials  # noqa: E402
from notes.clock import Clock, get_clock  # noqa: E402
from notes.config import get_settings  # noqa: E402
from notes.dependencies import get_table  # noqa: E402
from notes.main import create_app  # noqa: E402
from notes.table_schema import TTL_ATTRIBUTE, create_table_args  # noqa: E402


class FakeClock(Clock):
    """A clock the test moves by hand, so window rollover is deterministic."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += timedelta(seconds=seconds)


def _clear_caches() -> None:
    get_settings.cache_clear()
    get_signing_key.cache_clear()
    get_team_credentials.cache_clear()
    get_table.cache_clear()


@pytest.fixture(autouse=True)
def _isolate_caches() -> Iterator[None]:
    """Keep per-execution-environment caches from leaking between tests."""
    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture
def clock() -> FakeClock:
    """A controllable clock anchored near real time.

    It cannot be an arbitrary fixed date: tokens are issued against this clock
    but PyJWT validates `exp` against the system clock, so a clock set in the
    past would hand every test an already-expired token. Truncating to a minute
    boundary keeps the rate limiter's window arithmetic easy to follow.
    """
    now = datetime.now(UTC).replace(microsecond=0)
    return FakeClock(now - timedelta(seconds=now.second))


@pytest.fixture
def table(clock: FakeClock) -> Iterator[Any]:
    with mock_aws():
        client = boto3.client("dynamodb", region_name=REGION)
        client.create_table(**create_table_args(TABLE_NAME))
        client.update_time_to_live(
            TableName=TABLE_NAME,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": TTL_ATTRIBUTE},
        )
        yield boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)


@pytest.fixture
def make_client(
    table: Any,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """Build a client, optionally overriding settings for this test only."""

    def _make(**overrides: object) -> TestClient:
        for key, value in overrides.items():
            monkeypatch.setenv(key, str(value))
        _clear_caches()
        app = create_app()
        app.dependency_overrides[get_clock] = lambda: clock
        # raise_server_exceptions=False so the catch-all handler's 500 response
        # can be asserted on instead of the exception escaping into pytest.
        return TestClient(app, raise_server_exceptions=False)

    return _make


@pytest.fixture
def client(make_client: Any) -> TestClient:
    return make_client()


@dataclass(frozen=True)
class Actor:
    """A team member holding a session token, ready to make requests."""

    member: str
    team: str
    token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@pytest.fixture
def sign_in() -> Any:
    """Trade a team's API token for a session token, as a client would."""

    def _sign_in(client: TestClient, member: str, team: str) -> Actor:
        issued = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS[team], "member": member},
        )
        assert issued.status_code == 200, issued.text
        return Actor(member=member, team=team, token=issued.json()["access_token"])

    return _sign_in


@pytest.fixture
def alice(client: TestClient, sign_in: Any) -> Actor:
    return sign_in(client, "alice", "acme")


@pytest.fixture
def bob(client: TestClient, sign_in: Any) -> Actor:
    """Alice's teammate: same team token, different attributed member."""
    return sign_in(client, "bob", "acme")


@pytest.fixture
def carol(client: TestClient, sign_in: Any) -> Actor:
    """A different team entirely, for isolation tests."""
    return sign_in(client, "carol", "globex")
