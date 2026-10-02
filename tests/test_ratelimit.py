"""Rate limiting.

The limiter is the part of this service most likely to be wrong in a way that
only shows up under load, so it is tested through the API rather than by
inspecting the counter: the assertions are about what a client observes.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from notes.dependencies import get_client_ip
from notes.ratelimit import RateLimiter
from tests.conftest import TEAM_TOKENS, FakeClock


class TestTeamLimit:
    def test_requests_within_the_limit_are_allowed(self, make_client: Any, sign_in: Any) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=3)
        alice = sign_in(client, "alice", "acme")

        for _ in range(3):
            assert client.get("/notes", headers=alice.headers).status_code == 200

    def test_the_request_past_the_limit_is_refused(self, make_client: Any, sign_in: Any) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=3)
        alice = sign_in(client, "alice", "acme")
        for _ in range(3):
            client.get("/notes", headers=alice.headers)

        response = client.get("/notes", headers=alice.headers)

        assert response.status_code == 429
        assert response.json()["type"] == "urn:notes:error:rate-limit-exceeded"

    def test_a_refusal_says_when_to_retry(self, make_client: Any, sign_in: Any) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=1, NOTES_RATE_LIMIT_WINDOW_SECONDS=60)
        alice = sign_in(client, "alice", "acme")
        client.get("/notes", headers=alice.headers)

        response = client.get("/notes", headers=alice.headers)

        assert response.status_code == 429
        assert 1 <= int(response.headers["Retry-After"]) <= 60
        assert response.headers["X-RateLimit-Remaining"] == "0"

    def test_allowance_is_reported_on_successful_responses(
        self, make_client: Any, sign_in: Any
    ) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=5)
        alice = sign_in(client, "alice", "acme")

        first = client.get("/notes", headers=alice.headers)
        second = client.get("/notes", headers=alice.headers)

        assert first.headers["X-RateLimit-Limit"] == "5"
        assert first.headers["X-RateLimit-Remaining"] == "4"
        assert second.headers["X-RateLimit-Remaining"] == "3"

    def test_the_allowance_resets_in_the_next_window(
        self, make_client: Any, sign_in: Any, clock: FakeClock
    ) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=2, NOTES_RATE_LIMIT_WINDOW_SECONDS=60)
        alice = sign_in(client, "alice", "acme")
        for _ in range(2):
            client.get("/notes", headers=alice.headers)
        assert client.get("/notes", headers=alice.headers).status_code == 429

        clock.advance(60)

        assert client.get("/notes", headers=alice.headers).status_code == 200

    def test_members_of_a_team_share_one_allowance(self, make_client: Any, sign_in: Any) -> None:
        """Deliberate, and the direct consequence of a shared team credential.

        Keying on the member name instead would be free to escape: the name is
        declared by the caller, so a client could exchange a token under a new
        name whenever it ran out of allowance. The team is the only thing the
        credential actually proves, so it is the only safe key.
        """
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=2)
        alice = sign_in(client, "alice", "acme")
        bob = sign_in(client, "bob", "acme")
        for _ in range(2):
            client.get("/notes", headers=alice.headers)

        assert client.get("/notes", headers=bob.headers).status_code == 429

    def test_teams_do_not_consume_each_other_s_allowance(
        self, make_client: Any, sign_in: Any
    ) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=2)
        alice = sign_in(client, "alice", "acme")
        carol = sign_in(client, "carol", "globex")
        for _ in range(2):
            client.get("/notes", headers=alice.headers)
        assert client.get("/notes", headers=alice.headers).status_code == 429

        assert client.get("/notes", headers=carol.headers).status_code == 200

    def test_an_exhausted_allowance_blocks_writes_too(self, make_client: Any, sign_in: Any) -> None:
        client = make_client(NOTES_RATE_LIMIT_REQUESTS=2)
        alice = sign_in(client, "alice", "acme")
        for _ in range(2):
            client.get("/notes", headers=alice.headers)

        response = client.post("/notes", json={"note": "blocked"}, headers=alice.headers)

        assert response.status_code == 429


class TestAuthLimit:
    def test_token_exchanges_are_limited_by_address(self, make_client: Any) -> None:
        client = make_client(NOTES_AUTH_RATE_LIMIT_REQUESTS=3)

        statuses = [
            client.post(
                "/auth/token", json={"api_token": "nt_wrong-token-value", "member": "alice"}
            ).status_code
            for _ in range(4)
        ]

        assert statuses == [401, 401, 401, 429]

    def test_failed_attempts_count_against_the_limit(self, make_client: Any) -> None:
        """Otherwise the limit would not slow token guessing at all."""
        client = make_client(NOTES_AUTH_RATE_LIMIT_REQUESTS=2)
        for _ in range(2):
            client.post("/auth/token", json={"api_token": "nt_guess", "member": "alice"})

        response = client.post(
            "/auth/token", json={"api_token": TEAM_TOKENS["acme"], "member": "alice"}
        )

        # Even the correct token is refused, which is what makes the limit a
        # defence rather than a nuisance.
        assert response.status_code == 429

    def test_the_auth_limit_is_separate_from_the_team_limit(
        self, make_client: Any, sign_in: Any
    ) -> None:
        """Exhausting the exchange allowance must not disable an existing session."""
        client = make_client(NOTES_AUTH_RATE_LIMIT_REQUESTS=3, NOTES_RATE_LIMIT_REQUESTS=50)
        alice = sign_in(client, "alice", "acme")

        for _ in range(5):
            client.post("/auth/token", json={"api_token": "nt_wrong", "member": "alice"})

        assert client.get("/notes", headers=alice.headers).status_code == 200


class TestCounterMechanics:
    """Properties of the counter itself, below the HTTP layer."""

    def test_the_counter_is_shared_rather_than_per_instance(
        self, table: Any, clock: FakeClock
    ) -> None:
        """The whole point: two limiters, as two Lambda containers would be.

        An in-process counter would give each instance its own allowance and
        let twice the configured traffic through.
        """
        first = RateLimiter(table, clock)
        second = RateLimiter(table, clock)

        assert first.check(subject="team:x", limit=2, window_seconds=60).allowed
        assert second.check(subject="team:x", limit=2, window_seconds=60).allowed
        assert not second.check(subject="team:x", limit=2, window_seconds=60).allowed

    def test_counters_carry_a_ttl_so_nothing_accumulates(
        self, table: Any, clock: FakeClock
    ) -> None:
        limiter = RateLimiter(table, clock)
        limiter.check(subject="team:x", limit=5, window_seconds=60)

        items = table.scan()["Items"]
        counter = next(item for item in items if item["PK"] == "RL#team:x")

        # Expiry sits beyond the window's end, so DynamoDB's TTL sweep can
        # never delete a counter that is still in use.
        assert int(counter["expires_at"]) > clock.epoch_seconds() + 60

    def test_each_window_gets_its_own_counter(self, table: Any, clock: FakeClock) -> None:
        limiter = RateLimiter(table, clock)
        limiter.check(subject="team:x", limit=5, window_seconds=60)
        clock.advance(60)
        limiter.check(subject="team:x", limit=5, window_seconds=60)

        counters = [item for item in table.scan()["Items"] if item["PK"] == "RL#team:x"]

        assert len(counters) == 2
        assert all(int(item["request_count"]) == 1 for item in counters)

    def test_remaining_counts_down_to_zero(self, table: Any, clock: FakeClock) -> None:
        limiter = RateLimiter(table, clock)

        remaining = [
            limiter.check(subject="team:x", limit=3, window_seconds=60).remaining for _ in range(3)
        ]

        assert remaining == [2, 1, 0]


class TestClientIdentification:
    """Which address the per-IP limit is keyed on."""

    @staticmethod
    def _request(client: tuple[str, int] | None, forwarded: str | None = None) -> Request:
        headers: list[tuple[bytes, bytes]] = []
        if forwarded is not None:
            headers.append((b"x-forwarded-for", forwarded.encode()))
        return Request({"type": "http", "headers": headers, "client": client})

    def test_the_connection_address_beats_a_forwarded_header(self) -> None:
        """X-Forwarded-For is caller-supplied, so it must not take precedence.

        API Gateway reports the true address out of band. Trusting the header
        instead would let a caller send a different value on every request and
        get an unlimited number of fresh allowances.
        """
        request = self._request(("203.0.113.9", 443), forwarded="1.2.3.4")

        assert get_client_ip(request) == "203.0.113.9"

    def test_the_forwarded_header_is_only_a_fallback(self) -> None:
        """Used behind a local proxy, where there is no peer address."""
        request = self._request(None, forwarded="1.2.3.4, 5.6.7.8")

        assert get_client_ip(request) == "1.2.3.4"

    def test_an_unidentifiable_caller_still_gets_a_bucket(self) -> None:
        request = self._request(None)

        assert get_client_ip(request) == "unknown"
