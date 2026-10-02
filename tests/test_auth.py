"""The token exchange, and the ways a session token can be forged."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from tests.conftest import JWT_SECRET, TEAM_TOKENS, Actor

ISSUER = "note-taking-api"
AUDIENCE = "note-taking-clients"


def mint(
    *,
    secret: str = JWT_SECRET,
    algorithm: str = "HS256",
    **claim_overrides: Any,
) -> str:
    """Build a token directly, to test what verification must reject."""
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": "attacker",
        "team": "acme",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    claims.update(claim_overrides)
    claims = {key: value for key, value in claims.items() if value is not None}
    return jwt.encode(claims, secret, algorithm=algorithm)


class TestTokenExchange:
    def test_returns_a_short_lived_bearer_token(self, client: TestClient) -> None:
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"], "member": "alice"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 3600
        assert body["team"] == "acme"
        assert body["member"] == "alice"
        assert body["access_token"]

    @pytest.mark.parametrize("team", sorted(TEAM_TOKENS))
    def test_every_team_token_resolves_to_its_own_team(self, client: TestClient, team: str) -> None:
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS[team], "member": "someone"},
        )

        assert response.status_code == 200
        assert response.json()["team"] == team

    def test_the_team_comes_from_the_token_not_the_request(self, client: TestClient) -> None:
        """A caller cannot name the team they would like to be in.

        The schema forbids unknown fields, so an attempt to pass one is a 422
        rather than a silently ignored field that might later be honoured.
        """
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"], "member": "alice", "team": "globex"},
        )

        assert response.status_code == 422

    def test_token_carries_the_member_and_team(self, alice: Actor) -> None:
        claims = jwt.decode(
            alice.token, JWT_SECRET, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER
        )

        assert claims["sub"] == "alice"
        assert claims["team"] == "acme"
        assert claims["jti"], "a unique id is needed for any future revocation list"

    def test_unknown_api_token_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/auth/token",
            json={"api_token": "nt_not-a-real-token-but-the-right-shape", "member": "alice"},
        )

        assert response.status_code == 401
        assert response.json()["type"] == "urn:notes:error:invalid-credentials"

    def test_a_near_miss_is_indistinguishable_from_nonsense(self, client: TestClient) -> None:
        """Getting most of a token right must not be reported differently."""
        almost = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"][:-1] + "x", "member": "alice"},
        )
        nonsense = client.post(
            "/auth/token",
            json={"api_token": "completely-wrong-but-long-enough-value", "member": "alice"},
        )

        assert almost.status_code == nonsense.status_code == 401
        assert almost.json() == nonsense.json()

    def test_an_absurdly_short_token_is_rejected_without_comparison(
        self, client: TestClient
    ) -> None:
        response = client.post("/auth/token", json={"api_token": "nt_x", "member": "alice"})

        assert response.status_code == 401

    def test_the_api_token_is_never_echoed_back(self, client: TestClient) -> None:
        """Not in the success body, and not in the 401 either."""
        secret = TEAM_TOKENS["acme"]

        issued = client.post("/auth/token", json={"api_token": secret, "member": "alice"})
        refused = client.post("/auth/token", json={"api_token": "nt_wrong", "member": "alice"})

        assert secret not in issued.text
        assert "nt_wrong" not in refused.text

    @pytest.mark.parametrize("member", ["", "   ", "-alice", "alice\x00bob", "al/ice", "a" * 65])
    def test_malformed_member_names_are_rejected(self, client: TestClient, member: str) -> None:
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"], "member": member},
        )

        assert response.status_code == 422
        assert response.json()["type"] == "urn:notes:error:validation-failed"

    def test_member_whitespace_is_collapsed(self, client: TestClient) -> None:
        """So 'Alice  Smith' and 'Alice Smith' are not two different authors."""
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"], "member": "  Alice   Smith  "},
        )

        assert response.status_code == 200
        assert response.json()["member"] == "Alice Smith"

    @pytest.mark.parametrize("member", ["alice\nbob", "alice\nINFO forged line", "alice\r\nbob"])
    def test_an_embedded_newline_never_survives(self, client: TestClient, member: str) -> None:
        """The name reaches log lines and a JWT claim, so a raw newline would
        let a caller forge an extra log entry. Collapsing whitespace is what
        prevents it; a name that is still malformed afterwards is rejected
        instead. Either outcome satisfies the invariant.
        """
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"], "member": member},
        )

        if response.status_code == 200:
            assert "\n" not in response.json()["member"]
        else:
            assert response.status_code == 422

    def test_an_email_address_is_an_acceptable_member_name(self, client: TestClient) -> None:
        response = client.post(
            "/auth/token",
            json={"api_token": TEAM_TOKENS["acme"], "member": "alice@acme.example"},
        )

        assert response.status_code == 200
        assert response.json()["member"] == "alice@acme.example"

    def test_the_api_token_is_required(self, client: TestClient) -> None:
        response = client.post("/auth/token", json={"member": "alice"})

        assert response.status_code == 422


class TestTokenVerification:
    def test_identity_endpoint_echoes_the_token(self, client: TestClient, alice: Actor) -> None:
        response = client.get("/auth/me", headers=alice.headers)

        assert response.status_code == 200
        assert response.json() == {"member": "alice", "team": "acme"}

    def test_missing_header_is_unauthorised(self, client: TestClient) -> None:
        response = client.get("/auth/me")

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")

    def test_garbage_token_is_rejected(self, client: TestClient) -> None:
        response = client.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"})

        assert response.status_code == 401

    def test_an_api_token_is_not_a_session_token(self, client: TestClient) -> None:
        """The long-lived credential must only work at the exchange endpoint."""
        response = client.get(
            "/auth/me", headers={"Authorization": f"Bearer {TEAM_TOKENS['acme']}"}
        )

        assert response.status_code == 401

    def test_token_signed_with_another_key_is_rejected(self, client: TestClient) -> None:
        forged = mint(secret="a-different-key-of-sufficient-length-here")

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})

        assert response.status_code == 401

    def test_unsigned_token_is_rejected(self, client: TestClient) -> None:
        """An `alg: none` token must not be accepted on the strength of its claims."""
        unsigned = jwt.encode(
            {
                "sub": "attacker",
                "team": "acme",
                "iss": ISSUER,
                "aud": AUDIENCE,
                "iat": int(datetime.now(UTC).timestamp()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            },
            key="",
            algorithm="none",
        )

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {unsigned}"})

        assert response.status_code == 401

    # PyJWT warns that our key is short for SHA-512. That is a property of the
    # forged token this test builds on purpose, not of anything the service does.
    @pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
    def test_token_using_a_different_algorithm_is_rejected(self, client: TestClient) -> None:
        """Correct secret, wrong algorithm: still rejected, because alg is pinned."""
        forged = mint(algorithm="HS512")

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})

        assert response.status_code == 401

    def test_expired_token_is_rejected(self, client: TestClient) -> None:
        past = datetime.now(UTC) - timedelta(hours=2)
        expired = mint(
            iat=int(past.timestamp()),
            exp=int((past + timedelta(hours=1)).timestamp()),
        )

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {expired}"})

        assert response.status_code == 401
        assert "expired" in response.json()["detail"].lower()

    @pytest.mark.parametrize("claim", ["sub", "team", "exp", "iat"])
    def test_token_missing_a_required_claim_is_rejected(
        self, client: TestClient, claim: str
    ) -> None:
        incomplete = mint(**{claim: None})

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {incomplete}"})

        assert response.status_code == 401

    @pytest.mark.parametrize(
        ("field", "value"),
        [("iss", "https://evil.example"), ("aud", "some-other-service")],
    )
    def test_token_for_another_issuer_or_audience_is_rejected(
        self, client: TestClient, field: str, value: str
    ) -> None:
        """A valid token minted for a different service must not work here."""
        foreign = mint(**{field: value})

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {foreign}"})

        assert response.status_code == 401

    def test_tampering_with_the_team_claim_invalidates_the_signature(
        self, client: TestClient, alice: Actor
    ) -> None:
        header, _original_payload, signature = alice.token.split(".")
        other_team = mint(team="globex", sub=alice.member).split(".")[1]
        spliced = f"{header}.{other_team}.{signature}"

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {spliced}"})

        assert response.status_code == 401
