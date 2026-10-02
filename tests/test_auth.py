"""Registration, token issuance, and the ways a token can be forged."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from tests.conftest import DEFAULT_PASSWORD, JWT_SECRET, Actor

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
        "sub": "01M3Z4HMB1VS68PXB1QS3EA6GT",
        "email": "attacker@evil.example",
        "team": "acme",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    claims.update(claim_overrides)
    claims = {key: value for key, value in claims.items() if value is not None}
    return jwt.encode(claims, secret, algorithm=algorithm)


class TestRegistration:
    def test_creates_a_user_and_returns_its_identity(self, client: TestClient) -> None:
        response = client.post(
            "/auth/register",
            json={"email": "alice@acme.example", "password": DEFAULT_PASSWORD, "team": "acme"},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "alice@acme.example"
        assert body["team"] == "acme"
        assert body["user_id"]

    def test_duplicate_email_is_rejected(self, client: TestClient) -> None:
        payload = {"email": "alice@acme.example", "password": DEFAULT_PASSWORD, "team": "acme"}
        assert client.post("/auth/register", json=payload).status_code == 201

        duplicate = client.post("/auth/register", json=payload)

        assert duplicate.status_code == 409
        assert duplicate.json()["type"] == "urn:notes:error:conflict"

    def test_email_is_normalised_to_lowercase(self, client: TestClient) -> None:
        created = client.post(
            "/auth/register",
            json={"email": "Alice@acme.example", "password": DEFAULT_PASSWORD, "team": "acme"},
        )
        assert created.json()["email"] == "alice@acme.example"

        # The normalised form is what the account is keyed on, so either
        # spelling must authenticate.
        issued = client.post(
            "/auth/token", json={"email": "ALICE@acme.example", "password": DEFAULT_PASSWORD}
        )
        assert issued.status_code == 200

    def test_password_shorter_than_the_minimum_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/auth/register",
            json={"email": "alice@acme.example", "password": "short", "team": "acme"},
        )

        assert response.status_code == 422
        assert response.json()["type"] == "urn:notes:error:validation-failed"

    @pytest.mark.parametrize("team", ["-acme", "acme-", "acme team", "acme_team", "acme!", ""])
    def test_malformed_team_names_are_rejected(self, client: TestClient, team: str) -> None:
        response = client.post(
            "/auth/register",
            json={"email": "alice@acme.example", "password": DEFAULT_PASSWORD, "team": team},
        )

        assert response.status_code == 422

    def test_team_names_are_case_insensitive(self, client: TestClient) -> None:
        """'Acme' and 'acme' are the same team, not two teams that look alike."""
        created = client.post(
            "/auth/register",
            json={"email": "alice@acme.example", "password": DEFAULT_PASSWORD, "team": "ACME"},
        )

        assert created.status_code == 201
        assert created.json()["team"] == "acme"

    def test_unexpected_fields_are_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/auth/register",
            json={
                "email": "alice@acme.example",
                "password": DEFAULT_PASSWORD,
                "team": "acme",
                "is_admin": True,
            },
        )

        assert response.status_code == 422


class TestTokenIssuance:
    def test_returns_a_bearer_token(self, client: TestClient, alice: Actor) -> None:
        response = client.post(
            "/auth/token", json={"email": alice.email, "password": DEFAULT_PASSWORD}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 3600
        assert body["access_token"]

    def test_token_carries_the_user_and_team(self, client: TestClient, alice: Actor) -> None:
        claims = jwt.decode(
            alice.token, JWT_SECRET, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER
        )

        assert claims["sub"] == alice.user_id
        assert claims["team"] == "acme"
        assert claims["email"] == alice.email
        assert claims["jti"], "a unique id is needed for any future revocation list"

    def test_wrong_password_is_rejected(self, client: TestClient, alice: Actor) -> None:
        response = client.post(
            "/auth/token", json={"email": alice.email, "password": "not-the-password"}
        )

        assert response.status_code == 401
        assert response.json()["type"] == "urn:notes:error:invalid-credentials"

    def test_unknown_account_is_indistinguishable_from_a_wrong_password(
        self, client: TestClient, alice: Actor
    ) -> None:
        unknown = client.post(
            "/auth/token", json={"email": "nobody@acme.example", "password": DEFAULT_PASSWORD}
        )
        wrong_password = client.post(
            "/auth/token", json={"email": alice.email, "password": "not-the-password"}
        )

        # Identical bodies, so the endpoint cannot be used to enumerate accounts.
        assert unknown.status_code == wrong_password.status_code == 401
        assert unknown.json() == wrong_password.json()


class TestTokenVerification:
    def test_identity_endpoint_echoes_the_token(self, client: TestClient, alice: Actor) -> None:
        response = client.get("/auth/me", headers=alice.headers)

        assert response.status_code == 200
        assert response.json() == {
            "user_id": alice.user_id,
            "email": alice.email,
            "team": "acme",
        }

    def test_missing_header_is_unauthorised(self, client: TestClient) -> None:
        response = client.get("/auth/me")

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")

    def test_garbage_token_is_rejected(self, client: TestClient) -> None:
        response = client.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"})

        assert response.status_code == 401

    def test_token_signed_with_another_key_is_rejected(self, client: TestClient) -> None:
        forged = mint(secret="a-different-key-of-sufficient-length-here")

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})

        assert response.status_code == 401

    def test_unsigned_token_is_rejected(self, client: TestClient) -> None:
        """An `alg: none` token must not be accepted on the strength of its claims."""
        unsigned = jwt.encode(
            {
                "sub": "whoever",
                "email": "attacker@evil.example",
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

    @pytest.mark.parametrize("claim", ["sub", "email", "team", "exp", "iat"])
    def test_token_missing_a_required_claim_is_rejected(
        self, client: TestClient, claim: str
    ) -> None:
        incomplete = mint(**{claim: None})

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {incomplete}"})

        assert response.status_code == 401

    @pytest.mark.parametrize(
        ("field", "value"),
        [("iss", "https://evil.test"), ("aud", "some-other-service")],
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
        other_team = mint(team="globex", sub=alice.user_id, email=alice.email).split(".")[1]
        spliced = f"{header}.{other_team}.{signature}"

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {spliced}"})

        assert response.status_code == 401
