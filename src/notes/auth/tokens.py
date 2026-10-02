"""JWT issuance and verification.

The token is the only thing the API trusts to say who you are and which team
you belong to, so the team claim is what every DynamoDB key is built from.
That makes verification the single most security-sensitive function here.

Stateless tokens were chosen over opaque tokens looked up in the database: the
authenticated path costs zero reads, and the team and user identity travel with
the request. The cost is that a token cannot be revoked before it expires,
which the one-hour lifetime bounds but does not remove. A revocation list keyed
on `jti` is the natural next step.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
from ulid import ULID

from notes.errors import AuthenticationError

# Pinned to a single symmetric algorithm. Passing this to jwt.decode is what
# rejects a token that claims "alg": "none", and what prevents an attacker from
# presenting an HMAC token signed with a public key when the server expects RSA.
ALGORITHM = "HS256"

MINIMUM_KEY_LENGTH = 32

REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "email", "team"]


@dataclass(frozen=True, slots=True)
class Principal:
    """The verified identity behind a request."""

    user_id: str
    email: str
    team_id: str


def issue_token(
    *,
    principal: Principal,
    signing_key: str,
    issuer: str,
    audience: str,
    ttl_seconds: int,
    now: datetime,
) -> str:
    expires_at = now + timedelta(seconds=ttl_seconds)
    claims = {
        "sub": principal.user_id,
        "email": principal.email,
        "team": principal.team_id,
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        # Unique per token, so a future revocation list has something to key on.
        "jti": str(ULID()),
    }
    return jwt.encode(claims, signing_key, algorithm=ALGORITHM)


def decode_token(token: str, *, signing_key: str, issuer: str, audience: str) -> Principal:
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=[ALGORITHM],
            audience=audience,
            issuer=issuer,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Token has expired. Request a new one.") from exc
    except jwt.InvalidTokenError as exc:
        # Covers a bad signature, a disallowed algorithm, a wrong audience or
        # issuer, and missing claims. The client learns nothing about which.
        raise AuthenticationError("Token is invalid.") from exc

    return Principal(
        user_id=str(claims["sub"]),
        email=str(claims["email"]),
        team_id=str(claims["team"]),
    )
