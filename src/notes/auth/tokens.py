"""Session token issuance and verification.

A session token is what the API accepts on every request, and its `team` claim
is what every DynamoDB key is built from. That makes verification the single
most security-sensitive function here.

Stateless JWTs were chosen over opaque tokens looked up in the database: the
authenticated path costs zero reads, and the team travels with the request. The
cost is that a token cannot be revoked before it expires, which the one-hour
lifetime bounds but does not remove. A revocation list keyed on `jti` is the
natural next step, and `jti` is already issued so that it can be added without
invalidating anything.
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

REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "team"]


@dataclass(frozen=True, slots=True)
class Principal:
    """The identity behind a request.

    `team_id` is authenticated: it came from an API token the caller proved
    they hold. `member` is only attributed: it is whatever the caller declared
    at exchange time. Nothing that needs to be trustworthy may depend on
    `member` alone - see the note in notes/auth/team_tokens.py.
    """

    member: str
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
        "sub": principal.member,
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

    return Principal(member=str(claims["sub"]), team_id=str(claims["team"]))
