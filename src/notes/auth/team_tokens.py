"""The long-lived team credentials that can be exchanged for a session token.

Each of the four teams holds one API token. Presenting it to POST /auth/token
returns a short-lived JWT, and that JWT is what the rest of the API accepts.
The split matters: the long-lived secret is sent once per session rather than
on every request, and the thing travelling on each call expires within the hour.

Only a SHA-256 digest of each token is stored, so reading the registry out of
Parameter Store does not yield a usable credential. SHA-256 rather than bcrypt
is deliberate - these tokens are 256 bits of CSPRNG output, so there is no
low-entropy guess space for a slow KDF to protect, and paying bcrypt's cost per
exchange would buy nothing. Passwords would be a different matter.

The honest limitation: an API token authenticates a *team*, not a person. The
member name in the exchange is attribution, not authentication, so anyone
holding a team's token can write as any member of that team. The README says so
plainly; it is the cost of a shared credential, and the fix is per-member
credentials rather than anything clever here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import boto3

from notes.config import get_settings
from notes.errors import InvalidCredentialsError

#: Recognisable prefix so leaked tokens are easy to spot in logs, and so secret
#: scanners have a pattern to match on.
TOKEN_PREFIX = "nt_"  # noqa: S105  # a format marker, not a secret

MINIMUM_TOKEN_LENGTH = 32


@dataclass(frozen=True, slots=True)
class TeamCredential:
    team_id: str
    token_sha256: str


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_registry(raw: str) -> tuple[TeamCredential, ...]:
    """Read the registry document.

    Records may carry either `token_sha256`, which is what the bootstrap script
    writes to Parameter Store, or a plaintext `token`, which keeps a local
    .env file readable. Both end up as a digest, so there is one comparison
    path regardless of how the registry was written.
    """
    document = json.loads(raw)
    records = document["teams"] if isinstance(document, dict) else document

    credentials: list[TeamCredential] = []
    for record in records:
        team_id = str(record["team_id"]).strip().lower()
        if "token_sha256" in record:
            digest = str(record["token_sha256"]).strip().lower()
        else:
            digest = fingerprint(str(record["token"]))
        credentials.append(TeamCredential(team_id=team_id, token_sha256=digest))

    if not credentials:
        raise RuntimeError("Team token registry is empty; no caller could authenticate.")

    return tuple(credentials)


@lru_cache(maxsize=1)
def get_team_credentials() -> tuple[TeamCredential, ...]:
    """Load the registry once per execution environment."""
    settings = get_settings()

    if settings.team_tokens:
        raw = settings.team_tokens
    else:
        client: Any = boto3.client("ssm")
        response = client.get_parameter(Name=settings.team_tokens_param, WithDecryption=True)
        raw = str(response["Parameter"]["Value"])

    return _parse_registry(raw)


def resolve_team(presented_token: str) -> str:
    """Return the team a token belongs to, or reject it.

    Every credential is compared even after a match, so the time taken does not
    reveal which team matched or how far down the list it sat. The comparison
    itself is over fixed-length digests via compare_digest, so it leaks nothing
    about the secret either.
    """
    # Rejecting an obviously malformed token early returns faster than a real
    # comparison, which reveals that the value was the wrong shape. The shape
    # is documented, so there is nothing secret in that; the point of the
    # constant-time path below is to protect the bytes, not the format.
    if not presented_token.startswith(TOKEN_PREFIX) or len(presented_token) < MINIMUM_TOKEN_LENGTH:
        raise InvalidCredentialsError

    presented = fingerprint(presented_token)

    matched: str | None = None
    for credential in get_team_credentials():
        if hmac.compare_digest(presented, credential.token_sha256):
            matched = credential.team_id

    if matched is None:
        raise InvalidCredentialsError

    return matched
