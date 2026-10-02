"""Password hashing with bcrypt.

bcrypt is used directly rather than through passlib, which has been
intermittently unmaintained and broke against bcrypt 4.x. The cost factor is
configurable (NOTES_BCRYPT_ROUNDS, default 12) because it is the one knob that
trades login latency against resistance to offline cracking, and the right
setting depends on the hardware it runs on.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from functools import lru_cache

import bcrypt


def _prepare(password: str) -> bytes:
    """Normalise any password into 44 bytes that bcrypt can hash losslessly.

    bcrypt silently truncates input beyond 72 bytes and stops at the first NUL
    byte, so two different long passwords can collide. Hashing with SHA-256
    first and base64-encoding the digest produces a fixed-length,
    NUL-free input, which removes both problems.
    """
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str, *, rounds: int) -> str:
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(password), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        # A stored hash that bcrypt cannot parse is a failed verification, not
        # a server error.
        return False


@lru_cache(maxsize=4)
def _decoy_hash(rounds: int) -> str:
    return hash_password(secrets.token_urlsafe(32), rounds=rounds)


def spend_verification_time(*, rounds: int) -> None:
    """Burn the same CPU a real check would, for an account that does not exist.

    Without this, an unknown email returns in microseconds while a known email
    with a wrong password takes a few hundred milliseconds, which turns the
    token endpoint into an account enumeration oracle. Computed once per
    execution environment and reused.
    """
    verify_password("", _decoy_hash(rounds))
