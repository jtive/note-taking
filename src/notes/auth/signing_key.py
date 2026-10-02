"""Loading the JWT signing key.

In AWS the key is an SSM Parameter Store SecureString, fetched once per Lambda
execution environment and reused for every invocation that container serves.
Parameter Store was chosen over Secrets Manager because this needs encrypted
storage with an IAM-scoped read and nothing else; Secrets Manager's rotation
machinery would cost $0.40 per secret per month for features we do not use.

The key never passes through CI. The deploy role can write a placeholder but
the pipeline has no reason to read the value back.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import boto3

from notes.auth.tokens import MINIMUM_KEY_LENGTH
from notes.config import get_settings


@lru_cache(maxsize=1)
def get_signing_key() -> str:
    settings = get_settings()

    if settings.jwt_secret:
        key = settings.jwt_secret
    else:
        client: Any = boto3.client("ssm")
        response = client.get_parameter(Name=settings.jwt_secret_param, WithDecryption=True)
        key = str(response["Parameter"]["Value"])

    if len(key) < MINIMUM_KEY_LENGTH:
        # Fail at startup rather than issue tokens an attacker could brute
        # force offline. A short HMAC key is the weakest link in the scheme.
        raise RuntimeError(
            f"JWT signing key must be at least {MINIMUM_KEY_LENGTH} characters; got {len(key)}."
        )

    return key
