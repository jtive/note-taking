"""Loading the JWT signing key from Parameter Store."""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from pydantic import ValidationError as PydanticValidationError

from notes.auth.signing_key import get_signing_key
from notes.config import Settings, get_settings
from tests.conftest import REGION

PARAMETER_NAME = "/notes/test/jwt-signing-key"
KEY = "a-signing-key-from-parameter-store-long-enough"


@pytest.fixture
def ssm(table: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Point configuration at SSM instead of an inline secret."""
    monkeypatch.delenv("NOTES_JWT_SECRET", raising=False)
    monkeypatch.setenv("NOTES_JWT_SECRET_PARAM", PARAMETER_NAME)
    get_settings.cache_clear()
    get_signing_key.cache_clear()
    return boto3.client("ssm", region_name=REGION)


def test_reads_a_securestring_parameter(ssm: Any) -> None:
    ssm.put_parameter(Name=PARAMETER_NAME, Value=KEY, Type="SecureString")

    assert get_signing_key() == KEY


def test_the_parameter_is_fetched_once_per_execution_environment(ssm: Any) -> None:
    """Otherwise every request would pay an SSM round trip and risk throttling."""
    ssm.put_parameter(Name=PARAMETER_NAME, Value=KEY, Type="SecureString")
    assert get_signing_key() == KEY

    ssm.delete_parameter(Name=PARAMETER_NAME)

    # Still served from cache, which is only possible if SSM was not consulted.
    assert get_signing_key() == KEY


def test_a_short_key_is_refused(ssm: Any) -> None:
    """A weak HMAC key would be the weakest link, so startup fails loudly."""
    ssm.put_parameter(Name=PARAMETER_NAME, Value="too-short", Type="SecureString")

    with pytest.raises(RuntimeError, match="at least 32 characters"):
        get_signing_key()


def test_configuration_without_any_key_source_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NOTES_JWT_SECRET", raising=False)
    monkeypatch.delenv("NOTES_JWT_SECRET_PARAM", raising=False)

    with pytest.raises(PydanticValidationError, match="NOTES_JWT_SECRET"):
        Settings()  # type: ignore[call-arg]
