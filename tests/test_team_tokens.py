"""Loading and comparing the team API token registry."""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest
from pydantic import ValidationError as PydanticValidationError

from notes.auth.team_tokens import fingerprint, get_team_credentials, resolve_team
from notes.config import Settings, get_settings
from notes.errors import InvalidCredentialsError
from tests.conftest import REGION, TEAM_TOKENS

PARAMETER_NAME = "/notes/test/team-tokens"
SSM_TOKEN = "nt_a-token-that-only-exists-in-parameter-store"


@pytest.fixture
def ssm(table: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Point configuration at SSM instead of an inline registry."""
    monkeypatch.delenv("NOTES_TEAM_TOKENS", raising=False)
    monkeypatch.setenv("NOTES_TEAM_TOKENS_PARAM", PARAMETER_NAME)
    get_settings.cache_clear()
    get_team_credentials.cache_clear()
    return boto3.client("ssm", region_name=REGION)


def _put(ssm: Any, records: list[dict[str, str]]) -> None:
    ssm.put_parameter(Name=PARAMETER_NAME, Value=json.dumps(records), Type="SecureString")


class TestRegistryLoading:
    def test_reads_digests_from_a_securestring_parameter(self, ssm: Any) -> None:
        """The deployed shape: Parameter Store holds hashes, never plaintext."""
        _put(ssm, [{"team_id": "acme", "token_sha256": fingerprint(SSM_TOKEN)}])

        assert resolve_team(SSM_TOKEN) == "acme"

    def test_accepts_a_plaintext_registry_for_local_use(self, ssm: Any) -> None:
        """So a developer's .env stays readable without a hashing step."""
        _put(ssm, [{"team_id": "acme", "token": SSM_TOKEN}])

        assert resolve_team(SSM_TOKEN) == "acme"

    def test_a_wrapped_document_is_also_understood(self, ssm: Any) -> None:
        ssm.put_parameter(
            Name=PARAMETER_NAME,
            Value=json.dumps({"teams": [{"team_id": "acme", "token": SSM_TOKEN}]}),
            Type="SecureString",
        )

        assert resolve_team(SSM_TOKEN) == "acme"

    def test_team_ids_are_normalised(self, ssm: Any) -> None:
        """'ACME' in the registry is the same partition as 'acme' in a key."""
        _put(ssm, [{"team_id": "  ACME  ", "token": SSM_TOKEN}])

        assert resolve_team(SSM_TOKEN) == "acme"

    def test_the_registry_is_fetched_once_per_execution_environment(self, ssm: Any) -> None:
        """Otherwise every exchange would pay an SSM round trip and risk throttling."""
        _put(ssm, [{"team_id": "acme", "token": SSM_TOKEN}])
        assert resolve_team(SSM_TOKEN) == "acme"

        ssm.delete_parameter(Name=PARAMETER_NAME)

        # Still served from cache, which is only possible if SSM was not consulted.
        assert resolve_team(SSM_TOKEN) == "acme"

    def test_an_empty_registry_fails_loudly(self, ssm: Any) -> None:
        """A silently empty registry would look like every token being wrong."""
        _put(ssm, [])

        with pytest.raises(RuntimeError, match="empty"):
            get_team_credentials()

    def test_configuration_without_any_token_source_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("NOTES_TEAM_TOKENS", raising=False)
        monkeypatch.delenv("NOTES_TEAM_TOKENS_PARAM", raising=False)

        with pytest.raises(PydanticValidationError, match="NOTES_TEAM_TOKENS"):
            Settings()  # type: ignore[call-arg]


class TestResolution:
    @pytest.mark.parametrize("team", sorted(TEAM_TOKENS))
    def test_each_token_maps_to_exactly_one_team(self, table: Any, team: str) -> None:
        assert resolve_team(TEAM_TOKENS[team]) == team

    @pytest.mark.parametrize(
        "presented",
        [
            "",
            "nt_",
            "nt_too-short",
            "no-prefix-but-otherwise-long-enough-value",
            "nt_wrong-token-of-a-perfectly-plausible-length",
        ],
    )
    def test_anything_unrecognised_is_refused(self, table: Any, presented: str) -> None:
        with pytest.raises(InvalidCredentialsError):
            resolve_team(presented)

    def test_a_single_wrong_character_is_enough_to_refuse(self, table: Any) -> None:
        """The comparison is over digests, so there is no partial credit."""
        with pytest.raises(InvalidCredentialsError):
            resolve_team(TEAM_TOKENS["acme"][:-1] + "Z")
