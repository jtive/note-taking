#!/usr/bin/env python
"""Exercise a deployed instance over HTTP.

    python scripts/smoke_test.py https://abc123.execute-api.us-east-2.amazonaws.com

A successful CloudFormation deploy only proves CloudFormation was satisfied. It
says nothing about whether the handler path resolves, whether the execution
role can actually reach DynamoDB, or whether the function can decrypt its
secrets - all of which fail at request time, not at deploy time. This script is
what turns those into a red build.

Standard library only, on purpose: the runner installs nothing for this step,
so the check cannot fail because of a dependency unrelated to the service.

Set NOTES_SMOKE_API_TOKEN to one team's API token and the full authenticated
round trip runs too. Without it the unauthenticated checks still run, so a
missing secret degrades coverage rather than breaking the pipeline.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

TIMEOUT_SECONDS = 20


class SmokeFailure(Exception):
    pass


def request(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"

    if not url.startswith("https://"):
        raise SmokeFailure(f"Refusing to smoke test a non-HTTPS URL: {url}")

    call = urllib.request.Request(url, data=payload, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(call, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        # Every error status here is an expected outcome to assert on, not an
        # exception: a 401 from /notes is the point of one of the checks.
        raw = error.read()
        return error.code, json.loads(raw) if raw else {}
    except urllib.error.URLError as error:
        raise SmokeFailure(f"{method} {url} did not connect: {error.reason}") from error


def expect(condition: bool, description: str) -> None:
    if not condition:
        raise SmokeFailure(description)
    print(f"  ok  {description}")


def check_public_surface(base: str) -> None:
    status, body = request("GET", f"{base}/healthz")
    expect(status == 200, f"GET /healthz returns 200 (got {status})")
    expect(body.get("status") == "ok", "health body reports ok")

    status, _ = request("GET", f"{base}/notes")
    expect(status == 401, f"GET /notes without a token is refused (got {status})")

    # Proves the function can reach its secrets: resolving a token requires
    # decrypting the registry from Parameter Store, so a missing ssm:GetParameter
    # or kms:Decrypt grant surfaces as a 500 rather than this 401.
    status, _ = request(
        "POST",
        f"{base}/auth/token",
        body={"api_token": "nt_deliberately-invalid-smoke-test-value", "member": "smoke"},
    )
    expect(status == 401, f"an invalid API token is refused cleanly (got {status})")


def check_round_trip(base: str, api_token: str) -> None:
    status, body = request(
        "POST", f"{base}/auth/token", body={"api_token": api_token, "member": "smoke-test"}
    )
    expect(status == 200, f"POST /auth/token issues a session token (got {status})")
    token = str(body["access_token"])

    status, created = request("POST", f"{base}/notes", body={"note": "smoke test"}, token=token)
    expect(status == 201, f"POST /notes creates a note (got {status})")
    note_id = str(created["id"])

    status, fetched = request("GET", f"{base}/notes/{note_id}", token=token)
    expect(status == 200, f"GET /notes/{{id}} reads it back (got {status})")
    expect(fetched.get("note") == "smoke test", "the stored text round-trips unchanged")

    status, _ = request("DELETE", f"{base}/notes/{note_id}", token=token)
    expect(status == 204, f"DELETE /notes/{{id}} removes it (got {status})")

    status, _ = request("GET", f"{base}/notes/{note_id}", token=token)
    expect(status == 404, f"the deleted note is gone (got {status})")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2

    base = argv[1].rstrip("/")
    print(f"Smoke testing {base}")

    try:
        check_public_surface(base)

        api_token = os.environ.get("NOTES_SMOKE_API_TOKEN", "").strip()
        if api_token:
            check_round_trip(base, api_token)
        else:
            print("  --  NOTES_SMOKE_API_TOKEN is unset; skipping the authenticated round trip")
    except SmokeFailure as failure:
        print(f"\nFAILED: {failure}", file=sys.stderr)
        return 1

    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
