#!/usr/bin/env python
"""One-time AWS setup, run by a human before the first deploy.

    python scripts/bootstrap.py --repository jtive/note-taking

Does four things, all idempotent:

  1. Deploys infra/bootstrap-oidc.yaml, which establishes GitHub OIDC trust,
     an artifact bucket, and a deploy role that only this repository's main
     branch can assume.
  2. Generates the JWT signing key into SSM Parameter Store as a SecureString,
     if it is not already there. CloudFormation cannot create SecureString
     parameters, which is why this step is a script rather than a resource in
     the template - and keeping it out of CloudFormation has the side benefit
     that the plaintext never appears in a stack event, a template, or a CI
     log.
  3. Mints one API token per team and stores only their SHA-256 digests. The
     plaintext is printed once, here, and is unrecoverable afterwards.
  4. Prints what to put in GitHub.

Requires credentials with permission to create IAM resources, so it is the one
thing here that is not done by the scoped deploy role.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = REPOSITORY_ROOT / "infra" / "bootstrap-oidc.yaml"
BOOTSTRAP_STACK = "note-taking-bootstrap"

# 48 random bytes, URL-safe encoded to 64 characters: comfortably above the
# 32-character minimum the application enforces, and above the 64-byte block
# size where HMAC-SHA256 would start folding the key.
SIGNING_KEY_BYTES = 48

# The four teams the service is provisioned for. Real tenant onboarding would
# be an API; a fixed list is honest about the scope of this exercise.
TEAMS = ("acme", "globex", "initech", "umbrella")

# 32 random bytes, so guessing a token is not a realistic attack regardless of
# how fast the comparison is.
TEAM_TOKEN_BYTES = 32

# GitHub switched the default OIDC subject format on this date. Repositories
# created afterwards embed numeric owner and repository IDs in `sub`, so that a
# deleted-and-recreated namespace cannot inherit the old subject. Getting this
# wrong produces a bare "Not authorized to perform sts:AssumeRoleWithWebIdentity"
# with no hint as to which claim mismatched, so it is worth deriving rather
# than guessing.
IMMUTABLE_SUBJECT_CUTOVER = datetime(2026, 7, 15, tzinfo=UTC)


def subject_claim(*, repository: str, branch: str) -> str:
    """Build the `sub` claim the deploy role should trust.

    Reads the repository's creation date and numeric ids from the public
    GitHub API to decide between the immutable and legacy subject formats.
    A repository created before the cutover that has since *opted in* to
    immutable claims will be misclassified here; pass --subject to override.
    """
    url = f"https://api.github.com/repos/{repository}"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
        metadata = json.loads(response.read())

    owner = metadata["owner"]["login"]
    name = metadata["name"]
    created = datetime.fromisoformat(metadata["created_at"].replace("Z", "+00:00"))

    if created < IMMUTABLE_SUBJECT_CUTOVER:
        return f"repo:{owner}/{name}:ref:refs/heads/{branch}"

    owner_id = metadata["owner"]["id"]
    repository_id = metadata["id"]
    return f"repo:{owner}@{owner_id}/{name}@{repository_id}:ref:refs/heads/{branch}"


def deploy_bootstrap_stack(*, repository: str, branch: str, region: str, subject: str) -> None:
    print(f"Deploying {BOOTSTRAP_STACK} to {region}...")
    subprocess.run(
        [
            "aws",
            "cloudformation",
            "deploy",
            "--stack-name",
            BOOTSTRAP_STACK,
            "--template-file",
            str(TEMPLATE),
            "--region",
            region,
            # The deploy role has an explicit name so the workflow can be
            # pointed at a stable ARN, which requires the named-IAM capability.
            "--capabilities",
            "CAPABILITY_NAMED_IAM",
            "--no-fail-on-empty-changeset",
            "--parameter-overrides",
            f"GitHubRepository={repository}",
            f"AllowedBranch={branch}",
            f"SubjectClaim={subject}",
        ],
        check=True,
        shell=False,
    )


def stack_outputs(*, region: str) -> dict[str, str]:
    client: Any = boto3.client("cloudformation", region_name=region)
    stacks = client.describe_stacks(StackName=BOOTSTRAP_STACK)["Stacks"]
    return {output["OutputKey"]: output["OutputValue"] for output in stacks[0].get("Outputs", [])}


def ensure_signing_key(*, stage: str, region: str) -> tuple[str, bool]:
    name = f"/note-taking/{stage}/jwt-signing-key"
    client: Any = boto3.client("ssm", region_name=region)

    try:
        client.get_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    else:
        # Never overwrite: rotating the key invalidates every token in flight,
        # so that has to be a deliberate act rather than a side effect of
        # re-running setup.
        return name, False

    client.put_parameter(
        Name=name,
        Description=f"HS256 signing key for {stage}. Rotating this logs everyone out.",
        Value=secrets.token_urlsafe(SIGNING_KEY_BYTES),
        Type="SecureString",
        Tier="Standard",
    )
    return name, True


def ensure_team_tokens(*, stage: str, region: str) -> tuple[str, dict[str, str]]:
    """Mint an API token per team, storing only digests.

    Returns the parameter name and, when the tokens were created on this run,
    the plaintext keyed by team. On a re-run the mapping is empty: the digests
    cannot be reversed, so a lost token has to be rotated rather than looked
    up. Overwriting is left to an explicit rotation rather than happening as a
    side effect of re-running setup.
    """
    name = f"/note-taking/{stage}/team-tokens"
    client: Any = boto3.client("ssm", region_name=region)

    try:
        client.get_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    else:
        return name, {}

    plaintext = {team: f"nt_{secrets.token_urlsafe(TEAM_TOKEN_BYTES)}" for team in TEAMS}
    registry = [
        {
            "team_id": team,
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        }
        for team, token in plaintext.items()
    ]

    client.put_parameter(
        Name=name,
        Description=f"SHA-256 digests of the {stage} team API tokens. Plaintext is not stored.",
        Value=json.dumps(registry, separators=(",", ":")),
        Type="SecureString",
        Tier="Standard",
    )
    return name, plaintext


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="jtive/note-taking", help="owner/repo")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--stage", default="prod")
    parser.add_argument(
        "--subject",
        default=None,
        help="Override the OIDC subject claim instead of deriving it from the GitHub API.",
    )
    arguments = parser.parse_args()

    subject = arguments.subject or subject_claim(
        repository=arguments.repository, branch=arguments.branch
    )
    print(f"Trusting OIDC subject: {subject}")

    deploy_bootstrap_stack(
        repository=arguments.repository,
        branch=arguments.branch,
        region=arguments.region,
        subject=subject,
    )

    outputs = stack_outputs(region=arguments.region)
    parameter_name, created = ensure_signing_key(stage=arguments.stage, region=arguments.region)
    tokens_name, tokens = ensure_team_tokens(stage=arguments.stage, region=arguments.region)

    print()
    print("Signing key:", "generated" if created else f"already present at {parameter_name}")

    if tokens:
        print()
        print("Team API tokens - copy these now, they are not recoverable:")
        print()
        for team, token in tokens.items():
            print(f"  {team:<10} {token}")
    else:
        print("Team tokens: already present at", tokens_name)

    print()
    print("Add these to the GitHub repository, then push to main:")
    print()
    print(f"  gh secret set AWS_DEPLOY_ROLE_ARN --body {outputs['DeployRoleArn']}")
    print(f"  gh variable set AWS_REGION --body {arguments.region}")
    print(f"  gh variable set SAM_ARTIFACT_BUCKET --body {outputs['ArtifactBucketName']}")
    print()
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
