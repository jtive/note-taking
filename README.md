# Notes API

A REST service for small teams to capture and work with shared notes. Python,
FastAPI, DynamoDB, running on Lambda behind an API Gateway HTTP API, deployed
only by GitHub Actions.

Every note belongs to a team. Any member of that team can read the team's
notes; only the member a note is attributed to can edit or delete it. No note
is reachable from outside its team.

| | |
|---|---|
| Live API | `https://<api-id>.execute-api.us-east-2.amazonaws.com` |
| Interactive docs | `/docs` on that host |
| Tests | 137, 98% line and branch coverage |

---

## Contents

- [Quickstart](#quickstart)
- [How authentication works](#how-authentication-works)
- [API reference](#api-reference)
- [Architecture](#architecture)
- [Data model](#data-model)
- [The three design choices I spent the most time on](#the-three-design-choices-i-spent-the-most-time-on)
- [Known limitations](#known-limitations)
- [What I would change, add, or stop doing with more time](#what-i-would-change-add-or-stop-doing-with-more-time)
- [Deploying this yourself](#deploying-this-yourself)
- [Development](#development)

---

## Quickstart

Against the live API, using one of the four team tokens:

```bash
API=https://<api-id>.execute-api.us-east-2.amazonaws.com

# 1. Trade the team's long-lived API token for a session token.
TOKEN=$(curl -sS -X POST "$API/auth/token" \
  -H 'Content-Type: application/json' \
  -d '{"api_token":"nt_...","member":"alice"}' | jq -r .access_token)

# 2. Write a note.
curl -sS -X POST "$API/notes" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"note":"Ship the rate limiter before the demo."}' | jq

# 3. Read the team's notes, newest first.
curl -sS "$API/notes" -H "Authorization: Bearer $TOKEN" | jq
```

Locally, with no AWS account involved:

```bash
python -m venv .venv && . .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt

cp .env.example .env          # includes four local team tokens
docker compose up -d          # DynamoDB Local
python scripts/create_local_table.py

uvicorn notes.main:app --reload --app-dir src
# http://127.0.0.1:8000/docs
```

Run the suite with `pytest`. It uses [moto](https://github.com/getmoto/moto)
rather than DynamoDB Local, so Docker is not needed for tests.

---

## How authentication works

Two kinds of credential, and the distinction matters for everything below.

**A team API token** (`nt_…`) is long-lived and identifies a *team*. There are
four, one per team, provisioned out of band by `scripts/bootstrap.py`. Only
their SHA-256 digests are stored.

**A session token** is a JWT that expires in an hour. It is what every other
endpoint accepts, and its `team` claim is what scopes every database key.

```
POST /auth/token  { api_token, member }  ->  { access_token, team, member }
                    ^^^^^^^^^            ^^^^^^^^^^^^^^^
                    authenticates        the team is read from the
                    the team             token, never from the request
```

The `member` field is **attribution, not authentication**. The API token proves
which team is calling; it does not prove which person. Anyone holding a team's
token can write as any member of that team. This is stated plainly here, in the
code, and in a test that asserts it, because it is a real consequence of a
shared credential rather than something to paper over. See
[Known limitations](#known-limitations).

---

## API reference

All endpoints accept and return JSON. Errors are
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem documents with
content type `application/problem+json`:

```json
{
  "type": "urn:notes:error:not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "No note with that id exists in your team.",
  "instance": "/notes/01M3Z4HMB1VS68PXB1QS3EA6GT"
}
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness. No auth. |
| `POST` | `/auth/token` | Exchange a team API token for a session token. |
| `GET` | `/auth/me` | Echo the identity the session token asserts. |
| `POST` | `/notes` | Create a note in your team. |
| `GET` | `/notes` | List your team's notes, newest first. |
| `GET` | `/notes/{id}` | Read one note. |
| `PATCH` | `/notes/{id}` | Edit a note attributed to you. |
| `DELETE` | `/notes/{id}` | Delete a note attributed to you. |

A note:

```json
{
  "id": "01M3Z4HMB1VS68PXB1QS3EA6GT",
  "user": "alice",
  "team": "acme",
  "date": "2026-10-02T20:23:00.193Z",
  "note": "Ship the rate limiter before the demo.",
  "updated_at": "2026-10-02T20:23:00.193Z",
  "version": 1
}
```

`user`, `team`, `date` and `note` are the four fields from the brief. `id` and
`version` are the two things a REST resource needs beyond them: a stable
address, and something to hang an ETag on.

### Listing and search

```bash
curl -sS "$API/notes?limit=10"                     -H "Authorization: Bearer $TOKEN"
curl -sS "$API/notes?cursor=eyJQSyI6..."           -H "Authorization: Bearer $TOKEN"
curl -sS "$API/notes?q=rate%20limiter"             -H "Authorization: Bearer $TOKEN"
```

`limit` defaults to 25 and is clamped to 100 rather than rejected. `next_cursor`
is an opaque, tamper-checked cursor; follow it until it is `null`.

With `q`, DynamoDB applies the page size *before* the filter, so a page can
contain fewer matches than requested while more exist further back. Follow
`next_cursor` to the end rather than stopping at the first short page. This is a
real limitation of filtering without a search index, not a bug.

### Concurrent edits

Reads and writes return an `ETag` carrying the note's version. Send it back as
`If-Match` to make an edit conditional:

```bash
curl -sS -X PATCH "$API/notes/$ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'If-Match: "1"' \
  -H 'Content-Type: application/json' \
  -d '{"note":"revised"}'
# 412 if someone else got there first; re-read and retry.
```

Omitting `If-Match` means last write wins, which is the right default for a
single-client editor.

### Rate limits

Every response carries the current allowance:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 97
X-RateLimit-Reset: 1790000160
```

A refusal is a `429` with `Retry-After`. Two tiers: **100 requests per minute
per team** on the authenticated surface, and **10 per minute per source address**
on `POST /auth/token`, where the threat is someone guessing an API token rather
than a runaway client.

### Status codes

| Code | When |
|---|---|
| `401` | Missing, malformed, expired or unrecognised credential. |
| `403` | The note is visible to your team but attributed to someone else. |
| `404` | No such note *in your team* — including when it exists in another team. |
| `409` | A concurrent write raced yours. |
| `412` | `If-Match` did not match the current version. |
| `422` | Request body, path or query parameter failed validation. |
| `429` | Rate limit exceeded. |

---

## Architecture

```
                   ┌─────────────────────────┐
  GitHub Actions   │  OIDC token ──► STS     │   no AWS key stored in GitHub
  (main branch)    │  1-hour credentials     │
                   └───────────┬─────────────┘
                               │ sam deploy
                               ▼
  client ──► API Gateway HTTP API ──► Lambda (one function, all routes)
                 │  throttling          │  FastAPI + Mangum
                 │  access logs         │
                                        ├──► DynamoDB  (notes + rate counters)
                                        └──► SSM Parameter Store (SecureString)
                                               signing key, team token registry
```

One Lambda serves every route via [Mangum](https://github.com/Kludex/mangum)
rather than a function per endpoint. A function per endpoint would multiply cold
starts across a surface this small and split shared concerns like the error
format and the rate limiter across deployment units. The cost is that the whole
API scales and fails as one unit; at this size that is the better trade.

Secrets are read from Parameter Store once per execution environment and cached,
so a warm container costs no extra calls and cannot be throttled by SSM.

---

## Data model

One DynamoDB table, two item types, **no secondary indexes**:

| Item | PK | SK |
|---|---|---|
| Note | `TEAM#{team}` | `NOTE#{ulid}` |
| Rate limit counter | `RL#{subject}` | `W#{window_start}` |

There is no user or team item. Teams and their credentials live in the token
registry, so the table holds only what the application itself generates.

Pay-per-request billing, TTL on `expires_at` (counters only), point-in-time
recovery, and encryption at rest. `src/notes/table_schema.py` mirrors
`template.yaml`, so tests and local development build a byte-identical table
rather than an approximation of one.

---

## The three design choices I spent the most time on

### 1. Making tenant isolation structural rather than a check

The obvious implementation of "a team can only see its own notes" is a filter
or an `if` on the way out. I did not want isolation to depend on remembering to
write that line in every new handler, because the one place it gets forgotten is
a cross-tenant data leak.

So the team is the partition key, and the partition key is only ever built from
the verified `team` claim in the session token:

```python
def note_key(team_id: str, note_id: str) -> dict[str, str]:
    return {PARTITION_KEY: team_partition(team_id), SORT_KEY: note_sort_key(note_id)}
```

Every repository method takes the caller's team and derives keys from it. There
is no code path that can address another team's data, so another team's note is
not *forbidden*, it is *unaddressable*. A new endpoint written by someone who
has never read this README inherits the property for free, because the only way
to reach the table is through a function that demands a team.

Two consequences I decided to accept:

- **A cross-team read returns 404, not 403.** A 403 would confirm that the id
  exists somewhere, which is itself information about another team. The cursor
  is re-validated against the caller's partition for the same reason: it is
  client-visible state, so an edited one must not resume paging elsewhere.
- **There is no cross-team query.** An admin view over all teams would need a
  scan or a new access pattern. That is the right price for the guarantee.

**The tradeoff:** a single team is a single partition. DynamoDB caps a partition
at 3,000 read and 1,000 write units per second, so one enormous team would hit a
hot-partition ceiling that per-user partitioning would not. For "several small
teams" this is the correct shape; past that, notes would shard by
`TEAM#{team}#{yyyy-mm}` and listing would fan out across a bounded set of
partitions.

### 2. The rate limiter had to be wrong in-process before it could be right

My first instinct was a dictionary of counters in the module. On Lambda that is
quietly broken: each execution environment keeps its own counter, so with *N*
warm containers the effective limit is *N* × the configured one, and it drifts
with traffic. The limit would appear to work in testing and fail exactly when it
mattered.

The counter therefore lives in DynamoDB, incremented by a single conditional
atomic `UpdateItem`:

```text
UpdateExpression     SET #ttl = if_not_exists(#ttl, :expires) ADD #count :one
ConditionExpression  attribute_not_exists(#count) OR #count < :limit
```

One round trip per request. No read-then-write, so two containers cannot both
observe "99" and both allow a request. A `ConditionalCheckFailedException` *is*
the refusal, not an error to retry. TTL cleans up expired windows, so nothing
accumulates and nothing needs sweeping.

I chose **fixed window** over sliding log and token bucket after sketching all
three. A sliding log is the most accurate and costs a write plus a range read
plus a prune per request, roughly 3× the cost for a precision nobody here
needs. A token bucket needs read-modify-write on a float, which means either
optimistic retries or losing atomicity. Fixed window is one atomic write, and
its flaw is bounded and documentable: a client can send `limit` requests at the
end of one window and `limit` more at the start of the next, so a burst of up to
2× the limit can cross a boundary. Sustained throughput is still correct, and
API Gateway's own throttling sits in front as a coarse backstop.

**The subject key is the team, not the member, and that was the subtle part.**
The member name is declared by the caller at token-exchange time, so a per-member
limit would be free to escape: run out of allowance, exchange a new token under
a new name, continue. Keying on the source address is wrong in the other
direction — a whole office behind one NAT would share one allowance. The team is
the only thing the credential actually proves, so it is the only safe key. The
cost is that one busy member consumes their team's allowance; fixing that
properly requires per-member credentials, not a cleverer key.

There is a test that stands up two `RateLimiter` instances to represent two
Lambda containers and asserts they share one allowance. That test is the whole
reason the counter is where it is.

### 3. Where the credentials live, and what the token actually proves

The brief wanted token issuing and token usage. Three questions took the most
thought.

**Stateless JWT or opaque token looked up in the database?** I chose a
self-issued HS256 JWT. Every authenticated request then costs zero reads for
auth, and the team claim travels with the request so the handler can build keys
without a lookup. The cost is honest: a stateless token cannot be revoked before
it expires. I bounded it with a one-hour lifetime and issue a `jti` on every
token, so a revocation list can be added later without invalidating anything in
flight. I did not reach for Cognito — it would have added a managed dependency
and a hosted UI for a token exchange that is twenty lines, and it would have
made the thing I most wanted to demonstrate someone else's black box.

Verification is where the risk is concentrated, so the algorithm is pinned
(`algorithms=["HS256"]`, which rejects both `alg: none` and HS/RS confusion),
`iss` and `aud` are validated so a valid token for another service does not
work here, and the required claims are declared rather than assumed present.
There are tests for each of those forgeries.

**Two tiers of credential rather than one.** The long-lived team token is sent
once per session; the thing travelling on every subsequent call expires on its
own. That is the whole reason for the exchange — it shrinks the window in which
an intercepted credential is useful from forever to an hour.

**SHA-256, not bcrypt, for the stored token digests.** This looks wrong at a
glance and is deliberate. A slow KDF protects a *guessable* secret by making
each guess expensive. These tokens are 256 bits of CSPRNG output; there is no
guess space to protect, and bcrypt would only add latency to every exchange.
Passwords would be a different matter entirely, which is part of why the model
moved to tokens. Comparison uses `hmac.compare_digest` over every registered
credential with no early exit, so the response time reveals neither which team
matched nor how far down the registry it sat.

Neither the signing key nor the registry exists in the repository, in a
CloudFormation template, or in a CI log. Both are SecureString parameters
created by `scripts/bootstrap.py`. CloudFormation cannot create SecureString
parameters, which forced the script — and that turned out to be a feature,
because it also keeps the plaintext out of every stack event.

---

## Known limitations

Stated plainly, because a reviewer will find them anyway and they are mostly
consequences of choices rather than oversights.

- **A team token authenticates a team, not a person.** Members share one
  credential, so anyone holding it can exchange it for a session attributed to
  any name — including a teammate's. The author-only rule on edit and delete
  therefore prevents accidents, not a deliberate act by someone already inside
  the team. Cross-team isolation is unaffected: the team claim comes from the
  token and never from the request. `tests/test_authorization.py` asserts this
  behaviour explicitly rather than leaving it implied.
- **Session tokens cannot be revoked** before they expire. One hour of exposure,
  bounded by the TTL. `jti` is issued so a deny list can be added.
- **Search is a DynamoDB filter, not an index.** It reads the page then
  discards non-matches, so it costs reads proportional to the team's notes and
  can return short pages. Fine for small teams; not a search feature.
- **Notes sort by creation time only.** That ordering is free from the ULID sort
  key. Ordering by last update would need a GSI.
- **Teams are a fixed list of four.** Onboarding a tenant means re-running the
  bootstrap script. A real service needs a provisioning API.
- **CORS is permissive** so the live URL can be poked at from anywhere.
  `template.yaml` flags the line to pin before this served a browser app.
- **One partition per team** — see the ceiling discussed above.

---

## What I would change, add, or stop doing with more time

**Change**

- **Per-member credentials.** This is the single highest-value change, and it
  closes the limitation above: member identity would become authenticated rather
  than declared, which makes author-only editing a real boundary and lets the
  rate limiter key on the person instead of the team. It is roughly an API for
  issuing per-member tokens plus a member item in the table, and I would do it
  first.
- **Swap fixed-window for a sliding window** on the auth endpoint specifically,
  where the 2× boundary burst is worth the extra read and the traffic volume is
  low enough that the cost does not matter.
- **Pin the CORS origins and put the API behind a custom domain** with a
  certificate, instead of the generated execute-api hostname.
- **Scope the API Gateway IAM statement.** It is the loosest statement in the
  deploy policy, because API Gateway ARNs identify resources by generated id
  rather than by name. A two-stage bootstrap that creates the API first and then
  grants on its id would fix it.

**Add**

- **Structured observability.** Logs are already JSON with a request id; what is
  missing is tracing (X-Ray, to see the DynamoDB call inside a slow request) and
  alarms on 5xx rate, p99 latency and throttles. Right now a production problem
  is discovered by looking.
- **Soft delete and an audit trail.** `DELETE` is currently permanent, which is
  a poor fit for shared team notes. A `deleted_at` attribute plus a filter on
  read would make deletion recoverable, and DynamoDB Streams would give an
  append-only history of edits cheaply.
- **Note sharing between teams**, which the brief hints at with "shared amongst
  several small teams". This is the one feature where the current schema fights
  back: a note lives in exactly one partition. I would add an explicit share
  item (`PK=TEAM#{recipient}`, `SK=SHARE#{ulid}`) pointing at the original, so a
  share is a deliberate grant rather than a weakening of the isolation rule.
- **Tags or notebooks**, which the brief's "work with their notes" implies, and
  which the sort key can accommodate without a new table.
- **A staging stage.** `template.yaml` is already parameterised by `Stage`; the
  workflow just needs a second deploy with a gate between them.
- **Contract tests against the OpenAPI schema** so a response shape cannot
  change without a test noticing.

**Stop doing**

- **Stop storing a lowercase shadow copy of every note.** It exists so `?q=`
  can match case-insensitively, and it doubles the storage of the only large
  attribute. The moment search matters it should be OpenSearch or a Streams-fed
  index, and this column should go.
- **Stop returning the full note body in list responses.** A summary plus a
  point read would keep pages small and predictable.
- **Stop using root account access keys locally.** The bootstrap step currently
  runs with the account's root credentials, which cannot be scoped and cannot be
  rotated safely. It should be a scoped IAM user with an MFA-protected console
  login, and the root keys should be deleted. CI already never uses a static key
  at all, which is the model to extend.
- **Stop deleting the table on stack deletion.** `DeletionPolicy: Delete` is
  right for a demo and wrong for anything with real notes in it; production
  wants `Retain` and a generated table name.

---

## Deploying this yourself

Three steps, and only the first touches your local credentials.

### 1. Bootstrap (once, by a human)

```bash
python scripts/bootstrap.py --repository <owner>/<repo> --region us-east-2
```

This deploys `infra/bootstrap-oidc.yaml`, which creates:

- the **GitHub OIDC provider**, establishing that tokens signed by
  `token.actions.githubusercontent.com` may be exchanged for AWS credentials;
- a **deploy role** whose trust policy accepts only tokens whose audience is
  `sts.amazonaws.com` *and* whose subject is
  `repo:<owner>/<repo>:ref:refs/heads/main`. Both conditions matter: without the
  audience check the role would accept tokens minted for other relying parties,
  and without the subject check any repository on GitHub could assume it;
- an **artifact bucket** for SAM packages.

It then generates the JWT signing key and mints the four team API tokens,
storing only their SHA-256 digests in SSM. **The plaintext tokens are printed
once and are not recoverable** — copy them then.

Re-running is safe and will not rotate either secret, since rotating the signing
key logs everyone out and rotating a team token breaks that team's clients.

### 2. Tell GitHub about it

The script prints these. The role ARN is the only secret, and it is not a
credential — it is useless without a signed token from this repository.

```bash
gh secret   set AWS_DEPLOY_ROLE_ARN    --body arn:aws:iam::<account>:role/note-taking-github-deploy
gh variable set AWS_REGION             --body us-east-2
gh variable set SAM_ARTIFACT_BUCKET    --body note-taking-sam-artifacts-<account>-us-east-2
# Optional: lets the post-deploy smoke test run a full authenticated round trip.
gh secret   set NOTES_SMOKE_API_TOKEN  --body nt_...
```

### 3. Push to main

`.github/workflows/deploy.yml` reuses `ci.yml` rather than duplicating it, so a
deploy physically cannot run without lint, type checks and tests passing on the
same commit. It then requests an OIDC token, exchanges it for one-hour STS
credentials, runs `sam build` and `sam deploy`, reads the stack's `ApiUrl`
output, and runs `scripts/smoke_test.py` against the live URL.

That last step matters: a green CloudFormation deploy only proves CloudFormation
was satisfied. The smoke test is what proves the handler path resolves, the
execution role can reach DynamoDB, and the function can decrypt its secrets —
all failures that happen at request time, not at deploy time.

**No AWS access key is ever stored in GitHub.** Nothing deploys from a laptop;
local credentials are used once, for step 1.

### Least privilege

The deploy role is confined to `note-taking-*` resources and gets DynamoDB
**control plane only** — it can create, configure and delete the table but
deliberately cannot `GetItem`, `Query` or `Scan`, so a compromised CI token
cannot read anyone's notes. The Lambda execution role gets the four item
operations plus `Query` (no `Scan`) on exactly one table, and `ssm:GetParameter`
on exactly two parameter paths. Neither role uses an AWS managed policy.

---

## Development

```bash
pip install -r requirements-dev.txt

ruff check . && ruff format --check .
mypy
pytest --cov --cov-report=term-missing
```

CI runs all four on every push and pull request, plus `sam validate --lint`.
The coverage floor is 90% as a ratchet against regression; the suite currently
sits near 98%.

### Layout

```
src/notes/
  main.py            application factory, router wiring
  handler.py         Mangum adapter: the Lambda entry point
  config.py          NOTES_* settings, validated at startup
  models.py          request/response schemas
  errors.py          error hierarchy and RFC 9457 handlers
  table_schema.py    the physical DynamoDB layout and why
  repository.py      all DynamoDB access, conditional writes
  ratelimit.py       the distributed fixed-window counter
  dependencies.py    DI wiring and the auth/limit dependencies
  clock.py           injectable time, so windows are testable
  auth/
    team_tokens.py   the team API token registry
    tokens.py        JWT issue and verify
    signing_key.py   SSM-backed key loading, cached per container
  routes/
infra/               the bootstrap stack (OIDC, deploy role, bucket)
scripts/             bootstrap, local table, smoke test
template.yaml        the application stack
```

The files worth reading first are `table_schema.py` and `ratelimit.py`: between
them they carry most of the design, and both carry comments explaining what was
rejected and why.
