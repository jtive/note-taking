"""Distributed rate limiting with a conditional DynamoDB counter.

Why the counter cannot live in the process
------------------------------------------
Lambda runs one request per execution environment at a time, and scales by
starting more environments. A counter held in module scope is therefore
per-container: with N warm containers the effective limit becomes N times the
configured limit, and it drifts with traffic and scaling. Worse, it fails
silently - the code looks correct and the limit is simply not what it says.
The counter has to live somewhere every container can see, and DynamoDB is
already a dependency.

Why fixed window
----------------
Each request is one `UpdateItem` that increments a counter and refuses to
exceed the limit in the same atomic operation, so there is no read-then-write
race and no need for a transaction. The known cost is boundary burst: a client
can spend its full allowance at the end of one window and again at the start of
the next, briefly achieving twice the rate. A token bucket or sliding window
log would smooth that out, at the price of optimistic-concurrency retries or a
stored timestamp per request respectively. For a limit meant to stop runaway
clients and slow credential stuffing, the simpler primitive is the better
trade - and being explicit about the boundary beats pretending it is exact.

Expired counters are reaped by DynamoDB's TTL rather than by any code here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from notes import table_schema as schema
from notes.clock import Clock

CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"
COUNTER_ATTRIBUTE = "request_count"


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_at: int
    retry_after: int

    def headers(self) -> dict[str, str]:
        """Conventional X-RateLimit-* headers, plus Retry-After when blocked."""
        values = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(self.reset_at),
        }
        if not self.allowed:
            values["Retry-After"] = str(self.retry_after)
        return values


class RateLimiter:
    def __init__(self, table: Any, clock: Clock) -> None:
        self._table = table
        self._clock = clock

    def check(self, *, subject: str, limit: int, window_seconds: int) -> RateLimitDecision:
        """Count this request against `subject`'s allowance and decide.

        `subject` is the identity the limit applies to: the user id for
        authenticated routes, the source IP for the auth routes where no user
        is known yet.
        """
        now = self._clock.epoch_seconds()
        window_start = now - (now % window_seconds)
        reset_at = window_start + window_seconds

        try:
            response: dict[str, Any] = self._table.update_item(
                Key=schema.rate_limit_key(subject, window_start),
                # ADD creates the attribute at 1 when it is absent, so the
                # first request of a window needs no special case.
                UpdateExpression="SET #ttl = if_not_exists(#ttl, :expires) ADD #count :one",
                # The increment only happens if it would stay within the limit,
                # which is what makes this safe without a transaction.
                ConditionExpression="attribute_not_exists(#count) OR #count < :limit",
                ExpressionAttributeNames={
                    "#count": COUNTER_ATTRIBUTE,
                    "#ttl": schema.TTL_ATTRIBUTE,
                },
                ExpressionAttributeValues={
                    ":one": 1,
                    ":limit": limit,
                    # One window of slack so TTL deletion, which DynamoDB runs
                    # on its own schedule, never races a live counter.
                    ":expires": reset_at + window_seconds,
                },
                ReturnValues="UPDATED_NEW",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == CONDITIONAL_CHECK_FAILED:
                return RateLimitDecision(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_at=reset_at,
                    retry_after=max(1, reset_at - now),
                )
            raise

        used = int(response["Attributes"][COUNTER_ATTRIBUTE])
        return RateLimitDecision(
            allowed=True,
            limit=limit,
            remaining=max(0, limit - used),
            reset_at=reset_at,
            retry_after=0,
        )
