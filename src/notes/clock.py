"""The current time, behind a seam.

Rate limiting is defined in terms of wall-clock windows, so tests need to be
able to move time forward deliberately rather than by sleeping. Routes depend
on this through FastAPI's dependency system, which lets a test substitute a
controllable clock without patching module globals.
"""

from __future__ import annotations

from datetime import UTC, datetime


class Clock:
    """Wall-clock time in UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def epoch_seconds(self) -> int:
        return int(self.now().timestamp())


_DEFAULT_CLOCK = Clock()


def get_clock() -> Clock:
    return _DEFAULT_CLOCK


def to_iso8601(moment: datetime) -> str:
    """Render a UTC instant with millisecond precision and a trailing Z.

    Stored as a string attribute rather than a number so that items are
    readable in the DynamoDB console and sort correctly if the ordering is ever
    moved onto a timestamp.
    """
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
