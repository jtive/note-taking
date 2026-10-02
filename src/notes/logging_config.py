"""JSON logging with a request id attached to every line.

CloudWatch Logs Insights can query structured fields but only does string
matching on free text, so logging JSON is what makes "show me every 429 for
this user" a query rather than a grep.

The Lambda runtime installs its own handler on the root logger before our code
imports. Adding a second one would double every line in CloudWatch, so the
existing handler's formatter is replaced instead.
"""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())

    formatter = JsonFormatter()
    filter_ = RequestIdFilter()

    if not root.handlers:
        root.addHandler(logging.StreamHandler())

    for handler in root.handlers:
        handler.setFormatter(formatter)
        handler.addFilter(filter_)
