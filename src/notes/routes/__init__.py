"""HTTP routes, grouped by resource."""

from typing import Any

from notes.models import ProblemResponse

#: Reusable OpenAPI declarations so every endpoint documents the error shape it
#: actually returns rather than FastAPI's default.
PROBLEM_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ProblemResponse, "description": "Missing, expired or invalid bearer token."},
    403: {"model": ProblemResponse, "description": "Authenticated, but not permitted."},
    404: {"model": ProblemResponse, "description": "No such resource in your team."},
    422: {"model": ProblemResponse, "description": "Request failed validation."},
    429: {"model": ProblemResponse, "description": "Rate limit exceeded; see Retry-After."},
}
