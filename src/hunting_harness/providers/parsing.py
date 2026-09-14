"""Shared response handling without inventing dates, candidates or coverage."""

import json
import re
from typing import Any

from ..models import Record, indicator
from .base import Page


def indicators(values: list[Any]) -> list[str]:
    result = []
    for value in values:
        if isinstance(value, str):
            try:
                result.append(indicator(value))
            except (ValueError, UnicodeError):
                pass
    return list(dict.fromkeys(result))


def payload(raw: Any) -> Any:
    """Unwrap FastMCP result envelopes, including Censys's JSON strings."""
    while True:
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                return raw
        elif isinstance(raw, dict) and "result" in raw and not raw.get("error"):
            raw = raw["result"]
        else:
            return raw


def object_rows(value: Any) -> tuple[list[Record], bool]:
    """Retain valid rows even if another row is malformed."""
    if not isinstance(value, list):
        return [], True
    rows = [row for row in value if isinstance(row, dict)]
    return rows, len(rows) != len(value)


def coverage(page: Page, *gaps: str | None) -> Page:
    """Record contextual limits without preventing successful query completion."""
    missing = list(
        dict.fromkeys([*page.metadata.get("coverage_gaps", []), *(gap for gap in gaps if gap)])
    )
    if missing:
        page.metadata["coverage_gaps"] = missing
    return page


def error_code(value: Any, default: str = "provider_report_unavailable") -> str:
    """Classify upstream errors without copying credential-bearing messages."""
    message = str(value).lower()
    codes = (
        (r"\b429\b|quotaexceeded|toomanyrequests|rate.?limit", "provider_rate_limited"),
        (
            r"\b401\b|authentication|wrongcredentials|invalid.?api.?key",
            "provider_authentication_failed",
        ),
        (r"\b403\b|forbidden|not.?entitled|permissiondenied", "provider_access_denied"),
        (r"\b404\b|notfounderror|not found", "provider_record_not_found"),
    )
    return next((code for pattern, code in codes if re.search(pattern, message)), default)
