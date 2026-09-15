"""Parse Google's pinned GTI report and relationship responses."""

from typing import Any

from ..models import Record
from .base import Observation, Page, observation_time
from .parsing import coverage, indicators, object_rows


def gti_page(operation: str, arguments: Record, raw: Any) -> Page:
    collection = operation == "search_iocs" or operation.startswith("get_entities_")
    rows, malformed = object_rows(raw if collection else [raw])
    records = []
    for row in rows:
        attrs = row.get("attributes", {})
        if not isinstance(attrs, dict) or not isinstance(row.get("type"), str):
            malformed = True
            continue
        values = [attrs.get("ip_address"), attrs.get("host_name")]
        if row["type"] in ("domain", "ip_address"):
            values.append(row.get("id"))
        values += [arguments.get("domain"), arguments.get("ip_address")]
        # Only the resolution's own date establishes its DNS association time.
        # Analysis/modification/WHOIS dates do not date an infrastructure link.
        observed = observation_time(attrs.get("date")) if row["type"] == "resolution" else None
        records.append(Observation(indicators(values), observed, row, row.get("id")))
        if not attrs and arguments.get("descriptors_only") is not True:
            malformed = True
    page = Page(
        records,
        raw,
        complete=not collection and not malformed,
        gap="unrecognized_provider_records" if malformed else None,
        metadata={
            "history_dates_available": any(r.observed_at for r in records),
            "raw_limitations": "GTI excludes last_analysis_results and aggregations, "
            "and sanitizes empty string values upstream",
        },
    )
    if collection:
        limit = arguments.get("limit", 10)
        # The pinned helper returns only after consuming vt-py's iterator. A
        # short list (or limit=0, meaning exhaust the iterator) demonstrates
        # exhaustion; reaching a positive limit loses any remaining cursor.
        exhausted = not malformed and (limit == 0 or len(rows) < limit)
        page.complete = exhausted
        if not exhausted:
            page.gap = page.gap or "upstream_cursor_and_total_unavailable"
        page.metadata.update(
            result_limit=arguments.get("limit", 10),
            result_limit_source="query" if "limit" in arguments else "provider_default",
            internal_pagination="GTI consumes vt-py iterators; no cursor or total is returned",
        )
        coverage(page, "upstream_cursor_and_total_unavailable")
    if not collection or any(r.observed_at is None for r in records):
        coverage(page, "historical_association_dates_unavailable")
    return page
