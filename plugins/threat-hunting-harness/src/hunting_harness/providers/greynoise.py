"""GreyNoise observations preserve context without classifying candidates."""

from typing import Any

from ..models import Record
from .base import Observation, Page, observation_time
from .parsing import coverage, indicators, object_rows


def greynoise_page(operation: str, arguments: Record, raw: Any) -> Page:
    if not isinstance(raw, dict):
        raise ValueError("Expected a GreyNoise object")
    records = []
    malformed = False
    metadata: Record = {
        "interpretation": "Scanner and business-service context are alternative explanations, "
        "not conclusive evidence of benignness or malicious use",
        "upstream_retries": "GreyNoise may retry GET requests; attempts are not observable",
    }
    if operation == "gnql-timeseries":
        buckets = raw["buckets"]
        if not isinstance(buckets, dict):
            raise ValueError("Expected time buckets")
        for observed, values in buckets.items():
            rows, invalid = object_rows(values)
            malformed |= invalid
            for row in rows:
                ips = indicators([row.get("ip")])
                if not ips:
                    malformed = True
                records.append(
                    Observation(
                        ips, observation_time(observed), {"bucket": observed, "record": row}
                    )
                )
        page = Page(
            records,
            raw,
            complete=False,
            gap=(
                "unrecognized_provider_records"
                if malformed
                else "per_bucket_history_coverage_unverified"
            ),
            metadata={**metadata, "results_per_bucket": arguments.get("size", 25)},
        )
        return coverage(
            page,
            "per_bucket_history_coverage_unverified",
            "observation_dates_unavailable"
            if any(r.observed_at is None for r in records)
            else None,
        )
    rows, malformed = object_rows(raw.get("data") if operation == "gnql-query" else [raw])
    for row in rows:
        context = row.get("internet_scanner_intelligence") or {}
        if not isinstance(context, dict):
            context, malformed = {}, True
        ips = indicators([row.get("ip")])
        if not ips:
            malformed = True
        observed = observation_time(context.get("last_seen") or row.get("last_seen"))
        records.append(Observation(ips, observed, row))
    request_metadata = raw.get("request_metadata", {})
    if not isinstance(request_metadata, dict):
        request_metadata, malformed = {}, True
    metadata.update(request_metadata)
    token = request_metadata.get("scroll")
    if token is not None and not isinstance(token, str):
        token, malformed = None, True
    complete = operation != "gnql-query" or request_metadata.get("complete") is True
    # Conflicting pagination markers must never hide retrievable records.
    if token:
        complete = False
    page = Page(
        records,
        raw,
        complete=complete and not malformed,
        continuation={**arguments, "scroll": token} if token else None,
        gap="unrecognized_provider_records" if malformed else None,
        metadata=metadata,
    )
    if request_metadata.get("restricted_fields"):
        page.gap = page.gap or "fields_restricted_by_entitlement"
    if not page.complete and not token:
        page.gap = page.gap or "pagination_cursor_unavailable"
    return coverage(
        page,
        "pagination_cursor_unavailable" if not page.complete and not token else None,
        "fields_restricted_by_entitlement" if request_metadata.get("restricted_fields") else None,
        "observation_dates_unavailable" if any(r.observed_at is None for r in records) else None,
    )
