"""Normalize Censys API JSON while preserving source rows and coverage boundaries."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from ..models import Record
from .base import Observation, Page, observation_time
from .parsing import coverage, indicators, object_rows


def instant(value: str, *, upper: bool = False) -> datetime:
    """Use UTC; round a finer upper bound outward so SDK serialization cannot skip events."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    parsed = parsed.replace(tzinfo=parsed.tzinfo or UTC).astimezone(UTC)
    fraction = re.search(r"[T ]\d\d:\d\d:\d\d\.(\d+)", value)
    if upper and fraction and any(c != "0" for c in fraction[1][6:]):
        parsed += timedelta(microseconds=1)
    return parsed


def _asset(row: Record) -> Record:
    value = row.get("resource")
    if not isinstance(value, dict):
        raise ValueError("Missing asset resource")
    return value


def _host(row: Record, fallback: str | None = None) -> tuple[list[Observation], bool]:
    host = _asset(row)
    values = indicators([host.get("ip"), fallback])
    malformed = not values
    services = row.get("matched_services") or host.get("services", [])
    records = []
    rows, invalid = object_rows(services)
    malformed |= invalid
    for service in rows:
        records.append(
            Observation(
                values,
                observation_time(service.get("scan_time") or service.get("observed_at")),
                {"record": row, "service": service},
            )
        )
    if not rows:
        records.append(Observation(values, observation_time(host.get("observed_at")), row))
    return records, malformed


def _certificate(row: Record) -> tuple[list[Observation], bool]:
    cert = _asset(row)
    names = cert.get("names", [])
    malformed = not isinstance(names, list)
    names = names if isinstance(names, list) else []
    # Certificate membership/validity is not evidence of deployment time.
    return [Observation(indicators(names), None, row, cert.get("fingerprint_sha256"))], malformed


def _timeline(arguments: Record, data: Record) -> Page:
    rows, malformed = object_rows(data.get("events") if data.get("events") is not None else [])
    records = []
    lower, upper = instant(arguments["start_time"]), instant(arguments["end_time"], upper=True)
    for row in rows:
        try:
            event = _asset(row)
        except ValueError:
            malformed = True
            continue
        date = observation_time(event.get("event_time"))
        if date is None or not lower <= instant(date) <= upper:
            malformed = True
        records.append(Observation(indicators([arguments["host_id"]]), date, row))
    page = Page(records, data, complete=False)
    bound = data.get("scanned_to")
    page.metadata["timeline_scanned_to"] = bound
    if not isinstance(bound, str):
        page.gap = "provider_pagination_boundary_unavailable"
    else:
        try:
            boundary = instant(bound, upper=True)
        except (ValueError, OverflowError):
            page.gap = "provider_pagination_boundary_unavailable"
        else:
            if boundary >= upper:
                page.gap = "provider_pagination_no_progress"
            elif boundary <= lower:
                page.complete = True
            else:
                page.continuation = {**arguments, "end_time": bound}
    if malformed:
        page.complete = False
        page.gap = "unrecognized_provider_records"
    # Completion describes retrieval only, never entitlement to all historical observations.
    return coverage(page, "historical_coverage_depends_on_entitlement")


def censys_page(operation: str, arguments: Record, raw: Any) -> Page:
    if not isinstance(raw, dict) or not isinstance(raw.get("result"), dict):
        raise ValueError("Missing Censys result envelope")
    data = raw["result"]
    if operation == "get_host_timeline":
        return _timeline(arguments, data)
    if operation == "get_host":
        records, malformed = _host(data, arguments["host_id"])
        page = Page(
            records,
            raw,
            complete=not malformed,
            gap="unrecognized_provider_records" if malformed else None,
        )
    elif operation == "get_certificate":
        records, malformed = _certificate(data)
        page = Page(
            records,
            raw,
            complete=not malformed,
            gap="unrecognized_provider_records" if malformed else None,
        )
    else:
        rows, malformed = object_rows(data.get("hits") if data.get("hits") is not None else [])
        records = []
        for row in rows:
            try:
                if isinstance(row.get("host_v1"), dict):
                    found, invalid = _host(row["host_v1"])
                elif isinstance(row.get("certificate_v1"), dict):
                    found, invalid = _certificate(row["certificate_v1"])
                else:
                    malformed = True
                    continue
                records.extend(found)
                malformed |= invalid
            except (ValueError, TypeError, AttributeError):
                malformed = True
        token = data.get("next_page_token")
        page = Page(records, raw, complete=isinstance(token, str) and not token and not malformed)
        if isinstance(token, str) and token and token != arguments.get("page_token"):
            page.continuation = {**arguments, "page_token": token}
        elif token:
            page.gap = (
                "provider_pagination_no_progress"
                if isinstance(token, str)
                else "invalid_provider_cursor"
            )
        elif token is None:
            page.gap = "provider_pagination_boundary_unavailable"
        if malformed:
            page.gap = "unrecognized_provider_records"
    return coverage(
        page,
        "observation_dates_unavailable" if any(r.observed_at is None for r in records) else None,
        "provider_field_projection" if arguments.get("fields") else None,
    )
