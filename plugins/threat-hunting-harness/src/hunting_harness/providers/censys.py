"""Censys existing host, certificate and timeline evidence."""

from typing import Any

from ..models import Record
from .base import Observation, Page, observation_time
from .parsing import coverage, indicators, object_rows


def censys_page(operation: str, arguments: Record, raw: Any) -> Page:
    if not isinstance(raw, dict):
        raise ValueError("Expected a Censys object")
    continuation = None
    complete = True
    if operation == "search":
        rows, malformed = object_rows(raw["hits"])
        token = raw.get("next_page_token")
        if token is not None and not isinstance(token, str):
            raise ValueError("Invalid continuation token")
        complete = "next_page_token" in raw and not token
        if token:
            continuation = {**arguments, "page_token": token}
    elif operation == "get_host_timeline":
        rows, malformed = object_rows(raw.get("events", raw.get("timeline")))
        complete = False  # No verified exhaustive history contract or cursor input.
    else:
        rows, malformed = object_rows([raw.get("resource", raw)])
    records = []
    for row in rows:
        host = row.get("host", row)
        if not isinstance(host, dict):
            malformed = True
            continue
        if operation == "get_certificate" or "certificate" in row or "cert" in row:
            cert = row.get("certificate", row.get("cert", row))
            if not isinstance(cert, dict):
                malformed = True
                continue
            # SAN membership is evidence of a certificate relationship, not host
            # ownership or a certificate deployment at its issuance/expiry time.
            parsed = cert.get("parsed") or {}
            if not isinstance(parsed, dict):
                parsed, malformed = {}, True
            names = cert.get("names", parsed.get("names", []))
            if not isinstance(names, list):
                names, malformed = [], True
            records.append(
                Observation(
                    indicators(names),
                    None,
                    row,
                    cert.get("fingerprint_sha256") or arguments.get("certificate_id"),
                )
            )
            continue
        values = indicators([host.get("ip"), arguments.get("host_id")])
        if not values:
            malformed = True
        services = host.get("services", [])
        if not isinstance(services, list):
            services, malformed = [], True
        service_rows, invalid = object_rows(services)
        malformed |= invalid
        if service_rows:
            for service in service_rows:
                records.append(
                    Observation(
                        values,
                        observation_time(service.get("observed_at")),
                        {"record": row, "service": service},
                        row.get("id"),
                    )
                )
        else:
            records.append(
                Observation(
                    values,
                    observation_time(host.get("observed_at") or host.get("timestamp")),
                    row,
                    row.get("id"),
                )
            )
    page = Page(
        records,
        raw,
        complete=complete and not malformed,
        continuation=continuation,
        gap="unrecognized_provider_records" if malformed else None,
    )
    if not page.complete and not continuation:
        page.gap = page.gap or "history_or_pagination_incomplete"
    return coverage(
        page,
        "history_or_pagination_incomplete" if not page.complete and not continuation else None,
        "observation_dates_unavailable" if any(r.observed_at is None for r in records) else None,
        "provider_field_projection" if arguments.get("fields") else None,
    )
