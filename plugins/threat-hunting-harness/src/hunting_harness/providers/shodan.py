"""Narrow Shodan API adapter. No scan or DNS resolution interface exists."""

import ipaddress
import logging
from typing import Any

import httpx
from pydantic import Field, SecretStr, StrictBool, StrictInt, field_validator

from ..models import Input, Record, now
from .base import Observation, Page, SourceGap, observation_time
from .parsing import coverage, object_rows


class Host(Input):
    ip: str
    history: StrictBool = True

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))


class Search(Input):
    query: str = Field(min_length=1)
    page: StrictInt = Field(default=1, ge=1)


class Shodan:
    name = "shodan"
    version = "api-v1"
    api_requests_per_call: int | None = 1
    mcp_calls_per_call = 0

    def __init__(self, key: str, transport: httpx.AsyncBaseTransport | None = None):
        self.key = SecretStr(key)
        self.transport = transport

    def operations(self) -> Record:
        return {"host": Host.model_json_schema(), "search": Search.model_json_schema()}

    def validate(self, operation: str, arguments: Record) -> None:
        if operation not in self.operations():
            raise ValueError("Unsupported existing-observation operation")
        (Host if operation == "host" else Search).model_validate(arguments)

    async def request(self, path: str, params: Record) -> Record:
        # Shodan authenticates in the URL; request logging must not emit it.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        async with httpx.AsyncClient(
            transport=self.transport, timeout=20, follow_redirects=False, trust_env=False
        ) as client:
            try:
                response = await client.get(
                    "https://api.shodan.io" + path,
                    params={**params, "key": self.key.get_secret_value()},
                )
            except httpx.HTTPError:
                raise SourceGap("transport_unavailable") from None
        # A missing host report is not a successful empty search. It may reflect
        # unavailable coverage; never retry it using fresh scans or DNS lookups.
        errors = {
            401: "provider_authentication_failed",
            403: "provider_access_denied",
            404: "provider_record_not_found",
            429: "provider_rate_limited",
        }
        if response.status_code != 200:
            raise SourceGap(
                errors.get(response.status_code, f"provider_http_{response.status_code}")
            )
        try:
            result: Any = response.json()
        except ValueError:
            raise SourceGap("invalid_provider_response") from None
        if not isinstance(result, dict) or "error" in result:
            raise SourceGap("invalid_provider_response")
        return result

    async def fetch(self, operation: str, arguments: Record) -> Page:
        self.validate(operation, arguments)
        if operation == "search":
            search = Search.model_validate(arguments)
            raw = await self.request("/shodan/host/search", search.model_dump())
            page = self._search_page(search, raw)
        else:
            host = Host.model_validate(arguments)
            raw = await self.request(
                f"/shodan/host/{host.ip}", {"history": str(host.history).lower()}
            )
            rows, malformed = object_rows(raw.get("data"))
            records = []
            for row in rows:
                # The endpoint's validated IP is a safe fallback for banners
                # without ip_str; do not substitute a host's last_update date.
                records.append(self._observation(row, host.ip))
            page = Page(
                records,
                raw,
                complete=not malformed,
                gap="unrecognized_provider_records" if malformed else None,
                metadata={"history_requested": host.history},
            )
            if not host.history:
                page.metadata["history_coverage"] = "latest_only"
                coverage(page, "historical_observations_not_requested")
            else:
                page.metadata["history_coverage"] = "available_provider_history_only"
                # The API returns stored history, with no promised start date or
                # guarantee that it covers every instant in the campaign window.
                coverage(page, "historical_coverage_bounds_unavailable")
        page.metadata.update(
            provider_version=self.version,
            retrieved_at=now(),
            raw_scope="provider_API_response",
            credit_accounting="unavailable",
        )
        return coverage(
            page,
            "observation_dates_unavailable"
            if any(record.observed_at is None for record in page.records)
            else None,
        )

    @staticmethod
    def _observation(row: Record, ip: str) -> Observation:
        source = row.get("_shodan")
        source_id = source.get("id") if isinstance(source, dict) else None
        return Observation(
            [ip],
            observation_time(row.get("timestamp")),
            row,
            source_id if isinstance(source_id, str) else None,
        )

    def _search_page(self, search: Search, raw: Record) -> Page:
        rows, malformed = object_rows(raw.get("matches"))
        records = []
        for row in rows:
            try:
                ip = str(ipaddress.ip_address(row["ip_str"]))
            except (KeyError, ValueError, TypeError):
                malformed = True
                continue
            records.append(self._observation(row, ip))
        total = raw.get("total")
        result_total: int | None = total if type(total) is int and total >= 0 else None
        offset = (search.page - 1) * 100
        complete = result_total is not None and offset + len(rows) >= result_total and not malformed
        # A short/empty page before total is reached is incomplete. Only a full
        # page with a known remaining total gives a documented next-page offset.
        continuation = None
        if (
            not complete
            and len(rows) == 100
            and result_total is not None
            and offset + len(rows) < result_total
        ):
            continuation = {"query": search.query, "page": search.page + 1}
        page = Page(
            records,
            raw,
            complete=complete,
            continuation=continuation,
            gap="unrecognized_provider_records" if malformed else None,
            metadata={
                "page": search.page,
                "page_size": 100,
                "total": result_total,
                "history_coverage": "search_observations_only",
            },
        )
        if len(rows) > 100 or (
            result_total is not None and rows and offset + len(rows) > result_total
        ):
            page.complete, page.continuation = False, None
            page.gap = "inconsistent_provider_pagination"
        if result_total is None:
            page.gap = page.gap or "unknown_result_total"
        elif not page.complete and not page.continuation:
            page.gap = page.gap or "incomplete_provider_page"
        return coverage(
            page,
            "unknown_result_total" if result_total is None else None,
            "incomplete_provider_page" if not complete and not continuation else None,
        )
