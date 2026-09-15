"""Shodan Python SDK retrieval with one observable request and raw JSON per page."""

import asyncio
import ipaddress
import logging
from typing import Any

import requests
from pydantic import Field, SecretStr, StrictBool, StrictInt, field_validator
from requests.adapters import BaseAdapter
from shodan import APIError  # type: ignore[import-untyped]
from shodan import Shodan as SDK

from ..models import Input, Record, now
from .base import Observation, Page, SourceGap, observation_time
from .parsing import coverage, object_rows

SDK_VERSION = "1.31.0"


def http_gap(status: int) -> str:
    return {
        400: "provider_invalid_request",
        401: "provider_authentication_failed",
        403: "provider_access_denied",
        404: "provider_record_not_found",
        429: "provider_rate_limited",
    }.get(status, f"provider_http_{status}")


class _Session(requests.Session):
    """Bound and observe the pinned SDK's synchronous Requests transport."""

    def __init__(self, transport: BaseAdapter | None):
        super().__init__()
        self.trust_env = False
        self.requests = 0
        self.response: requests.Response | None = None
        if transport is not None:
            self.mount("https://", transport)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        # One attempted dispatch is the reservation ceiling, including SDK changes.
        if self.requests:
            raise self.failure("unexpected_provider_request")
        kwargs.update(timeout=20, allow_redirects=False)
        self.requests += 1
        self.response = super().send(request, **kwargs)
        return self.response

    def failure(self, code: str) -> SourceGap:
        return SourceGap(
            code,
            usage={
                "api_requests": self.requests,
                "mcp_calls": 0,
                "returned_records": None if self.requests else 0,
                "credits": None if self.requests else 0,
            },
        )


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
    version = f"sdk-{SDK_VERSION}-adapter-1"
    api_requests_per_call: int | None = 1
    mcp_calls_per_call = 0

    def __init__(self, key: str, transport: BaseAdapter | None = None):
        self.key = SecretStr(key)
        self.transport = transport

    def operations(self) -> Record:
        return {"host": Host.model_json_schema(), "search": Search.model_json_schema()}

    def validate(self, operation: str, arguments: Record) -> None:
        if operation not in self.operations():
            raise ValueError("Unsupported existing-observation operation")
        (Host if operation == "host" else Search).model_validate(arguments)

    def _request(self, operation: str, arguments: Record) -> tuple[Any, Record]:
        # urllib3 debug messages include the credential-bearing request URL.
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
        with _Session(self.transport) as session:
            try:
                sdk = SDK(self.key.get_secret_value())
                sdk._session.close()
                sdk._session = session
                # Ignore SHODAN_API_URL; credentials go only to the reviewed provider.
                sdk.base_url = "https://api.shodan.io"
                if operation == "host":
                    host = Host.model_validate(arguments)
                    sdk.host(host.ip, history=host.history, minify=False)
                elif operation == "search":
                    search = Search.model_validate(arguments)
                    sdk.search(search.query, page=search.page, minify=False)
                elif operation == "account_check":
                    sdk.info()
                else:
                    raise ValueError("Unsupported Shodan operation")
            except APIError:
                # SDK exceptions discard status and may include credentials. Use
                # the captured response instead, including malformed success bodies.
                if session.response is None:
                    raise session.failure("provider_transport_unavailable") from None
            except Exception:
                raise session.failure("provider_sdk_unavailable") from None
            response = session.response
            if response is None:
                raise session.failure("provider_response_unavailable")
            if response.status_code != 200:
                raise session.failure(http_gap(response.status_code))
            try:
                raw = response.json()
            except ValueError:
                raw = response.text
            return raw, {"http_status": response.status_code, "api_requests": session.requests}

    async def check_connection(self) -> Record:
        try:
            raw, metadata = await asyncio.to_thread(self._request, "account_check", {})
            return {
                "status": "authenticated"
                if isinstance(raw, dict) and "error" not in raw
                else "response_schema_changed",
                "http_status": metadata["http_status"],
                "requests": metadata["api_requests"],
            }
        except SourceGap as error:
            return {"status": str(error), "requests": (error.usage or {}).get("api_requests", 0)}

    async def fetch(self, operation: str, arguments: Record) -> Page:
        self.validate(operation, arguments)
        raw, metadata = await asyncio.to_thread(self._request, operation, arguments)
        if not isinstance(raw, dict) or "error" in raw:
            page = Page([], raw, complete=False, gap="invalid_provider_response")
        elif operation == "search":
            page = self._search_page(Search.model_validate(arguments), raw)
        else:
            host = Host.model_validate(arguments)
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
        page.api_requests, page.mcp_calls = metadata.pop("api_requests"), 0
        page.metadata.update(
            metadata,
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
