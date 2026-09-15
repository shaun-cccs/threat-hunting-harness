"""Censys SDK retrieval with one observable request and retained raw JSON per page."""

import asyncio
import ipaddress
import logging
import re
from typing import Any

import httpx
from censys_platform import SDK, models
from pydantic import Field, SecretStr, StrictInt, StrictStr, field_validator, model_validator

from ..models import Input, Record, now
from .base import Page, SourceGap
from .censys_response import censys_page, instant

SDK_VERSION = "0.16.2"
QUIET = logging.Logger("censys-sdk-quiet")
QUIET.addHandler(logging.NullHandler())
QUIET.propagate = False


def http_gap(status: int) -> str:
    return {
        400: "provider_invalid_request",
        401: "provider_authentication_failed",
        403: "provider_access_denied",
        404: "provider_record_not_found",
        429: "provider_rate_limited",
    }.get(status, f"provider_http_{status}")


class Host(Input):
    host_id: StrictStr = Field(description="IPv4 or IPv6 address of the recorded host.")
    at_time: StrictStr | None = Field(
        default=None, description="ISO 8601 snapshot time; omit for latest."
    )

    @field_validator("host_id")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @field_validator("at_time")
    @classmethod
    def valid_time(cls, value: str | None) -> str | None:
        if value is not None:
            instant(value)
        return value


class Timeline(Input):
    host_id: StrictStr
    start_time: StrictStr = Field(
        description="Older bound, ISO 8601; retained across continuations."
    )
    end_time: StrictStr = Field(
        description="Newer bound, ISO 8601; copy returned continuation exactly."
    )

    @field_validator("host_id")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @model_validator(mode="after")
    def valid_interval(self) -> "Timeline":
        if instant(self.start_time) >= instant(self.end_time, upper=True):
            raise ValueError("History end must follow start")
        return self


class Certificate(Input):
    certificate_id: StrictStr = Field(
        pattern=r"^[a-fA-F0-9]{64}$", description="SHA-256 fingerprint."
    )


class Search(Input):
    query: StrictStr = Field(min_length=1, description="Censys Query Language expression.")
    fields: list[StrictStr] | None = None
    page_size: StrictInt | None = Field(default=50, ge=1, le=100)
    page_token: StrictStr | None = None

    @field_validator("query")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Search query cannot be blank")
        return value


OPERATIONS: dict[str, type[Input]] = {
    "get_host": Host,
    "get_host_timeline": Timeline,
    "get_certificate": Certificate,
    "search": Search,
}


class Censys:
    name = "censys"
    version = f"sdk-{SDK_VERSION}-adapter-1"
    api_requests_per_call: int | None = 1
    mcp_calls_per_call = 0

    def __init__(
        self,
        key: str,
        organization_id: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.key, self.organization_id, self.transport = SecretStr(key), organization_id, transport

    def operations(self) -> Record:
        return {name: model.model_json_schema() for name, model in OPERATIONS.items()}

    def validate(self, operation: str, arguments: Record) -> None:
        if operation not in OPERATIONS:
            raise ValueError("Unsupported existing-observation operation")
        OPERATIONS[operation].model_validate(arguments)

    async def _request(self, operation: str, arguments: Record) -> tuple[Any, Record, bool]:
        requests = 0
        response: httpx.Response | None = None
        schema_changed = False

        async def dispatched(request: httpx.Request) -> None:
            nonlocal requests
            requests += 1

        async def capture(result: httpx.Response) -> None:
            nonlocal response
            await result.aread()
            response = result

        def failure(code: str) -> SourceGap:
            return SourceGap(
                code,
                usage={
                    "api_requests": requests,
                    "mcp_calls": 0,
                    "returned_records": None if requests else 0,
                    "credits": None if requests else 0,
                },
            )

        # SDK debug logging can expose headers; HTTPX can log organization URLs.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        try:
            async with (
                asyncio.timeout(30),
                httpx.AsyncClient(
                    transport=self.transport,
                    timeout=20,
                    follow_redirects=False,
                    trust_env=False,
                    event_hooks={"request": [dispatched], "response": [capture]},
                ) as client,
            ):
                with httpx.Client(follow_redirects=False, trust_env=False) as sync_client:
                    async with SDK(
                        personal_access_token=self.key.get_secret_value(),
                        # Disable the SDK environment fallback; use only workspace configuration.
                        organization_id=self.organization_id or "",
                        client=sync_client,
                        async_client=client,
                        retry_config=None,
                        timeout_ms=20000,
                        debug_logger=QUIET,
                    ) as sdk:
                        sdk.sdk_configuration.globals.organization_id = self.organization_id
                        if operation == "get_host":
                            await sdk.global_data.get_host_async(
                                host_id=arguments["host_id"],
                                at_time=instant(arguments["at_time"])
                                if arguments.get("at_time")
                                else None,
                            )
                        elif operation == "get_host_timeline":
                            await sdk.global_data.get_host_timeline_async(
                                host_id=arguments["host_id"],
                                start_time=instant(arguments["end_time"], upper=True),
                                end_time=instant(arguments["start_time"]),
                            )
                        elif operation == "get_certificate":
                            await sdk.global_data.get_certificate_async(
                                certificate_id=arguments["certificate_id"]
                            )
                        elif operation == "search":
                            body = models.SearchQueryInputBody(
                                **Search.model_validate(arguments).model_dump(exclude_none=True)
                            )
                            await sdk.global_data.search_async(search_query_input_body=body)
                        elif operation == "account_check":
                            if self.organization_id:
                                await sdk.account_management.get_organization_details_async(
                                    organization_id=self.organization_id
                                )
                            else:
                                await sdk.account_management.get_user_credits_async()
                        else:
                            raise ValueError("Unsupported Censys operation")
        except models.ResponseValidationError:
            # Keep valid rows and unknown fields from the captured original JSON.
            schema_changed = True
        except models.SDKBaseError as error:
            if error.status_code == 200:
                # An unexpected media type must not become the misleading
                # "provider_http_200" failure or discard the successful body.
                schema_changed = True
            else:
                raise failure(http_gap(error.status_code)) from None
        except (httpx.HTTPError, TimeoutError):
            raise failure("provider_transport_unavailable") from None
        except Exception:
            raise failure("provider_sdk_unavailable") from None
        if response is None:
            raise failure("provider_response_unavailable")
        if response.status_code != 200:
            raise failure(http_gap(response.status_code))
        try:
            raw = response.json()
        except ValueError:
            # Successful non-JSON responses are still retained as evidence of the gap.
            raw, schema_changed = response.text, True
        metadata: Record = {"http_status": response.status_code, "api_requests": requests}
        request_id = response.headers.get("x-request-id")
        if request_id and re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", request_id):
            metadata["request_id"] = request_id
        return raw, metadata, schema_changed

    async def check_connection(self) -> Record:
        try:
            _, metadata, changed = await self._request("account_check", {})
            return {
                "status": "authenticated" if not changed else "response_schema_changed",
                "http_status": metadata["http_status"],
                "requests": metadata["api_requests"],
                "organization_id_configured": bool(self.organization_id),
            }
        except SourceGap as error:
            return {
                "status": str(error),
                "requests": (error.usage or {}).get("api_requests", 0),
                "organization_id_configured": bool(self.organization_id),
            }

    async def fetch(self, operation: str, arguments: Record) -> Page:
        self.validate(operation, arguments)
        raw, metadata, changed = await self._request(operation, arguments)
        try:
            page = censys_page(operation, arguments, raw)
        except (ValueError, TypeError, KeyError, AttributeError):
            page = Page([], raw, complete=False, gap="unrecognized_provider_response")
        if changed:
            page.complete = False
            page.gap = page.gap or "provider_response_schema_changed"
        page.raw, page.api_requests, page.mcp_calls = raw, metadata.pop("api_requests"), 0
        page.metadata.update(
            metadata,
            provider_version=self.version,
            raw_scope="provider_API_response",
            retrieved_at=now(),
            credit_accounting="unavailable",
        )
        return page
