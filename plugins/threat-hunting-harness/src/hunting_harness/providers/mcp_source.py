"""Selected provider-owned MCP retrieval tools with pinned input schemas."""

import copy
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path

import jsonschema

from ..models import Record, indicator, now
from .base import Page, SourceGap, observation_time
from .greynoise import greynoise_page
from .gti import gti_page
from .parsing import error_code, payload
from .transport import McpTransport

VERSIONS = {
    "gti": "9885ec6856ec72333091cf1a3b2ac1bb26abe149",
    "greynoise": "cc3204dcde0994daebc09c0ac1a8ceea6cc59b81",
}
RELATIONSHIPS = {
    "get_entities_related_to_a_domain": {
        "resolutions",
        "historical_ssl_certificates",
        "historical_whois",
        "subdomains",
        "siblings",
    },
    "get_entities_related_to_an_ip_address": {
        "resolutions",
        "historical_ssl_certificates",
        "historical_whois",
    },
}


class McpSource:
    api_requests_per_call: int | None = None
    mcp_calls_per_call = 1

    def __init__(self, name: str, transport: McpTransport):
        if name not in VERSIONS:
            raise ValueError("Unknown provider")
        self.name, self.version, self.transport = name, VERSIONS[name], transport
        self.schemas: Record = json.loads(
            (Path(__file__).parent / "schemas" / f"{name}.json").read_text()
        )

    def operations(self) -> Record:
        # Callers cannot mutate the reviewed schema through a capability response.
        return copy.deepcopy(self.schemas)

    def validate(self, operation: str, arguments: Record) -> None:
        if operation not in self.schemas:
            raise ValueError("Unsupported existing-observation operation")
        schema = self.schemas[operation]
        try:
            jsonschema.validate(arguments, schema)
        except jsonschema.ValidationError:
            raise ValueError("Arguments do not match the reviewed provider schema") from None
        if not set(arguments) <= set(schema["properties"]):
            raise ValueError("Unexpected provider argument")
        if any(isinstance(value, str) and not value.strip() for value in arguments.values()):
            raise ValueError("Provider arguments cannot be blank")
        for key in ("ip", "ip_address", "host_id"):
            if key in arguments:
                ipaddress.ip_address(arguments[key])
        if "domain" in arguments:
            domain = indicator(arguments["domain"])
            if "/" in arguments["domain"] or domain != arguments["domain"].lower().rstrip("."):
                raise ValueError("Expected a canonical domain name")
            try:
                ipaddress.ip_address(domain)
            except ValueError:
                pass
            else:
                raise ValueError("Expected a domain, not an IP address")
        if "certificate_id" in arguments and not re.fullmatch(
            r"[a-fA-F0-9]{64}", arguments["certificate_id"]
        ):
            raise ValueError("Expected a SHA-256 certificate fingerprint")
        for key, minimum, maximum in (
            ("limit", 0, None),
            ("size", 1, 10000),
            ("page_size", 1, 1000),
        ):
            value = arguments.get(key)
            if value is not None and (
                type(value) is not int
                or value < minimum
                or (maximum is not None and value > maximum)
            ):
                raise ValueError(f"Invalid {key}")
        if operation in RELATIONSHIPS:
            if arguments["relationship_name"] not in RELATIONSHIPS[operation]:
                raise ValueError("Relationship is outside the reviewed infrastructure subset")
        for key in ("at_time", "start_time", "end_time"):
            if arguments.get(key) is not None and observation_time(arguments[key]) is None:
                raise ValueError("Expected an ISO 8601 time")
        start, end = arguments.get("start_time"), arguments.get("end_time")
        if start and end:
            # Compare normalized instants rather than strings with differing offsets.
            parsed_start, parsed_end = observation_time(start), observation_time(end)
            assert parsed_start is not None and parsed_end is not None
            if datetime.fromisoformat(parsed_start) > datetime.fromisoformat(parsed_end):
                raise ValueError("History end precedes start")

    async def fetch(self, operation: str, arguments: Record) -> Page:
        self.validate(operation, arguments)
        try:
            raw = await self.transport.invoke(operation, arguments, self.schemas[operation])
        except SourceGap:
            raise
        except Exception:
            raise SourceGap("provider_mcp_unavailable") from None
        data = payload(raw)
        if isinstance(data, dict) and (data.get("error") or data.get("errors")):
            raise SourceGap(error_code(data.get("error") or data["errors"]))
        parser = {"gti": gti_page, "greynoise": greynoise_page}[self.name]
        try:
            page = parser(operation, arguments, data)
        except (KeyError, TypeError, ValueError, AttributeError):
            page = Page([], data, complete=False, gap="unrecognized_provider_response")
        page.raw = raw
        page.api_requests, page.mcp_calls = None, 1
        page.metadata.update(
            provider_version=self.version,
            raw_scope="provider_MCP_response",
            retrieved_at=now(),
            api_request_accounting="unobservable",
            credit_accounting="unavailable",
        )
        return page
