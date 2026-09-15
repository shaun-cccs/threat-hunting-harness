"""Explicit, small authentication checks. These never query indicators."""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import httpx
from dotenv import dotenv_values

from .models import Record, now
from .providers.transport import McpTransport

PROVIDER_VARIABLES = (
    "SHODAN_API_KEY",
    "CENSYS_API_KEY",
    "CENSYS_ORG_ID",
    "GTI_API_KEY",
    "VT_APIKEY",
    "GREYNOISE_API_KEY",
)
METADATA_TIMEOUT = 15
CENSYS_TIMEOUT = 35


def credentials(env_file: Path) -> dict[str, str]:
    values = {k: v for k, v in dotenv_values(env_file).items() if v and k in PROVIDER_VARIABLES}
    for name in PROVIDER_VARIABLES:
        if os.environ.get(name):
            values[name] = os.environ[name]
    return values


def write_report(path: Path, report: Record | list[Record]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, filename = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


async def _metadata_check(key: str | None, url: str, auth: str) -> Record:
    if not key:
        return {"status": "not_configured", "requests": 0}
    try:
        # HTTPX's per-operation timeout alone does not bound total response time.
        async with asyncio.timeout(METADATA_TIMEOUT):
            async with httpx.AsyncClient(
                timeout=METADATA_TIMEOUT, follow_redirects=False, trust_env=False
            ) as client:
                response = await client.get(
                    url,
                    params={"key": key} if auth == "query" else None,
                    headers={auth: key} if auth != "query" else None,
                )
        return {
            "status": "authenticated" if response.status_code == 200 else "not_validated",
            "http_status": response.status_code,
            "requests": 1,
        }
    except (httpx.HTTPError, TimeoutError):
        return {"status": "transport_unavailable", "requests": 1}


async def _censys_check(keys: dict[str, str], output: Path) -> Record:
    if not keys.get("CENSYS_API_KEY"):
        return {"status": "not_configured", "sessions": 0}
    headers = {"Authorization": "Bearer " + keys["CENSYS_API_KEY"]}
    if keys.get("CENSYS_ORG_ID"):
        headers["X-Organization-ID"] = keys["CENSYS_ORG_ID"]
    source = McpTransport(url="https://mcp.platform.censys.io/platform/mcp/", headers=headers)
    try:
        async with asyncio.timeout(CENSYS_TIMEOUT):
            inventory = await source.inventory()
        write_report(output / "censys-inventory.json", inventory)
        return {"status": "mcp_connected", "tools": len(inventory), "sessions": 1, "tool_calls": 0}
    except Exception:
        return {
            "status": "connection_not_validated",
            "sessions": 1,
            "tool_calls": 0,
            "organization_id_configured": bool(keys.get("CENSYS_ORG_ID")),
        }


async def validate_connections(keys: dict[str, str], output: Path) -> Record:
    """Check each configured account once, concurrently, without indicator queries."""
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    report: Record = {
        "checked_at": now(),
        "purpose": "authentication and metadata only",
        "intelligence_queries": 0,
        "providers": {},
    }
    endpoints = {
        "shodan": ("SHODAN_API_KEY", "https://api.shodan.io/api-info", "query"),
        "gti": ("GTI_API_KEY", "https://www.virustotal.com/api/v3/users/me", "x-apikey"),
        "greynoise": ("GREYNOISE_API_KEY", "https://api.greynoise.io/v3/user", "key"),
    }
    checks = [
        _metadata_check(
            keys.get(variable) or (keys.get("VT_APIKEY") if provider == "gti" else None),
            url,
            auth,
        )
        for provider, (variable, url, auth) in endpoints.items()
    ]
    # All checks fit within the longest individual deadline instead of accumulating
    # three metadata deadlines before starting the Censys handshake.
    results = await asyncio.gather(*checks, _censys_check(keys, output))
    report["providers"] = dict(zip([*endpoints, "censys"], results, strict=True))
    write_report(output / "connections.json", report)
    return report
