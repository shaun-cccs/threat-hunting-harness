"""Explicit, small authentication checks. These never query indicators."""

import asyncio
import json
import os
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


def credentials(env_file: Path) -> dict[str, str]:
    values = {k: v for k, v in dotenv_values(env_file).items() if v and k in PROVIDER_VARIABLES}
    for name in PROVIDER_VARIABLES:
        if os.environ.get(name):
            values[name] = os.environ[name]
    return values


def write_report(path: Path, report: Record | list[Record]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps(report, indent=2) + "\n")


async def validate_connections(keys: dict[str, str], output: Path) -> Record:
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
    for provider, (variable, url, auth) in endpoints.items():
        key = keys.get(variable) or (keys.get("VT_APIKEY") if provider == "gti" else None)
        if not key:
            report["providers"][provider] = {"status": "not_configured", "requests": 0}
            continue
        try:
            async with httpx.AsyncClient(
                timeout=15, follow_redirects=False, trust_env=False
            ) as client:
                response = await client.get(
                    url,
                    params={"key": key} if auth == "query" else None,
                    headers={auth: key} if auth != "query" else None,
                )
            report["providers"][provider] = {
                "status": "authenticated" if response.status_code == 200 else "not_validated",
                "http_status": response.status_code,
                "requests": 1,
            }
        except httpx.HTTPError:
            report["providers"][provider] = {"status": "transport_unavailable", "requests": 1}
    if keys.get("CENSYS_API_KEY"):
        headers = {"Authorization": "Bearer " + keys["CENSYS_API_KEY"]}
        if keys.get("CENSYS_ORG_ID"):
            headers["X-Organization-ID"] = keys["CENSYS_ORG_ID"]
        source = McpTransport(url="https://mcp.platform.censys.io/platform/mcp/", headers=headers)
        try:
            async with asyncio.timeout(35):
                inventory = await source.inventory()
            write_report(output / "censys-inventory.json", inventory)
            report["providers"]["censys"] = {
                "status": "mcp_connected",
                "tools": len(inventory),
                "sessions": 1,
                "tool_calls": 0,
            }
        except Exception:
            report["providers"]["censys"] = {
                "status": "connection_not_validated",
                "sessions": 1,
                "tool_calls": 0,
                "organization_id_configured": bool(keys.get("CENSYS_ORG_ID")),
            }
    else:
        report["providers"]["censys"] = {"status": "not_configured", "sessions": 0}
    write_report(output / "connections.json", report)
    return report
