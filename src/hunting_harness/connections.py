"""Explicit, small authentication checks. These never query indicators."""

import json
import os
from pathlib import Path

import httpx
from dotenv import dotenv_values

from .models import Record, now

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
    write_report(output / "connections.json", report)
    return report
