"""A single explicitly requested lookup of existing Shodan observations."""

import asyncio
import ipaddress
from datetime import date
from pathlib import Path

from .connections import write_report
from .gateway import Gateway
from .models import CaseSpec, QuerySpec, Record
from .providers.shodan import Shodan


async def shodan_smoke(keys: dict[str, str], ip: str, output: Path) -> Record:
    ip = str(ipaddress.ip_address(ip))
    if not keys.get("SHODAN_API_KEY"):
        raise ValueError("SHODAN_API_KEY is not configured")
    async with Gateway(output / "cases", {"shodan": Shodan(keys["SHODAN_API_KEY"])}) as gateway:
        case = gateway.case_create(
            CaseSpec(
                hypothesis="Connectivity check of one existing Shodan host report",
                seeds=[ip],
                start=date(1970, 1, 1),
                end=date.today(),
                limits={"query_calls": 1, "api_requests": 1},
            )
        )
        job = await gateway.query_submit(
            case["id"],
            QuerySpec(
                provider="shodan",
                operation="host",
                arguments={"ip": ip, "history": False},
                pivot_from=ip,
                purpose="One opt-in existing-report smoke check; no search or retry",
            ),
        )
        await asyncio.gather(*gateway.tasks)
        job = gateway.job_read(case["id"], job["id"])
        retained = gateway.case_read(case["id"])
        report = {
            "validation": "live_existing_observation",
            "provider": "shodan",
            "case_id": case["id"],
            "query_id": job["id"],
            "ip": ip,
            "status": job["status"],
            "source_gap": job.get("gap"),
            "usage": retained["usage"],
            "limits": retained["limits"],
            "observations": len(retained["evidence"]),
            "searches": 0,
            "retries": 0,
            "provider_credits": job["usage"]["credits"],
        }
    write_report(output / "shodan-smoke.json", report)
    return report
