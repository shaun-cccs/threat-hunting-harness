import asyncio

import httpx
import pytest

from hunting_harness.gateway import Gateway
from hunting_harness.models import CaseSpec, QuerySpec
from hunting_harness.providers.shodan import Shodan


def case_spec():
    return CaseSpec(
        hypothesis="Service reuse", seeds=["192.0.2.1"], start="2024-01-01", end="2024-02-01"
    )


async def finished(gateway, case_id, job_id):
    async with asyncio.timeout(3):
        while gateway.job_read(case_id, job_id)["status"] in ("queued", "active"):
            await asyncio.sleep(0.01)
    return gateway.job_read(case_id, job_id)


async def test_query_retains_evidence_and_reopens_without_repeating_provider_request(tmp_path):
    def response(request):
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "ip_str": "192.0.2.1",
                        "timestamp": "2024-01-03",
                        "port": 443,
                        "data": "banner",
                    }
                ]
            },
        )

    providers = {"shodan": Shodan("fixture", transport=httpx.MockTransport(response))}
    async with Gateway(tmp_path, providers) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="shodan",
            operation="host",
            arguments={"ip": "192.0.2.1"},
            pivot_from="192.0.2.1",
            purpose="Inspect recorded services",
        )
        job = await gateway.query_submit(case["id"], query)
        assert (await finished(gateway, case["id"], job["id"]))["status"] == "completed"
    async with Gateway(tmp_path, {}) as gateway:
        case = gateway.case_read(case["id"])
        assert case["evidence"][0]["raw"]["data"] == "banner"
        assert case["evidence"][0]["query_ids"] == [job["id"]]
        assert case["evidence"][0]["observed_at"] == "2024-01-03T00:00:00+00:00"
        assert case["queries"][0]["status"] == "completed"


@pytest.mark.parametrize("measure", ["query_calls", "api_requests"])
async def test_shared_limit_and_deduplication_while_status_remains_responsive(tmp_path, measure):
    released = asyncio.Event()

    async def response(request):
        await released.wait()
        return httpx.Response(200, json={"data": []})

    providers = {"shodan": Shodan("fixture", transport=httpx.MockTransport(response))}
    async with Gateway(tmp_path, providers) as gateway:
        spec = case_spec().model_copy(update={"limits": {measure: 1}})
        case = gateway.case_create(spec)
        query = QuerySpec(
            provider="shodan",
            operation="host",
            arguments={"ip": "192.0.2.1"},
            pivot_from="192.0.2.1",
            purpose="Inspect recorded services",
        )
        first, second = await asyncio.gather(
            gateway.query_submit(case["id"], query), gateway.query_submit(case["id"], query)
        )
        assert first["id"] == second["id"]
        assert gateway.case_read(case["id"])["usage"]["query_calls"] == 1
        with pytest.raises(ValueError, match="limit"):
            await gateway.query_submit(case["id"], query.model_copy(update={"refresh": True}))
        released.set()
        assert (await finished(gateway, case["id"], first["id"]))["status"] == "completed"


async def test_submitted_query_is_immutable_even_if_caller_changes_its_input(tmp_path):
    requested = []

    def response(request):
        requested.append(request.url.path)
        return httpx.Response(200, json={"data": []})

    provider = Shodan("fixture", transport=httpx.MockTransport(response))
    async with Gateway(tmp_path, {"shodan": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="shodan",
            operation="host",
            arguments={"ip": "192.0.2.1"},
            pivot_from="192.0.2.1",
            purpose="Recorded services",
        )
        job = await gateway.query_submit(case["id"], query)
        query.arguments["ip"] = "192.0.2.99"
        await finished(gateway, case["id"], job["id"])
        assert requested == ["/shodan/host/192.0.2.1"]
        assert gateway.job_read(case["id"], job["id"])["arguments"] == {"ip": "192.0.2.1"}


async def test_interrupted_query_survives_restart_without_automatic_retry(tmp_path):
    entered = asyncio.Event()
    calls = []

    async def response(request):
        calls.append(request.url.path)
        entered.set()
        await asyncio.Event().wait()
        return httpx.Response(200, json={"data": []})

    provider = Shodan("fixture", transport=httpx.MockTransport(response))
    async with Gateway(tmp_path, {"shodan": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="shodan",
            operation="host",
            arguments={"ip": "192.0.2.1"},
            pivot_from="192.0.2.1",
            purpose="Recorded history",
        )
        job = await gateway.query_submit(case["id"], query)
        await asyncio.wait_for(entered.wait(), 3)
        assert gateway.job_read(case["id"], job["id"])["status"] == "active"
    async with Gateway(tmp_path, {"shodan": provider}) as reopened:
        assert reopened.job_read(case["id"], job["id"])["status"] == "interrupted"
        assert reopened.hunt_settle(case["id"])["status"] == "paused"
        reopened.case_resume(case["id"], refresh=True)
        with pytest.raises(ValueError, match="explicit refresh"):
            await reopened.query_submit(case["id"], query)
        assert calls == ["/shodan/host/192.0.2.1"]


class FixtureSource:
    """Synthetic external source; gateway behavior uses only the Provider contract."""

    name = "fixture"
    version = "fixture-v1"
    api_requests_per_call = None
    mcp_calls_per_call = 1

    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = 0

    def operations(self):
        return {"lookup": {}}

    def validate(self, operation, arguments):
        if operation != "lookup":
            raise ValueError("Unsupported operation")

    async def fetch(self, operation, arguments):
        self.calls += 1
        return self.pages.pop(0)


async def test_unknown_api_accounting_cannot_bypass_configured_limit(tmp_path):
    from hunting_harness.providers.base import Page

    provider = FixtureSource([Page([], {}, api_requests=None, mcp_calls=1)])
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        spec = case_spec().model_copy(update={"limits": {"api_requests": 1}})
        case = gateway.case_create(spec)
        query = QuerySpec(
            provider="fixture",
            operation="lookup",
            arguments={},
            pivot_from="192.0.2.1",
            purpose="Recorded context",
        )
        with pytest.raises(ValueError, match="Cannot enforce api_requests"):
            await gateway.query_submit(case["id"], query)
        assert provider.calls == 0
        assert gateway.case_read(case["id"])["queries"] == []
        unlimited = gateway.case_create(case_spec())
        job = await gateway.query_submit(unlimited["id"], query)
        await finished(gateway, unlimited["id"], job["id"])
        usage = gateway.case_read(unlimited["id"])["usage"]
        assert usage == {
            "query_calls": 1,
            "api_requests": None,
            "mcp_calls": 1,
            "returned_records": 0,
            "credits": None,
        }


async def test_shutdown_marks_even_not_yet_started_jobs_interrupted(tmp_path):
    provider = FixtureSource([])
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        case = gateway.case_create(case_spec())
        job = await gateway.query_submit(
            case["id"],
            QuerySpec(
                provider="fixture",
                operation="lookup",
                arguments={},
                pivot_from="192.0.2.1",
                purpose="Queued context",
            ),
        )
    assert gateway.job_read(case["id"], job["id"])["status"] == "interrupted"
    assert provider.calls == 0


async def test_abrupt_restart_preserves_uncertain_execution_and_branch_state(tmp_path):
    import json
    import subprocess
    import sys

    program = """
import asyncio
import json
import os
import sys
from pathlib import Path
import httpx
from hunting_harness.gateway import Gateway
from hunting_harness.models import CaseSpec, QuerySpec
from hunting_harness.providers.shodan import Shodan

async def run():
    entered = asyncio.Event()
    async def response(request):
        entered.set()
        await asyncio.Event().wait()
    provider = Shodan("offline-fixture", transport=httpx.MockTransport(response))
    async with Gateway(Path(sys.argv[1]), {"shodan": provider}) as gateway:
        case = gateway.case_create(CaseSpec(hypothesis="Campaign", seeds=["192.0.2.1"],
                                            start="2024-01-01", end="2024-02-01"))
        gateway.branch_record(case["id"], "192.0.2.1", "Service reuse",
                              "active", "Fetching history")
        job = await gateway.query_submit(case["id"], QuerySpec(provider="shodan", operation="host",
            arguments={"ip": "192.0.2.1"}, pivot_from="192.0.2.1", purpose="Recorded service"))
        await entered.wait()
        print(json.dumps({"case_id": case["id"], "job_id": job["id"]}), flush=True)
        os._exit(0)
asyncio.run(run())
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    refs = json.loads(result.stdout)
    async with Gateway(tmp_path) as reopened:
        job = reopened.job_read(refs["case_id"], refs["job_id"])
        assert job["status"] == "interrupted"
        assert job["gap"] == "execution_uncertain_after_restart"
        assert job["usage"]["api_requests"] is None
        case = reopened.case_read(refs["case_id"])
        assert case["branches"][0]["status"] == "waiting"
        assert reopened.hunt_settle(refs["case_id"])["status"] == "paused"
        assert len(case["queries"]) == 1
