"""Authenticated SDK replay sessions and deterministic fixture workflows."""

import asyncio
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from .clients import ROLE_TOOLS, TOOLS, prepare_client
from .exports import write_exports
from .gateway import Gateway
from .models import Record
from .providers.shodan import Shodan
from .server import create_app
from .shodan_fixture import ShodanFixtureTransport


class ReplaySession:
    """A real MCP SDK session over in-process HTTP, with an inspectable role transcript."""

    def __init__(self, session: ClientSession, role: str, transcript: list[Record]):
        self.session, self.role, self.transcript = session, role, transcript

    async def call(self, name: str, arguments: Record | None = None) -> Record:
        if name not in ROLE_TOOLS[self.role]:
            raise ValueError(f"{self.role} is not permitted to call {name} in this replay")
        result = await self.session.call_tool(name, arguments or {})
        if result.isError or result.structuredContent is None:
            raise ValueError(f"MCP replay tool failed: {name}")
        value = dict(result.structuredContent)
        self.transcript.append(
            {"role": self.role, "tool": name, "arguments": arguments or {}, "result": value}
        )
        return value

    async def finished(self, case_id: str, job: Record) -> Record:
        async with asyncio.timeout(15):
            while True:
                result = await self.call("job_read", {"case_id": case_id, "job_id": job["id"]})
                if result["status"] not in ("queued", "active"):
                    return result
                await asyncio.sleep(0.005)


@asynccontextmanager
async def replay_session(
    app: Starlette, role: str, transcript: list[Record]
) -> AsyncIterator[ReplaySession]:
    """Open a distinct authenticated session against the supplied local ASGI app."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        headers={"Authorization": "Bearer " + "fixture-token-" * 4},
        timeout=15,
    ) as http:
        async with streamable_http_client("http://127.0.0.1:8765/mcp", http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                inventory = await session.list_tools()
                if {tool.name for tool in inventory.tools} != set(TOOLS):
                    raise ValueError("Gateway inventory differs from the profile allowlist")
                yield ReplaySession(session, role, transcript)


async def fixture_workflow(client: str, output_dir: Path) -> Record:
    """Exercise shared MCP state with synthetic Shodan data; no installed model is launched."""
    output_dir.mkdir(parents=True, exist_ok=False)
    prepare_client(client, output_dir / "profile", "http://127.0.0.1:8765/mcp")
    transcript: list[Record] = []

    def response(request: httpx.Request) -> httpx.Response:
        time.sleep(0.02)  # Keep one query active long enough to observe status.
        if request.url.path == "/shodan/host/search":
            return httpx.Response(
                200,
                json={
                    "total": 2,
                    "matches": [
                        {
                            "ip_str": "192.0.2.2",
                            "timestamp": "2024-01-15T00:00:00Z",
                            "data": "synthetic distinctive fingerprint",
                        },
                        {
                            "ip_str": "192.0.2.3",
                            "timestamp": "2024-01-15T00:00:00Z",
                            "data": "synthetic shared hosting, insufficient relationship",
                        },
                    ],
                },
            )
        return httpx.Response(200, json={"data": []})

    provider = Shodan("fixture-only", transport=ShodanFixtureTransport(response))
    root = output_dir / "cases"
    app = create_app(root, "fixture-token-" * 4, {"shodan": provider})
    transport_app = cast(Starlette, app.app)
    async with transport_app.router.lifespan_context(transport_app):
        async with replay_session(cast(Starlette, app), "coordinator", transcript) as coordinator:
            case = await coordinator.call(
                "case_create",
                {
                    "spec": {
                        "hypothesis": "Synthetic service-fingerprint replay",
                        "seeds": ["192.0.2.1"],
                        "start": "2024-01-01",
                        "end": "2024-01-31",
                        "limits": {"query_calls": 2},
                    }
                },
            )
            case_id = case["id"]
            await coordinator.call("playbooks")
            branch = await coordinator.call(
                "branch_record",
                {
                    "case_id": case_id,
                    "pivot": "192.0.2.1",
                    "hypothesis": case["hypothesis"],
                    "status": "active",
                    "reason": "Coordinator assigned a scoped investigator branch",
                },
            )
            async with replay_session(
                cast(Starlette, app), "investigator", transcript
            ) as investigator:
                query = {
                    "provider": "shodan",
                    "operation": "search",
                    "arguments": {"query": "synthetic-fingerprint", "page": 1},
                    "pivot_from": "192.0.2.1",
                    "purpose": "Recorded fixture search",
                }
                job = await investigator.call("query_submit", {"case_id": case_id, "query": query})
                active = await coordinator.call("case_read", {"case_id": case_id})
                await investigator.finished(case_id, job)
                duplicate = await investigator.call(
                    "query_submit", {"case_id": case_id, "query": query}
                )
                if duplicate["id"] != job["id"]:
                    raise ValueError("Shared query deduplication failed")
                state = await investigator.call("case_read", {"case_id": case_id})
                findings = []
                for candidate in state["candidates"]:
                    findings.append(
                        await investigator.call(
                            "finding_propose",
                            {
                                "case_id": case_id,
                                "claim": {
                                    "candidate": candidate["indicator"],
                                    "kind": "relatedness",
                                    "statement": "Synthetic relationship for review",
                                    "evidence_ids": candidate["evidence_ids"],
                                    "alternative_explanations": [
                                        "Shared infrastructure or copied banner"
                                    ],
                                },
                            },
                        )
                    )
                    await investigator.call(
                        "candidate_defer",
                        {
                            "case_id": case_id,
                            "deferral": {
                                "candidate": candidate["indicator"],
                                "rationale": (
                                    "Inspected retained observations; no expansion proposed "
                                    "for this candidate"
                                ),
                                "basis": "out_of_scope",
                                "basis_evidence_ids": list(candidate["evidence_ids"]),
                                "reopen_if": "New dated evidence links this candidate to a seed",
                            },
                        },
                    )
                await investigator.call(
                    "branch_record",
                    {
                        "case_id": case_id,
                        "pivot": "192.0.2.1",
                        "hypothesis": case["hypothesis"],
                        "status": "completed",
                        "reason": "Fixture investigation retained both candidates",
                        "branch_id": branch["id"],
                    },
                )
            async with replay_session(
                cast(Starlette, app), "evidence-reviewer", transcript
            ) as reviewer:
                await reviewer.call("case_read", {"case_id": case_id})
                for index, finding in enumerate(findings):
                    await reviewer.call(
                        "finding_review",
                        {
                            "case_id": case_id,
                            "finding_id": finding["id"],
                            "review": {
                                "reviewer": "separate-fixture-reviewer",
                                "assessment": "supported" if index == 0 else "challenged",
                                "rationale": (
                                    "Distinctive dated synthetic relationship"
                                    if index == 0
                                    else "Shared hosting alone is insufficient"
                                ),
                            },
                        },
                    )
            # This trusted API is intentionally absent from the model-facing MCP inventory.
            analyst = Gateway(root)
            for index, finding in enumerate(findings):
                decision = analyst.analyst_decide(
                    case_id,
                    finding["id"],
                    "accept" if index == 0 else "reject",
                    "Scripted fixture decision, not a human assessment",
                )
                transcript.append(
                    {"role": "scripted-analyst", "tool": "analyst_decide", "result": decision}
                )
            settled = await coordinator.call("hunt_settle", {"case_id": case_id})
    # Restart the gateway and reconnect a new client session to the same state.
    reopened_app = create_app(root, "fixture-token-" * 4, {"shodan": provider})
    reopened_transport = cast(Starlette, reopened_app.app)
    async with reopened_transport.router.lifespan_context(reopened_transport):
        async with replay_session(
            cast(Starlette, reopened_app), "coordinator", transcript
        ) as reopened:
            retained = await reopened.call("case_read", {"case_id": case_id})
            await reopened.call("case_resume", {"case_id": case_id, "refresh": True})
            final = await reopened.call("hunt_settle", {"case_id": case_id})
            exported = await reopened.call("case_export", {"case_id": case_id})
    write_exports(output_dir, exported)
    result: Record = {
        "client": client,
        "validation": "offline_mcp_sdk_replay",
        "case_id": case_id,
        "native_model_workflow": "not_exercised",
        "live_provider_calls": 0,
        "scripted_analyst_decisions": True,
        "active_status": active,
        "settled": settled,
        "reopened_settled": final,
        "retained_usage": retained["usage"],
        "limits": retained["limits"],
        "transcript": str(output_dir / "transcript.json"),
        "runtime_enforcement": "not_verified",
    }
    (output_dir / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
    (output_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
