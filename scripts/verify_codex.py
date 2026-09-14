"""Opt-in native Codex fixture: one synthetic query, no live provider access."""

import argparse
import asyncio
import json
import logging
import os
import secrets
import signal
import socket
import tempfile
from datetime import date
from pathlib import Path

import httpx
import uvicorn

from hunting_harness.clients import client_environment, command, prepare_client
from hunting_harness.gateway import Gateway
from hunting_harness.models import CaseSpec
from hunting_harness.providers.shodan import Shodan
from hunting_harness.server import create_app


async def verify(root: Path, timeout: int) -> bool:
    client = "codex"
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = Path(tempfile.mkdtemp(prefix="hunting-codex-fixture-"))
    token = secrets.token_urlsafe(32)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    endpoint = f"http://127.0.0.1:{port}/mcp"
    requests: list[dict[str, str]] = []

    def response(request: httpx.Request) -> httpx.Response:
        requests.append({"method": request.method, "path": request.url.path})
        return httpx.Response(
            200,
            json={
                "total": 2,
                "matches": [
                    {
                        "ip_str": "192.0.2.2",
                        "timestamp": "2024-01-15T00:00:00Z",
                        "data": "fixture campaign fingerprint",
                    },
                    {
                        "ip_str": "192.0.2.3",
                        "timestamp": "2024-01-15T00:00:00Z",
                        "data": "fixture shared hosting coincidence",
                    },
                ],
            },
        )

    store = Gateway(root / "cases")
    case = store.case_create(
        CaseSpec(
            hypothesis="Synthetic native client integration; fixture only",
            seeds=["192.0.2.1"],
            start=date(2024, 1, 1),
            end=date(2024, 1, 31),
            limits={"query_calls": 1, "api_requests": 1},
        )
    )
    app = create_app(
        root / "cases",
        token,
        {"shodan": Shodan("fixture-only", transport=httpx.MockTransport(response))},
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False)
    )
    service = asyncio.create_task(server.serve())
    while not server.started:
        if service.done():
            await service
        await asyncio.sleep(0.05)
    prepare_client(client, profile, endpoint)
    prompt = f"""
Run the native hunting integration fixture for existing case {case["id"]}. You are already
connected to the authenticated hunting MCP gateway. All provider responses are synthetic.
Use only hunting MCP tools and native delegation. Do not call shell, file, browser, network
or other provider tools. The case has exactly one query permitted. Read the case and shared
playbooks. Delegate to investigator if native role delegation is available: submit exactly
one shodan search with arguments {{"query":"fixture-campaign-fingerprint","page":1}},
pivot_from 192.0.2.1 and explicit purpose. Read job until it settles. The query returns
192.0.2.2 and 192.0.2.3. Retain both, propose one historical_association finding for
192.0.2.2 using its evidence ID, hypothesis, dated evidence and an alternative explanation
that service similarity alone does not prove malicious use. Have a separate evidence-
reviewer agent review it if native delegation is available, flag uncertainty. Leave analyst
decision to the trusted analyst CLI. Defer candidates after the completed fixture evidence
collection with a reason and settle the hunt, preserving all evidence. Return concise JSON
with case_id, finding_id, reviewer_used, status, available_tool_categories, and any
unavailable control or delegation feature. Never invent successful tool calls or review. No
live provider calls are possible through this fixture gateway."""
    args = command(client, profile, endpoint)
    args += ["exec", "--skip-git-repo-check", "--json", prompt]
    outcome = "completed"
    with (root / "stdout.jsonl").open("w") as stdout, (root / "stderr.log").open("w") as stderr:
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=profile,
            env={
                key: value
                for key, value in client_environment(token).items()
                if not key.startswith("HERDR_")
            },
            stdout=stdout,
            stderr=stderr,
            stdin=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout)
        except TimeoutError:
            outcome = "timeout"
            os.killpg(process.pid, signal.SIGTERM)
            await process.wait()
    server.should_exit = True
    await service
    retained = store.case_read(case["id"])
    reviewed = [finding for finding in retained["findings"] if finding["reviews"]]
    for finding in reviewed:
        store.analyst_decide(
            case["id"],
            finding["id"],
            "accept" if finding["reviews"][-1]["assessment"] == "supported" else "needs_work",
            "Scripted fixture-only decision; not a real analyst assessment",
        )
    report = {
        "client": client,
        "process_outcome": outcome,
        "exit_code": process.returncode,
        "case_id": case["id"],
        "queries": len(retained["queries"]),
        "synthetic_requests": len(requests),
        "live_provider_requests": 0,
        "candidates": len(retained["candidates"]),
        "findings": len(retained["findings"]),
        "reviews": sum(len(f["reviews"]) for f in retained["findings"]),
        "status": retained["status"],
        "usage": retained["usage"],
        "profile_directory": str(profile),
        "scripted_analyst_decisions": len(reviewed),
        "runtime_egress_enforcement": "not_verified",
    }
    verified = bool(
        process.returncode == 0
        and len(requests) == 1
        and reviewed
        and retained["status"] in ("completed", "paused")
    )
    report["workflow_verified"] = verified
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return verified


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/native-codex-check"))
    parser.add_argument("--timeout", type=int, default=180)
    arguments = parser.parse_args()
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")
    logging.getLogger("mcp").setLevel(logging.ERROR)
    raise SystemExit(0 if asyncio.run(verify(arguments.output, arguments.timeout)) else 1)
