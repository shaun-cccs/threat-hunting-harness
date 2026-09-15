"""Private, automatically managed backend for the installed Codex plugin."""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import cast

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from . import analysis
from .config import gateway_token
from .connections import credentials, validate_connections, write_report
from .exports import write_exports
from .gateway import Gateway
from .models import Record
from .providers.base import Provider
from .providers.censys import Censys
from .providers.mcp_source import McpSource
from .providers.shodan import Shodan
from .providers.transport import McpTransport
from .server import create_app


def configured_providers(keys: dict[str, str], paths: dict[str, str]) -> dict[str, Provider]:
    """Use the plugin's prepared dependencies, independent of the user's checkout."""
    result: dict[str, Provider] = {}
    if key := keys.get("SHODAN_API_KEY"):
        result["shodan"] = Shodan(key)
    if key := keys.get("CENSYS_API_KEY"):
        result["censys"] = Censys(key, keys.get("CENSYS_ORG_ID"))
    if key := keys.get("GTI_API_KEY") or keys.get("VT_APIKEY"):
        result["gti"] = McpSource("gti", McpTransport(command=paths["gti"], env={"VT_APIKEY": key}))
    if key := keys.get("GREYNOISE_API_KEY"):
        result["greynoise"] = McpSource(
            "greynoise",
            McpTransport(
                command=paths["node"],
                args=[paths["greynoise"]],
                env={"GREYNOISE_API_KEY": key},
            ),
        )
    return result


def configure_tools(mcp: FastMCP, gateway: Gateway, workspace: Path, state: Path) -> None:
    connection_lock = asyncio.Lock()

    @mcp.tool()
    def case_list() -> Record:
        """List this workspace's retained hunts to reopen a case without starting over."""
        return {
            "cases": [
                {key: case[key] for key in ("id", "hypothesis", "seeds", "start", "end", "status")}
                for case in (gateway.case_read(case_id) for case_id in gateway.store.case_ids())
            ]
        }

    @mcp.tool()
    def analyst_decide(
        case_id: str, finding_id: str, decision: str, rationale: str, confirmation: str
    ) -> Record:
        """Record an analyst's explicit chat decision; quote their instruction in confirmation.

        Only the coordinator may call this after the user has accepted, rejected, or requested
        more work on the finding. Investigator/reviewer judgments are not analyst decisions.
        The confirmation is an audit record, not authentication of a human identity.
        """
        if not confirmation.strip():
            raise ValueError("An explicit analyst instruction is required")

        def record_confirmation(case: Record) -> Record:
            result = analysis.decide(case, finding_id, decision, rationale)
            result.update(confirmation=confirmation, origin="codex_chat")
            return result

        return gateway.store.change(case_id, record_confirmation)

    @mcp.tool()
    async def provider_connections(live: bool = False, refresh: bool = False) -> Record:
        """Inspect .env configuration; live=True opts into bounded account metadata checks.

        Cached live results are reused unless refresh=True. Never queries an indicator.
        """
        keys = credentials(workspace / ".env")
        cached = state / "connections" / "connections.json"
        if not live:
            return {
                "configured_providers": sorted(gateway.providers),
                "requests": 0,
                "cached_report": str(cached) if cached.exists() else None,
            }
        async with connection_lock:
            fingerprint = hashlib.sha256(
                json.dumps([keys, Censys.version], sort_keys=True).encode()
            ).hexdigest()
            identity = cached.parent / "configuration.json"
            same_configuration = False
            if identity.exists():
                same_configuration = (
                    json.loads(identity.read_text()).get("fingerprint") == fingerprint
                )
            if cached.exists() and same_configuration and not refresh:
                return {**cast(Record, json.loads(cached.read_text())), "cached": True}
            result = await validate_connections(keys, cached.parent)
            write_report(identity, {"fingerprint": fingerprint})
            return {**result, "cached": False}

    @mcp.tool()
    def case_export_files(case_id: str) -> Record:
        """Write retained Markdown, JSON and CSV reports and return their local file paths."""
        exported = gateway.case_export(case_id)
        output = state / "exports" / case_id
        write_exports(output, exported)
        return {
            "case_id": case_id,
            "status": exported["json"]["status"],
            "markdown": str(output / "report.md"),
            "json": str(output / "case.json"),
            "csv": str(output / "candidates.csv"),
        }

    @mcp.tool()
    async def evaluate_benchmarks() -> Record:
        """Run synthetic benchmarks and save metrics/exports without live calls or models."""
        from uuid import uuid4

        from .evaluation import evaluate

        root = Path(__file__).resolve().parents[2]
        output = state / "evaluations" / uuid4().hex
        result = await evaluate(root / "benchmarks", output)
        return {"result": result, "artifacts": str(output), "live_provider_requests": 0}


class Runtime:
    def __init__(self, workspace: Path, state: Path, paths: dict[str, str]):
        self.workspace, self.state, self.paths = workspace, state, paths
        self.last_seen = time.monotonic()
        self.retiring = False
        self.version = os.environ.get("HUNT_PLUGIN_VERSION", "0.1.0")
        self.keys: dict[str, str] | None = None
        self.gateway: Gateway
        self.token = gateway_token(state)
        self.app = create_app(state / "cases", self.token, configure=self.configure)
        application = cast(Starlette, self.app.app)
        application.router.routes.append(Route("/plugin/health", self.health))
        application.router.routes.append(Route("/plugin/retire", self.retire, methods=["POST"]))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == "/mcp" and self.retiring:
            await JSONResponse({"status": "updating"}, status_code=503)(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def configure(self, mcp: FastMCP, gateway: Gateway) -> None:
        self.mcp = mcp
        self.gateway = gateway
        configure_tools(mcp, gateway, self.workspace, self.state)

    def refresh(self) -> None:
        self.last_seen = time.monotonic()
        keys = credentials(self.workspace / ".env")
        if self.keys != keys:
            self.gateway.providers = configured_providers(keys, self.paths)
            self.keys = keys

    async def health(self, request: Request) -> JSONResponse:
        try:
            self.refresh()
        except (OSError, ValueError):
            return JSONResponse(
                {"status": "configuration_error", "env_file": str(self.workspace / ".env")}
            )
        return JSONResponse(
            {
                "status": "updating" if self.retiring else "ready",
                "version": self.version,
                "workspace": str(self.workspace),
                "env_file": str(self.workspace / ".env"),
                "configured_providers": sorted(self.gateway.providers),
                "active_queries": len(self.gateway.tasks),
                "state_directory": str(self.state),
                "live_requests_during_setup": 0,
            }
        )

    async def retire(self, request: Request) -> JSONResponse:
        self.retiring = True
        return JSONResponse({"status": "updating", "active_queries": len(self.gateway.tasks)})

    async def serve(self, idle_seconds: float) -> None:
        self.refresh()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(self, log_level="error", access_log=False, lifespan="on")
        )
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("Plugin backend did not start")
                await asyncio.sleep(0.02)
            write_report(
                self.state / "service.json",
                {
                    "status": "ready",
                    "url": f"http://127.0.0.1:{port}",
                    "token": self.token,
                    "version": self.version,
                    "pid": os.getpid(),
                },
            )
            while not task.done():
                if (
                    self.retiring or time.monotonic() - self.last_seen > idle_seconds
                ) and not self.gateway.tasks:
                    server.should_exit = True
                await asyncio.sleep(min(1, idle_seconds / 2))
            await task
        finally:
            server.should_exit = True
            if not task.done():
                await task
            listener.close()
            write_report(
                self.state / "service.json", {"status": "stopped", "version": self.version}
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--paths", type=Path, required=True)
    args = parser.parse_args()
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)
    try:
        paths = json.loads(args.paths.read_text())
        runtime = Runtime(args.workspace, args.state, paths)
        asyncio.run(runtime.serve(float(os.environ.get("HUNT_PLUGIN_IDLE_SECONDS", "90"))))
    except Exception:
        write_report(
            args.state / "service.json",
            {
                "status": "setup_failed",
                "error": "backend_start_failed",
                "log": str(args.state / "setup.log"),
                "version": os.environ.get("HUNT_PLUGIN_VERSION", "0.1.0"),
            },
        )
        raise


if __name__ == "__main__":
    main()
