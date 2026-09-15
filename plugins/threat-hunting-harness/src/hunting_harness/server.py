"""Authenticated loopback Streamable HTTP MCP transport."""

import hmac
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .gateway import Gateway
from .models import CaseSpec, Record
from .playbooks import PLAYBOOKS
from .providers.base import Provider


class BearerAuth:
    def __init__(self, app: ASGIApp, token: str):
        if len(token) < 32:
            raise ValueError("Gateway token must contain at least 32 characters")
        self.app, self.token = app, token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            supplied = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, f"Bearer {self.token}".encode()):
                await JSONResponse({"error": "Authentication required"}, status_code=401)(
                    scope, receive, send
                )
                return
        await self.app(scope, receive, send)


def create_app(
    root: Path,
    token: str,
    providers: dict[str, Provider] | None = None,
    configure: Callable[[FastMCP, Gateway], None] | None = None,
) -> BearerAuth:
    gateway = Gateway(root, providers)
    mcp = FastMCP(
        "Threat hunting",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        ),
    )

    @mcp.tool()
    def case_create(spec: CaseSpec) -> Record:
        """Create a case without contacting any provider."""
        return gateway.case_create(spec)

    @mcp.tool()
    def case_read(
        case_id: str,
        view: str = "summary",
        section: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> Record:
        """Read the retained case and recorded hunt status.

        The default view omits retained provider payloads so a grown case stays readable. Pass
        section with offset to page one list, or view="full" for whole records under a size
        ceiling. Reading evidence raw payloads requires view="full".
        """
        return gateway.case_read(case_id, view=view, section=section, offset=offset, limit=limit)

    @mcp.tool()
    def playbooks() -> Record:
        """Read shared playbooks before selecting an investigation strategy."""
        return PLAYBOOKS

    for method in (
        gateway.provider_operations,
        gateway.query_submit,
        gateway.job_read,
        gateway.candidate_select,
        gateway.candidate_defer,
        gateway.coverage_record,
        gateway.finding_propose,
        gateway.finding_review,
        gateway.branch_record,
        gateway.hunt_settle,
        gateway.case_resume,
        gateway.case_export,
    ):
        mcp.add_tool(method)
    if configure is not None:
        configure(mcp, gateway)
    app = mcp.streamable_http_app()
    transport_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[Record]:
        async with gateway:
            async with transport_lifespan(app) as state:
                yield dict(state or {})

    app.router.lifespan_context = lifespan
    return BearerAuth(app, token)
