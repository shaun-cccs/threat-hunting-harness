"""MCP sessions with explicit transports and no credential-bearing error output."""

import asyncio
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from ..models import Record
from .base import SourceGap
from .parsing import error_code


def _known_gap(error: BaseException) -> SourceGap | None:
    if isinstance(error, SourceGap):
        return error
    if isinstance(error, BaseExceptionGroup):
        return next((gap for child in error.exceptions if (gap := _known_gap(child))), None)
    return None


class McpTransport:
    def __init__(
        self,
        *,
        url: str | None = None,
        headers: dict[str, str] | None = None,
        command: str | None = None,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ):
        if bool(url) == bool(command):
            raise ValueError("Configure exactly one provider MCP transport")
        self.url, self.headers = url, headers or {}
        self.command, self.args, self.env = command, args or [], env or {}

    @asynccontextmanager
    async def session(self) -> AsyncIterator[ClientSession]:
        async with asyncio.timeout(45):
            if self.url:
                async with httpx.AsyncClient(
                    headers=self.headers, timeout=20, follow_redirects=False, trust_env=False
                ) as client:
                    async with streamable_http_client(
                        self.url, http_client=client, terminate_on_close=False
                    ) as streams:
                        async with ClientSession(
                            streams[0], streams[1], read_timeout_seconds=timedelta(seconds=25)
                        ) as s:
                            await s.initialize()
                            yield s
            else:
                if not self.command:
                    raise ValueError("Missing provider MCP command")
                # The MCP SDK adds only a small OS environment allowlist, not the
                # gateway's full environment or other providers' credentials.
                parameters = StdioServerParameters(
                    command=self.command, args=self.args, env=self.env
                )
                with open(os.devnull, "w") as quiet:
                    async with stdio_client(parameters, errlog=quiet) as streams:
                        async with ClientSession(
                            streams[0], streams[1], read_timeout_seconds=timedelta(seconds=25)
                        ) as s:
                            await s.initialize()
                            yield s

    @staticmethod
    async def _inventory(session: ClientSession) -> list[Record]:
        inventory: list[Record] = []
        cursor = None
        seen = set()
        while True:
            result = await session.list_tools(cursor=cursor)
            inventory.extend(
                tool.model_dump(mode="json", exclude_none=True) for tool in result.tools
            )
            cursor = result.nextCursor
            if cursor is None:
                return inventory
            if cursor in seen:
                raise SourceGap("provider_inventory_pagination_loop")
            seen.add(cursor)

    async def inventory(self) -> list[Record]:
        async with self.session() as session:
            return await self._inventory(session)

    async def invoke(self, tool: str, arguments: Record, schema: Record) -> Any:
        try:
            async with self.session() as session:
                inventory = await self._inventory(session)
                matches = [item for item in inventory if item["name"] == tool]
                if len(matches) != 1 or matches[0]["inputSchema"] != schema:
                    raise SourceGap("provider_tool_schema_changed")
                result = await session.call_tool(tool, arguments)
                if result.isError:
                    messages = [part.text for part in result.content if part.type == "text"]
                    raise SourceGap(error_code(messages, "provider_tool_error"))
                if result.structuredContent is not None:
                    return result.structuredContent
                values: list[Any] = []
                for part in result.content:
                    if part.type != "text":
                        # Preserve unexpected response types in the retained raw
                        # artifact; parsers will report incomplete retrieval.
                        values.append(part.model_dump(mode="json", exclude_none=True))
                        continue
                    try:
                        values.append(json.loads(part.text))
                    except ValueError:
                        values.append(part.text)
                return values[0] if len(values) == 1 else values
        except Exception as error:
            # AnyIO wraps errors raised inside a session in ExceptionGroup.
            # Keep our safe code instead of losing an entitlement/schema failure.
            if gap := _known_gap(error):
                raise gap from None
            raise SourceGap("provider_mcp_unavailable") from None
