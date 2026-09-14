"""Synthetic upstream MCP server; never contacts a provider."""

import json
import os
from pathlib import Path

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

source = os.environ["FIXTURE_PROVIDER"]
schemas = json.loads(
    (
        Path(__file__).parents[2] / "src/hunting_harness/providers/schemas" / f"{source}.json"
    ).read_text()
)
server = Server("fixture-provider")


@server.list_tools()
async def tools():
    if os.environ.get("FIXTURE_SCHEMA_CHANGED") == "True":
        for schema in schemas.values():
            schema["properties"]["unreviewed"] = {"type": "boolean"}
    return [Tool(name=name, inputSchema=schema) for name, schema in schemas.items()]


@server.call_tool()
async def call(name, arguments):
    if "FIXTURE_PAYLOAD" in os.environ:
        payload = json.loads(os.environ["FIXTURE_PAYLOAD"])
        if os.environ.get("FIXTURE_ERROR") == "True":
            return CallToolResult(
                isError=True, content=[TextContent(type="text", text=json.dumps(payload))]
            )
    elif source == "censys":
        payload = {
            "result": {
                "hits": [
                    {
                        "host": {
                            "ip": "192.0.2.4",
                            "services": [
                                {
                                    "observed_at": "2024-01-06T00:00:00Z",
                                    "cert": {"fingerprint_sha256": "a" * 64},
                                }
                            ],
                        }
                    }
                ],
                "next_page_token": "page-two",
            }
        }
    elif source == "gti":
        payload = [
            {
                "type": "resolution",
                "id": "resolution-1",
                "attributes": {
                    "ip_address": "192.0.2.5",
                    "host_name": "seed.example",
                    "date": 1704585600,
                },
            }
        ]
    else:
        payload = {
            "data": [
                {
                    "ip": "192.0.2.6",
                    "internet_scanner_intelligence": {
                        "last_seen": "2024-01-08",
                        "classification": "benign",
                    },
                }
            ],
            "request_metadata": {
                "complete": False,
                "scroll": "next",
                "query": "last_seen:2024-01-08",
            },
        }
    return [TextContent(type="text", text=json.dumps(payload))]


async def main():
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())


anyio.run(main)
