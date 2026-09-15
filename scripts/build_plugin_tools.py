"""Refresh the dependency-free plugin's tool catalog from the authoritative MCP schema."""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from hunting_harness.plugin_runtime import Runtime


async def catalog() -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        runtime = Runtime(root / "workspace", root / "state", {})
        tools = [
            tool.model_dump(mode="json", exclude_none=True)
            for tool in await runtime.mcp.list_tools()
        ]
    tools.extend(
        [
            {
                "name": "hunting_setup",
                "description": "Prepare this workspace and read .env without provider queries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"workspace": {"type": "string"}},
                    "required": ["workspace"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "hunting_status",
                "description": "Read setup progress and configuration without provider queries.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        ]
    )
    return tools


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "assets" / "plugin-tools.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(asyncio.run(catalog()), indent=2) + "\n")
