"""Installed-client boundary fixture; never launches models or connects to MCP."""

import json
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("codex-fixture 1.0")
elif args[-3:] == ["mcp", "list", "--json"]:
    print(json.dumps([{"name": "hunting", "enabled": True}]))
elif args[-4:] == ["mcp", "get", "hunting", "--json"]:
    tools = next(
        a.split("=", 1)[1] for a in args if a.startswith("mcp_servers.hunting.enabled_tools=")
    )
    print(
        json.dumps(
            {
                "name": "hunting",
                "enabled": True,
                "transport": {
                    "url": "http://127.0.0.1:8765/mcp",
                    "bearer_token_env_var": "HUNT_GATEWAY_TOKEN",
                },
                "enabled_tools": json.loads(tools),
            }
        )
    )
elif args[-2:] == ["features", "list"]:
    for value in args:
        if value.startswith("features.") and "=" in value:
            feature, state = value.removeprefix("features.").split("=", 1)
            # Simulate an installed client that ignores the unified_exec override.
            print(feature, "stable", "true" if feature == "unified_exec" else state)
else:
    print("Unexpected CLI invocation: fixture refuses to launch a model", file=sys.stderr)
    sys.exit(2)
