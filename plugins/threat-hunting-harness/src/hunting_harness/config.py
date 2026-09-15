"""Provider configuration stays in the trusted gateway process."""

import os
import secrets
from pathlib import Path

from .providers.base import Provider
from .providers.censys import Censys
from .providers.mcp_source import McpSource
from .providers.shodan import Shodan
from .providers.transport import McpTransport


def gateway_token(root: Path) -> str:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "gateway.token"
    if not path.exists():
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(secrets.token_urlsafe(32))
        except FileExistsError:
            pass
    return path.read_text().strip()


def providers(keys: dict[str, str], project: Path) -> dict[str, Provider]:
    project = project.resolve()
    result: dict[str, Provider] = {}
    if key := keys.get("SHODAN_API_KEY"):
        result["shodan"] = Shodan(key)
    if key := keys.get("CENSYS_API_KEY"):
        result["censys"] = Censys(key, keys.get("CENSYS_ORG_ID"))
    if key := keys.get("GTI_API_KEY") or keys.get("VT_APIKEY"):
        # Use the project's pinned optional dependency, not an unrelated global
        # executable whose matching schema says nothing about its implementation.
        command = str(project / ".venv/bin/gti_mcp")
        result["gti"] = McpSource("gti", McpTransport(command=command, env={"VT_APIKEY": key}))
    if key := keys.get("GREYNOISE_API_KEY"):
        result["greynoise"] = McpSource(
            "greynoise",
            McpTransport(
                command="node",
                args=[str(project / ".venv/greynoise/build/index.js")],
                env={"GREYNOISE_API_KEY": key},
            ),
        )
    return result
