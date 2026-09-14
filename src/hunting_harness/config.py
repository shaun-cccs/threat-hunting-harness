"""Provider configuration stays in the trusted gateway process."""

import os
import secrets
from pathlib import Path

from .providers.base import Provider
from .providers.shodan import Shodan


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
    return result
