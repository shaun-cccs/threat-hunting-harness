#!/usr/bin/env python3
"""Install the self-contained bundle through Codex's personal marketplace."""

from __future__ import annotations

import argparse
import json
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

PLUGIN = "threat-hunting-harness"
TOP_LEVEL = (
    ".codex-plugin/plugin.json",
    ".claude-plugin/plugin.json",
    ".mcp.json",
    ".env.example",
    "pyproject.toml",
    "uv.lock",
    "assets/plugin-tools.json",
    "benchmarks/README.md",
)
SCRIPTS = (
    "plugin_stdio.py",
    "plugin_bootstrap.py",
    "plugin-runtime-pins.json",
    "install_plugin.py",
)
MARKER = ".hunting-plugin-install.json"


class ConfigApi(Protocol):
    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]: ...


class CodexConfigApi:
    """Bounded JSON-RPC client for Codex's supported configuration API."""

    def __init__(self, timeout: float = 30) -> None:
        self.timeout, self.identifier = timeout, 0
        self.messages: queue.Queue[str | None] = queue.Queue()
        self.process = subprocess.Popen(
            ["codex", "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        try:
            for line in self.process.stdout:
                self.messages.put(line)
        finally:
            self.messages.put(None)

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.identifier += 1
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(
                {
                    "id": self.identifier,
                    "method": method,
                    "params": params,
                }
            )
            + "\n"
        )
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                line = self.messages.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                raise ValueError(f"Codex configuration API timed out during {method}") from None
            if line is None:
                raise ValueError("Codex configuration API exited unexpectedly")
            message = json.loads(line)
            if message.get("id") != self.identifier:
                continue
            if "error" in message:
                # Config errors can contain local settings; report only the operation/code.
                code = message["error"].get("code", "unknown")
                raise ValueError(f"Codex configuration API rejected {method} (code {code})")
            result = message.get("result")
            if not isinstance(result, dict):
                raise ValueError("Unexpected Codex configuration API response")
            return result

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdin:
            self.process.stdin.close()
        if self.process.stdout:
            self.process.stdout.close()


def configure_tool_policies(
    plugin: Path, selector: str, api: ConfigApi, *, file_path: Path | None = None
) -> dict[str, Any]:
    """Fill missing policies for this bundle's named tools, preserving explicit host choices."""
    if not re.fullmatch(re.escape(PLUGIN) + r"@[A-Za-z0-9_-]+", selector):
        raise ValueError("Unexpected plugin selector")
    tools = sorted(
        {tool["name"] for tool in json.loads((plugin / "assets/plugin-tools.json").read_text())}
    )
    if not tools or any(not re.fullmatch(r"[A-Za-z0-9_]+", name) for name in tools):
        raise ValueError("Plugin tool catalog contains invalid names")
    read = api.request("config/read", {"includeLayers": True})
    layers = read.get("layers") or []
    user = next(
        (
            layer
            for layer in layers
            if layer["name"].get("type") == "user" and not layer["name"].get("profile")
        ),
        None,
    )
    if user is None:
        raise ValueError("Codex did not expose its writable user configuration layer")
    target = str(file_path) if file_path is not None else user["name"]["file"]
    existing_tools: set[str] = set()
    has_default = False
    for layer in layers:
        if layer.get("disabledReason"):
            continue
        server = (
            layer.get("config", {})
            .get("plugins", {})
            .get(selector, {})
            .get("mcp_servers", {})
            .get("hunting", {})
        )
        has_default |= "default_tools_approval_mode" in server
        existing_tools.update(
            name
            for name, settings in server.get("tools", {}).items()
            if "approval_mode" in settings
        )
    prefix = "plugins." + json.dumps(selector) + ".mcp_servers.hunting"
    edits = [
        {
            "keyPath": f"{prefix}.tools.{name}.approval_mode",
            "mergeStrategy": "upsert",
            "value": "approve",
        }
        for name in tools
        if name not in existing_tools
    ]
    if not has_default:
        edits.insert(
            0,
            {
                "keyPath": prefix + ".default_tools_approval_mode",
                "mergeStrategy": "upsert",
                "value": "prompt",
            },
        )
    result: dict[str, Any] = {"status": "unchanged", "filePath": target}
    if edits:
        params: dict[str, Any] = {
            "edits": edits,
            "filePath": target,
            "reloadUserConfig": True,
        }
        if target == user["name"]["file"]:
            params["expectedVersion"] = user["version"]
        result = api.request("config/batchWrite", params)
    return {
        "status": result["status"],
        "configured_tools": len(tools) - len(set(tools) & existing_tools),
        "preserved_tools": sorted(set(tools) & existing_tools),
    }


def install_tool_policies(plugin: Path, selector: str) -> dict[str, Any]:
    api = CodexConfigApi()
    try:
        api.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "threat-hunting-plugin-installer",
                    "version": "0.1.0",
                }
            },
        )
        return configure_tool_policies(plugin, selector, api)
    finally:
        api.close()


def payload_paths(source: Path) -> list[Path]:
    """Copy only package inputs; workspace credentials and artifacts never enter the bundle."""
    paths = [source / name for name in TOP_LEVEL]
    paths += [source / "scripts" / name for name in SCRIPTS]
    for directory, suffixes in (
        ("src", {".py", ".json"}),
        ("skills", {".md", ".yaml"}),
        ("benchmarks", {".json"}),
    ):
        paths.extend(
            path
            for path in (source / directory).rglob("*")
            if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts
        )
    for path in paths:
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(source):
            raise ValueError(f"Missing or unsafe plugin input: {path.relative_to(source)}")
    return sorted(paths)


def marketplace_payload(path: Path) -> tuple[dict[str, Any], str]:
    """Register the initial entry while preserving the catalog's name, metadata, and order."""
    payload = (
        json.loads(path.read_text())
        if path.exists()
        else {"name": "personal", "interface": {"displayName": "Personal"}, "plugins": []}
    )
    if not isinstance(payload, dict):
        raise ValueError("Personal marketplace must be a JSON object")
    name = payload.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("Personal marketplace has an invalid name")
    entries = payload.setdefault("plugins", [])
    if not isinstance(entries, list):
        raise ValueError("Personal marketplace plugins must be an array")
    source = {"source": "local", "path": f"./plugins/{PLUGIN}"}
    matches = [
        entry for entry in entries if isinstance(entry, dict) and entry.get("name") == PLUGIN
    ]
    if len(matches) > 1 or (matches and matches[0].get("source") != source):
        raise ValueError("Existing hunting plugin entry points to a different source")
    if not matches:
        entries.append(
            {
                "name": PLUGIN,
                "source": source,
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Productivity",
            }
        )
    return payload, name


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    temporary.replace(path)


def prepare(source: Path, user_root: Path) -> dict[str, Any]:
    source, user_root = source.resolve(), user_root.resolve()
    files = payload_paths(source)
    manifest = json.loads((source / ".codex-plugin/plugin.json").read_text())
    if manifest.get("name") != PLUGIN:
        raise ValueError("Unexpected plugin manifest name")
    target = user_root / "plugins" / PLUGIN
    marketplace = user_root / ".agents/plugins/marketplace.json"
    catalog, name = marketplace_payload(marketplace)
    if target.exists():
        marker = target / MARKER
        if not marker.is_file() or target.is_symlink():
            raise ValueError(f"Refusing to replace an unmanaged plugin directory: {target}")
        previous = json.loads(marker.read_text())
        managed = set(previous.get("files", [])) | {MARKER}
        present = {str(path.relative_to(target)) for path in target.rglob("*") if path.is_file()}
        if present - managed:
            raise ValueError(
                "Existing plugin directory has unmanaged files; preserve them before updating"
            )
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{PLUGIN}-", dir=target.parent))
    try:
        for path in files:
            copied = stage / path.relative_to(source)
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, copied)
        version = manifest["version"].split("+", 1)[0]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")  # noqa: UP017 (Python 3.9)
        manifest["version"] = version + "+codex." + stamp
        write_json(stage / ".codex-plugin/plugin.json", manifest)
        write_json(stage / MARKER, {"files": [str(p.relative_to(source)) for p in files]})
        if target.exists():
            backup = stage.with_name(stage.name + "-previous")
            target.rename(backup)
            try:
                stage.rename(target)
            except OSError:
                backup.rename(target)
                raise
            shutil.rmtree(backup)
        else:
            stage.rename(target)
        if not marketplace.exists() or json.loads(marketplace.read_text()) != catalog:
            write_json(marketplace, catalog)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return {
        "plugin": str(target),
        "marketplace": str(marketplace),
        "command": ["codex", "plugin", "add", f"{PLUGIN}@{name}"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare-only", action="store_true", help="Stage the bundle without invoking Codex"
    )
    parser.add_argument("--user-root", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.user_root.resolve() != Path.home().resolve() and not args.prepare_only:
        parser.error("An isolated --user-root requires --prepare-only")
    if not args.prepare_only and shutil.which("codex") is None:
        parser.error("Install Codex before installing this plugin")
    try:
        result = prepare(Path(__file__).resolve().parents[1], args.user_root)
        if not args.prepare_only:
            subprocess.run(result["command"], check=True, timeout=120)
            result["tool_policies"] = install_tool_policies(
                Path(result["plugin"]), result["command"][-1]
            )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Plugin installation failed: {exc}\n")
    print(json.dumps(result, indent=2))
    if not args.prepare_only:
        print("Start a new Codex conversation in your workspace, fill .env, and use $hunt.")


if __name__ == "__main__":
    main()
