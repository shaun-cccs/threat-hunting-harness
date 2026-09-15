#!/usr/bin/env python3
"""Dependency-free MCP entry point; the host owns this process and its automatic backend."""

from __future__ import annotations

import concurrent.futures
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

Record = dict[str, Any]

PLUGIN = Path(__file__).resolve().parent.parent
VERSION = json.loads((PLUGIN / ".codex-plugin/plugin.json").read_text())["version"]
INSTRUCTIONS = (
    "Call hunting_setup with the user's workspace before hunting, then hunting_status until ready. "
    "The plugin manages its own dependencies and backend. Use retained provider observations only; "
    "all native agents share the same case ID and limits. Investigator/reviewer judgments are not "
    "analyst decisions. Record analyst_decide only after an explicit user decision in chat."
)


def private_json(path: Path, value: Record) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + "." + uuid4().hex)
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output)
    os.replace(temporary, path)


def directory(kind: str) -> Path:
    override = os.environ.get("HUNT_PLUGIN_" + kind.upper())
    if override:
        return Path(override).expanduser().resolve()
    base = os.environ.get("XDG_DATA_HOME" if kind == "data" else "XDG_CACHE_HOME")
    default = Path.home() / (".local/share" if kind == "data" else ".cache")
    return (Path(base) if base else default) / "threat-hunting-harness"


def state_for(workspace: Path) -> Path:
    digest = hashlib.sha256(str(workspace).encode()).hexdigest()[:24]
    return directory("data") / "workspaces" / digest


def version_key(version: str) -> tuple[int, ...]:
    """Order our semver releases and installer's monotonically increasing cachebusters."""
    base, separator, stamp = version.partition("+codex.")
    if separator and stamp.isdigit() and 14 <= len(stamp) <= 20:
        # The Codex helper uses seconds; the legacy installer uses microseconds.
        # Compare at the same precision when migrating to a Git installation.
        return (*[int(part) for part in re.findall(r"\d+", base)], int(stamp.ljust(20, "0")))
    return tuple(int(part) for part in re.findall(r"\d+", version))


def process_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "HUNT_PLUGIN_DATA",
        "HUNT_PLUGIN_CACHE",
        "HUNT_PLUGIN_IDLE_SECONDS",
        "HUNT_PLUGIN_TEST_RUNTIME",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def locked(state: Path) -> bool:
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / "service.lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def worker(workspace: Path) -> None:
    state = state_for(workspace)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = (state / "service.lock").open("a")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    os.set_inheritable(handle.fileno(), True)
    private_json(state / "service.json", {"status": "preparing", "version": VERSION})
    try:
        # Explicit test injection bypasses downloads only; production installs use prepare().
        injected = os.environ.get("HUNT_PLUGIN_TEST_RUNTIME")
        if injected:
            paths = json.loads(Path(injected).read_text())
        else:
            from plugin_bootstrap import prepare

            paths = prepare(PLUGIN, directory("cache") / "runtime")
        paths_file = state / "runtime-paths.json"
        private_json(paths_file, paths)
        env = process_environment()
        env.update(
            PYTHONPATH=str(PLUGIN / "src"), PYTHONDONTWRITEBYTECODE="1", HUNT_PLUGIN_VERSION=VERSION
        )
        os.execve(
            paths["python"],
            [
                paths["python"],
                "-m",
                "hunting_harness.plugin_runtime",
                "--workspace",
                str(workspace),
                "--state",
                str(state),
                "--paths",
                str(paths_file),
            ],
            env,
        )
    except Exception:
        private_json(
            state / "service.json",
            {
                "status": "setup_failed",
                "error": "dependency_or_backend_setup_failed",
                "log": str(state / "setup.log"),
                "version": VERSION,
            },
        )
        raise


class Plugin:
    def __init__(self) -> None:
        self.workspace: Path | None = None
        self.last_start = 0.0
        self.mutex = threading.RLock()
        self.stopped = threading.Event()
        self.output_lock = threading.Lock()
        self.tools = json.loads((PLUGIN / "assets" / "plugin-tools.json").read_text())
        threading.Thread(target=self.heartbeat, daemon=True).start()

    def descriptor(self) -> Record:
        if self.workspace is None:
            return {}
        try:
            return cast(
                Record, json.loads((state_for(self.workspace) / "service.json").read_text())
            )
        except (OSError, ValueError):
            return {}

    def health(self, descriptor: Record) -> Record:
        request = urllib.request.Request(
            descriptor["url"] + "/plugin/health",
            headers={"Authorization": "Bearer " + descriptor["token"]},
        )
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=2
        ) as response:
            return cast(Record, json.load(response))

    def status(self, retry: bool = False) -> Record:
        with self.mutex:
            if self.workspace is None:
                return {"status": "needs_workspace", "next_step": "Call hunting_setup(workspace)."}
            state = state_for(self.workspace)
            descriptor = self.descriptor()
            active = locked(state)
            previous_version = descriptor.get("version", VERSION)
            if version_key(previous_version) > version_key(VERSION):
                return {
                    "status": "plugin_updated",
                    "next_step": "Use a new Codex conversation to load the installed update.",
                }
            if previous_version != VERSION and active:
                if descriptor.get("status") == "ready":
                    request = urllib.request.Request(
                        descriptor["url"] + "/plugin/retire",
                        data=b"",
                        headers={"Authorization": "Bearer " + descriptor["token"]},
                    )
                    try:
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                            request, timeout=2
                        ):
                            pass
                    except OSError:
                        pass
                return {
                    "status": "updating",
                    "next_step": "Waiting for active queries to settle; poll hunting_status.",
                }
            if descriptor.get("status") == "ready":
                try:
                    return self.health(descriptor)
                except (OSError, ValueError, KeyError):
                    if active:
                        return {
                            "status": "backend_unavailable",
                            "log": str(state / "setup.log"),
                            "next_step": "The backend is not responding; inspect setup.log.",
                        }
            failed = descriptor.get("status") in ("setup_failed", "preparing") and not active
            if failed and not retry and time.monotonic() - self.last_start < 1:
                return {"status": "preparing", "next_step": "Poll hunting_status."}
            if not active and (not failed or retry):
                with (state / "setup.log").open("ab") as log:
                    os.chmod(log.name, 0o600)
                    subprocess.Popen(
                        [
                            sys.executable,
                            str(Path(__file__).resolve()),
                            "--worker",
                            str(self.workspace),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=log,
                        env=process_environment(),
                        start_new_session=True,
                        close_fds=True,
                    )
                self.last_start = time.monotonic()
                return {
                    "status": "preparing",
                    "workspace": str(self.workspace),
                    "next_step": "Preparation is automatic. Poll hunting_status.",
                }
            return {
                "status": "preparing" if active else "setup_failed",
                "workspace": str(self.workspace),
                "env_file": str(self.workspace / ".env"),
                "next_step": "Poll hunting_status." if active else "Call hunting_setup to retry.",
                "log": str(state / "setup.log"),
            }

    def setup(self, workspace: str) -> Record:
        path = Path(workspace).expanduser()
        if not path.is_absolute() or not path.is_dir():
            raise ValueError("workspace must be an existing absolute directory")
        path = path.resolve()
        if path == PLUGIN or PLUGIN in path.parents:
            raise ValueError("Use the user's workspace, not the installed plugin directory")
        with self.mutex:
            self.workspace = path
            env_file = path / ".env"
            try:
                descriptor = os.open(env_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, "w") as output:
                    output.write((PLUGIN / ".env.example").read_text())
            return self.status(retry=True)

    def heartbeat(self) -> None:
        while not self.stopped.wait(10):
            with self.mutex:
                descriptor = self.descriptor()
            if descriptor.get("status") == "ready" and descriptor.get("version") == VERSION:
                try:
                    self.health(descriptor)
                except (OSError, ValueError, KeyError):
                    pass

    def call(self, name: str, arguments: Record) -> Record:
        if name == "hunting_setup":
            return self.result(self.setup(arguments["workspace"]))
        if name == "hunting_status":
            return self.result(self.status())
        with self.mutex:
            status = self.status()
            if status["status"] != "ready":
                return self.result(status, error=True)
            descriptor = self.descriptor()
        request = urllib.request.Request(
            descriptor["url"] + "/mcp",
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": uuid4().hex,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            ).encode(),
            headers={
                "Authorization": "Bearer " + descriptor["token"],
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        # One request only: a lost response must not silently repeat a provider action.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=55
        ) as response:
            envelope = json.load(response)
        if "result" not in envelope:
            return self.result({"error": "backend_request_failed"}, error=True)
        return cast(Record, envelope["result"])

    @staticmethod
    def result(value: Record, error: bool = False) -> Record:
        return {
            "content": [{"type": "text", "text": json.dumps(value)}],
            "structuredContent": value,
            "isError": error,
        }

    def respond(self, message: Record) -> None:
        result: Record
        request_id = message.get("id")
        method = message.get("method")
        if request_id is None:
            return
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": message.get("params", {}).get(
                        "protocolVersion", "2025-03-26"
                    ),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "threat-hunting-harness", "version": VERSION},
                    "instructions": INSTRUCTIONS,
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self.tools}
            elif method == "tools/call":
                params = message.get("params", {})
                if params.get("name") not in {tool["name"] for tool in self.tools}:
                    result = self.result({"error": "unknown_tool"}, error=True)
                else:
                    result = self.call(params["name"], params.get("arguments", {}))
            else:
                self.emit(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                )
                return
        except (KeyError, TypeError, ValueError):
            result = self.result({"error": "invalid_request_arguments"}, error=True)
        except Exception:
            result = self.result(
                {
                    "error": "backend_unavailable",
                    "next_step": "Check hunting_status; inspect jobs before retrying.",
                },
                error=True,
            )
        self.emit({"jsonrpc": "2.0", "id": request_id, "result": result})

    def emit(self, message: Record) -> None:
        with self.output_lock:
            print(json.dumps(message), flush=True)

    def run(self) -> None:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                while line := sys.stdin.buffer.readline(4 * 1024 * 1024 + 1):
                    try:
                        message = json.loads(line)
                        if not isinstance(message, dict) or len(line) > 4 * 1024 * 1024:
                            raise ValueError
                    except ValueError:
                        self.emit(
                            {
                                "jsonrpc": "2.0",
                                "id": None,
                                "error": {"code": -32700, "message": "Invalid JSON request"},
                            }
                        )
                        continue
                    executor.submit(self.respond, message)
        finally:
            self.stopped.set()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(Path(sys.argv[2]).resolve())
    else:
        Plugin().run()
