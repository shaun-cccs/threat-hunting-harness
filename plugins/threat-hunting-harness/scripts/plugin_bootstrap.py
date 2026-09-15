#!/usr/bin/env python3
"""Prepare the plugin's private runtime without modifying its installed bundle.

This file uses only the Python standard library. Downloads are pinned and verified;
Python dependencies come from uv.lock, including the GTI extra. GreyNoise is built
from the reviewed revision and its npm integrity lock because its published 0.5.0
binary was built from a different revision. No provider credentials are needed or
passed to installers, and no provider API is contacted.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any


class SetupError(RuntimeError):
    """An incomplete setup can be retried without trusting its partial output."""


def _platform() -> str:
    machine = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    result = platform.system().lower() + "-" + machine
    if result not in {"linux-x86_64", "linux-aarch64", "darwin-x86_64", "darwin-aarch64"}:
        raise SetupError("Automatic setup supports Linux and macOS on x86_64 or ARM64")
    if result.startswith("linux") and platform.libc_ver()[0] == "musl":
        raise SetupError("The bundled Node runtime requires a glibc-based Linux distribution")
    return result


def _installer_env(root: Path, node_bin: Path | None = None) -> dict[str, str]:
    """Use explicit private configuration, never the analyst's environment."""
    installer_config_dir = root / "installer-config"
    installer_config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = root / "tmp"
    temporary.mkdir(exist_ok=True, mode=0o700)
    for name in ("user.npmrc", "global.npmrc", "netrc"):
        (installer_config_dir / name).write_text("", encoding="utf-8")
    return {
        "PATH": str(node_bin) + os.pathsep + os.defpath if node_bin else os.defpath,
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_CONFIG_HOME": str(installer_config_dir / "config"),
        "XDG_DATA_HOME": str(installer_config_dir / "data"),
        "NETRC": str(installer_config_dir / "netrc"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "UV_CACHE_DIR": str(root / "uv-cache"),
        "UV_PYTHON_INSTALL_DIR": str(root / "python"),
        "UV_PYTHON_BIN_DIR": str(root / "python-bin"),
        "UV_NO_CONFIG": "1",
        "UV_NO_PROGRESS": "1",
        "UV_SYSTEM_CERTS": "true",
        "UV_DEFAULT_INDEX": "https://pypi.org/simple",
        "NPM_CONFIG_USERCONFIG": str(installer_config_dir / "user.npmrc"),
        "NPM_CONFIG_GLOBALCONFIG": str(installer_config_dir / "global.npmrc"),
        "NPM_CONFIG_CACHE": str(root / "npm-cache"),
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NO_COLOR": "1",
        "CI": "true",
    }


@contextlib.contextmanager
def _setup_lock(root: Path, timeout: float = 1800) -> Iterator[None]:
    with (root / "setup.lock").open("a", encoding="utf-8") as lock:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    message = "Another plugin setup is still running; retry shortly"
                    raise SetupError(message) from None
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(artifact: dict[str, str], root: Path) -> Path:
    """Revalidate cached archives; a failed download never becomes a cache hit."""
    digest = artifact["sha256"]
    cache = root / "downloads"
    cache.mkdir(exist_ok=True, mode=0o700)
    destination = cache / digest
    if destination.is_file() and _sha256(destination) == digest:
        return destination
    destination.unlink(missing_ok=True)
    if not artifact["url"].startswith("https://"):
        raise SetupError("Dependency download must use HTTPS")
    # Do not inherit proxy credentials or provider configuration from the host.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
            temporary = Path(stream.name)
            with opener.open(artifact["url"], timeout=60) as response:
                shutil.copyfileobj(response, stream)
        if _sha256(temporary) != digest:
            raise SetupError("Dependency archive checksum does not match the packaged pin")
        temporary.replace(destination)
        return destination
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _unpack(archive: Path, destination: Path, prefix: str) -> None:
    """Extract regular source files, excluding links and unrelated repository paths."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        for member in source:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise SetupError("Dependency archive contains an unsafe path")
            try:
                relative = name.relative_to(prefix)
            except ValueError:
                continue
            # Node's npm/npx links are unnecessary: invoke npm-cli.js directly.
            if not member.isfile():
                continue
            target = destination.joinpath(*relative.parts)
            if target.is_symlink() or any(p.is_symlink() for p in target.parents):
                raise SetupError("Dependency extraction would follow a symbolic link")
            target.parent.mkdir(parents=True, exist_ok=True)
            content = source.extractfile(member)
            if content is None:
                raise SetupError("Dependency archive contains an unreadable file")
            with content, target.open("wb") as output:
                shutil.copyfileobj(content, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def _run(command: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True, timeout=900, check=False
    )
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode:
        if result.stdout:
            print(result.stdout.rstrip(), file=sys.stderr)
        raise SetupError(f"Dependency command {Path(command[0]).name} failed ({result.returncode})")
    return result.stdout.strip()


def _uv(pins: dict[str, Any], system: str, root: Path) -> Path:
    archive = _download(pins["uv"][system], root)
    destination = root / "uv" / str(pins["uv_version"]) / system / "uv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as wheel:
        names = [name for name in wheel.namelist() if name.endswith(".data/scripts/uv")]
        if len(names) != 1:
            raise SetupError("Pinned uv wheel is missing its executable")
        # Re-extract this small executable even after an interrupted prior setup.
        with wheel.open(names[0]) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)
    destination.chmod(0o755)
    return destination


def _paths(release: Path) -> dict[str, str]:
    return {
        "python": str(release / "venv/bin/python"),
        "gti": str(release / "venv/bin/gti_mcp"),
        "node": str(release / "node/bin/node"),
        "greynoise": str(release / "greynoise/build/index.js"),
        "environment": str(release / "venv"),
        "runtime": str(release),
    }


def _ready(release: Path) -> dict[str, str] | None:
    expected = _paths(release)
    try:
        manifest = json.loads((release / "ready.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if manifest != expected:
        return None
    if not all(Path(expected[key]).is_file() for key in ("python", "gti", "node", "greynoise")):
        return None
    return expected


def _build(
    plugin: Path, root: Path, release: Path, pins: dict[str, Any], system: str
) -> dict[str, str]:
    env = _installer_env(root)
    uv = str(_uv(pins, system, root))
    _run([uv, "python", "install", "--no-bin", pins["python_version"]], root, env)
    python = _run(
        [uv, "python", "find", "--managed-python", "--no-python-downloads", pins["python_version"]],
        root,
        env,
    )
    paths = _paths(release)
    _run([uv, "venv", "--python", python, paths["environment"]], root, env)
    project = release / "project"
    project.mkdir()
    for filename in ("pyproject.toml", "uv.lock"):
        shutil.copyfile(plugin / filename, project / filename)
    requirements = project / "requirements.txt"
    _run(
        [
            uv, "export", "--frozen", "--extra", "gti", "--no-dev", "--no-emit-project",
            "--no-emit-package", "gti-mcp", "--no-emit-package", "shodan",
            "--no-header", "--output-file", str(requirements),
        ],
        project,
        env,
    )
    _run(
        [
            uv, "pip", "sync", "--python", paths["python"], "--require-hashes",
            "--only-binary=:all:", str(requirements),
        ],
        root,
        env,
    )
    # Build the reviewed GTI source without git or unpinned build dependencies.
    build_requirements = project / "build-requirements.txt"
    build_requirements.write_text(
        "".join(f"{p['url']} --hash=sha256:{p['sha256']}\n" for p in pins["build_wheels"]),
        encoding="utf-8",
    )
    _run(
        [
            uv, "pip", "install", "--python", paths["python"], "--no-deps", "--require-hashes",
            "--only-binary=:all:", "--requirements", str(build_requirements),
        ],
        root,
        env,
    )
    # shodan ships no wheel for any release; build the pinned sdist against the wheels above.
    source_requirements = project / "source-requirements.txt"
    source_requirements.write_text(
        "".join(f"{p['url']} --hash=sha256:{p['sha256']}\n" for p in pins["source_sdists"]),
        encoding="utf-8",
    )
    _run(
        [
            uv, "pip", "install", "--python", paths["python"], "--no-deps", "--require-hashes",
            "--no-build-isolation", "--requirements", str(source_requirements),
        ],
        root,
        env,
    )
    gti = release / "gti-source"
    _unpack(_download(pins["gti"], root), gti, f"mcp-security-{pins['gti_revision']}/server/gti")
    _run(
        [
            uv, "pip", "install", "--python", paths["python"], "--no-deps",
            "--no-build-isolation", "--offline", str(gti),
        ],
        root,
        env,
    )
    node_artifact = pins["node"][system]
    node_prefix = node_artifact["url"].rsplit("/", 1)[-1].removesuffix(".tar.gz")
    _unpack(_download(node_artifact, root), release / "node", node_prefix)
    greynoise = release / "greynoise"
    _unpack(
        _download(pins["greynoise"], root),
        greynoise,
        f"greynoise-mcp-server-{pins['greynoise_revision']}",
    )
    env = _installer_env(root, Path(paths["node"]).parent)
    npm = [paths["node"], str(release / "node/lib/node_modules/npm/bin/npm-cli.js")]
    _run(npm + ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], greynoise, env)
    _run(npm + ["run", "build"], greynoise, env)
    _run([paths["python"], "-c", "import mcp, httpx, shodan, gti_mcp.server"], root, env)
    _run([paths["node"], "--check", paths["greynoise"]], root, env)
    return paths


def prepare(plugin_root: Path, runtime_root: Path) -> dict[str, str]:
    """Return executable paths, reusing a complete setup across Codex workspaces."""
    plugin, root = plugin_root.resolve(), runtime_root.resolve()
    if root == plugin or plugin in root.parents:
        raise SetupError("Runtime cache must be outside the installed plugin")
    system = _platform()
    pin_path = plugin / "scripts/plugin-runtime-pins.json"
    pins = json.loads(pin_path.read_text(encoding="utf-8"))
    inputs = [plugin / "pyproject.toml", plugin / "uv.lock", pin_path, Path(__file__)]
    identity = hashlib.sha256(system.encode())
    for path in inputs:
        identity.update(path.read_bytes())
    # Fail closed if a future dependency edit changes the reviewed GTI revision.
    for path in inputs[:2]:
        if pins["gti_revision"] not in path.read_text(encoding="utf-8"):
            raise SetupError("GTI dependency and packaged runtime pin disagree")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    release = root / "releases" / identity.hexdigest()[:24]
    with _setup_lock(root):
        ready = _ready(release)
        if ready is not None:
            return ready
        if release.exists():
            shutil.rmtree(release)
        release.mkdir(parents=True, mode=0o700)
        try:
            paths = _build(plugin, root, release, pins, system)
            temporary = release / "ready.json.tmp"
            temporary.write_text(json.dumps(paths, sort_keys=True) + "\n", encoding="utf-8")
            temporary.replace(release / "ready.json")
        except BaseException:
            # Keep verified download/package caches, but never reuse an incomplete venv.
            shutil.rmtree(release, ignore_errors=True)
            raise
        return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin_root", type=Path)
    parser.add_argument("runtime_root", type=Path)
    arguments = parser.parse_args()
    try:
        result = prepare(arguments.plugin_root, arguments.runtime_root)
    except (OSError, ValueError, SetupError, subprocess.SubprocessError) as error:
        print(f"Plugin dependency setup failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
