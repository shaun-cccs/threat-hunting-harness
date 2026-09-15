"""The first-run boundary is recoverable, shared, and credential-free."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/plugin_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("plugin_bootstrap", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    plugin = tmp_path / "installed-plugin"
    (plugin / "scripts").mkdir(parents=True)
    (plugin / "scripts/plugin-runtime-pins.json").write_text(
        json.dumps({"gti_revision": "reviewed-revision"})
    )
    for name in ("pyproject.toml", "uv.lock"):
        (plugin / name).write_text("reviewed-revision\n")
    return plugin


def fake_build(
    plugin: Path, root: Path, release: Path, pins: dict[str, Any], system: str
) -> dict[str, str]:
    paths = bootstrap._paths(release)
    for key in ("python", "gti", "node", "greynoise"):
        target = Path(paths[key])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("ready")
    return paths


def test_cold_then_warm_setup_does_not_touch_bundle_or_repeat_installers(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    calls = []

    def build(*args: Any) -> dict[str, str]:
        calls.append(args)
        return fake_build(*args)

    monkeypatch.setattr(bootstrap, "_build", build)
    root = tmp_path / "runtime"
    first = bootstrap.prepare(bundle, root)
    assert bootstrap.prepare(bundle, root) == first
    assert len(calls) == 1
    assert all(str(root) in value for value in first.values())
    after = {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    assert after == before


def test_changed_lock_and_missing_executable_each_rebuild(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def build(*args: Any) -> dict[str, str]:
        calls.append(args)
        return fake_build(*args)

    monkeypatch.setattr(bootstrap, "_build", build)
    root = tmp_path / "runtime"
    first = bootstrap.prepare(bundle, root)
    Path(first["node"]).unlink()
    assert bootstrap.prepare(bundle, root) == first
    (bundle / "uv.lock").write_text("reviewed-revision\nupdated dependency\n")
    second = bootstrap.prepare(bundle, root)
    assert second["runtime"] != first["runtime"]
    assert len(calls) == 3


def test_failed_setup_removes_partial_environment_but_preserves_downloads(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"

    def fail(plugin: Path, cache: Path, release: Path, *args: Any) -> dict[str, str]:
        (cache / "downloads").mkdir(exist_ok=True)
        (cache / "downloads/verified").write_text("archive")
        (release / "partial").write_text("incomplete")
        raise bootstrap.SetupError("download interrupted")

    monkeypatch.setattr(bootstrap, "_build", fail)
    with pytest.raises(bootstrap.SetupError, match="interrupted"):
        bootstrap.prepare(bundle, root)
    assert list((root / "releases").iterdir()) == []
    assert (root / "downloads/verified").read_text() == "archive"
    monkeypatch.setattr(bootstrap, "_build", fake_build)
    assert Path(bootstrap.prepare(bundle, root)["gti"]).is_file()


def test_concurrent_workspaces_only_build_once(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = threading.Event()
    release_build = threading.Event()
    calls = []

    def build(*args: Any) -> dict[str, str]:
        calls.append(args)
        entered.set()
        assert release_build.wait(5)
        return fake_build(*args)

    monkeypatch.setattr(bootstrap, "_build", build)
    root = tmp_path / "runtime"
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(bootstrap.prepare, bundle, root)
        assert entered.wait(5)
        second = executor.submit(bootstrap.prepare, bundle, root)
        time.sleep(0.05)
        release_build.set()
        assert first.result(timeout=5) == second.result(timeout=5)
    assert len(calls) == 1


def test_installers_cannot_inherit_credentials_configs_or_code_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "SHODAN_API_KEY", "GTI_API_KEY", "VT_APIKEY", "CENSYS_API_KEY", "GREYNOISE_API_KEY",
        "NPM_TOKEN", "GITHUB_TOKEN", "UV_INDEX_URL", "PYTHONPATH", "NODE_OPTIONS",
        "HERDR_PANE", "HTTPS_PROXY", "CODEX_HOME", "NPM_CONFIG_USERCONFIG",
    ):
        monkeypatch.setenv(name, "must-not-inherit")
    env = bootstrap._installer_env(tmp_path)
    assert "must-not-inherit" not in env.values()
    assert "HOME" not in env
    assert env["UV_DEFAULT_INDEX"] == "https://pypi.org/simple"
    assert Path(env["NPM_CONFIG_USERCONFIG"]).read_text() == ""


def test_cached_archives_are_verified_and_corruption_is_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"immutable published artifact"
    pin = {"url": "https://example.test/pinned", "sha256": hashlib.sha256(payload).hexdigest()}
    requests = []

    class Opener:
        def open(self, url: str, timeout: int) -> io.BytesIO:
            requests.append(url)
            return io.BytesIO(payload)

    monkeypatch.setattr(bootstrap.urllib.request, "build_opener", lambda *args: Opener())
    artifact = bootstrap._download(pin, tmp_path)
    assert bootstrap._download(pin, tmp_path) == artifact
    assert len(requests) == 1
    artifact.write_bytes(b"corrupt cache")
    assert bootstrap._download(pin, tmp_path).read_bytes() == payload
    assert len(requests) == 2


def test_checksum_failure_leaves_no_trusted_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Opener:
        def open(self, url: str, timeout: int) -> io.BytesIO:
            return io.BytesIO(b"different archive")

    monkeypatch.setattr(bootstrap.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(bootstrap.SetupError, match="checksum"):
        bootstrap._download({"url": "https://example.test/pinned", "sha256": "0" * 64}, tmp_path)
    assert list((tmp_path / "downloads").iterdir()) == []


def test_runtime_inside_plugin_is_rejected(bundle: Path) -> None:
    with pytest.raises(bootstrap.SetupError, match="outside"):
        bootstrap.prepare(bundle, bundle / "runtime")
    assert not (bundle / "runtime").exists()


def test_archive_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        member = tarfile.TarInfo("source/../../escape")
        member.size = 4
        stream.addfile(member, io.BytesIO(b"oops"))
    with pytest.raises(bootstrap.SetupError, match="unsafe path"):
        bootstrap._unpack(archive, tmp_path / "extracted", "source")
    assert not (tmp_path / "escape").exists()
