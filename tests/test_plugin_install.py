"""Installation packages code without copying investigation data or replacing user files."""

import importlib.util
import io
import json
import queue
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@pytest.fixture
def installer() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/install_plugin.py"
    spec = importlib.util.spec_from_file_location("install_plugin", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_bundle(root: Path, installer: ModuleType) -> Path:
    for name in installer.TOP_LEVEL:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    for name in installer.SCRIPTS:
        path = root / "scripts" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# bundled runtime\n")
    (root / ".codex-plugin/plugin.json").write_text(
        json.dumps({"name": installer.PLUGIN, "version": "0.1.0+codex.previous"})
    )
    for name in ("src/hunting_harness/__init__.py", "skills/hunt/SKILL.md"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# package\n")
    for kind in ("campaigns", "observations", "truth"):
        path = root / "benchmarks" / kind / "fixture.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"benchmark": kind}))
    return root


def test_bundle_excludes_secrets_and_preserves_marketplace(
    tmp_path: Path, installer: ModuleType
) -> None:
    source = source_bundle(tmp_path / "source", installer)
    (source / ".env").write_text("SHODAN_API_KEY=do-not-package-this\n")
    (source / "artifacts").mkdir()
    (source / "artifacts/private.json").write_text('{"secret": "case data"}')
    user = tmp_path / "user"
    catalog_path = user / ".agents/plugins/marketplace.json"
    catalog_path.parent.mkdir(parents=True)
    existing = {"name": "existing", "source": {"source": "local", "path": "./plugins/other"}}
    catalog_path.write_text(
        json.dumps(
            {
                "name": "my_personal",
                "interface": {"displayName": "Keep this"},
                "plugins": [existing],
            }
        )
    )

    result = installer.prepare(source, user)
    target = Path(result["plugin"])
    catalog = json.loads(catalog_path.read_text())

    assert result["command"] == ["codex", "plugin", "add", "threat-hunting-harness@my_personal"]
    assert catalog["interface"] == {"displayName": "Keep this"}
    assert catalog["plugins"][0] == existing
    assert catalog["plugins"][1]["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert (target / "assets/plugin-tools.json").is_file()
    assert (target / "benchmarks/README.md").is_file()
    for kind in ("campaigns", "observations", "truth"):
        assert json.loads((target / "benchmarks" / kind / "fixture.json").read_text()) == {
            "benchmark": kind
        }
    assert not (target / ".env").exists()
    assert not (target / "artifacts").exists()
    assert all("do-not-package-this" not in p.read_text() for p in target.rglob("*") if p.is_file())
    assert json.loads((target / ".codex-plugin/plugin.json").read_text())["version"].startswith(
        "0.1.0+codex."
    )

    installer.prepare(source, user)
    assert len(json.loads(catalog_path.read_text())["plugins"]) == 2


def test_update_preserves_unmanaged_user_files(tmp_path: Path, installer: ModuleType) -> None:
    source = source_bundle(tmp_path / "source", installer)
    user = tmp_path / "user"
    target = Path(installer.prepare(source, user)["plugin"])
    retained = target / ".env"
    retained.write_text("user data")
    with pytest.raises(ValueError, match="unmanaged files"):
        installer.prepare(source, user)
    assert retained.read_text() == "user data"


def test_rejects_conflicting_marketplace_source(tmp_path: Path, installer: ModuleType) -> None:
    source = source_bundle(tmp_path / "source", installer)
    user = tmp_path / "user"
    catalog = user / ".agents/plugins/marketplace.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps(
            {
                "name": "personal",
                "plugins": [
                    {"name": installer.PLUGIN, "source": {"source": "local", "path": "./different"}}
                ],
            }
        )
    )
    before = catalog.read_bytes()
    with pytest.raises(ValueError, match="different source"):
        installer.prepare(source, user)
    assert catalog.read_bytes() == before
    assert not (user / "plugins").exists()


def test_rejects_symlink_payload(tmp_path: Path, installer: ModuleType) -> None:
    source = source_bundle(tmp_path / "source", installer)
    secret = tmp_path / "private.py"
    secret.write_text("private = True")
    (source / "src/hunting_harness/leak.py").symlink_to(secret)
    with pytest.raises(ValueError, match="unsafe plugin input"):
        installer.prepare(source, tmp_path / "user")


def test_main_invokes_codex_installer_once(
    tmp_path: Path, installer: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = source_bundle(tmp_path / "source", installer)
    user = tmp_path / "user"
    commands: list[list[str]] = []

    def run(command: list[str], *, check: bool, timeout: int) -> None:
        assert check
        assert timeout == 120
        commands.append(command)

    monkeypatch.setattr(installer, "__file__", str(source / "scripts/install_plugin.py"))
    monkeypatch.setattr(installer.Path, "home", lambda: user)
    monkeypatch.setattr(installer.shutil, "which", lambda command: "/usr/bin/codex")
    monkeypatch.setattr(installer.subprocess, "run", run)
    monkeypatch.setattr(
        installer, "install_tool_policies", lambda plugin, selector: {"status": "ok"}
    )
    monkeypatch.setattr(sys, "argv", ["install_plugin.py"])
    installer.main()
    assert commands == [["codex", "plugin", "add", "threat-hunting-harness@personal"]]


def test_policies_use_scoped_api_and_preserve_explicit_choices(
    tmp_path: Path, installer: ModuleType
) -> None:
    source = source_bundle(tmp_path / "source", installer)
    (source / "assets/plugin-tools.json").write_text(
        json.dumps([{"name": name} for name in ("hunting_setup", "analyst_decide", "query_submit")])
    )
    config_path = tmp_path / "isolated-config.toml"
    calls: list[tuple[str, dict[str, object]]] = []

    class Api:
        def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
            calls.append((method, params))
            if method == "config/read":
                return {
                    "layers": [
                        {
                            "name": {"type": "user", "file": str(config_path)},
                            "version": "sha256:old",
                            "config": {
                                "approval_policy": "never",
                                "plugins": {
                                    "unrelated@personal": {"enabled": False},
                                    "threat-hunting-harness@personal": {
                                        "mcp_servers": {
                                            "hunting": {
                                                "tools": {
                                                    "query_submit": {"approval_mode": "prompt"}
                                                },
                                            }
                                        }
                                    },
                                },
                            },
                        }
                    ]
                }
            assert method == "config/batchWrite"
            return {"status": "ok", "version": "sha256:new", "filePath": str(config_path)}

    result = installer.configure_tool_policies(
        source, "threat-hunting-harness@personal", Api(), file_path=config_path
    )
    prefix = 'plugins."threat-hunting-harness@personal".mcp_servers.hunting'
    assert calls[0] == ("config/read", {"includeLayers": True})
    assert calls[1] == (
        "config/batchWrite",
        {
            "edits": [
                {
                    "keyPath": prefix + ".default_tools_approval_mode",
                    "mergeStrategy": "upsert",
                    "value": "prompt",
                },
                {
                    "keyPath": prefix + ".tools.analyst_decide.approval_mode",
                    "mergeStrategy": "upsert",
                    "value": "approve",
                },
                {
                    "keyPath": prefix + ".tools.hunting_setup.approval_mode",
                    "mergeStrategy": "upsert",
                    "value": "approve",
                },
            ],
            "filePath": str(config_path),
            "reloadUserConfig": True,
            "expectedVersion": "sha256:old",
        },
    )
    assert result == {"status": "ok", "configured_tools": 2, "preserved_tools": ["query_submit"]}


def test_existing_policies_need_no_write(tmp_path: Path, installer: ModuleType) -> None:
    source = source_bundle(tmp_path / "source", installer)
    (source / "assets/plugin-tools.json").write_text('[{"name":"analyst_decide"}]')

    class Api:
        def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
            assert method == "config/read"
            return {
                "layers": [
                    {
                        "name": {"type": "user", "file": str(tmp_path / "config.toml")},
                        "version": "v",
                        "config": {
                            "plugins": {
                                "threat-hunting-harness@personal": {
                                    "mcp_servers": {
                                        "hunting": {
                                            "default_tools_approval_mode": "prompt",
                                            "tools": {
                                                "analyst_decide": {"approval_mode": "prompt"}
                                            },
                                        },
                                    }
                                }
                            }
                        },
                    }
                ]
            }

    result = installer.configure_tool_policies(source, "threat-hunting-harness@personal", Api())
    assert result["status"] == "unchanged"
    assert result["preserved_tools"] == ["analyst_decide"]


def test_config_api_timeout_is_bounded(installer: ModuleType) -> None:
    api = installer.CodexConfigApi.__new__(installer.CodexConfigApi)
    api.timeout, api.identifier = 0, 0
    api.messages = queue.Queue()
    api.process = SimpleNamespace(stdin=io.StringIO())
    with pytest.raises(ValueError, match="timed out during config/read"):
        api.request("config/read", {"includeLayers": True})
