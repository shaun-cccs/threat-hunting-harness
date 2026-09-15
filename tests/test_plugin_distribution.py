"""The Git marketplace must install the tested runtime without copying workspace secrets."""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_marketplace_bundle_matches_sources(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "plugin_bundle", ROOT / "scripts/build_plugin_bundle.py"
    )
    assert spec and spec.loader
    bundle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bundle)
    catalog = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())
    entry = catalog["plugins"][0]
    target = ROOT / entry["source"]["path"]
    manifest = json.loads((target / ".codex-plugin/plugin.json").read_text())
    assert manifest["name"] == entry["name"] == "threat-hunting-harness"
    assert bundle.build(ROOT, check=True) == []
    assert not (target / "scripts/install_plugin.py").exists()
    assert not (target / ".env").exists()
    assert not (target / "artifacts").exists()
    assert not (target / "tests").exists()
    assert (target / "scripts/plugin_stdio.py").is_file()
    assert (target / "src/hunting_harness/plugin_runtime.py").is_file()
    sys.modules.pop("install_plugin", None)
