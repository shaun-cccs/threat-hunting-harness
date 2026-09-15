"""The hunt skill's disclosed Censys references must survive plugin packaging."""

import hashlib
import importlib.metadata
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ROOT / "skills/hunt/references"


def local_links(path: Path) -> set[Path]:
    return {
        (path.parent / target.split("#", 1)[0]).resolve()
        for target in re.findall(r"\]\(([^\s)]+)\)", path.read_text())
        if not target.startswith(("https:", "http:", "mailto:", "#"))
    }


def test_packaged_skill_discloses_resolvable_method_references(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "censys_docs_installer", ROOT / "scripts/install_plugin.py"
    )
    assert spec and spec.loader
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    for source in installer.payload_paths(ROOT):
        relative = source.relative_to(ROOT)
        if relative.parts[0] == "skills":
            destination = tmp_path / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())

    skill = tmp_path / "skills/hunt/SKILL.md"
    guide = tmp_path / "skills/hunt/references/censys.md"
    sdk = guide.parent / "censys-sdk"
    assert guide in local_links(skill)
    # The entry point routes to the guide; method details stay behind that guide.
    assert all(path.parent != sdk for path in local_links(skill))
    methods = {
        sdk / f"{name}.md"
        for name in ("get-host", "get-host-timeline", "get-certificate", "search")
    }
    assert methods <= local_links(guide)
    for document in [skill, *guide.parent.rglob("*.md")]:
        for target in local_links(document):
            assert target.is_relative_to(tmp_path), (document, target)
            assert target.is_file(), (document, target)


def test_official_snapshots_match_provenance_and_installed_release() -> None:
    sdk = REFERENCES / "censys-sdk"
    manifest = json.loads((sdk / "provenance.yaml").read_text())
    assert importlib.metadata.version(manifest["package"]) == manifest["version"]
    assert manifest["release_tag"] == f"v{manifest['version']}"
    assert manifest["release_revision"] == manifest["revision"]
    for artifact in manifest["artifacts"]:
        assert (
            hashlib.sha256((sdk / artifact["file"]).read_bytes()).hexdigest() == artifact["sha256"]
        )
        assert artifact["sources"]
        for source in artifact["sources"]:
            assert f"/blob/{manifest['revision']}/" in source["source_url"]
