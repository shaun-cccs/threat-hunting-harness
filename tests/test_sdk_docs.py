"""Official SDK references must retain provenance and survive plugin packaging."""

import hashlib
import importlib.metadata
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ROOT / "skills/hunt/references"


def local_links(path: Path) -> set[Path]:
    return {
        (path.parent / target.split("#", 1)[0]).resolve()
        for target in re.findall(r"\]\(([^\s)]+)\)", path.read_text())
        if not target.startswith(("https:", "http:", "mailto:", "#"))
    }


@pytest.mark.parametrize(
    "provider,operations",
    [
        ("censys", ("get-host", "get-host-timeline", "get-certificate", "search")),
        ("shodan", ("host", "search")),
    ],
)
def test_packaged_skill_discloses_resolvable_method_references(
    tmp_path: Path, provider: str, operations: tuple[str, ...]
) -> None:
    spec = importlib.util.spec_from_file_location(
        "sdk_docs_installer", ROOT / "scripts/install_plugin.py"
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
    guide = tmp_path / f"skills/hunt/references/{provider}.md"
    sdk = guide.parent / f"{provider}-sdk"
    assert guide in local_links(skill)
    # The entry point routes to the guide; method details stay behind that guide.
    assert all(path.parent != sdk for path in local_links(skill))
    methods = {sdk / f"{name}.md" for name in operations}
    assert methods <= local_links(guide)
    for document in [skill, *guide.parent.rglob("*.md")]:
        for target in local_links(document):
            assert target.is_relative_to(tmp_path), (document, target)
            assert target.is_file(), (document, target)


@pytest.mark.parametrize("provider", ["censys", "shodan"])
def test_official_snapshots_match_provenance_and_installed_release(provider: str) -> None:
    sdk = REFERENCES / f"{provider}-sdk"
    manifest = json.loads((sdk / "provenance.yaml").read_text())
    assert importlib.metadata.version(manifest["package"]) == manifest["version"]
    if provider == "censys":
        assert manifest["release_tag"] == f"v{manifest['version']}"
        assert manifest["release_revision"] == manifest["revision"]
    for artifact in manifest["artifacts"]:
        assert (
            hashlib.sha256((sdk / artifact["file"]).read_bytes()).hexdigest() == artifact["sha256"]
        )
        assert artifact["sources"]
        for source in artifact["sources"]:
            assert f"/blob/{manifest['revision']}/" in source["source_url"]


def test_shodan_references_match_installed_sdk_source() -> None:
    sdk = REFERENCES / "shodan-sdk"
    manifest = json.loads((sdk / "provenance.yaml").read_text())
    distribution = importlib.metadata.distribution(manifest["package"])
    for artifact in manifest["artifacts"]:
        for source in artifact["sources"]:
            if not source["source_path"].startswith("shodan/"):
                continue
            data = Path(distribution.locate_file(source["source_path"])).read_bytes()
            assert hashlib.sha256(data).hexdigest() == source["source_sha256"]
            excerpt = b"".join(
                data.splitlines(keepends=True)[source["line_start"] - 1 : source["line_end"]]
            )
            assert hashlib.sha256(excerpt).hexdigest() == source["excerpt_sha256"]
