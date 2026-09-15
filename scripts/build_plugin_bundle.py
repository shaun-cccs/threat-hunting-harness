"""Build the checked-in Git marketplace package; end users use native Codex installation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from install_plugin import PLUGIN, payload_paths


def bundle_inputs(root: Path) -> dict[Path, bytes]:
    paths = [path for path in payload_paths(root) if path.name != "install_plugin.py"]
    paths.extend(root / name for name in ("README.md", "docs/plugin.md"))
    return {path.relative_to(root): path.read_bytes() for path in paths}


def build(root: Path, *, check: bool = False) -> list[str]:
    """Reject unexpected files, especially credentials, instead of copying a checkout wholesale."""
    target = root / "plugins" / PLUGIN
    inputs = bundle_inputs(root)
    present = {path.relative_to(target) for path in target.rglob("*") if path.is_file()}
    unexpected = present - inputs.keys()
    if unexpected:
        raise ValueError("Unmanaged files in plugin bundle: " + ", ".join(map(str, unexpected)))
    changed = []
    for relative, content in inputs.items():
        destination = target / relative
        if destination.is_symlink():
            raise ValueError(f"Symlink in plugin bundle: {relative}")
        if destination.exists() and destination.read_bytes() == content:
            continue
        changed.append(str(relative))
        if not check:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the bundle needs rebuilding")
    args = parser.parse_args()
    try:
        changed = build(Path(__file__).resolve().parents[1], check=args.check)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    if args.check and changed:
        print("Rebuild with python3 scripts/build_plugin_bundle.py: " + ", ".join(changed))
        return 1
    print(f"Marketplace bundle {'verified' if args.check else 'built'} ({len(changed)} changes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
