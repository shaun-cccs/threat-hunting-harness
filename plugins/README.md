# Git marketplace distribution

`threat-hunting-harness/` is the installable bundle referenced by
`../.agents/plugins/marketplace.json`. Codex copies this directory when installing
from GitHub, so it must contain all runtime inputs. It excludes workspace `.env`,
cases, test artifacts, virtual environments, and the local Python installer.

Edit the canonical source files at the repository root, then run
`python3 scripts/build_plugin_bundle.py` before committing. The distribution test
checks that the bundle exactly matches those sources. Update the plugin manifest
version before publishing runtime updates so Codex refreshes its installed cache.

End users install through `codex plugin marketplace add` and `codex plugin add`;
they do not run the build script or `install_plugin.py`.
