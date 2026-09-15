# Git marketplace distribution

`threat-hunting-harness/` is the installable bundle referenced by
`../.agents/plugins/marketplace.json` for Codex and
`../.claude-plugin/marketplace.json` for Claude Code. Both hosts copy this directory
when installing from GitHub, so it must contain all runtime inputs. It excludes workspace `.env`,
cases, test artifacts, virtual environments, and the local Python installer.

Edit the canonical source files at the repository root, then run
`python3 scripts/build_plugin_bundle.py` before committing. The distribution test
checks that the bundle exactly matches those sources. Update both plugin manifest
versions before publishing runtime updates so each host refreshes its installed cache.
The shared runtime uses the Codex manifest's version to coordinate service upgrades,
including when launched by Claude Code.

End users install through `codex plugin marketplace add` and `codex plugin add`,
or `claude plugin marketplace add` and `claude plugin install`; they do not run the
build script or `install_plugin.py`.
