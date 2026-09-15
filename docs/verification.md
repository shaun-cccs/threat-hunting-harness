# Verification record

Checks on 2026-09-14 used Python 3.12.3 on Linux. Live provider credentials were loaded from the ignored `.env` file. Account responses and raw case evidence remain in ignored local artifacts.

## Claude Code plugin installation (2026-09-15)

Claude Code 2.1.269 installed the local repository marketplace and its plugin using
an isolated `CLAUDE_CONFIG_DIR`. The check ran from a separate investigation
directory and left the user's normal Claude configuration unchanged:

```bash
claude plugin marketplace add /absolute/path/to/threat-hunting-harness
claude plugin install threat-hunting-harness@threat-hunting
claude plugin details threat-hunting-harness@threat-hunting
claude mcp list
```

The installed component inventory contained the `hunt` skill and one `hunting`
MCP server. The native health check reported
`plugin:threat-hunting-harness:hunting` connected, using the absolute script path
from the Claude manifest instead of the relative Codex launcher configuration.
Strict Claude validation passed for both the marketplace and bundled plugin;
Codex plugin validation and shared skill validation also passed.

The full suite passed **137 tests**. Ruff, strict mypy across 27 source files,
bundle consistency, and `git diff --check` passed. The test run reported the two
existing upstream Starlette/AnyIO deprecation warnings.

The runtime regression test copies the bundle to a path containing spaces,
launches the Claude manifest's command from another workspace, and initializes
the shared backend through the MCP SDK. A simultaneous Codex-style connection
reads the same case; the Claude-style connection exports it. The test verifies
that setup makes zero provider requests, the investigation `.env` is preserved,
and runtime use leaves the installed bundle unchanged. Provider runtime paths
are injected fixtures, so this test does not download dependencies.

These checks made no live provider or model calls. They verify native local
installation, skill discovery, MCP connectivity, and shared runtime behavior.
Remote GitHub installation of this change and a Claude model-driven hunt with
native subagent review have not been run.

## Censys SDK migration (2026-09-15)

The `debug/censys-history` worktree replaces the provider-owned Censys MCP
transport with `censys-platform==0.16.2`. CLI and plugin factories use the same
SDK adapter. The checked-in plugin bundle includes the dependency lock, adapter,
and the hunt skill's conditionally loaded Censys guide and individual method
references. Documentation snapshots match release `v0.16.2` at
`43a8a3ac1161e655eff3061ba3b7ab934c185c55`.

A bounded live check used the original workspace's `.env` and organization
context through a separate diagnostic gateway case. Four API requests were
made, with zero provider MCP tool calls and no automatic retries:

| Operation | Result |
| --- | --- |
| Historical host snapshot | HTTP 200; one service observation, retained as raw JSON |
| Search for the same host | HTTP 200; successful empty result |
| 90-day host timeline, first page | HTTP 200; 100 dated events and a continuation |
| Timeline continuation | HTTP 200; 100 dated events and a further continuation |

The timeline remained partial; this check did not retrieve the whole 90-day
interval. The API returned submicrosecond `scanned_to` values. The adapter keeps
them in continuation arguments and raw evidence, rounding the SDK request's
upper bound outward to avoid dropping events. Each page was retained before
its continuation was submitted. Request IDs and actual API request counts were
recorded; per-call credits remain unknown. Certificate retrieval was verified
with synthetic SDK responses rather than another live lookup.

Local smoke evidence is retained under
`/tmp/censys-sdk-assessment/migration-live/`, case
`f0a16f3924004dc98fd4d713bb9ac511`, with `summary.json` and raw page artifacts.
No original case records or workspace credentials were modified. Changes are
in the isolated worktree and its rebuilt plugin bundle; the installed plugin
has not been replaced by this check.

Offline tests cover the real SDK over HTTPX mock transports, gateway page
retention and request limits, identical-timestamp event preservation, raw unknown
fields, multiline banners, date ordering and precision, HTTP/transport failures,
credential mapping, schema changes, and the packaged skill/reference links.

Final validation passed: **136 tests**, Ruff for source/tests/scripts, strict
mypy across 27 source files, plugin bundle consistency, and `git diff --check`.
The test run reported two existing upstream Starlette/AnyIO deprecation warnings.

## Native GitHub installation

On 2026-09-15, Codex CLI 0.154.0 installed the marketplace directly from the pushed `implement/plugin` branch with:

```bash
codex plugin marketplace add shaun-cccs/threat-hunting-harness --ref implement/plugin
codex plugin add threat-hunting-harness@threat-hunting
```

Codex reported `marketplaceSource.sourceType: git`, the expected GitHub URL, and installed version `0.1.0+codex.20260915002728`. The native plugin configuration contained only `enabled: true`; the Python installer was not run and no per-tool approval settings were written. The earlier personal installation was removed after the Git installation succeeded, avoiding duplicate MCP servers.

A fresh native Codex app-server thread used normal `on-request` approval handling. The test client accepted exactly three individual prompts for `hunting_setup`, `hunting_status`, and `provider_connections(live=false)`, without persisting permission changes. All three completed using plugin ID `threat-hunting-harness@threat-hunting`; the runtime became ready and reported zero provider requests. A separate installed-bundle setup check loaded the original workspace's `.env`, detected all four configured providers, and reported zero requests. Sanitized native tool results and approval evidence are retained locally in `artifacts/git-plugin-install/report.json`.

The final suite passed **109 tests**, including marketplace/source consistency and a regression check for timestamp precision when migrating from the old installer. Strict mypy, Ruff, plugin validation, and credential exclusion checks passed. The 51-file Git bundle contains all runtime inputs and excludes the Python installer, workspace credentials, tests, and case artifacts. Its generated files are checked against the canonical source by `tests/test_plugin_distribution.py`; developers rebuild with `scripts/build_plugin_bundle.py` before publishing changes.

The plugin uses normal Codex permissions. A noninteractive host that rejects all unapproved tools must permit them through its own controls; Git installation does not bypass that policy. This distribution is a repository marketplace, not a submission to a public plugin directory. Provider authentication limitations and runtime confinement limits below still apply.

## Plugin runtime and earlier personal installation

The plugin workflow replaces manual gateway/client startup. Checks on 2026-09-14–15 used Codex CLI 0.154.0 and the installed personal-marketplace bundle on Linux x86_64. Codex launched the stdio entry point, which prepared its own pinned Python, GTI, Node, and GreyNoise dependencies from a cold cache. The installed bundle was independent of the development virtual environment. A warm preparation reused the completed runtime.

A native Codex session, with no per-run tool-policy overrides or manually started service, created one case with a zero-query limit. Exactly one native subagent initialized the same workspace and read the same case and allowance. The retained branch remained waiting, settlement returned `paused`, and Markdown, JSON, and CSV files were exported. Parent/child session records verify delegation and the child's actual case read; the model's final message alone is not the verification. This fixture made zero provider queries and recorded no findings or analyst decisions.

The headless developer check is `python scripts/verify_plugin.py --output artifacts/native-plugin-check` after installation, with the host already permitting the hunting tools. The successful personal-installation run and sanitized delegation evidence are retained locally under `artifacts/native-plugin-verified/`. This checks plugin setup, shared state, delegation, and exports. The earlier synthetic Shodan workflow below separately checks reviewed findings.

The installed plugin also loaded the original workspace's `.env`, detected all four configured providers, and reported zero requests during setup/configuration inspection. Its `evaluate_benchmarks` tool successfully ran the bundled offline corpus and wrote evaluation artifacts with zero live provider requests. No additional live authentication or intelligence calls were made for plugin verification; the previously observed GreyNoise HTTP 401 remains unresolved.

Runtime tests exercise real stdio processes and an automatically started backend: concurrent clients share query deduplication and limits, cases survive idle shutdown, credentials reload after editing `.env`, and plugin upgrades replace the service without discarding cases. Failure tests cover interrupted preparation, configuration errors, retry, and connection-check serialization. Bootstrap and installer tests check package integrity, credential isolation, preserved user files/settings, and scoped tool policies. The final suite passed **107 tests**; strict mypy, Ruff, lock validation, source/wheel builds, and plugin/skill validation passed. Two upstream Starlette test-client deprecation warnings remain.

The installer uses Codex's configuration API to approve only the 21 bundled named tools and preserve explicit existing tool settings; unknown tools retain the default prompt policy. Reinstallation preserved all 21 existing policies. A bundle scan confirmed that none of the workspace credential values entered its 50 allowlisted files. Analyst confirmation is a retained chat audit record, not authentication of a human identity. OS/network confinement of Codex's other tools remains unverified. macOS and ARM64 package pins are present, but the native check ran only on Linux x86_64.

## Limited live checks

| Provider | Check | Result | Recorded usage |
| --- | --- | --- | --- |
| Shodan | Account metadata | HTTP 200 | One metadata request |
| GTI / VirusTotal | Account metadata | HTTP 200 | One metadata request |
| GreyNoise | Account metadata | HTTP 401; account access not validated | One metadata request |
| Censys | Authenticated MCP initialization and tool inventory | Connected; 22 tools returned; four selected schemas match | One MCP session; zero intelligence tool calls |
| Shodan | Existing host report for `1.1.1.1`, `history=false` | Completed; 16 observations retained | One query, one API request, zero searches and retries; credits unknown |

These checks made no direct target requests and requested no fresh scans. Metadata authentication does not establish all search/history entitlements. No live GTI, Censys, or GreyNoise intelligence queries were performed. Provider MCP dependencies can expand into upstream calls internally; unknown request counts remain unknown.

Reproduce the metadata checks with `hunt connections --live --refresh`. `hunt connections --live` uses the cached result if available. The explicit Shodan check is `hunt smoke --ip 1.1.1.1`; each invocation creates a new case limited to one query and one API request.

Local artifacts:

- `artifacts/connection-validation/connections.json`
- `artifacts/connection-validation/censys-inventory.json`
- `artifacts/live-smoke/shodan-smoke.json`
- `artifacts/live-smoke/cases/` (retained source records and case state)

## Offline and client checks

The final offline suite passed: 78 tests. Strict mypy checking passed across 25 source files and the native verification script, Ruff passed for source/tests/scripts, and the locked dependency check and source/wheel builds passed. Two upstream Starlette test-client deprecation warnings remain. Provider contract fixtures and campaign replays run without provider credentials. Client fixtures use local authenticated MCP and Shodan-shaped synthetic observations. The [implementation review](implementation-review.md) records the independently reviewed findings and their fixes.

Installed-client preflight and fixture replay are separate checks. See [client verification](clients.md) for the tested versions and unsupported runtime controls, and [evaluation](evaluation.md) for measured replay results and limits on their interpretation.

Codex CLI 0.154.0 accepted the dedicated configuration with only the hunting MCP server enabled and all three native roles present. Its preflight reports `unified_exec` as an unsupported control. Claude Code 2.1.269 advertised the required flags and the generated files parsed successfully. Both reports retain `effective_runtime_enforcement: not_verified`; these checks did not invoke a model.

The Codex-labeled SDK fixture replay completed a hunt and reopened the same case through authenticated MCP. It retained one synthetic query, two observations, reviewer assessments, scripted analyst decisions, the query limit, and a completed status. The retained transcript is `artifacts/client-codex-replay/transcript.json`. This is an SDK workflow replay, not a native Codex model run.

A native Claude Code fixture attempt was blocked before inference by `Not logged in · Please run /login`. It made zero provider requests. The user then deferred Claude work (issue #11) in favor of Codex. Its retained scaffolding and SDK fixture are not a verified native workflow.

The three-campaign evaluation command completed using synthetic Shodan observations and cited campaign indicator sets. Outputs under `artifacts/evaluation/` retain baseline/coordinated cases, transcripts, exports, query usage, and source gaps. All credited observations are retrospective in this corpus; the in-window-available recovery count is zero. These measurements support pipeline verification, not empirical discovery accuracy or a numeric production acceptance target.

## Native Codex workflow

The corrected Codex 0.154.0 profile completed a native model workflow through the authenticated local fixture gateway: one synthetic Shodan search, two retained candidates, one historical-association finding, a separate reviewer assessment, and recorded completion. The reviewer marked campaign association insufficient rather than treating a service fingerprint as proof of maliciousness. The trusted verification script then recorded a fixture-only analyst decision. Both query and API-request limits were one; live provider requests were zero.

The check is reproducible with `python scripts/verify_codex.py --output artifacts/native-check` in the project environment. It invokes the installed model client and stores case evidence and event logs in the selected new directory. The successful run's report is `artifacts/native-codex-verified/report.json`.

Native testing exposed and fixed role files missing their MCP transport, the disabled tool host, and missing per-tool approval settings. The final profile enables only the named gateway tools with explicit scoped approvals. Working tool access and delegation are verified; operating-system egress confinement and absence of every alternate client capability remain unverified and are reported as such.
