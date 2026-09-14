# Verification record

Checks on 2026-09-14 used Python 3.12.3 on Linux. Live provider credentials were loaded from the ignored `.env` file. Account responses and raw case evidence remain in ignored local artifacts.

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

The complete reviewed implementation passed 78 tests; this branch excludes the evaluation tests introduced next. Strict mypy checking passed across 25 source files and the native verification script, Ruff passed for source/tests/scripts, and the locked dependency check and source/wheel builds passed. Two upstream Starlette test-client deprecation warnings remain. Provider contract fixtures and campaign replays run without provider credentials. Client fixtures use local authenticated MCP and Shodan-shaped synthetic observations. Independent implementation review findings were resolved before this branch split.

Installed-client preflight and fixture replay are separate checks. See [client verification](clients.md) for the tested versions and unsupported runtime controls.

Codex CLI 0.154.0 accepted the dedicated configuration with only the hunting MCP server enabled and all three native roles present. Its preflight reports `unified_exec` as an unsupported control. Claude Code 2.1.269 advertised the required flags and the generated files parsed successfully. Both reports retain `effective_runtime_enforcement: not_verified`; these checks did not invoke a model.

The Codex-labeled SDK fixture replay completed a hunt and reopened the same case through authenticated MCP. It retained one synthetic query, two observations, reviewer assessments, scripted analyst decisions, the query limit, and a completed status. The retained transcript is `artifacts/client-codex-replay/transcript.json`. This is an SDK workflow replay, not a native Codex model run.

A native Claude Code fixture attempt was blocked before inference by `Not logged in · Please run /login`. It made zero provider requests. The user then deferred Claude work (issue #11) in favor of Codex. Its retained scaffolding and SDK fixture are not a verified native workflow.

## Native Codex workflow

The corrected Codex 0.154.0 profile completed a native model workflow through the authenticated local fixture gateway: one synthetic Shodan search, two retained candidates, one historical-association finding, a separate reviewer assessment, and recorded completion. The reviewer marked campaign association insufficient rather than treating a service fingerprint as proof of maliciousness. The trusted verification script then recorded a fixture-only analyst decision. Both query and API-request limits were one; live provider requests were zero.

The check is reproducible with `python scripts/verify_codex.py --output artifacts/native-check` in the project environment. It invokes the installed model client and stores case evidence and event logs in the selected new directory. The successful run's report is `artifacts/native-codex-verified/report.json`.

Native testing exposed and fixed role files missing their MCP transport, the disabled tool host, and missing per-tool approval settings. The final profile enables only the named gateway tools with explicit scoped approvals. Working tool access and delegation are verified; operating-system egress confinement and absence of every alternate client capability remain unverified and are reported as such.
