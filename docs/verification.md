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

The full offline suite passed: 69 tests. Strict mypy checking passed across 24 source files, Ruff passed for source/tests/scripts, and the locked dependency check and source/wheel builds passed. Two upstream Starlette test-client deprecation warnings remain. Provider contract fixtures and campaign replays run without provider credentials. Client fixtures use local authenticated MCP and Shodan-shaped synthetic observations.

Installed-client preflight and fixture replay are separate checks. See [client verification](clients.md) for the tested versions and unsupported runtime controls, and [evaluation](evaluation.md) for measured replay results and limits on their interpretation.

Codex CLI 0.154.0 accepted the dedicated configuration with only the hunting MCP server enabled and all three native roles present. Its preflight reports `unified_exec` as an unsupported control. Claude Code 2.1.269 advertised the required flags and the generated files parsed successfully. Both reports retain `effective_runtime_enforcement: not_verified`; these checks did not invoke a model.

The Codex-labeled SDK fixture replay completed a hunt and reopened the same case through authenticated MCP. It retained one synthetic query, two observations, reviewer assessments, scripted analyst decisions, the query limit, and a completed status. The retained transcript is `artifacts/client-codex-replay/transcript.json`. This is an SDK workflow replay, not a native Codex model run.

A native Claude Code fixture attempt was blocked before inference by `Not logged in · Please run /login`. It made zero provider requests. The user then deferred Claude work (issue #11) in favor of Codex. Its retained scaffolding and SDK fixture are not a verified native workflow.

The three-campaign evaluation command completed using synthetic Shodan observations and cited campaign indicator sets. Outputs under `artifacts/evaluation/` retain baseline/coordinated cases, transcripts, exports, query usage, and source gaps. All credited observations are retrospective in this corpus; the in-window-available recovery count is zero. These measurements support pipeline verification, not empirical discovery accuracy or a numeric production acceptance target.
