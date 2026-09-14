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

## Branch validation

This branch adds Censys, GTI, and GreyNoise to the core gateway. Offline schema, provider contract, accounting, and gateway checks are recorded in its commit message. All prior live results above are retained; the branch split made no new provider calls. Native client and evaluation validation is introduced in the later branches.
