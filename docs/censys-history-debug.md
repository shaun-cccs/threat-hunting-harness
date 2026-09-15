# Censys history failures, 2026-09-15

Implementation follow-up: the worktree now uses the Python SDK, retains raw API
JSON, and exposes time-based continuation. The flattened-MCP parser developed
during this investigation has been replaced. See [migration verification](verification.md#censys-sdk-migration-2026-09-15).

After the user populated `CENSYS_ORG_ID`, the seven-day timeline and historical
snapshot returned data. Their successful responses exposed a second adapter
bug: the hosted MCP returns flattened `path:value` text, which the harness only
attempted to parse as JSON. The worktree now reads those history responses while
retaining their original text and incomplete-coverage signals. See the retest
below for the remaining 90-day request failure.

Censys history is implemented in the harness: the reviewed MCP schema exposes
`get_host_timeline(host_id, start_time, end_time)` and `get_host(host_id, at_time)`.
The observed failures are upstream access denials. A separate harness classifier
bug hid the timeline denial behind `provider_tool_error`.

## Reproduction and upstream evidence

The retained case `c5f99a7a2142431fb81e5422be659638` contains two timeline calls for
`173.236.196.47`, ending at `2026-09-15T00:00:00Z`, starting at
`2026-06-17T00:00:00Z` and `2026-09-08T00:00:00Z`. Both were saved as
`provider_tool_error`. Its snapshot at `2026-09-14T00:00:00Z` was saved as
`provider_access_denied`.

Replaying those exact requests through the real adapter recovered these MCP
errors before classification. Both timeline windows returned:

> The data needed to answer your question is not available to free users. Please
> upgrade to a Censys Starter or Enterprise tier to enable the Censys Assistant to
> access additional data. Permission denied: get_host_timeline

The snapshot returned HTTP status 403 in the tool error, with:

> Your account does not have access to historical data at the requested time.

These are new reproductions of the saved requests; the original upstream messages
were not retained. The provider's current responses establish the access denial,
not the precise subscription settings or whether supplying an organization ID
would grant access.

## Credential path

The saved case belongs to `/home/shaun.mathew/Projects/threat-hunting-harness`.
The reproduction used that workspace's `.env`, not the new worktree's `.env`.
Initially, `CENSYS_API_KEY` was populated and `CENSYS_ORG_ID` was blank. No shell override for
either variable was present. Boolean checks confirmed the plugin's provider
factory constructs the Bearer authorization header from that credential.
No organization header is sent when the organization ID is blank. The subsequent
retest confirmed both variables were populated, neither had a shell override,
and the organization header matched `.env` exactly, without exposing its value.

The plugin reads `credentials(workspace / ".env")` on runtime refresh and rebuilds
its providers when credentials change. `credentials()` allows nonempty process
environment variables to override `.env`; the normal plugin launcher omits
provider credentials from its inherited process environment.

If paid history access is associated with an organization, check that the token
belongs to that organization and configure its `CENSYS_ORG_ID`. Missing organization
context is a possible explanation, not a confirmed entitlement fix. Shortening
the timeline window did not resolve the observed denial.

## Fix and validation

`error_code()` matched `permissiondenied` but not Censys's `Permission denied`.
The classifier now accepts a separator between the words. Raw provider messages
remain excluded from retained error codes because they may contain credentials.
The plugin bundle contains the same classifier fix.

Regression tests replay the captured timeline denial through a synthetic MCP
server and the real `McpTransport`/`McpSource` path, including exception wrapping
and request accounting. Both windows failed before the fix and passed afterward:

```sh
PYTHONPATH=src python -m pytest tests/test_provider_contracts.py -k timeline_free_tier -q
```

The full offline suite passed: 113 tests. Ruff and mypy passed. A second live
replay returned `provider_access_denied` for all three requests, with the same
upstream denials. This fixes diagnosis; it does not grant historical-data access.
The two live passes dispatched six MCP tools in total; upstream API request and
credit counts are unobservable.

Local redacted before/after captures and the manual replay script are retained
outside the patch in `/tmp/censys-history-diagnostics/`. Running that script issues
three live existing-observation requests and may consume Censys credits. The
original case records were not modified.

## Retest with organization context

Three more live calls used the same host and timestamps with the newly populated
organization header. These were the results before the response-parser fix:

| Request | Upstream response | Harness result |
| --- | --- | --- |
| 90-day timeline | No usable response captured after tool dispatch | `provider_mcp_unavailable` |
| Seven-day timeline | `isError: false`; 100 flattened event records | `unrecognized_provider_response` |
| Historical snapshot | `isError: false`; flattened host and service fields | `unrecognized_provider_response` |

The successful results have the shape `{"result": "events.0.resource.event_time:..."}`
and `{"result": "ip:...\nservices.0.scan_time:..."}` inside MCP `structuredContent`.
Text content carries the same flattened value. JSON-only unwrapping leaves these
values as strings, which the old Censys parser rejected.

The updated parser reads only the verified host/service and timeline/event
boundaries. It preserves dotted domain keys and colon-containing values as flat
fields, retains the original MCP payload, and flags malformed records or missing
services. It uses event timestamps and service scan timestamps, never the
requested snapshot time as an invented observation date.

Offline replay of both complete captured responses through the real MCP adapter
now yields:

- **Timeline:** 100 dated events, from `2026-09-12T19:31:05.972322+00:00` to
  `2026-09-14T23:19:05.721976+00:00`. The provider reports
  `scanned_to:2026-09-12 19:25:11.607695+00:00`. Retrieval remains incomplete;
  the reviewed tool schema has no continuation argument. This is not evidence
  covering all seven requested days.
- **Snapshot:** one NTP service on port 123, observed at
  `2026-09-13T01:09:41+00:00`, from the snapshot requested at
  `2026-09-14T00:00:00Z`. Retrieval is complete for this response.

The captured-data regression tests failed before the fix and pass afterward.
They cover structured and text MCP envelopes, dates, IPv6, dotted DNS keys,
partial history, malformed data, and unknown text. All 123 tests, including the
45 provider contract tests, pass; Ruff and mypy pass too. No extra live queries
were used to develop the parser fix.

Retest captures are in `/tmp/censys-history-diagnostics/censys_history_with_org.*.raw.json`.
The offline full-response replay is
`/tmp/censys-history-diagnostics/censys_history_org_replay.py`, with its results
in the adjacent `.json` file. Across the initial investigation and retest, nine
MCP tools were dispatched; upstream API request and credit counts remain unknown.
The original case records and installed plugin were not changed.

## 30-day follow-up

One additional live request for `173.236.196.47`, from
`2026-08-16T00:00:00Z` through `2026-09-15T00:00:00Z`, succeeded in 11.2 seconds
with organization context. It returned 100 dated events spanning September
12–14, with the same `scanned_to` bound as the seven-day response. The patched
adapter parsed them successfully and retained `history_or_pagination_incomplete`:
the accepted 30-day range does not establish complete 30-day coverage.

The redacted response and summary are retained in
`/tmp/censys-history-diagnostics/censys_history_30_day.1.raw.json` and
`/tmp/censys-history-diagnostics/censys_history_30_day.json`. This brings the total
to ten dispatched MCP tools across the investigation, without observable credit
or upstream API request counts.

## 89-day follow-up

One additional live request for the same host, from `2026-06-18T00:00:00Z`
through `2026-09-15T00:00:00Z`, succeeded in 10.73 seconds. It again returned
100 events covering September 12–14 with the same `scanned_to` bound, and was
marked incomplete. This confirms acceptance of an 89-day window; it does not
establish full coverage or the cause of the earlier 90-day failure.

The redacted response and summary are retained in
`/tmp/censys-history-diagnostics/censys_history_89_day.1.raw.json` and
`/tmp/censys-history-diagnostics/censys_history_89_day.json`. Eleven MCP tools
have now been dispatched across the investigation.

## Exact 90-day retry

To test a possible boundary error, the original organization-enabled 90-day
request (`2026-06-17T00:00:00Z` through `2026-09-15T00:00:00Z`) was repeated
without changing the adapter's timeout or request parameters. It succeeded in
7.76 seconds, returning the same 100 events and incomplete-coverage bound.
This argues against a deterministic off-by-one range limit. The original
organization-enabled failure remains unexplained; a transient failure is
consistent with the successful retry, but its cause was not captured.

The redacted response and summary are retained in
`/tmp/censys-history-diagnostics/censys_history_90_day_retry.1.raw.json` and
`/tmp/censys-history-diagnostics/censys_history_90_day_retry.json`. Twelve MCP
tools have now been dispatched across the investigation.

## Batch size and time-based pagination

A comparison query for `1.1.1.1` over the same 90-day range succeeded in 6.2
seconds and returned exactly 100 events, spanning
`2026-09-14T21:11:41.752825+00:00` through
`2026-09-14T23:59:38.916440+00:00`. Its `scanned_to` bound was
`2026-09-14T21:11:28.851576+00:00`. Direct inspection confirms the raw upstream
response has 100 indexed events; the harness does not truncate the results.

To test pagination on the original host, another request retained the original
lower bound (`2026-06-17T00:00:00Z`) and set the upper bound to the previous
response's `scanned_to` (`2026-09-12T19:25:11.607695+00:00`). It succeeded in
6.88 seconds and returned **99 additional dated events**, spanning
`2026-09-09T14:42:37.883791+00:00` through
`2026-09-12T18:10:23.984598+00:00`. All were older than the first batch, with no
repeated event timestamps. The new `scanned_to` moved back to
`2026-09-09T09:36:35.002333+00:00`, still later than the requested lower bound.
Receiving fewer than 100 events therefore does not establish completion.

This confirms that time-based pagination retrieves additional history. A larger
initial date range does not make the first response contain the whole range.
The deployed MCP tool exposes only host ID and two timestamps, with no page-size
or cursor argument. Its description says it sorts the supplied times. The
[underlying REST reference](https://docs.censys.com/reference/v3-globaldata-asset-host-timeline)
defines its own start time as the newer bound and end time as the older bound;
the MCP wrapper accepts the chronological ordering used in these tests.
The docs inspected expose `scanned_to` but do not specify a configurable batch
size. The 100-event first batches and successful time-bound continuation above
are directly observed behavior.

The timeline adapter currently retains `scanned_to` as metadata and marks the
page incomplete; it does not expose a continuation request yet. The absence of
an explicit cursor parameter does not prevent requesting the next older batch.

Both new responses contain multiline HTTP banner values in Censys's flattened
format. All dated events were retained, but the conservative parser flags
`unrecognized_provider_records` for ambiguous continuation lines and repeated
header names. Raw MCP responses are preserved; multiline banner reconstruction
remains a parser limitation.

Comparison and next-batch captures are retained under
`/tmp/censys-history-diagnostics/censys_history_comparison_host.*` and
`/tmp/censys-history-diagnostics/censys_history_next_batch.*`. Fourteen MCP tools
have now been dispatched across the investigation.
