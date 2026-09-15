# Censys Python SDK behind the hunting gateway

Research date: 2026-09-15. Scope: compare the official Censys Python SDK with this worktree's Censys MCP adapter. SDK source was inspected at immutable commit `43a8a3ac1161e655eff3061ba3b7ab934c185c55` (package version `0.16.2`), checked out at `/tmp/censys-sdk-research`. Official Censys API documentation was also read. No credentials were accessed and no authenticated provider queries were executed for this research. The only SDK execution used synthetic HTTPX responses. This is a recommendation, not an implemented migration. [1][2]

Follow-up: the SDK migration is now implemented in this worktree; see the
[provider contract](../providers.md) and [migration verification](../verification.md#censys-sdk-migration-2026-09-15).
The assessment below records the research that informed it.

## Findings

**The SDK would most improve structured evidence, error diagnosis, and control over individual API requests. It does not solve timeline pagination automatically.** It could replace the hosted Censys MCP connection behind the existing provider interface while the agents continue using the shared hunting MCP gateway. [3][4][5][13]

| Concern | Inspected SDK behavior | Implication for this harness |
| --- | --- | --- |
| Historical snapshots | `global_data.get_host_async(host_id=..., at_time=...)` sends a direct host lookup with an RFC3339 time and parses the nested JSON response. `get_hosts` also supports a common `at_time` for multiple host IDs. [3][6] | Avoid reconstructing structured services, nested fields, and multiline banners from flattened MCP text. Historical access still depends on the account's entitlements. [7][14] |
| Host timelines | `get_host_timeline_async` makes one request and returns typed `events` and `scanned_to`. Its arguments contain no page-size, page-token, or automatic paging iterator. Both source and API reference define `start_time` as the newer bound and `end_time` as the older bound. [3][4][8] | The harness still has to create continuation arguments and account for every subsequent page. Do not copy the MCP wrapper's chronological input ordering directly into SDK calls. |
| Raw evidence | Successful calls return typed results and response headers. The typed result is not the original response body: the base model uses Pydantic's default handling of unknown fields, and timeline serializers enumerate declared fields. [4][5][9] | Capture the response body at the HTTP client before model parsing, then retain it separately from normalized observations. A model dump can lose newly added provider fields. |
| Provider errors | `SDKBaseError` exposes status code, body, headers, and raw response. Host and timeline calls raise typed `AuthenticationError` for the documented 401 response and `ErrorModel` for matching problem-JSON responses, including 403; other HTTP errors use SDK errors. [3][10] | Classify from HTTP status and structured detail instead of guessing from flattened text. Retain suitably redacted diagnostic evidence; replacing the transport alone will not fix the gateway's current policy of saving only a safe failure code. [13] |
| Client control | The SDK has async methods, accepts a supplied HTTPX async client, exposes operation timeouts, and supports optional retries. In the inspected host/timeline source, retries are enabled only when a `RetryConfig` is supplied. Supported retry statuses are 429, 500, 502, 503, and 504; the retry helper handles `Retry-After`. [3][5][11] | Use the existing async execution path and observe each outbound request. Start with explicit `retry_config=None`; any future retries must fit reservations and actual request accounting. Avoid SDK debug logging as the evidence channel: its source logs request headers and bodies. [5] |
| Organization settings | The constructor accepts a PAT explicitly and an organization ID globally, with per-operation overrides. The SDK's organization environment fallback is `ORGANIZATION_ID`. Censys says an omitted organization ID falls back to Free-account permissions. [5][7][12] | Continue loading the harness's `.env`, then explicitly pass `CENSYS_API_KEY` as `personal_access_token` and `CENSYS_ORG_ID` as `organization_id`. The SDK does not automatically adopt those harness-specific variable names. |
| Additional read operations | The package includes service-observation history, DNS resolution bounds/ranges, certificate-to-host history, bulk host/certificate lookup, search, aggregation, and account credit endpoints. Search and service-history inputs expose explicit page tokens and documented page-size maxima of 100. [6][15] | Service-history ranges can answer when a port/protocol was observed without enumerating every scan event. Certificate history can support infrastructure pivots, subject to Adversary Investigation entitlement. These are candidates for later allowlisted operations. [7][15] |

### Pagination and coverage limits

The earlier live investigation returned 100 events for each of two hosts. Moving the newer bound to the returned `scanned_to` then retrieved 99 additional older events for the original host. That is evidence that temporal continuation works; fewer than 100 events did **not** imply completion. These observations are recorded in the existing [history diagnosis](../censys-history-debug.md#batch-size-and-time-based-pagination). [14]

The inspected SDK and official timeline schema expose `scanned_to` but do not document its boundary-inclusion or completion rules, and do not specify a configurable timeline batch size. The 100-event behavior therefore remains an observed service behavior, not a promise established by the SDK source. Switching SDKs cannot be claimed to lift it. A production continuation implementation must verify progress and stop conditions, retain the original requested lower bound, and avoid losing distinct events sharing a timestamp. It must also keep retrieval completion separate from historical coverage and entitlement. [3][4][8][13]

Censys documents no historical access for Free accounts, seven days for Starter, and 31 days or more for Search/Core depending on purchased access. Accepting a 90-day request and returning recent events does not establish access to all 90 days. [7][14]

### Credit and request accounting

The SDK's organization balance and usage operations can help diagnose billing context and report aggregate consumption. Usage models describe totals and daily/monthly time buckets; they do not provide a demonstrated exact credit charge attributable to each host or timeline call. Successful responses expose headers, and the official timeline schema names `X-Request-ID`, but no per-call credit field was established in the inspected contract. Keep `Page.credits=None` unless reliable call-specific evidence is available. [4][8][15][16]

Direct client access makes HTTP requests observable and removes the provider-owned MCP session/inventory layer. This is an architectural simplification; no latency improvement was measured. Disabling automatic retries and redirects, or counting every underlying dispatch when enabled, is necessary before promising a reliable one-request reservation. [3][5][13]

## Recommendation

Introduce a narrow Censys SDK provider behind the existing `Provider` interface, beginning with the current host, timeline, certificate, and search operations. Keep the shared agent-facing MCP gateway. The repository already has a direct Shodan API adapter using this seam. [13]

1. Retain raw JSON and selected response metadata through a supplied HTTPX client before typed parsing; preserve original timestamp strings in the raw artifact. Classify errors from status and structured details, with redacted retained diagnostics.
2. Keep each `fetch` to one requested page. Return `Page.continuation` for the next temporal or token-based request; let the gateway persist the current page before executing any continuation. Preserve budget reservations and actual usage accounting.
3. Explicitly map the existing `.env` values into SDK construction. Update both CLI and plugin provider construction, plus the connectivity check that currently tests the MCP tool inventory.
4. Pin the SDK version and update dependency locks and the plugin bundle together. The package is named `censys-platform`, imports as `censys_platform`, and requires Python >=3.10, HTTPX >=0.28.1, Pydantic >=2.11.2, and HTTP Core >=1.0.9. These requirements overlap the harness's Python >=3.11 and existing HTTPX/Pydantic ranges, but an actual dependency resolution remains part of implementation. The SDK README calls it beta and warns that breaking changes may occur without a major-version change. [1][2][13]

The SDK also exposes active scanning and mutation operations. The proposed adapter should publish only selected existing-observation reads, matching the current provider seam. No new operation or migration was implemented during this investigation. [2][13]

## Verification and remaining uncertainty

The root agent ran the real SDK's async timeline method against HTTPX `MockTransport`, using the inspected checkout and the existing harness environment. The synthetic successful response caused exactly one request, serialized the explicit organization ID into query parameters, preserved a nanosecond event-time string, and exposed `X-Request-ID` through response headers. Unknown future fields disappeared from `model_dump()` while the response hook retained the original JSON. A second synthetic 403 raised `ErrorModel` with HTTP status, structured detail, and body intact. Both calls used `retry_config=None`. The script and result are retained at `/tmp/censys-sdk-assessment/verify_sdk_contract.py` and `/tmp/censys-sdk-assessment/verify_sdk_contract.json`.

This verifies local SDK behavior against controlled responses. It does not verify authenticated API compatibility, production retention coverage, all timeline boundary cases, credit costs, or performance. No package was installed for the mock verification.

## Sources

SDK links below are pinned to the inspected revision. Official documentation links describe the pages fetched on the research date.

1. [SDK package metadata](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/pyproject.toml).
2. [SDK README: installation, operations, custom HTTP client, and beta maturity](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/README.md).
3. [Global Data implementation: host lookup, timeline, and search](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/global_data.py#L1427).
4. [Timeline request/response models](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/v3_globaldata_asset_host_timelineop.py) and [timeline data model](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/hosttimeline.py).
5. [SDK constructor](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/sdk.py#L55) and [HTTP dispatch implementation](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/basesdk.py#L239).
6. [Global Data operation documentation](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/globaldata/README.md) and [bulk host input model](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/assethostlistinputbody.py).
7. [Censys API getting started: permissions, organization ID, and limits](https://docs.censys.com/reference/get-started) and [Platform Historical Data](https://docs.censys.com/docs/platform-historical-data).
8. [Official host timeline reference and embedded OpenAPI](https://docs.censys.com/reference/v3-globaldata-asset-host-timeline.md).
9. [SDK base model](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/types/basemodel.py) and [timeline event serializer](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/hosttimelineevent.py).
10. [SDKBaseError](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/sdkbaseerror.py) and [ErrorModel](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/errormodel.py).
11. [SDK retry implementation](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/utils/retries.py).
12. [Explicit value / environment fallback implementation](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/utils/values.py#L60).
13. Local worktree: [provider/page contract](../../src/hunting_harness/providers/base.py), [gateway persistence and continuation](../../src/hunting_harness/gateway.py), [Shodan precedent](../../src/hunting_harness/providers/shodan.py), [CLI construction](../../src/hunting_harness/config.py), [plugin construction](../../src/hunting_harness/plugin_runtime.py), [connection checks](../../src/hunting_harness/connections.py), [project dependencies](../../pyproject.toml), and [bundle builder](../../scripts/build_plugin_bundle.py).
14. [Existing live Censys history diagnosis](../censys-history-debug.md).
15. [Certificate-host history operation](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/adversaryinvestigation/README.md#get_host_observations_with_certificate), [search paging input](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/searchqueryinputbody.py), [service-history paging input](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/v3_globaldata_service_on_hostop.py), and [account management documentation](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/accountmanagement/README.md).
16. [Credit usage report model](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/models/creditusagereport.py).
