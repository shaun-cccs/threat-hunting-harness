# Censys queries and historical evidence

Use this guide when selecting Censys operations, following history/search pages, or interpreting Censys source gaps. The gateway uses the Python SDK internally. Hunting agents use `provider_operations`, `query_submit`, `job_read`, and `case_read`; direct SDK calls bypass case evidence and accounting and are not part of the hunting workflow.

## Choose and submit

Read the live `provider_operations` schema for `censys` before constructing arguments. It is authoritative for enabled operations and input validation.

| Question | Gateway operation | Arguments |
| --- | --- | --- |
| What has Censys observed on this host? | `get_host` | `host_id`; optional `at_time` for a historical snapshot |
| What changed during a host's time window? | `get_host_timeline` | `host_id`, chronological `start_time` (oldest), `end_time` (newest) |
| What names and properties does this certificate contain? | `get_certificate` | `certificate_id`, a SHA-256 fingerprint |
| Which existing records match these conditions? | `search` | `query`; optional `fields`, `page_size` (default 50, maximum 100), `page_token` |

Submit one operation through `query_submit`, using the existing case and its allowed scope. Inspect the finished job and retained case before deciding whether another request is needed. Each fetch makes one Censys API request and no provider MCP tool calls; credit cost remains unknown. The shared agent-facing gateway still uses MCP.

## Follow returned continuation

1. Inspect the retained query's status, `continuation`, and coverage gaps. A successful response can cover only part of the requested interval.
2. When another page is needed within the case's scope and allowance, copy the returned `continuation` object exactly as the next query's arguments. Set `continuation_of` to the prior job ID and preserve its provider, operation, and pivot context.
3. Repeat only after the new page is retained. End when the gateway reports retrieval complete, no usable continuation remains, or the case's scope or allowance ends. Preserve partial findings and the reason retrieval stopped.

For timelines, the continuation keeps the original oldest bound and moves the newest bound to the returned `scanned_to`. The adapter handles the SDK's reversed time-parameter naming. Use returned arguments rather than calculating a timestamp offset or reversing them manually. The SDK itself returns one page.

Boundary overlap may repeat an observation because SDK datetimes have microsecond precision while provider timestamps can be finer. The gateway retains the raw precision and identifies duplicate record content. Equal timestamps alone do not make two events duplicates.

The number of events does not establish completion: an observed 99-event page still had older history to fetch. Completion depends on progress toward the requested lower bound and the gateway's validation of that progress. Repeated or malformed bounds are source gaps. An accepted 90-day request that returns recent events does not establish 90-day coverage or entitlement.

For search, the continuation carries `next_page_token` forward as `page_token`. A missing or unusable paging marker is not proof that all matches were retrieved.

## Interpret evidence and gaps

Use the record's observation dates. A requested snapshot time is not a service scan time, and certificate validity dates are not deployment dates. Search field projections may omit dates or other useful fields; retain that limitation in the claim. Raw provider JSON is retained separately from typed SDK parsing, including fields the SDK does not recognize.

For access-denied results, report the source gap and check configured organization context through the setup/connectivity tools. The runtime loads `CENSYS_API_KEY` and `CENSYS_ORG_ID` from the workspace configuration; credentials never belong in query arguments. Censys applies the organization's entitlements, or Free-account permissions when organization context is absent. A working connection alone does not establish historical access. Authentication, access denial, throttling, unavailable records, and malformed responses remain distinct from an empty successful result.

Retries are explicit new gateway submissions. Follow the case's scope and remaining allowance. Preserve previously retained evidence when a page fails.

## Consult SDK details only for the relevant branch

The locally saved official documentation below is for checking an operation's upstream contract or maintaining the adapter. It does not enable additional gateway operations. Read only the matching method reference:

- Host snapshots or service fields: [get_host](censys-sdk/get-host.md).
- Timeline bounds, response shape, or `scanned_to`: [get_host_timeline](censys-sdk/get-host-timeline.md).
- Certificate lookup and its response envelope: [get_certificate](censys-sdk/get-certificate.md).
- Search fields, result envelopes, or page tokens: [search](censys-sdk/search.md).
- SDK configuration, error detail, nullable models, or raw-body capture: [client and errors](censys-sdk/client-and-errors.md).
- Updating references or checking source integrity: [snapshot index and provenance](censys-sdk/README.md).

For adapter development, map the four gateway operations to `sdk.global_data.get_host_async`, `get_host_timeline_async`, `get_certificate_async`, and `search_async`. Host `at_time` becomes a timezone-aware `datetime` when present and `None` when omitted. Timeline SDK `start_time` receives the gateway's newest `end_time`; SDK `end_time` receives its oldest `start_time`. Search arguments go inside `search_query_input_body`; inspect the live gateway schema before passing optional/null values. Returned SDK data is nested under `response.result.result`, which may be absent. Keep raw JSON as the evidence source and maintain the gateway's one-page contract.
