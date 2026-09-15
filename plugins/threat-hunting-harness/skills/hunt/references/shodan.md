# Shodan queries and historical evidence

Use this guide for Shodan operation choice, query construction, continuation, and source gaps. For evaluating a pivot, read [infrastructure discovery](infrastructure-discovery.md). The gateway uses the official Python SDK internally. Hunting agents use `provider_operations`, `query_submit`, `job_read`, and `case_read` to retain evidence and shared accounting.

## Choose and submit

Read the live `provider_operations` schema for `shodan` before constructing arguments.

| Question | Gateway operation | Arguments |
| --- | --- | --- |
| What service banners has Shodan retained for this IP? | `host` | `ip`; optional `history` (default true) |
| Which stored service observations match this query? | `search` | `query`; optional `page` (default 1) |

Submit one operation within the existing case's scope and allowance, then inspect its retained result. Each fetch dispatches one API request, with zero provider MCP tool calls. The shared agent-facing gateway still uses MCP. Full banners are requested explicitly; search's upstream `minify=True` default would truncate larger fields. SDK scans, DNS resolution, streaming, mutations, count, and cursor iteration are outside the gateway allowlist. The separate connectivity check uses SDK `info()` once.

## Construct and assess a search

Before constructing the first Shodan search in a branch, read the [query-language reference](shodan-query-language.md). It covers filter syntax, quoted values, conjunctions, alternatives, exclusions, comparisons, common pivots, JSON encoding, and documented limits. Shodan and CenQL use different grammars; build the provider's query from its own examples.

Use observed values and documented search filters. Returned JSON field names do not by themselves establish valid query syntax. The gateway validates operation arguments, not query meaning. Consult the [official search contract](https://developer.shodan.io/api#shodan-host-search) for upstream details.

Keep hash types and signs intact. For example, a retained Shodan favicon mmh3 hash belongs in `http.favicon.hash`; a SHA-256 value cannot substitute for it. Censys exposes the corresponding value as `host.services.endpoints.http.favicons.hash_shodan`. Treat a shared fingerprint as a pivot hypothesis until dated retained evidence establishes a more specific relationship.

For an unexpected zero, check a retained known-positive observation, simplify the query, verify its filter syntax, and compare observation periods before treating absence as meaningful. Submit any revised query explicitly within the case's scope and allowance. Search matches are service banners: several can belong to one IP. Report the distinction between returned banners, retained unique IPs, and the provider's total.

## Follow returned continuation

Search uses pages of up to 100. The adapter returns continuation only for a full page with a known remaining total. Unknown totals, short pages before the total is reached, malformed records, and inconsistent counts remain retrieval gaps.

When another page is needed, copy the returned `continuation` object exactly into the next query's arguments and set `continuation_of` to the preceding job ID. Preserve the provider, operation, and pivot context. Inspect the new retained result before continuing. Stop when retrieval is complete, no usable continuation remains, or the case's scope or allowance ends. Keep partial findings and the stopping reason.

The SDK's `search_cursor()` automatically retrieves pages and retries failures. Use the gateway's explicit continuation instead. Host history has no exposed page or time-window parameters; search pagination does not extend host-history coverage.

## Interpret history, errors, and credits

`host` defaults to `history=true`, requesting available historical banners. `history=false` is latest-only. Shodan documents ordinary search/latest lookup as the most recent banner per IP and port from the past 30 days, and historical IP lookup as up to 90 days with at most 1,000 banners. These limits do not establish account entitlement or completeness of an individual response. See [time windows and absence](shodan-query-language.md#time-windows-and-absence) before interpreting missing historical matches.

Use each banner's `timestamp`, the UTC collection time, as its observation date. A host's `last_update`, retrieval time, and certificate validity dates do not replace a missing banner date. Raw evidence retains the original timestamp string, multiline content, protocol fields, unknown fields, and `_shodan.id` where present. Search results are stored observations, not proof of current malicious use. See the [official banner schema](https://datapedia.shodan.io/) for field definitions.

A successful empty search differs from missing host coverage, authentication failure, access denial, throttling, or malformed responses. Preserve the source gap. Retries and refreshes are new gateway submissions; they never trigger fresh scans or direct target requests. The runtime loads `SHODAN_API_KEY` from workspace configuration; credentials are not query arguments.

Per-query charged credits remain unknown. Shodan documents query-credit charges for filtered searches or page two and later, with one credit providing 100 results. These expected billing rules and account balances do not establish an exact charge for a retained query. See [credit types](https://help.shodan.io/the-basics/credit-types-explained). Keep request counts separate from credit accounting.

## Consult the relevant SDK reference

The following official source and documentation excerpts are bundled locally for upstream-contract checks and adapter maintenance:

- Host history, banner options, or defaults: [host](shodan-sdk/host.md).
- Search arguments, full banners, result envelopes, or pages: [search](shodan-sdk/search.md).
- Authentication, timeout/redirect controls, errors, or account checks: [client and errors](shodan-sdk/client-and-errors.md).
- Source integrity or reference updates: [snapshot index and provenance](shodan-sdk/README.md).

These references describe upstream methods. The live gateway schema remains authoritative for hunting operations and arguments.
