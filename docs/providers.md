# Provider contracts

All integrations retrieve provider-held observations. The gateway owns credentials,
case/query references, retrieval time, retained raw artifacts and candidate retention.
`Provider.fetch` returns one explicitly requested result. It never follows a returned
continuation, retries a failed operation, contacts a candidate, or falls back to a
fresh scan. Underlying MCP implementations can paginate or retry internally, as
recorded below. No internal datalake is implemented; the same Provider/Observation/Page
interface is the seam once its backend, tables and schema mapping are supplied.

`Page.complete` describes retrieval completion. `Page.gap` describes a retrieval,
entitlement or response-shape problem. `metadata.coverage_gaps` also records contextual
limits, including missing dates and unknown historical coverage bounds. Those contextual
limits alone do not block completion. Neither a completed page nor a fresh retrieval
establishes current malicious use. Undated evidence stays undated.

| Provider | Enabled operations | Accounting and continuation |
| --- | --- | --- |
| Shodan API v1 | `host`, `search` | Exactly one API request per fetch, no MCP tool calls or adapter retries. Search uses documented pages of 100, retains all returned records, and returns the next page arguments when a full page has a known remaining total. Short/inconsistent pages and unknown totals are incomplete. Credits remain unknown. |
| Censys Platform MCP | `get_host`, `get_host_timeline`, `search`, `get_certificate` | One MCP tool call; upstream requests and credits unknown. Search preserves `next_page_token`. Missing pagination markers and unverified timeline completeness are explicit gaps. |
| Google GTI MCP | `get_domain_report`, `get_ip_address_report`, `get_entities_related_to_a_domain`, `get_entities_related_to_an_ip_address`, `search_iocs` | One MCP tool call; internal vt-py iterator requests and credits unknown. Reaching a positive result limit is partial because the server discards cursors/totals. A shorter successful list, including an empty list, establishes iterator exhaustion. `limit=0` exhausts the iterator; omitted limit uses the provider's default of 10, which is recorded in metadata. |
| GreyNoise MCP | `lookup-ip-context`, `gnql-query`, `gnql-timeseries` | One MCP tool call; GET retries can make up to four upstream attempts, so requests and credits remain unknown. GNQL retains scroll arguments. Recall results preserve hourly bucket dates and report unverified per-bucket completeness. |

MCP initialization and inventory messages are protocol overhead, not MCP **tool**
calls. Inventory pagination is followed before selecting the tool, with repeated
cursors rejected. Every invocation rechecks the deployed tool's exact input schema
against the packaged allowlist. Added/changed schemas fail before dispatch; discovering
extra upstream tools does not enable them. Input arguments also reject extra fields,
invalid IPs/domains/fingerprints, invalid times, and unsupported relationship names.
Optional API-request limits cannot be promised for MCP integrations; the gateway must
reject those limits when request accounting is unknown.

Shodan `host` defaults to `history=true`; each banner retains its own timestamp,
raw data and `_shodan.id` where supplied. Host `last_update` is never substituted for
a banner timestamp. `history=false` is explicitly latest-only. Available history has
unknown coverage bounds; it does not establish exhaustive campaign-window coverage.
A successful empty search differs from a missing host report, authentication failure,
access denial, rate limit and malformed response. No scan, target fetch or DNS
resolution operation is exposed.

Censys accepts the Platform hosted endpoint only through trusted gateway configuration.
The four input schemas match the inventory captured on 2026-09-14. JSON-string result
envelopes are decoded while the original response remains retained. Host services keep
individual observation dates; certificate SAN names become retained candidates but
certificate validity dates do not establish observation or deployment time. Search
field projections and absent dates remain explicit coverage notes. Adversary
Investigation scan tools, collection writes and unverified compound tools are excluded.

GTI uses Google `mcp-security` revision
`9885ec6856ec72333091cf1a3b2ac1bb26abe149` (package 0.1.3). Relationships are limited to
`resolutions`, `historical_ssl_certificates`, `historical_whois`, plus domain
`subdomains` and `siblings`. Only a resolution's own `attributes.date` dates its DNS
association; report analysis/modification dates do not date an infrastructure link.
Google excludes `last_analysis_results` from these reports and removes aggregations
and empty string values upstream; the adapter cannot recover omitted material.
Partial valid records survive malformed neighbors. Missing reports remain source gaps,
with no upload, analysis submission, collection write or fresh-fetch fallback.

GreyNoise uses revision `cc3204dcde0994daebc09c0ac1a8ceea6cc59b81` (package 0.5.0).
Scanner classifications and Business Service Intelligence remain raw contextual evidence
for the analyst, including alternative explanations. They neither remove a candidate
nor conclusively label it benign or malicious. Restricted fields are entitlement gaps;
valid returned records and continuation markers are retained. Alert actions, webhook
tests, blocklist writes and all other unreviewed tools are unavailable.

## Setup and verification

Install the project's GTI extra with `uv sync --extra gti`; configuration uses
`.venv/bin/gti_mcp`, so an unrelated global executable cannot replace the pinned
implementation. GreyNoise requires Node and the reviewed build at
`.venv/greynoise/build/index.js`. The supplied environment has both installed; offline
MCP inventory verified all five GTI and three GreyNoise selected schemas on 2026-09-14.
Do not configure these upstream servers directly in analyst clients: their complete
tool inventories include operations that this gateway excludes.

Provider variables are `SHODAN_API_KEY`, `CENSYS_API_KEY` (and optional
`CENSYS_ORG_ID`), `GTI_API_KEY` or `VT_APIKEY`, and `GREYNOISE_API_KEY`.
Only the corresponding credential is passed to each subprocess; SDK inheritance
adds basic OS variables, not the gateway's full environment. Credentials are never
query arguments. Upstream errors become fixed safe codes; upstream error strings
and credential-bearing request URLs are not retained in case errors.

Run offline provider verification with:

```bash
.venv/bin/python -m pytest tests/test_shodan.py tests/test_mcp_providers.py tests/test_provider_contracts.py
.venv/bin/python -m mypy src
```

Live checks are separate and opt-in. `hunt connections --live` checks authentication
and Censys inventory; cached results avoid repeated checks unless explicitly refreshed.
`hunt smoke --ip 1.1.1.1` makes one existing Shodan host lookup with `history=false`,
without search or retries. Run only for an analyst-selected indicator and retain the
sanitized output. The coordinating agent already ran the bounded checks in this session:
Shodan and GTI metadata authenticated (HTTP 200), Censys inventory contained 22 tools,
and GreyNoise metadata returned HTTP 401. Shodan's one host lookup returned 16
observations. These results do not establish historical/search entitlements, and
GreyNoise account access remains unvalidated. No provider calls were made by this
implementation agent.

## Primary references

- [Shodan host/history and search/page API](https://developer.shodan.io/api)
- [Censys Platform MCP](https://docs.censys.com/docs/platform-mcp-server)
- [Google GTI implementation](https://github.com/google/mcp-security/tree/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti)
- [GreyNoise implementation](https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/tree/cc3204dcde0994daebc09c0ac1a8ceea6cc59b81)

Offline fixtures validate the adapter contract, not deployed account coverage or
historical completeness. Protocol schema verification does not prove that a hosted
implementation will never change its behavior; changes require renewed provider review.
