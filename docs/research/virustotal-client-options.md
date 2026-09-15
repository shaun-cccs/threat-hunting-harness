# VirusTotal: GTI MCP, Python SDK, or direct HTTP

Research date: 2026-09-15. Inspected Google's GTI MCP at commit
`9885ec6856ec72333091cf1a3b2ac1bb26abe149` and the official `vt-py` SDK at
`09a98c8f36d7b1cf04236b9f0fa4853c5b3325c1`. This is a design recommendation;
no integration was changed and no authenticated intelligence queries were made.

## Recommendation

For this Python harness's existing VirusTotal operations, prefer a small direct
HTTP adapter using the existing HTTPX dependency, behind the existing
agent-facing hunting MCP gateway. The main benefit is consistency with the
harness's explicit page, evidence, error, and request-accounting contract.
**Using `vt-py` at its low-level API is also a sound choice:** it can preserve
the same response information and fetch explicit pages. Direct HTTP has a
modest integration advantage here, not unique access to the data. [1][2][3]

| Option | Best fit | Relevant tradeoff |
| --- | --- | --- |
| Google's GTI MCP | Connecting an agent directly to a ready-made collection of threat intelligence tools. | Its current wrappers consume SDK iterators and return projected results; callers do not receive the original page envelopes and continuation metadata. [4][5] |
| Official `vt-py` SDK | General Python VirusTotal applications, especially those benefiting from object helpers, iterators, downloads, or submission workflows. | Both convenience and low-level interfaces exist. For this harness, use explicit page requests and retain raw responses instead of depending on automatic iteration. [1][2][6] |
| Direct HTTP | A narrow provider adapter needing full control of existing async HTTP infrastructure and retained responses. | The adapter must implement endpoint construction, authentication, status/error classification, timeouts, and continuation handling. This is engineering work, not better API entitlement. [2][3] |

## Findings

**These choices occupy different layers.** Google's GTI MCP uses `vt-py`, which
calls the VirusTotal REST API. The inspected GTI package depends on `vt-py` and
constructs `vt.Client` with `VT_APIKEY`. The SDK describes itself as the official
client for REST API v3. Choosing MCP changes the tool interface and packaging;
it does not establish additional service entitlement. Broader GTI product/API
coverage was not exhaustively compared. [1][4][7]

**The SDK does not require losing raw evidence or automatic pagination.**
`get_async()` returns `ClientResponse`, forwarding the underlying response's
status and headers and exposing `read_async()` and `json_async()`. It performs
no response parsing or error checking itself. `get_json_async()` preserves the
full parsed JSON envelope while checking errors; `get_data_async()` extracts
only `data`, and `get_object_async()` converts that data to a `vt.Object`.
Choose the interface deliberately. [2]

**SDK iteration is optional.** Its iterator fetches additional batches and
supports a result limit, batch size, metadata, and resumable cursor. The SDK
cursor is distinct from the API's cursor. Google's `consume_vt_iterator()`
consumes this iterator and returns a list without preserving its cursor or
metadata. Consequently, one MCP call can encompass several upstream API
requests. An SDK or HTTP adapter can instead fetch one API page and return the
API continuation through `Page.continuation`. [3][5][6]

**The current MCP output is an analyst-oriented projection.** Network reports
explicitly exclude `last_analysis_results`; shared helpers delete
`aggregations`; the sanitization helper drops empty strings and `None` values.
That may be useful for agent context, but retaining this output is not the same
as retaining the original API response. Capture full evidence at the provider
boundary and summarize it separately when completeness matters. [5][8]

**Retries and quotas still need an explicit policy.** The inspected SDK read
path makes an aiohttp call without an application-level retry/backoff loop;
its high-level `APIError` exposes `code` and `message`. Low-level responses
remain available when the harness needs HTTP status, headers, and error body.
The public `get_async()` signature does not expose per-call redirect controls
or a supplied HTTP session, although the constructor supports a custom
connector, timeout, proxy, and headers. A strict request-count contract should
also account for transport behavior. No numerical rate limit or account
entitlement was verified in this research. [2][9]

**Maintenance evidence does not establish a support guarantee.** At retrieval,
PyPI reported `vt-py` 0.22.0, uploaded 2025-10-28, requiring Python >=3.7 and
depending on `aiohttp` and `aiofiles`. Its GitHub repository was not archived;
the inspected head was also dated 2025-10-28. The inspected GTI MCP package
declares version 0.1.3, Python >=3.11, and an unpinned `vt-py` dependency. These
are source/release observations, not a claim of abandonment or measured
reliability. [4][10][11]

## Practical choice for the harness

Keep the shared hunting MCP interface for agents. Either implement the five
current GTI operations through a narrow HTTPX adapter, or use `vt-py`
`get_async()` within that same provider seam if SDK consistency is preferred.
Preserve the raw page and selected response metadata before normalization;
return explicit continuations; keep retries subject to the gateway's existing
request policy. Both approaches can meet the evidence contract. [2][3]

Official VirusTotal API-reference and GTI-reference pages returned HTTP 403
during retrieval. Account quotas, premium search access, supplementary GTI
services, and production latency therefore remain unverified; no live provider
comparison or synthetic execution was performed for this note.

## Sources

1. [Official SDK README](https://github.com/VirusTotal/vt-py/blob/09a98c8f36d7b1cf04236b9f0fa4853c5b3325c1/README.md).
2. [SDK client and raw response implementation](https://github.com/VirusTotal/vt-py/blob/09a98c8f36d7b1cf04236b9f0fa4853c5b3325c1/vt/client.py).
3. Local [provider contract](../providers.md), [page interface](../../src/hunting_harness/providers/base.py), [gateway](../../src/hunting_harness/gateway.py), and [dependencies](../../pyproject.toml).
4. [GTI MCP package metadata](https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/pyproject.toml).
5. [GTI MCP iterator, projection, and sanitization helpers](https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/utils.py).
6. [SDK iterator implementation](https://github.com/VirusTotal/vt-py/blob/09a98c8f36d7b1cf04236b9f0fa4853c5b3325c1/vt/iterator.py).
7. [GTI MCP client construction](https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/server.py) and [tool overview](https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/README.md).
8. [GTI MCP network report implementation](https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/tools/netloc.py).
9. [SDK APIError implementation](https://github.com/VirusTotal/vt-py/blob/09a98c8f36d7b1cf04236b9f0fa4853c5b3325c1/vt/error.py).
10. [PyPI package metadata](https://pypi.org/pypi/vt-py/json).
11. [SDK repository metadata](https://api.github.com/repos/VirusTotal/vt-py) and [inspected SDK commit](https://github.com/VirusTotal/vt-py/commit/09a98c8f36d7b1cf04236b9f0fa4853c5b3325c1).
