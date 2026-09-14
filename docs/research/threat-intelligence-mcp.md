# Threat-intelligence MCP reuse assessment

Design update: the user subsequently deferred the approval mechanism and selected no numeric limits by default, with optional user-configured limits. Approval-gateway recommendations below describe possible future controls; consult the [current design](../threat-hunting-design.md) for the initial-version scope.

Researched 2026-09-14 from provider documentation and public source repositories. This is a design recommendation, not an integration or deployment decision. No server was installed or executed, no credentials were read, and no intelligence queries were submitted. Source revisions below are snapshots; hosted services can change independently.

## Recommendation

Reuse existing MCP implementations where their operations fit the hunt, with a shared enforcement and evidence layer. Prefer Censys's hosted MCP services, Google's GTI MCP, and GreyNoise's own MCP over replacement implementations. Evaluate the independent Shodan server as a starting point, with narrow changes for historical evidence, pagination, and raw results. None of the reviewed full server configurations should be treated as an existing-observations-only interface without selecting and checking its operations. [C1][C2][G1][G3][S1][S2][N1]

| Source | Existing implementation and coverage | Transport and access | Reuse assessment |
| --- | --- | --- | --- |
| Censys | Provider-hosted **Platform MCP** offers asset lookups, search, history, certificate pivots and query/schema helpers. **Adversary Investigation MCP** adds historical certificate-to-host investigation and other module APIs. | Remote HTTP MCP. OAuth recommended, or PAT bearer header plus organization ID. Platform API access required; Adversary Investigation additionally requires that module. Calls consume Censys credits. | Wrap/select existing services. Adversary Investigation explicitly includes fresh scans; Platform also documents collection creation workflows. Exact deployed tool names and internal call counts were not obtained. [C1][C2] |
| VirusTotal / GTI | Google's `google/mcp-security`, package `gti-mcp`: IOC search, domain/IP/URL/file reports, relationships, threat collections, campaign/actor/report searches and existing behavior reports. | Shipped entry point uses **stdio**; Python >=3.11, `VT_APIKEY`, `vt-py`. The generic repository ADC instructions are not the GTI server's auth contract. Account-specific endpoint entitlements remain unverified. | Reuse its retrieval/search subset. Source also registers file uploads/analysis and collection writes. [G1][G2][G3][G4] |
| Shodan | Independent `w0h1v/mcp-shodan`, npm `@burtthecoder/mcp-shodan`: host information, host search, DNS resolution and CVE/CPE lookup. No provider-maintained Shodan MCP was identified in this bounded search; that is not proof none exists. | **stdio** in source; Node.js >=20 according to README; `SHODAN_API_KEY`. Search may consume query credits. | Adapt or use a small custom API adapter for evidence-complete host/history/search operations. Current MCP output and pagination are insufficiently faithful for the proposed historical hunt. [S1][S2][S3][S4] |
| GreyNoise | Provider-owned `GreyNoise-Intelligence/greynoise-mcp-server`: IP context, GNQL, Recall time series, tags/CVEs, sensor sessions, BSI and callback/C2 observations. Also contains operational tools. | **stdio** with `GREYNOISE_API_KEY`, or **Streamable HTTP** accepting the GreyNoise API key as a per-request bearer token. Plan entitlements control capabilities. | Reuse a selected retrieval/search subset. Exclude operational writes and webhook tests; decide separately whether existing PCAP/payload exports are needed. [N1][N2] |

## Operations compatible with the collection boundary

These are source-backed candidates for an allowlist, not permission to execute them. External-query approval still applies.

- **Censys:** recorded host/web-property/certificate retrieval, recorded history, corpus search, historical certificate-host observations, and schema/query validation. The public docs name helpers such as `validate_censys_query`, `search_field_help`, `get_data_definition`, and `get_query_examples`, but do not enumerate every underlying API tool. Establish exact names and schemas before enabling access. Do not enable broad compound investigation tools merely from their descriptions: their request expansion and side effects are undocumented here. [C1][C2]
- **Google GTI:** `get_domain_report`, `get_ip_address_report`, `get_url_report`, `get_file_report`, `get_file_behavior_report`, `get_file_behavior_summary`, the corresponding `get_entities_related_to_*` tools, `search_iocs`, `get_collection_report`, and the campaign/actor/malware/report search tools retrieve existing records in the inspected implementation. Relationship operations have `limit` and, in current source, `descriptors_only` parameters that the overview documentation does not fully describe. Inspect schemas from the pinned implementation rather than copying that overview verbatim. [G3][G4][G5][G6][G7]
- **Shodan:** `ip_lookup` and `shodan_search` call the host-information and host-search API endpoints. The registered tools contain no explicit scan-submission operation. Hold `dns_lookup` and `reverse_dns_lookup` out until provider behavior is confirmed: they call resolution endpoints, and the official reference does not establish that these use only previously stored observations. A GET method or `readOnlyHint` does not settle that collection question. [S1][S2][S3][S4]
- **GreyNoise:** candidate categories include `lookup-ip-context`, `quick-check-ip`, `multi-ip-check`, `gnql-query`, `gnql-metadata-query`, `gnql-stats`, `gnql-timeseries`, `gnql-timeseries-stats`, session metadata/search, BSI lookups, and callback/C2 lookups. `gnql-query` explicitly retrieves a page of stored data through `v3/gnql`, with `size` and `scroll`. Existing PCAP exports retrieve provider-held captures and can write local files; that is a separate artifact-handling choice, not fresh network collection. [N1][N3]

## Important incompatibilities and evidence gaps

**Censys Adversary Investigation includes active collection.** Its official examples explicitly instruct an agent to initiate a scan of a currently unobserved host or web-property service. Exclude scan operations even though the service is marketed for hunting. Censys Platform examples also create collections and alerts; these writes are outside the proposed retrieval workflow. Hosted implementation source, a complete deployed tool inventory, and per-tool upstream request accounting were not available in the inspected documentation. [C1][C2]

**Google's GTI server is not entirely read-only.** Current source exposes `analyse_file`, which opens a local file, uploads it using `scan_file_async`, and waits for analysis. It also exposes `create_collection`, `update_collection_attributes`, and `update_iocs_in_collection`. These are absent from the shorter overview's tool list. Google's `get_url_report` itself uses stored-object retrieval and returns an error on a retrieval failure; no fresh URL scan fallback appears in that path. [G3][G4][G6][G7]

**The independent VirusTotal alternative has a misleadingly broad retrieval operation.** `w0h1v/mcp-virustotal` supports stdio and HTTP streaming, reports, relationships and corpus search, but `get_url_report` submits `POST /urls` on a cached-report 404, polls analysis up to 12 times, then fetches the report. That operation violates existing-observations-only use. Prefer the Google implementation for the initial selection; if this alternative is reused, disable or change that path. [V1][V2]

**The Shodan candidate loses evidence and does not expose documented pagination/history controls.** `ip_lookup` supplies no `history` parameter, retains host-level `last_update`, and projects services by finding the first observation for each port; it omits per-banner timestamps and raw records. `shodan_search` preserves a match timestamp but projects selected fields, omitting raw banner/certificate data. It sends `max_results` as `limit`, while Shodan's official search reference documents `page` in batches of 100, not `limit`; the tool also does not slice results locally. Consequently, its advertised result bound is not established by source plus documentation. Expose documented history/page controls, preserve raw observations and timestamps, and verify limits before making it the evidence adapter. [S2][S3][S4]

**GreyNoise contains operational actions.** Its tools include create/update/delete blocklists, create/update/enable/disable/delete alerts, and `test-alert-webhook`, which sends a test payload. These should be excluded from this hunt interface. All tools are registered by the server; the README's annotations and client-confirmation descriptions are not a substitute for enforcement. No on-demand target scan was identified in the reviewed capability list, but this was not an exhaustive code audit. [N1][N2]

## Accounting and provenance

Count **MCP tool calls**, **provider API requests**, **returned records**, and **provider credits** separately. A gateway can cap calls it dispatches, but that does not establish an upstream request or cost cap. Google's relationship/search helpers consume `vt-py` iterators internally; one MCP call can require multiple pages. GreyNoise's inspected `gnql-query` exposes a page and continuation token. Shodan query credits depend on filters and pagination. Censys documents credit consumption without a per-tool request expansion contract. Enforce API-level budgets only where request activity is observable and controllable; otherwise describe the limit accurately as an MCP-call or result bound. [G7][N3][S4][C1][C2]

Preserve query parameters, source/version, retrieval time, source observation timestamps, continuation/completeness information and raw evidence before producing analyst summaries. This is a design recommendation motivated by the Shodan projections and Google's sanitization/iterator helpers, not a capability promised by every MCP server. Provider history coverage, retention, account quotas, contractual reuse rights and exact entitlements still require confirmation. [S2][S3][G7]

## License and maintenance evidence

| Implementation | Evidence observed on 2026-09-14 |
| --- | --- |
| Censys hosted MCP | First-party docs updated 2026-09-01. No open-source server license or source revision was found in these pages; hosted-service terms and account access apply. [C1][C2] |
| Google GTI | Apache-2.0 repository; inspected commit `9885ec6856ec72333091cf1a3b2ac1bb26abe149`; GTI package declares version `0.1.3`, Python >=3.11 and test dependencies. Repository has GTI tests. Repository metadata showed a 2026-09-11 push, which does not establish the latest GTI-specific release or a support SLA. [G2][M1][M2] |
| Independent Shodan | MIT; inspected commit `6a96d575dfe9338600a88ad44abf1fe03cab5078`; package version `1.0.32`. Repository metadata showed a 2026-09-08 push. The package scripts expose build/publish tasks, not an automated test task. This is maintenance activity, not reliability validation. [S5][M3] |
| GreyNoise | Inspected commit `cc3204dcde0994daebc09c0ac1a8ceea6cc59b81`; package version `0.5.0`, `license: MIT`, Jest/typecheck scripts and documented CI. No standalone LICENSE file appeared in the inspected tree and GitHub license metadata was null; confirm licensing text before redistribution. Metadata showed a 2026-07-22 push. [N4][M4][M5] |
| Independent VirusTotal alternative | MIT; inspected commit `75d27df75726cf84d8d3a6621854a96b06b67d83`. README documents unit tests and live smoke tests; none were run. Metadata showed a 2026-09-08 push. [V1][M6] |

The datalake interface and actual Codex/Claude client versions remain unspecified. This review establishes available MCP integrations and their limitations; it does not establish client interoperability in this environment or the appropriate datalake adapter.

## Primary sources

[C1]: https://docs.censys.com/docs/platform-mcp-server
[C2]: https://docs.censys.com/docs/platform-threat-hunting-mcp-server
[G1]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/docs/servers/gti_mcp.md
[G2]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/pyproject.toml
[G3]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/tools/files.py
[G4]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/tools/urls.py
[G5]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/tools/netloc.py
[G6]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/tools/collections.py
[G7]: https://github.com/google/mcp-security/blob/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/gti_mcp/utils.py
[S1]: https://github.com/w0h1v/mcp-shodan/blob/6a96d575dfe9338600a88ad44abf1fe03cab5078/src/index.ts
[S2]: https://github.com/w0h1v/mcp-shodan/blob/6a96d575dfe9338600a88ad44abf1fe03cab5078/src/tools/ip-lookup.ts
[S3]: https://github.com/w0h1v/mcp-shodan/blob/6a96d575dfe9338600a88ad44abf1fe03cab5078/src/tools/shodan-search.ts
[S4]: https://developer.shodan.io/api
[S5]: https://github.com/w0h1v/mcp-shodan/blob/6a96d575dfe9338600a88ad44abf1fe03cab5078/package.json
[N1]: https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/blob/cc3204dcde0994daebc09c0ac1a8ceea6cc59b81/README.md
[N2]: https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/blob/cc3204dcde0994daebc09c0ac1a8ceea6cc59b81/src/index.ts
[N3]: https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/blob/cc3204dcde0994daebc09c0ac1a8ceea6cc59b81/src/tools/gnql-query.ts
[N4]: https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/blob/cc3204dcde0994daebc09c0ac1a8ceea6cc59b81/package.json
[V1]: https://github.com/w0h1v/mcp-virustotal/blob/75d27df75726cf84d8d3a6621854a96b06b67d83/README.md
[V2]: https://github.com/w0h1v/mcp-virustotal/blob/75d27df75726cf84d8d3a6621854a96b06b67d83/src/handlers/url.ts
[M1]: https://api.github.com/repos/google/mcp-security
[M2]: https://github.com/google/mcp-security/tree/9885ec6856ec72333091cf1a3b2ac1bb26abe149/server/gti/tests
[M3]: https://api.github.com/repos/w0h1v/mcp-shodan
[M4]: https://api.github.com/repos/GreyNoise-Intelligence/greynoise-mcp-server
[M5]: https://api.github.com/repos/GreyNoise-Intelligence/greynoise-mcp-server/git/trees/cc3204dcde0994daebc09c0ac1a8ceea6cc59b81?recursive=1
[M6]: https://api.github.com/repos/w0h1v/mcp-virustotal
