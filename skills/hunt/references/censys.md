# Censys queries and historical evidence

Use this guide when constructing Censys queries, diagnosing unexpected empty results, selecting operations, following history/search pages, or interpreting source gaps. For choosing and evaluating a pivot, read [infrastructure discovery](infrastructure-discovery.md). The gateway uses the Python SDK internally. Hunting agents use `provider_operations`, `query_submit`, `job_read`, and `case_read`; direct SDK calls bypass case evidence and accounting and are not part of the hunting workflow.

## Choose and submit

Read the live `provider_operations` schema for `censys` before constructing arguments. It is authoritative for enabled operations and input validation.

| Question | Gateway operation | Arguments |
| --- | --- | --- |
| What has Censys observed on this host? | `get_host` | `host_id`; optional `at_time` for a historical snapshot |
| What changed during a host's time window? | `get_host_timeline` | `host_id`, chronological `start_time` (oldest), `end_time` (newest) |
| What names and properties does this certificate contain? | `get_certificate` | `certificate_id`, a SHA-256 fingerprint |
| Which existing records match these conditions? | `search` | `query`; optional `fields`, `page_size` (default 50, maximum 100), `page_token` |

Submit one operation through `query_submit`, using the existing case and its allowed scope. Inspect the finished job and retained case before deciding whether another request is needed. Each fetch makes one Censys API request and no provider MCP tool calls; credit cost remains unknown. The shared agent-facing gateway still uses MCP.

## Construct a search and check unexpected zeros

Before composing the first Censys search in a branch, read the [CenQL syntax](censys-query/censys_query_language.md). For `=~`, also read the [regex reference](censys-query/censys_regex_language.md). The [query documentation index](censys-query/README.md) explains how to choose references and encode queries as JSON.

Verify each field against the relevant saved catalog: [host](censys-query/queryable_fields/host_censys_queryable_fields.md), [web](censys-query/queryable_fields/web_censys_queryable_fields.md), [certificate](censys-query/queryable_fields/certificate_censys_queryable_fields.md), or [tags](censys-query/queryable_fields/misc_censys_queryable_fields.md). Search the exact field or prefix and inspect its type and nested parents; read only the rows needed for this query. A field returned in JSON is not necessarily searchable. The operation schema validates arguments; it does not validate the meaning of the CenQL string. Treat the following as known query failure modes and use controls when results are surprising.

- Bind related conditions to the same object. A top-level `AND` can match a port on one service and content on another. Nest vendor/product/version together, and header key/value together. Use full field paths rather than aliases inside nested expressions.
- `:` is tokenized and case-insensitive; `=` is exact and case-sensitive. Regex with `=~` is case-sensitive. Prefer exact observed values or meaningful pattern structure over common words.
- Use supported regex syntax. Inline flags such as `(?i)` and unescaped quotes have produced misleading empty results. Express case alternatives with character classes and escape literal markup characters. Remember that a query string encoded in JSON has an additional escaping layer.
- Quote CIDRs and specify the field, for example `host.ip="192.0.2.0/24"`. A fieldless quoted CIDR searches text. An exact stored BGP-prefix value answers a different question from IP membership in a subnet.
- Preserve the favicon hash algorithm. `host.services.endpoints.http.favicons.hash_shodan` corresponds to Shodan's `http.favicon.hash`; quote its signed decimal value in CenQL, including the minus sign. A SHA-256 hash is a different value and cannot be substituted into the mmh3 field.
- Read TLS subject, issuer and `fingerprint_sha256` on every host you intend to dispose of. Default certificate fields are among the cheapest tool-identity signals available, and a generated certificate carrying a tool's default organization with the host's own address as its common name is host-unique in fingerprint but operator-agnostic in pattern: it identifies the software, and links nothing to any other deployment using the same defaults.
- Check software, hardware and OS tags and decoded `host.services.protocol` fields. Inspect available `evidence[].data_path` on tags to understand the originating observation. A default protocol configuration identifies technology until other evidence gives it campaign significance.
- Version text comparisons can be lexicographic: `7.4.10` can sort before `7.4.2`. Enumerate observed versions when needed instead of assuming semantic-version range ordering. A version constraint also excludes unknown versions.

The following is a synthetic shape, not a campaign signature. Substitute evidence-backed values and confirmed field names:

```text
host.services: (port=443 and endpoints.http.html_title="Example console"
  and endpoints.http.headers: (key="X-Example-Node" and value="sample"))
```

This binds the title and header to one service and the header key/value to one header entry. If the hypothesis requires the same HTTP endpoint, bind the conditions at `host.services.endpoints` as well; one service can have several endpoints.

For an unexpected zero, check a retained known-positive example, simplify the pattern, verify the field and object scope, and compare observation periods. A failing control means the negative conclusion is unresolved; query semantics, changed data or coverage may explain it. For `C AND NOT B` returning zero, check `C` itself before deciding whether it found nothing or was already covered by `B`. Retry only with an explicit reason and within the case's scope and allowance.

A field can be searchable even when its returned value is truncated, redacted or omitted by a projection. Retain the provider match as such; do not claim to have inspected bytes that were not returned. Body-size limits vary by response surface, so use the actual response metadata rather than assuming a fixed cutoff. Likewise, no software-tag match does not establish that the service is absent.

Search can return host, web and certificate records. State the matched entity and use recorded relationships to pivot between them. The current gateway has no aggregation operation. Count retained results with their retrieval limits; do not present a sample as a global distribution. When interpreting supplied aggregations, distinguish host counts from service/field occurrences, query-matching objects from all objects on a host, and overlapping buckets from a unique union.

## Follow returned continuation

1. Inspect the retained query's status, `continuation`, and coverage gaps. A successful response can cover only part of the requested interval.
2. When another page is needed within the case's scope and allowance, copy the returned `continuation` object exactly as the next query's arguments. Set `continuation_of` to the prior job ID and preserve its provider, operation, and pivot context.
3. Repeat only after the new page is retained. End when the gateway reports retrieval complete, no usable continuation remains, or the case's scope or allowance ends. Preserve partial findings and the reason retrieval stopped.

For timelines, the continuation keeps the original oldest bound and moves the newest bound to the returned `scanned_to`. The adapter handles the SDK's reversed time-parameter naming. Use returned arguments rather than calculating a timestamp offset or reversing them manually. The SDK itself returns one page.

Boundary overlap may repeat an observation because SDK datetimes have microsecond precision while provider timestamps can be finer. The gateway retains the raw precision and identifies duplicate record content. Equal timestamps alone do not make two events duplicates.

The number of events does not establish completion: an observed 99-event page still had older history to fetch. Completion depends on progress toward the requested lower bound and the gateway's validation of that progress. Repeated or malformed bounds are source gaps. An accepted 90-day request that returns recent events does not establish 90-day coverage or entitlement.

For search, the continuation carries `next_page_token` forward as `page_token`. A missing or unusable paging marker is not proof that all matches were retrieved.

## Read a projected result as a view, not a record

A search that sets `fields` returns only the fields you named. Everything else is absent because you did not ask for it, not because the host lacks it — and nothing downstream can tell those apart. Certificates, decoded protocol configuration, tags and DNS records all disappear silently from a projection.

So a projected row is enough to triage and to page, and never enough to dispose of a host. Before selecting a candidate, deferring one into a named class, or recording any negative about it, retrieve it unprojected with `get_host`. The same applies to searching retained artefacts locally: grepping a projected payload for a certificate subject returns a guaranteed absence that carries no information. Record the projection as a limitation on any claim that rests on one, and treat a host you only ever saw projected as uninspected.

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
