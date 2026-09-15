# Censys query-language and field references

Use these references to construct CenQL expressions and select queryable fields. Read only the syntax and field definitions needed for the current branch.

## Read by task

| Task | Reference |
| --- | --- |
| Compose a CenQL query: operators, tokenization, Boolean expressions, nesting, ranges, CIDRs, aliases | [CenQL syntax](censys_query_language.md) |
| Write `=~`: delimiters, escaping, supported patterns, anchors, case, and controls | [Regex syntax](censys_regex_language.md) |
| Select `host.*` fields and inspect types/nested objects | [Host fields](queryable_fields/host_censys_queryable_fields.md) |
| Select `web.*` fields | [Web fields](queryable_fields/web_censys_queryable_fields.md) |
| Select `cert.*` fields | [Certificate fields](queryable_fields/certificate_censys_queryable_fields.md) |
| Select tag identifiers or names | [Miscellaneous fields](queryable_fields/misc_censys_queryable_fields.md) |

Read the syntax guide before composing the first Censys search in a branch. Read the regex guide before introducing `=~`. Search the relevant catalog for the exact field or prefix and read the matching rows, including parent fields that identify nested arrays. The host catalog is large; loading unrelated protocol definitions obscures the fields needed for the query. These are saved schemas, so account access and provider schema changes may still limit a field.

## Apply these references in this harness

Submit through the hunting gateway described in the [Censys guide](../censys.md). The gateway's operation schema controls arguments such as `page_size` and `fields`; the CenQL grammar controls the expression inside `arguments.query`. A valid operation schema does not establish valid CenQL semantics.

Choose host, web, or certificate records according to the hypothesis. The gateway has no aggregation operation; count retained results with their retrieval limits. Historical example counts do not establish current prevalence. Per-query credit costs remain unknown, and body-size observations do not establish universal coverage limits.

Use field-qualified, quoted CIDRs in API queries. Bind related criteria to the same nested service, endpoint, or header object. Use declared field names inside nested queries; aliases are for top-level queries. String version ranges are not semantic-version comparisons. A failed positive control leaves a negative conclusion unresolved; it can reflect syntax, data changes, or coverage. Any new control is an explicit query within the case allowance.

## Encode the query once as JSON

These synthetic examples show `QuerySpec.arguments` for operation `search`. Supply the existing case, pivot, and purpose in the enclosing `query_submit` call.

```json
{
  "query": "host.services: (port=\"443\" and endpoints.http.html_title=\"Example console\")",
  "page_size": 50
}
```

A CenQL pattern and the JSON string containing it have separate escaping layers. For this raw CenQL:

```text
host.services.endpoints.http.body=~`id=\"example-console\"`
```

the arguments are:

```json
{
  "query": "host.services.endpoints.http.body=~`id=\\\"example-console\\\"`",
  "page_size": 50
}
```

A JSON serializer handles the outer layer. Do not URL-encode the query yourself; the provider client handles transport encoding. Search dates filter indexed observation fields; they do not select a historical host snapshot. For a snapshot use the gateway's `get_host` with `at_time`, and for history follow its timeline continuation contract.
