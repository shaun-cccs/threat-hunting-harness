# Shodan query-language reference

Read this before constructing the `query` string for Shodan `search`. It describes the provider's search language; [Shodan operations](shodan.md) describes the gateway, pagination, and evidence handling. Checked against the first-party sources below on **2026-09-15**. Examples are synthetic, were not submitted, and use documentation networks or example organization names. Replace example values with retained observations within the case's scope.

## Query construction

Shodan searches **service banners**. An unqualified word searches the banner's top-level `data` text, not every JSON property. For HTTP, that text commonly contains the status line and response headers; HTML, title, organization, and certificate fields need the relevant filter. One IP can produce several banner matches. [1][2]

| Intent | Syntax | Meaning and source |
| --- | --- | --- |
| Banner text | `nginx` | Search the main service response text. This does not prove Shodan identified the service as product nginx. [1][2] |
| A particular property | `country:CA` | Use `filter:value`, with no space after the colon. Country takes a two-letter code. [1] |
| A value containing spaces | `org:"Example Research Network"` | Double quotes keep the value together. Do not include shell quoting around the entire query in a tool argument. [1] |
| Combine constraints | `org:"Example Research Network" country:CA` | Space-separated constraints narrow the result together: organization AND country. [1] |
| Alternative values for one filter | `product:MySQL,PostgreSQL` | Comma-separated values are OR alternatives within the filter. `port:80,443` means either port. [1][3] |
| Exclude a filter match | `port:23 -hash:0` | Prefix a filter with `-` to exclude its matches; this example excludes empty main banners. [4] |
| Exclude a text term | `HTTP -ftpd` | Datapedia uses this construction to narrow HTTP banner searches. [5] |
| A numeric bound | `port:<=1024` | Numeric comparison belongs inside the filter value. The official example uses `<=`, not CenQL's `field <= value` form. [3] |
| Exclude a numeric bound | `ssh -port:<=1024` | Official example for SSH text on ports above 1024. [3] |
| An observation-date lower bound | `after:01/09/2026` | The official example `after:01/03/2015` is explicitly described as after **March 1**, establishing **day/month/year** order. Date filtering does not extend retention. Exact midnight/inclusivity behavior is not documented in that example. [17] |

**Numeric comma expressions have conflicting documentation.** The Book describes `ssh port:>1024,<6000` as an exclusive interval, while the official search-engine article says comma values are OR-ed and demonstrates `port:<1024,>6000` as the union outside an interval. Do not rely on a comma to express an intersection. Prefer a single documented bound and check both desired limits against retained banner ports; a tighter compound query needs a known-positive check before using its absence as evidence. The article also lists `=<` in prose but uses `<=` in its actual example; use the example spelling. [1][3]

Do not transplant CenQL's `AND`, `OR`, `NOT`, `=`, `=~`, `IN`, `{...}` set literals, nested `field:(...)` expressions, or parenthesized expressions into Shodan. The inspected Shodan sources establish the forms above, not a general Boolean-expression or regex grammar. They also do not establish arbitrary wildcard, phrase-exactness, embedded-quote escaping, or case-sensitivity rules for every filter. Quotes demonstrably group a value containing spaces; verify any stronger matching assumption against a retained known positive. [1][2]

## Verified filters for common pivots

This is a curated reference, not an exhaustive catalog. The [official filter list](https://www.shodan.io/search/filters) is authoritative for available filter names. Entries below cite first-party sources that demonstrate or enumerate the filter. A field in returned JSON is **not sufficient evidence** that the same name is searchable. [2][6]

| Pivot | Query or filter | Use and interpretation |
| --- | --- | --- |
| One IP | Gateway `host` with `{"ip":"192.0.2.10","history":true}` | Prefer the supported IP lookup for complete returned host banners; this is an operation argument, not search syntax. [2] |
| Network | `net:192.0.2.0/24` | Constrain to an observed network. The official SDK builds `net:` queries and comma-separated network alternatives; official search documentation also confirms IPv6 support. [3][7] |
| Hostname | `hostname:example.org` | The official blog demonstrates the singular `hostname` filter. Returned `hostnames` can derive from reverse DNS or certificate information; this search does not perform forward DNS resolution. Matching a domain token is not proof of an exact FQDN or ownership. [14][18] |
| Organization | `org:"Example Research Network"` | IP-space organization metadata, not proof of the service operator's identity. [1] |
| Country / city | `country:CA city:Ottawa` | Geographic metadata. Both filter names and combining them are documented. [1] |
| ASN | `asn` filter | The API filter-list example explicitly enumerates `asn`. Returned ASN values use an `AS` prefix, for example `AS15169`; confirm the catalog's value contract when constructing a new ASN pivot. [2][8] |
| Port alternatives | `port:80,443` | Ports of the matching banner, not a join across all services of the same IP. [1][2] |
| Identified product | `product:nginx` | Uses Shodan's product classification. A port alone does not identify the product, and a product may run on nonstandard ports. [2][9] |
| HTTP title | `http.title:"Example Portal"` | The official SDK README demonstrates this filter with a quoted multiword value. [10] |
| HTML text | `html:examplemarker` | The official article's linked query uses `html:arris`, establishing the older `html` filter spelling. Use an observed distinctive token and verify retained HTML. The accessible sources do not establish whether `http.html` is an equivalent current alias or guarantee substring/regex semantics. [19] |
| HTTP header text | `"Server: nginx"` | Search main banner text containing the retained header. The basic HTTP banner example stores headers in `data`. Do not invent `http.headers.server` from a JSON path. [1] |
| Favicon | `http.favicon.hash:-123456789` | Use the observed **signed MurmurHash3** value of the base64 favicon data. Preserve the sign; do not substitute a SHA-256, MD5, raw-image hash, or HTML hash. [11] |
| Identical retained HTML | `http.html_hash:-123456789` | Numeric hash of `http.html`, distinct from the main banner hash. Use the retained HTML hash. [4] |
| Main banner hash | `hash:-123456789` | Numeric hash of the main `data` field. HTTP date headers can make it change between otherwise similar responses. [4] |
| TLS presence / broad TLS text | `has_ssl:true` or `ssl:example.org` | Officially documented SSL filters; the broad `ssl` filter searches SSL-related information. A name match is not an exact certificate identity. [12] |
| TLS version | `ssl.version:tlsv1.3` | Documented search example; note that returned JSON uses `ssl.versions`, whereas the filter is singular. [5] |
| TLS ALPN | `ssl.alpn:h2` | Documented example for HTTP/2 support in TLS observations. [5] |
| Certificate fingerprint | `ssl.cert.fingerprint:0123456789abcdef0123456789abcdef01234567` | The official SSL-analysis article links a search using this filter with a 40-hex digest, consistent with the SHA-1 field in the documented certificate schema. Preserve that algorithm and digest; do not put a Censys SHA-256 value into this example or invent a `.sha256` search suffix. [5][15] |
| Certificate attributes | `ssl.cert.serial`, `ssl.cert.expired`, `ssl.cert.pubkey.bits`, `ssl.cert.pubkey.type`, `ssl.cert.alg`, `ssl.cert.extension` | First-party SSL documentation explicitly enumerates these filters. Preserve the observed value and verify its current value format rather than converting large serials through floating point. [13] |

For **product-version filters, alternate HTML-filter spellings, SHA-256 certificate searches, or additional date operators**, consult the current filter catalog before adding a spelling or value grammar that is not verified above. Some verified examples above are older official documentation; their publication is evidence of syntax, not a live account/query validation. In particular:

- `version` and `http.html` are documented response properties, but that fact alone does not establish their search-filter names or matching semantics. A scoped product query can retrieve banners whose retained version or HTML values are then checked locally. [8][11]
- TLS response data has distinct `ssl.cert.fingerprint.sha1` and `ssl.cert.fingerprint.sha256` fields. The article provides both fingerprint **facet** examples and a linked **search** with a 40-hex digest. That verifies the search spelling and demonstrated digest shape; it does not establish SHA-256 query support. Keep the original Censys SHA-256 and Shodan SHA-1 evidence separately, and correlate actual retained certificates rather than treating the digests as interchangeable. [5][15]
- The `after` example establishes `DD/MM/YYYY`, not CenQL timestamp operators or ISO date literals. Exact `before` grammar and date boundary behavior remain unverified from accessible current sources; check retained UTC banner timestamps against both desired bounds instead of assuming inclusivity. [6][16][17]

## Defensive investigation examples

These are query strings, not shell commands. The example network and values have no expected live matches. Build the actual query from the case's retained evidence. [1][2][4][7][10][11]

```text
# Inventory an identified web-server product inside an observed network.
net:192.0.2.0/24 product:nginx

# Either of two web ports, constrained to an observed organization.
org:"Example Research Network" port:80,443

# Investigate a retained page title within the case's network scope.
net:192.0.2.0/24 http.title:"Example Portal"

# Constrain a retained hostname pivot to observations after 1 September 2026.
hostname:example.org after:01/09/2026

# Corroborate an observed favicon with a second retained characteristic.
http.favicon.hash:-123456789 http.title:"Example Portal"

# Find another banner with the same retained HTML fingerprint in scope.
net:192.0.2.0/24 http.html_hash:-123456789

# Look for nonempty banners on a particular port in scope.
net:192.0.2.0/24 port:23 -hash:0
```

The `#` lines explain the examples; omit them from submitted query strings. Shared favicon, title, product, certificate, or HTML observations can establish useful pivots but do not by themselves establish common ownership or malicious activity. Inspect the retained banners and dates before expanding the case.

## Tool arguments and escaping

Read `provider_operations` for provider `shodan`; choose operation `search`. Place the following object in `query_submit`'s query specification's `arguments`, alongside the required case and pivot metadata in the live tool schema:

```json
{
  "query": "net:192.0.2.0/24 http.title:\"Example Portal\"",
  "page": 1
}
```

After JSON decoding, Shodan receives exactly:

```text
net:192.0.2.0/24 http.title:"Example Portal"
```

The backslashes here escape JSON quotes; they are not additional Shodan operators. Let the structured tool/JSON serializer encode the string. Do not URL-encode it, double-escape it, wrap it in shell quotes, or add credentials. If the observed value itself contains a literal quote or backslash, JSON encoding alone does not establish how the Shodan parser treats that character; choose a verified alternate retained pivot or check the provider's documented parsing behavior first. The SDK passes the query as the search request's `query` parameter. [2]

Keep search continuation explicit: copy the gateway's returned continuation into the next submission and link the previous job with `continuation_of`. A new filter or changed value is a new query, not pagination. See [Shodan operations](shodan.md).

## Time windows and absence

Shodan's current Book and Help Center say ordinary search and latest host lookup show the **most recent banner for each IP and port from the past 30 days**. Historical IP lookup provides **up to 90 days and at most 1,000 banners**; frequently rescanned IPs can reach that cap. These documented limits do not establish account entitlement or completeness of a particular response. A search date condition, extra search pages, or successful connectivity check cannot extend this retention. [16]

Use individual banner `timestamp` values as the retained observation dates; neither retrieval time nor certificate validity dates substitute for them. A search returning zero can reflect an incorrect filter, tokenization, missing indexing, mismatched observation periods, or unavailable coverage. Simplify the query and check a retained known positive before concluding absence. Distinguish returned banners, unique retained IPs, and provider `total`; retain source gaps. [8][16]

## Sources

1. [Shodan Book: Search Query Syntax](https://book.shodan.io/getting-started/query-syntax/) and [Help Center: Search Query Fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals).
2. [Shodan API: search](https://developer.shodan.io/api#shodan-host-search), [host](https://developer.shodan.io/api#shodan-host-details), and [filter enumeration](https://developer.shodan.io/api#shodan-host-search-filters).
3. [Shodan: Search Engine Improvements](https://blog.shodan.io/search-engine-improvements/) — numeric comparisons, exclusion, comma OR, IPv6 networks; published 2020-09-06.
4. [Shodan Help: Pivoting with Property Hashes](https://help.shodan.io/mastery/property-hashes).
5. [Shodan Datapedia: SSL/TLS](https://datapedia.shodan.io/property/ssl.html) — use its explicit **Search Queries** separately from its response-property schema.
6. [Shodan: Understanding the Search Query Syntax](https://blog.shodan.io/understanding-the-shodan-search-query-syntax/) — establishes the public filter catalog and API enumeration as the available-filter authorities.
7. [Official Python SDK: network-query construction](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/cli/alert.py#L39).
8. [Shodan Datapedia: banner schema](https://datapedia.shodan.io/).
9. [Shodan: Don't Search by Port](https://blog.shodan.io/dont-search-by-port/).
10. [Official Python SDK README: HTTP-title search example](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/README.rst#L47).
11. [Shodan: Deep Dive — http.favicon](https://blog.shodan.io/deep-dive-http-favicon/) and [Datapedia: HTTP](https://datapedia.shodan.io/property/http.html).
12. [Shodan: Duplicate SSL Serial Numbers](https://blog.shodan.io/ssl-serial-number-weirdness/) — explicitly describes `ssl` and `has_ssl` filters; published 2015-10-10.
13. [Shodan: Keeping Up with SSL](https://blog.shodan.io/ssl-update/) — explicitly enumerates certificate filter names; published 2015-02-16. Check the live catalog when relying on this older enumeration.
14. [Shodan: Website Changelog](https://blog.shodan.io/changelog-www-shodan-io/) — hostname display may draw from reverse DNS or certificate information; DNSDB is separate.
15. [Shodan: Understanding Security by Country — SSL](https://blog.shodan.io/understanding-security-by-country-ssl/) and [Help Center version](https://help.shodan.io/data-analysis/ssl-analysis-by-country) — fingerprint facets and a link on “Ecommerce Corporation” to the search query `ssl.cert.fingerprint:e1369c0316542950dbf9bd0c96a9feae43ee41d8`. Preserve the link target when extracting this article; the query does not appear in the visible body text.
16. [Shodan Book: Data Timeframes](https://book.shodan.io/behind-the-scenes/data-timeframes/) and [Help Center: Data Timeframes](https://help.shodan.io/mastery/data_timeline).
17. [Shodan: Choose Your Adventure](https://blog.shodan.io/choose-your-adventure/) — the `after:01/03/2015` command and its explicit “after March 1st, 2015” explanation; published 2015-03-24.
18. [Shodan: The Country of Vietnam Resolves to Localhost](https://blog.shodan.io/the-country-of-vietnam-resolves-to-localhost/) — explicitly links `hostname:localhost`; published 2015-02-17.
19. [Shodan: Modems. Modems Everywhere. Especially Chile.](https://blog.shodan.io/modems-modems-everywhere-especially-chile/) — “looking into which of their models was most popular” links to `html:arris`; published 2015-03-10. Preserve this link target in article extracts.

The upstream `search_filters()` and `search_tokens()` APIs are outside this harness's host/search allowlist; do not call them through a second client during a hunt. Use the public documentation when checking a new filter.
