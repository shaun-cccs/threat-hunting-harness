# Local Censys SDK references

These selected official documents and source excerpts are bundled with the hunting skill for access without another network request. They describe `censys-platform==0.16.2` at release tag `v0.16.2`, revision [`43a8a3ac1161e655eff3061ba3b7ab934c185c55`](https://github.com/censys/censys-sdk-python/tree/43a8a3ac1161e655eff3061ba3b7ab934c185c55), retrieved on 2026-09-15. The tag resolves to that exact commit; 16 relevant client, method, model, and retry files were verified byte-identical to the installed PyPI package. They are API references, not instructions to bypass the gateway. For hunting, begin with the [Censys guide](../censys.md).

Read only the branch needed for the current task:

| Branch | Saved reference |
| --- | --- |
| Host lookup, historical `at_time`, result envelope | [get_host](get-host.md) |
| Timeline argument ordering, `events`, `scanned_to` | [get_host_timeline](get-host-timeline.md) |
| Certificate fingerprint lookup, result envelope | [get_certificate](get-certificate.md) |
| Search query body, projections, pagination | [search](search.md) |
| Constructor, organization context, raw evidence, errors, retries | [Client and errors](client-and-errors.md) |

Each method file contains the selected official operation documentation, exact async signature, and relevant model contracts. Relative links within upstream excerpts point to the immutable upstream revision; the selected content itself is present locally. The SDK examples reflect upstream defaults. The gateway's schema, date ordering, retry policy, and accounting remain authoritative for hunting.

[provenance.yaml](provenance.yaml) records the repository, revision, original source line ranges, SHA-256 hashes of complete source files and original excerpts, transformations, and hashes of the saved reference artifacts. It uses JSON syntax, a YAML subset. [LICENSE.md](LICENSE.md) retains the upstream license. To refresh, pin a new SDK revision, regenerate only the selected branches and their hashes, and review changed contracts alongside the adapter and locked package version.

The [upstream SDK catalog](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/README.md#available-resources-and-operations) includes service history, DNS history, certificate-host history, and other methods. Those are future integration candidates, **not exposed operations**. Use `provider_operations` to determine the actual allowlist.
