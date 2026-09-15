# Local Shodan SDK references

Selected official documentation and source excerpts for `shodan==1.31.0`, revision [`87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8`](https://github.com/achillean/shodan-python/tree/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8), retrieved on 2026-09-15. The client and exception source match the published package. No matching release tag was found; links use the inspected immutable commit. For hunting, begin with the [Shodan guide](../shodan.md).

Read the relevant branch:

| Branch | Saved reference |
| --- | --- |
| Host history, default options, banner retention | [Host](host.md) |
| Search fields, full banners, pages of 100 | [Search](search.md) |
| Authentication, session controls, errors, account metadata | [Client and errors](client-and-errors.md) |

[provenance.yaml](provenance.yaml) records source ranges, full-file and excerpt hashes, saved-artifact hashes, and the verified distribution digest. [LICENSE.md](LICENSE.md) preserves the upstream license. Refresh references together with the adapter and dependency lock, verifying source equality against the new installed release. The SDK's broader methods do not extend the gateway allowlist; consult `provider_operations` for enabled operations.
