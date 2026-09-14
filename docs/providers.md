# Provider contracts

This branch enables Shodan existing-observation `host` and `search` operations through the shared provider interface. Each fetch makes one API request, with no automatic retry, target contact, or scan fallback. Search pagination requires explicit continuation. Credentials belong to the gateway and are never query arguments.

Host banners preserve individual observation dates and raw records. Missing dates and unknown historical coverage stay explicit; `history=false` is latest-only. Empty results, failures, entitlement restrictions, and partial retrieval are distinct. Credits remain unknown.

Set `SHODAN_API_KEY` in the ignored `.env` file. `hunt connections --live` checks Shodan account metadata; cached reports are reused unless explicitly refreshed. `hunt smoke --ip 1.1.1.1` requests exactly one existing host report and retains its case. Each smoke invocation makes a new live request.

Censys, GTI, and GreyNoise adapters are introduced by the next branch in the implementation stack. The optional GTI dependency is already pinned in the shared package lock. No internal datalake connector is implemented.
