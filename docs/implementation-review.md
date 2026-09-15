# Implementation review

Two independent Codex agents reviewed commit `0c329fc9f4fb198cfb82f0e4c8adfc3f24b77f28` against `6d4cada27de2035ad85b11870cb93d5f1c9d4282` in separate Herdr tabs. The standards axis used the domain vocabulary, accepted design, ADRs, and code-smell baseline. The spec axis used GitHub issues #1–#10, #12, and #13. The user deferred Claude issue #11. Line references below describe the reviewed commit.

## Standards

The reviewer reported two documented-standard violations:

1. **P2 — Paginated recovery leaves a stale source gap** (`gateway.py:431`). After a failed search, a successful refresh returning multiple pages resolves its pagination gap but leaves the original failure unresolved. The hunt remains paused after successful recovery, contradicting the accepted stopping rule in `docs/threat-hunting-design.md:25`.
2. **P2 — Completed evidence scopes do not combine** (`lifecycle.py:116`). Separate completed branches covering evidence `{a}` and `{b}` do not satisfy the completion check for a selected candidate with evidence `{a,b}`. This contradicts the stopping rule and grounded status requirement in `docs/threat-hunting-design.md:60`.

The reviewer also reported one judgment call:

3. **Possible Divergent Change** (`clients.py:483`). Client configuration shared a module with synthetic provider responses, replay sessions, scripted analyst decisions, restart orchestration, and artifact generation. Evaluation imported that replay machinery and a private export writer. Client compatibility changes and benchmark workflow changes should have separate homes.

Resolution: recovery follows a successful continuation chain without clearing independent retrieval defects; completed branch coverage is combined while pending work and newly observed evidence remain outstanding. SDK replay moved into `hunting_harness.replay`, and shared report writing moved into `hunting_harness.exports`.

## Spec

The reviewer reported three defects, each reproduced offline:

1. **P2 — Paginated recovery leaves the original failure unresolved** (`gateway.py:443`). Issue #6 requires: “A hunt completes when no further candidates meet expansion criteria and no planned investigation remains waiting on unavailable sources.” Successful continuation did not recover the earlier failed query.
2. **P2 — Completed scoped branches cannot collectively satisfy completion** (`lifecycle.py:120`). The same issue #6 criterion was violated by requiring one branch to cover every evidence ID instead of combining completed scopes.
3. **P2 — Pre-dispatch rejection consumes nonexistent provider calls** (`gateway.py:321`). Issue #3 requires: “MCP calls, observable upstream API requests, returned records, and provider credits are accounted for separately; unavailable accounting is reported as unknown.” Schema verification could reject a call before dispatch while the job still recorded one tool call and exhausted its allowance.

Resolution: the lifecycle fixes address the first two findings. Provider failures now carry observed accounting. A failure before tool dispatch records zero calls; a failure after dispatch retains one MCP call with unknown upstream accounting when results are unavailable. The gateway records this failure accounting and preserves unused call allowances.

No concrete unrequested scope was found. Unknown provider entitlements/costs, empirical performance thresholds, and OS-level client confinement remain explicitly documented validation limitations. The initial GreyNoise authentication limitation was resolved on 2026-09-15 by correcting its account-check endpoint; see [verification](verification.md). Native Codex workflow execution subsequently passed its bounded synthetic check.

Follow-up review reproduced successful pagination recovery, preservation of restricted-record gaps, union of completed evidence scopes, and correct failure accounting before and after dispatch. The final offline suite passes all 78 tests; typechecking, Ruff, lock verification, and package builds also pass.

Review totals: Standards — 2 defects and 1 judgment call addressed; Spec — 3 defects addressed. The worst initial finding in each axis was P2.
