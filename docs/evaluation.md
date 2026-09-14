# Campaign evaluation

`hunt evaluate` compares seed enrichment with a coordinated evidence workflow using three cited historical indicator cohorts. The bundled source responses are explicitly **synthetic Shodan fixtures**, not recorded Shodan results. This is a reproducible pipeline evaluation. It does not measure live discovery performance, native model quality, current malicious use or attribution accuracy.

```bash
.venv/bin/hunt evaluate --benchmarks benchmarks --output /tmp/hunt-evaluation
.venv/bin/hunt evaluate --benchmarks benchmarks --case lunarweb-2020-2023 \
  --output /tmp/hunt-evaluation-lunar
```

Use a new output directory so previous runs remain intact. The Python API is `await evaluate(benchmark_root, output_dir, case_ids=None)`. `load_campaigns(benchmark_root)` returns only public seed manifests; `score_run(case, truth)` scores a retained case export independently. No model, provider credentials or network access is needed for replay. The Shodan adapter's external HTTP boundary is replaced by `httpx.MockTransport`; MCP sessions use authenticated in-process HTTP.

## Corpus and truth separation

See [the corpus manifest](../benchmarks/README.md) for reports and selected time windows. Each case separates:

- `campaigns/<id>.json`: hypothesis, selected seed subset, investigation dates, source citations and execution conditions.
- `observations/<id>.json`: responses available only through the synthetic provider during replay. They contain discoverable infrastructure, distinctive synthetic fingerprints, weak relationships and missing observation dates.
- `truth/<id>.json`: evaluator-only withheld indicators and optional real analyst assessments.

The runner passes only the manifest and provider interface to investigation. It reads withheld truth **after both workflows finish**. The evaluator's output truth snapshot is outside each investigation directory. Native clients must receive only an isolated seed profile and gateway access; mounting the entire benchmark repository into an agent runtime would defeat this logical separation. File separation is not an OS confidentiality boundary.

The corpus uses report-defined historical infrastructure associations. Some source indicator dates are unknown, and the chosen evaluation window is a documented slice rather than an asserted campaign lifetime. Fingerprint relationships, synthetic observation timestamps and mock failure behavior are constructed solely to exercise the pipeline. They are not facts established by the cited reports. Two documented withheld indicators are deliberately absent from available fixtures, so the metric does not assume complete source coverage.

## Comparable policies

Both policies receive the same seed manifests, provider response fixtures, campaign window and unset application limits. Input and response SHA-256 hashes are retained. There is no random selection or hidden query allowance; `random_seed: 0` records deterministic conditions.

The baseline retrieves recorded Shodan host history for each seed once, then retains the resulting observations and source gaps. It does not search for additional infrastructure.

The coordinated policy retrieves the same seed history, identifies dated synthetic certificate fingerprints, searches that exact fingerprint, retains all returned candidates, and selects candidates only when their dated fingerprint matches. It performs a host-history lookup on each selected candidate and records a scoped branch. A separate SDK reviewer session evaluates the evidence and records a review. Additional candidates with generic or undated relationships are retained and deferred. Partial history does not stop independent supported work; unresolved coverage or rate-limit gaps leave the hunt paused.

The coordinator and reviewer are deterministic scripts using the same public MCP interfaces as clients. Role separation exercises protocol and durable state, not independent model reasoning. Provider-owned source coverage beyond Shodan, native-client execution and live campaigns are separate validation layers.

## Metrics

Recovery counts unique, non-seed infrastructure appearing in a supported reviewed finding with a traceable path to a seed. Each path checks retained query IDs, evidence IDs and candidate membership. Duplicate findings and rediscovered seeds receive no additional credit. `withheld_recall` divides recovery by the withheld set size; an empty withheld set has an unknown/null rate.

`additional_candidates` contains credited discoveries outside the documented withheld set. Such indicators are **not** treated as false positives merely because the report omitted them. Analyst acceptance is measured only if evaluator truth provides actual `accept`, `reject`, or `needs_work` assessments. The bundled corpus has none, so assessed/accepted counts and acceptance rate remain null. Scripted reviewer support is not analyst acceptance.

Each mode records wall-clock elapsed seconds for the **local replay**, gateway MCP tool calls, gateway query calls, adapter MCP calls, upstream API-request accounting, returned records and provider credits. Gateway MCP calls and provider MCP calls are different measures. Unknown credits, monetary costs and model-token usage remain null; no invented dollar conversion is applied. Run-to-run elapsed time, UUIDs and retrieval timestamps vary even though inputs, queries and discovery counts are reproducible.

## Temporal leakage

Every observation retains its source observation time separately from retrieval time. Fixture metadata supplies `available_at` as the cited public report's publication date, explicitly a proxy rather than a claim about historical provider availability. Missing availability remains unknown. In this corpus the public reports appear after the selected window, so the runner labels those observations `post_window` and reports retrospective recovery separately.

`in_window_available_withheld_recovered` additionally requires a complete path whose observations were dated inside the campaign window and known by its end. An early final observation does not qualify if the intermediate pivot became available later. This is a conservative eligibility check, not proof of real contemporaneous discoverability, because source responses themselves are synthetic.

## Artifacts and interpretation

The output keeps `evaluation.json` and a Markdown comparison, plus separate baseline/coordinated directories for each case containing input conditions, metrics, full case JSON, Markdown report, candidate CSV, role transcript, SQLite state and raw query JSONL artifacts. Reviewed findings, alternative explanations, source gaps, branch state and observation/retrieval dates are retained. An evaluator-only truth snapshot and source-fixture snapshot permit inspection against recorded input hashes.

The regression corpus exercises a baseline recovery of zero and one traceable withheld fixture indicator per coordinated case: 1/2 for Turla Armenia, 1/2 for LunarWeb and 1/1 for the Lazarus report cohort. Baseline query usage is one per case; coordinated usage is three per case. All have explicit history-coverage gaps; the Lazarus fixture additionally rate-limits candidate host history. These counts describe constructed examples, not empirical acceptance targets. Elapsed-time results must come from the retained run, not a fixed expected value.

No numeric performance acceptance thresholds have been established. `acceptance_thresholds.values` is null. Setting useful thresholds requires real available-observation snapshots, independently sourced temporal coverage, more campaigns, actual analyst assessments and measured baseline costs/time. The current fixtures establish correctness checks—traceable credit, no seed/double credit, retained broad sets, visible gaps and unknown accounting—without claiming those empirical inputs exist.
