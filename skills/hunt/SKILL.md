---
name: hunt
description: Threat hunting with retained evidence. Use when the user asks to investigate infrastructure or campaign indicators, resume a hunt, check intelligence-provider connectivity, export a hunting case, or evaluate the bundled hunting benchmarks.
---

# Hunt

Coordinate the hunt in the current Codex or Claude Code conversation. Use the plugin's hunting MCP tools for case state, provider access, and exports. The host may prefix tool names; select the installed hunting server's tools by their names below. The plugin prepares and owns its runtime automatically.

## Prepare

1. Call `hunting_setup(workspace=<absolute current user workspace>)`. The workspace is the user's investigation folder in the current session; the installed plugin folder is a separate location. Setup loads that workspace's `.env` and creates a blank template when absent. Credentials stay in the runtime: report configured provider names and gaps, never credential values.
2. Call `hunting_status` until preparation finishes or reports an actionable failure. Continue the user's request when ready. If credentials are missing, direct the user to the returned `.env` path and continue work supported by available providers. Dependency installation, the shared service, and case storage need no user commands.
3. For a configuration check, call `provider_connections(live=false)`. When the user requests live connectivity, call `provider_connections(live=true, refresh=false)` and report cached versus newly checked results. Refresh only when requested or needed to verify credentials the user changed. Connectivity checks and intelligence lookups are distinct actions.

## Evaluate

When the user asks to evaluate the bundled benchmarks, call `evaluate_benchmarks` after preparation. It runs the bundled synthetic observations through enrichment and coordinated workflows, writes a fresh evaluation report, and returns the summary and artifact paths. Report that this is an offline fixture evaluation with zero live provider or model calls; its results do not establish live detection performance or human analyst acceptance. Link the returned report. Evaluation does not require provider credentials. Keep evaluator truth and full response fixtures out of investigator prompts; the evaluation tool controls that separation. For ordinary hunts, continue below without running benchmarks.

## Investigate

For seed inspection, pivot selection, noisy matches, or a stalled discovery branch, read [infrastructure discovery](references/infrastructure-discovery.md). Use the relevant technique for the branch; each technique states what would justify continuing or reconsidering.

For Censys searches, read [the Censys guide](references/censys.md) and follow its CenQL, regex, and field-catalog references before constructing a query. The same guide covers operation choice, history/search continuation, and source gaps; load SDK method details when that branch needs them.

For Shodan searches, read [the Shodan guide](references/shodan.md) and its query-language reference before constructing a query. The same guide covers host history, search continuation, and source gaps; load SDK method details when that branch needs them.

1. Read `playbooks` and `provider_operations` before choosing provider operations. For a resumed hunt, use `case_list` and `case_read` to identify the retained case. For a new hunt, create a case with the user's hypothesis, seeds, time window, and limits. Ask only for essential scope that cannot be inferred. Use only user-specified limits; an unset limit does not impose a hidden numeric budget. Respect existing case limits when resuming.
2. Use the host's native subagents in this session for independent investigation branches and a separate evidence reviewer. In Claude Code, use general-purpose subagents with access to the hunting MCP tools. Give each agent the absolute workspace, case ID, scoped hypothesis, branch, remaining shared allowance, these workflow instructions, and the relevant discovery or provider reference; each first calls `hunting_setup` with the same workspace. Confirm each agent can access the hunting tools. Keep their work bounded and wait for their results before settling their branches. If delegation or tool access is unavailable, report that limitation and keep any coordinator self-review explicitly identified.
3. Submit existing-observation lookups through `query_submit`, then inspect `job_read` and `case_read`. Provider operations and schemas are the allowlist. Never use shell HTTP calls, direct target requests, fresh scans, or a second provider client to bypass it. All agents share the case's query budget. API requests and credits with unknown accounting remain unknown; do not reinterpret a query limit as an exact API-request limit.
4. Retain every returned candidate. Use `candidate_select` only for a dated, evidence-backed expansion; use `candidate_defer` for candidates outside the expansion subset. Record branch hypotheses, status, evidence IDs, and query IDs with `branch_record`. Keep partial results useful while preserving source gaps. Pagination requires the returned continuation arguments and the prior job ID in `continuation_of`; retries and refreshes are explicit new submissions.
5. Propose claims with `finding_propose`, citing retained evidence and alternative explanations. Keep relatedness, historical association, current malicious use, and actor attribution distinct. The separate reviewer reads retained evidence, checks dates, independence, shared hosting, reassignment, conflicts, and attribution, and records `finding_review` as `supported`, `challenged`, or `insufficient`. Reviewer agreement is not additional source evidence.

## Finish or resume

Present the reviewed finding and its uncertainty to the human analyst. Only after the user explicitly accepts, rejects, or requests more work on that finding in chat, call `analyst_decide` with the matching decision, rationale, and `confirmation` describing that explicit instruction. A reviewer assessment or request to run a hunt is not an analyst decision. Agents must never invent human acceptance.

Record every branch's terminal or waiting state and call `hunt_settle`; report the returned status, unresolved evidence gaps, and outstanding analyst decisions. Call `case_export_files` to save the report and structured results, then link the returned absolute paths. A hunt awaiting a decision or further evidence remains waiting.

Resume the existing case with `case_resume` only when new seeds or an explicit refresh warrant reopening. Read its retained work first; reopening preserves prior evidence and allowances. Use `case_export_files` directly for export-only requests.
