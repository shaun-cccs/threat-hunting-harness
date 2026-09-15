# Standalone hunting clients (developer compatibility)

Ordinary Codex and Claude Code use now goes through the [self-contained plugin](plugin.md): install it, fill the workspace `.env`, and use `$hunt` in Codex or `/threat-hunting-harness:hunt` in Claude Code. This page documents the retained standalone gateway and generated client profiles for development and earlier validation. Its setup commands, separate analyst CLI, and HTTP tool restrictions apply to that legacy interface. The plugin starts its own shared service, uses native agents, writes exports, and records explicitly requested analyst decisions in chat through its additional plugin tools.

These standalone profiles retain their earlier verification limits; current plugin checks are recorded in [verification](verification.md). Both profiles connect coordinator, investigator, and evidence-reviewer roles to the same authenticated loopback hunting MCP gateway. The gateway owns the case ID, query deduplication, evidence, branches, source gaps, and optional limits. A separate analyst CLI records human decisions; `analyst_decide` is absent from the standalone gateway's MCP tool inventory.

## Prepare and inspect

Use a dedicated directory outside this checkout, benchmark data, provider configuration, and case artifacts. The gateway process holds provider credentials. Generated files contain only a reference to `HUNT_GATEWAY_TOKEN`, never the token value. Setup writes project configuration in the supplied directory; it does not update personal client configuration.

```bash
.venv/bin/hunt client prepare codex --workdir /tmp/hunting-codex
.venv/bin/hunt client preflight codex --workdir /tmp/hunting-codex
.venv/bin/hunt client prepare claude --workdir /tmp/hunting-claude
.venv/bin/hunt client preflight claude --workdir /tmp/hunting-claude
```

`--endpoint` defaults to `http://127.0.0.1:8765/mcp`. Profiles accept HTTP loopback endpoints and reject embedded credentials. `launch` uses the same public configuration and sanitized environment APIs as `preflight`; run the gateway first. Gateway authorization is separate from the client's own model account/login. Existing sessions must be restarted to pick up changed profiles.

## Native roles and shared workflow

Codex receives `.codex/config.toml`, explicit native role declarations, and standalone `.codex/agents/*.toml` files. Every role file includes the full hunting HTTP transport and environment token reference because the installed runtime deserializes role files independently. CLI overrides also set the endpoint and role paths, disable known personal MCP servers, and request read-only execution and disabled web search. Code Mode host remains enabled: Codex 0.154.0 uses it to route MCP tools. Disabling it blocked gateway access in the native fixture attempt.

Automatic gateway calls use the documented per-tool `mcp_servers.hunting.tools.<tool>.approval_mode = "approve"` setting. Each role preapproves only its named hunting tools, while `default_tools_approval_mode = "prompt"` keeps other tools gated. The main profile and launch overrides carry the same scoped rules. This permits the user-authorized case reads, mutations and existing-observation lookups without a global approval bypass. `approval_policy = "never"` alone does not preapprove MCP tools: the second native attempt exposed that distinction. The strict tool allowlist and omission of `analyst_decide` remain in place.

Claude receives `.mcp.json`, dedicated settings, `.claude/agents/*.md`, and explicit `--agents` definitions. The launcher uses `--restricted`, `--strict-mcp-config`, explicit settings and agents, an empty setting-source list, and only the Agent built-in plus named hunting MCP tools. Explicit role definitions avoid relying on project discovery while restricted mode is enabled. The investigator and reviewer have different tool lists; the reviewer can read retained evidence and submit reviews, but has no query/expansion tools in its definition.

Generated `HUNTING.md` and the user-invoked `hunt` skill share the repository's playbooks and workflow. The coordinator delegates a case ID, scoped hypothesis and branch; investigators retain all returned candidates before narrowing and cite evidence; a separate reviewer challenges dates, independence, shared infrastructure, reassignment and attribution. Reviewer agreement is not source evidence. Present both supported and challenged findings to the analyst.

Use `case_read` for grounded status, including its `status_summary`. Continue from partial results where available evidence supports a branch, while preserving source gaps. Pagination copies the returned continuation arguments and sets `QuerySpec.continuation_of` to the preceding job ID. Record branch `evidence_ids` and `query_ids` to preserve scope. Reopening uses the existing case ID; `case_resume` requires new seeds or explicit refresh, and does not silently repeat prior queries or reset allowances.

## What is verified

| Layer | Evidence and limits |
| --- | --- |
| Installed Codex | Version `codex-cli 0.154.0`. Read-only `mcp list`, `mcp get hunting --json`, and feature inspection validate the one configured hunting endpoint, bearer environment reference and tool allowlist. `unified_exec` remains reported enabled despite a false override; preflight reports it as an unsupported control. |
| Installed Claude | Version `2.1.269 (Claude Code)`. Required flags are advertised and profile JSON parses. This does not reveal the effective runtime tool inventory. |
| SDK fixture replay | Real MCP Python SDK sessions over in-process authenticated Streamable HTTP, separate coordinator/investigator/reviewer sessions, a mocked Shodan HTTP boundary, a separate scripted analyst decision, gateway restart, reopened case and settlement. This does **not** execute the installed Codex/Claude client or a model. |
| Native Codex | Codex 0.154.0 completed one synthetic query, retained two candidates, proposed a finding, requested separate evidence review, and settled the hunt. The reviewer marked campaign association insufficient. Native testing found and fixed role transport, tool host, and scoped approval configuration defects. See [verification.md](verification.md) for the result and retained artifacts. This verifies workflow execution, while OS egress confinement remains unverified. |
| Native Claude | The earlier standalone workflow attempt returned `Not logged in`; zero model tokens and zero provider requests were reported. That attempt did not verify the standalone model workflow. Current plugin installation and MCP checks are documented in [verification.md](verification.md). |
| Live providers | Separate sanitized metadata/connectivity and provider smoke artifacts are described in [verification.md](verification.md). They are not client role or model workflow validation. |

The SDK replay is reproducible with a new output directory:

```bash
.venv/bin/hunt client fixture codex --workdir /tmp/hunting-codex-replay
.venv/bin/hunt client fixture claude --workdir /tmp/hunting-claude-replay
```

The API is `await hunting_harness.replay.fixture_workflow(client, output_dir)`. Replay orchestration is separate from client configuration. It retains `result.json`, `transcript.json`, `case.json`, `report.md`, `candidates.csv`, and the case store/raw query artifacts. Generated profile files reside in a separate `profile/` child; no case or truth data is copied there. The workflow retains a supported and a challenged finding, scripted acceptance/rejection, one deduplicated provider query, configured limits, and the original case identity across restart. Scripted decisions are fixture events, not evidence of human acceptance.

## Enforcement limitations

`effective_runtime_enforcement` remains `not_verified`. Configuration parsing, prompts, allowlists and tool annotations do not establish an operating-system security boundary. The shared token does not authenticate a reviewer's distinct identity; role tool lists are client controls. Known provider credential environment variables are removed, but that does not prove absence of credentials in local files, aliases, helpers, unknown variable names or previously running clients.

Code Mode host is required for this Codex runtime's MCP access. Its exposed execution and network capabilities, and the observed ignored `unified_exec` override, require runtime assessment before claiming direct-target or alternate-provider access is prevented. Managed settings, future tools, plugins and client updates can alter behavior. The HTTP gateway's restricted provider-operation surface is independently enforced; neither profile claims it confines every possible client action. A production deployment needing that guarantee must validate effective tools and apply independently tested process/container/network restrictions around the client while permitting its model service and the loopback gateway.

## Configuration sources

Consulted on 2026-09-14:

- [Official OpenAI Codex configuration reference](https://developers.openai.com/codex/config-reference/) for MCP URL, bearer environment, tool allowlists, sandbox and role declarations.
- [Official OpenAI MCP configuration](https://developers.openai.com/codex/mcp/) for per-server and per-tool approval modes.
- [Official OpenAI multi-agent documentation](https://developers.openai.com/codex/multi-agent/) for native role files and delegation.
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents) and [settings](https://code.claude.com/docs/en/settings), together with the installed `claude --help`, for explicit agents, settings and restricted/strict-MCP flags.

Installed-client behavior takes precedence over assumptions from a static example. `preflight` reports unavailable clients, rejected configuration, unknown/ignored controls and timeout failures without echoing subprocess stderr or credential-bearing configuration.
