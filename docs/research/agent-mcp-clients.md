# Shared MCP tools for Codex and Claude Code

Design update: the user subsequently deferred the approval mechanism and selected no numeric limits by default, with optional user-configured limits. Approval-gateway recommendations below describe possible future controls; consult the [current design](../threat-hunting-design.md) for the initial-version scope.

Research date: 2026-09-14. Scope: official client documentation; no packages installed, configuration changed, credentials accessed, or intelligence-provider queries executed. Findings describe documented capabilities, not tested behavior of the installed client versions.

## Findings

One MCP server implementation can expose hunting tools to both clients. Local **stdio** and remote **Streamable HTTP** are the useful common transport choices. Client configuration and agent definitions remain client-specific. A local stdio process can still query remote intelligence-provider APIs; “local” describes the client/server connection, not where provider data resides. [1][3]

| Concern | Codex | Claude Code |
| --- | --- | --- |
| Transports | Local stdio; Streamable HTTP, including bearer-token and OAuth authentication. [1] | Local stdio; remote HTTP is recommended. SSE remains documented but deprecated; the page also documents WebSocket support. HTTP or stdio avoids depending on those additional transports. [3] |
| Tool restrictions | Server `enabled`, `enabled_tools` allowlist, and `disabled_tools` denylist, with denylist applied after allowlist. [1] | `permissions` rules match MCP servers or individual tools. Rules evaluate deny, then ask, then allow. Bare tool denies remove tools from the model's context. [4] |
| Tool approval | Server `default_tools_approval_mode` and per-tool `tools.<tool>.approval_mode`; documented values include `auto`, `prompt`, `writes`, and `approve`. `writes` prompts for tools not marked read-only. [1] | Permission rules and modes govern tool prompts. The server annotation `_meta["anthropic/requiresUserInteraction"]: true` requests a human approval on every call in supported versions; older versions ignore it. It is a Claude-specific mechanism, not a shared batch authorization protocol. [3][4] |
| Subagent inheritance | Subagents inherit the current sandbox policy. Custom agent configuration inherits `mcp_servers` when omitted. Parent turn runtime overrides for sandbox/approval choices are reapplied when a child starts. [2] | Subagents inherit available MCP tools unless narrowed with `tools` or `disallowedTools`. Built-in tools have additional foreground/background filters. Subagent `permissionMode` defaults to the parent's mode; some parent modes override the subagent's configured mode. [5] |
| Agent-specific configuration | Custom agent TOML configuration can override session settings, subject to the documented runtime inheritance behavior. [2] | Custom agent frontmatter can restrict tools and scope MCP servers. Plugin agents do not support the `mcpServers`, `hooks`, or `permissionMode` frontmatter fields. [5] |

For Codex CLI, approvals from inactive subagent threads can surface in the interactive approval overlay. An action requiring fresh approval fails when a non-interactive run cannot surface it. Do not assume a background worker can independently obtain consent in every client surface. [2]

Claude's documented MCP settings permission rules identify a server or tool; settings-file rules with parenthesized MCP parameters are skipped. The documentation describes a separate CLI deny-rule facility for matching a top-level MCP parameter. Neither facility specifies the hunt's aggregate batch authorization contract. [4]

## Design implications

These are proposals derived from the accepted hunt requirements, not features guaranteed by MCP or either client.

**Use a shared hunting gateway with provider adapters.** Skills and subagents use that gateway through MCP. Censys, Shodan, VirusTotal/GTI, GreyNoise, and datalake adapters sit behind its common query, evidence, and authorization interfaces. Existing provider MCPs can be wrapped behind the gateway when their tools satisfy the existing-observations-only requirement.

**Enforce exact query batches in application code.** Native prompts control tool invocation, but the documented client controls do not establish a shared ledger binding analyst consent to a provider, exact IOC values or filters, purpose, and request limit across all agents. The gateway should:

1. Store an immutable proposed batch and expose its complete reviewable contents without executing it.
2. Accept approval through a trusted human interaction or application authorization path. An agent-supplied `approved: true` field is insufficient.
3. Authorize execution only against that approved batch, with atomic request-budget consumption shared by all workers and both clients.
4. Reject additional identifiers, changed filters, and operations outside the approved batch. Define pagination, retries, and provider credit accounting so they cannot silently expand the approved allowance.
5. Record query arguments, provider, execution time, observation timestamps, returned evidence references, and approval linkage for each result.

**Keep provider credentials and bypass paths under the same controls.** A gateway is not an enforceable boundary if an agent can reach an unrestricted provider MCP, read the provider keys and call APIs through its shell, or directly contact suspected infrastructure. For enforcement, provider credentials belong behind the gateway and runtime network/tool access must restrict alternative paths. Prompts alone cannot provide this property. A provider endpoint being “read-only” does not mean its query avoids disclosing an IOC externally, so read-only auto-approval must not replace batch consent.

**Give subagents bounded analytical jobs.** A coordinator can dispatch approved searches and independent evidence analysis; a verifier can challenge relatedness, malicious-use, and attribution claims. All workers consume the same gateway authorization and budget state. A local stdio server per client must use shared authoritative state if multiple instances can act on one hunt; otherwise independent counters can exceed the approved limit. The exact agent roles remain a design choice.

## Sources

All pages below were fetched and read. The attempted official OpenAI search URL returned 404, and no web-search tool was available; the relevant official documentation pages were retrieved directly instead.

1. [OpenAI — Model Context Protocol](https://developers.openai.com/codex/mcp/), especially Supported MCP features and Other configuration options.
2. [OpenAI — Subagents](https://developers.openai.com/codex/subagents/), especially Approvals and sandbox controls and Custom agents.
3. [Claude Code — Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp), especially transport options and Require approval for a specific tool.
4. [Claude Code — Permissions](https://code.claude.com/docs/en/permissions), especially rule precedence, MCP matching, and parameter-based rules.
5. [Claude Code — Create custom subagents](https://code.claude.com/docs/en/sub-agents), especially Available tools, Scope MCP servers to a subagent, and Permission modes.
