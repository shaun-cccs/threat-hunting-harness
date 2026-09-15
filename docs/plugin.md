# Codex plugin

The plugin's entry point is `$hunt` in your current Codex conversation. Once installed, `.env` in the folder opened in Codex is the only configuration file you fill in. Your existing Codex account runs the coordinator, investigators, and reviewer.

## Installation and first use

Run `python3 scripts/install_plugin.py` from the downloaded repository once. It copies an allowlisted plugin bundle to `~/plugins/threat-hunting-harness`, registers it in `~/.agents/plugins/marketplace.json`, and runs Codex's plugin installer. Existing marketplace entries and their ordering are preserved. Workspace `.env`, case files, virtual environments, and run artifacts are excluded from the bundle. The documented synthetic benchmark corpus is included for offline evaluation.

Open a new Codex conversation in the investigation folder so Codex loads the installed skill and MCP tools. Fill that folder's `.env` with available provider keys. `$hunt` creates a blank template if one is absent and reports missing providers without exposing key values. You can investigate with a subset of providers.

The installer uses Codex's configuration API to preapprove only this plugin's named hunting tools, including recording your explicit analyst decisions. Unlisted tools keep the prompt default; existing explicit tool policies survive reinstall. It does not change global approval, sandbox, network, or other plugin settings. Host restrictions and explicit user overrides still apply. The analyst confirmation is a retained instruction from chat, not independent authentication of a human identity.

On first use, the plugin prepares its pinned Python and provider dependencies automatically. This needs internet access for dependency downloads. The preparation status appears through the hunting tools; initialization does not run an intelligence lookup. Subsequent sessions reuse the prepared runtime. The small bootstrap launcher needs Python 3.9+ on Linux (glibc) or macOS, on x86_64 or ARM64.

## Workspace and service lifecycle

Codex launches the plugin's stdio MCP entry point itself. The skill passes the absolute investigation workspace to `hunting_setup`; this avoids confusing the installed plugin directory with the folder containing your `.env`. The plugin then prepares or joins the workspace's shared service. You do not start a server, choose a port, copy a bearer token, modify Codex configuration, or launch another terminal.

The service owns query deduplication, optional shared limits, retained candidates, evidence, branches, and analyst decisions. Native Codex subagents use the same workspace and case IDs, so a second investigator cannot create a separate budget accidentally. The service runs outside the conversation's terminal UI and handles its own lifecycle.

By default, runtime caches live under `~/.cache/threat-hunting-harness/` and workspace state lives under `~/.local/share/threat-hunting-harness/workspaces/<workspace-hash>/`. Standard XDG cache and data directories are respected. Tool results report the actual paths. State is separate from the installed plugin, so updating the plugin preserves cases. Exports are written by `case_export_files`, which returns paths for Codex to link in the conversation.

## Providers and query budgets

`$hunt Check my provider configuration` inspects credentials and prepared dependencies without contacting providers. A request to test live connectivity performs bounded account metadata checks and the Censys inventory handshake. Existing connectivity results are reused; refreshing a report makes new checks. Neither kind of setup is a substitute for an intelligence query.

Every investigator shares the limits you specify for the case; unset limits impose no hidden numeric budget. Query submissions, upstream MCP calls, HTTP requests, and provider credits are different measures: GreyNoise's internal retries, for example, prevent exact API-request accounting. Unknown usage remains unknown, and providers reject numeric limits they cannot enforce. See [provider operations](providers.md) for the allowlists.

The plugin stores full source observations and candidates before narrowing. Pagination, retries, and refreshes require explicit submissions. A recovered query with uncertain execution is marked interrupted and is not silently rerun. Resume an existing case to preserve evidence and accounting.

## Review and analyst decisions

The coordinator delegates independent investigations and evidence review through Codex's native subagents in the same session. The reviewer examines evidence already in the case and records whether each finding is supported, challenged, or insufficient. That assessment does not imply human acceptance.

Codex presents the finding and uncertainty in chat. Your explicit acceptance, rejection, or request for more work allows it to record an analyst decision. Cases with unsettled branches, open evidence gaps, or pending decisions retain the corresponding waiting status. If a Codex environment lacks native subagents, Codex reports that limitation; a coordinator's self-review is identified as such.

## Updates and troubleshooting

Rerun the installation command from the updated repository, then start a new conversation. The installer versions the copied bundle to refresh Codex's cache. It replaces only its managed installation and refuses to overwrite an unrelated plugin directory or one containing unmanaged files.

If preparation fails, ask `$hunt` for status. Setup failures include a diagnostic log path; successful setup reports which providers are configured. Correct `.env` in the reported workspace and run `$hunt` again. GreyNoise's previously tested credentials returned HTTP 401; successful installation cannot correct provider account access.

The plugin controls its own provider operations and query accounting. It does not establish an operating-system network boundary around all of Codex's other tools. Tests and the installed-plugin Codex run are described in [verification](verification.md); synthetic fixtures do not establish campaign-detection performance or real analyst acceptance. Claude integration remains deferred.

## Offline evaluation

Ask `$hunt Evaluate the bundled benchmarks` to run `evaluate_benchmarks` inside the plugin. It uses the included campaign manifests, synthetic observations, and evaluator answers to compare enrichment and coordinated workflows. The evaluator keeps scoring answers out of investigator inputs and writes a new report and structured artifacts each run. Codex returns their paths in the conversation.

Evaluation needs no provider credentials and performs no live provider requests or model calls. It measures the fixture workflows rather than empirical campaign detection or real analyst acceptance. Normal hunts do not automatically run benchmarks. [Evaluation methodology](evaluation.md) explains the historical source material, constructed observations, scoring, and limitations.

## Packaging contract

The bundle uses Codex's supported `.codex-plugin/plugin.json` compatibility manifest, `.mcp.json`, and `skills/hunt/SKILL.md`. The MCP command is `python3 scripts/plugin_stdio.py` with `cwd: "."`. Codex resolves this relative working directory against the installed plugin root. The compatibility MCP parser does not expand `${PLUGIN_ROOT}`; that expansion belongs to the portable Agent Plugins manifest format. Explicit workspace setup supplies the independent user workspace path.

References checked against the current documentation and Codex source:

- [Codex plugin packaging](https://developers.openai.com/codex/build-plugins/)
- [Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [Compatibility MCP parser](https://github.com/openai/codex/blob/main/codex-rs/codex-mcp/src/plugin_config.rs)
- [Portable Agent Plugins MCP parser](https://github.com/openai/codex/blob/main/codex-rs/codex-mcp/src/agent_plugin_config.rs)
