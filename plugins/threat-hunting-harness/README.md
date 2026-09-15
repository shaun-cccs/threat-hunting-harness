# Threat Hunting for Codex

A Codex plugin for resumable threat investigations. Install it once, fill in your workspace's `.env`, and use **`$hunt` in your existing Codex conversation**. The plugin prepares its dependencies, connects available providers, retains evidence, coordinates native Codex agents, and writes reports automatically.

## Install once

With Codex and Python 3.9+ available on Linux or macOS, install directly from GitHub:

```bash
codex plugin marketplace add shaun-cccs/threat-hunting-harness --ref main
codex plugin add threat-hunting-harness@threat-hunting
```

These commands register this repository as a marketplace and install its bundled plugin. Repository access is required. Start a new Codex conversation in the folder where you want to investigate.

Codex handles its normal tool-permission prompts. The plugin does not rewrite your approval settings. A host configured to reject every unapproved tool must allow the hunting tools through its normal plugin controls before use.

Fill in `.env` in that folder using the keys in [.env.example](.env.example). Leave unavailable providers blank. If the file is missing, `$hunt` creates a blank template and tells you where to edit it.

```dotenv
SHODAN_API_KEY=
CENSYS_API_KEY=
CENSYS_ORG_ID=
GTI_API_KEY=
GREYNOISE_API_KEY=
```

Then ask Codex:

```text
$hunt Check my provider configuration.
$hunt Investigate <seed> for <hypothesis> during <date range>, using at most 5 queries.
$hunt Resume my latest case and export the report.
$hunt Evaluate the bundled benchmarks.
```

That is the complete setup. Runtime preparation happens on first use and may take a few minutes while dependencies download. Codex reports progress in the same conversation. Investigators and the evidence reviewer run as native Codex agents; the shared case service starts automatically in the background.

To update, run `codex plugin marketplace upgrade threat-hunting`, then repeat the
`codex plugin add` command and start a new conversation. The GitHub distribution is
on `main`. It has not been submitted to a public plugin directory. The old Python
installer remains a local development helper.

## Evidence and limits

Provider adapters retrieve existing observations from Shodan, Censys, GTI/VirusTotal, and GreyNoise. All returned candidates remain in the case, including candidates excluded from further expansion. Historical association, current malicious use, and actor attribution remain separate claims. Reviewer assessments and your analyst decisions are recorded separately; accept, reject, or request more work in chat.

Query limits are shared by every agent working on a case. Upstream API-request counts and credits remain unknown when the provider cannot report or enforce them. Pagination and refreshes are explicit, and interrupted queries are retained without silent replay. Configuration checks make no provider requests; ask `$hunt` to test live connectivity when needed.

Cases and exports persist outside the plugin installation and survive updates. Reports include evidence, source gaps, reviewer assessments, and recorded analyst decisions. See [plugin operation and troubleshooting](docs/plugin.md) for storage locations and lifecycle details.

## Verification and development

The installed plugin passed automatic first-use setup and a native Codex case/export workflow with zero provider queries. Its local tests cover shared limits, retained evidence, dependency preparation, configuration reload, and plugin updates. Live checks confirmed Shodan and GTI metadata access and the Censys inventory; GreyNoise returned HTTP 401. One Shodan host-report lookup was performed. [Verification](docs/verification.md) records the checks and their limits.

Use `$hunt Evaluate the bundled benchmarks` for an offline comparison of enrichment and coordinated workflows. Codex writes the evaluation report automatically. The bundled observations are synthetic; evaluation requires no provider credentials and makes no live provider or model calls.

The standalone gateway and client launchers remain available for development and compatibility; ordinary plugin use is entirely within Codex. See [legacy clients](docs/clients.md), [providers](docs/providers.md), and [evaluation](docs/evaluation.md). Developers can run `uv sync --locked`, `uv run pytest`, `uv run mypy src`, and `uv run ruff check src tests scripts` from a checkout.

Design references: [domain glossary](CONTEXT.md), [harness design](docs/threat-hunting-design.md), and [architectural decisions](docs/adr/).
