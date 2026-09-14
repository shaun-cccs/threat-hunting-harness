# Threat-hunting harness

An analyst-guided threat-hunting harness for Codex and Claude, using MCP integrations with Censys, Shodan, VirusTotal/GTI, GreyNoise, and future internal catalog sources.

The project is currently in the design phase. It contains the agreed workflow, proposed implementation defaults, domain vocabulary, and source-backed MCP research. Runtime implementation has not started.

## Purpose

Start from known malicious domains or IP addresses, preserve candidate infrastructure and evidence, narrow before expanding, and produce findings for analyst review. A coordinator and investigation subagents share an MCP gateway and resumable case state. The collection boundary permits existing provider observations only.

## Design documents

- [Harness design](docs/threat-hunting-design.md)
- [Domain glossary](CONTEXT.md)
- [MCP provider assessment](docs/research/threat-intelligence-mcp.md)
- [Codex and Claude MCP compatibility](docs/research/agent-mcp-clients.md)
- [Architectural decisions](docs/adr/)

## Prerequisites

Git is sufficient to work with the current documentation. The proposed runtime uses Python 3.11+; runtime dependencies and provider account setup will be documented when implementation begins. Keep credentials and hunt case data outside tracked files.

## Get the repository

Clone this repository directly:

```bash
git clone https://github.com/CybercentreCanada/threat-hunting-harness.git ~/Projects/threat-hunting-harness
```

The local checkout is `~/Projects/threat-hunting-harness`, alongside the FAI workshop repository at `~/Projects/fai_workshop_ci`.

## Run

There is no executable harness yet. Review the [design](docs/threat-hunting-design.md) for the proposed runtime, agent roles, provider integrations, and workflow.

## Verify

For documentation changes:

```bash
git diff --check
```

Implementation tests, client integration checks, and live provider verification remain to be added. The research notes distinguish documented capabilities from account access and behavior that have not been tested.
