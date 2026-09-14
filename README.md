# Threat-hunting harness

A local, authenticated MCP gateway for resumable threat hunts. Cases retain seeds, candidate infrastructure, source observations, query jobs, evidence reviews, analyst decisions, and exports. Provider adapters retrieve existing observations only.

## Install

Python 3.11+ and [uv](https://docs.astral.sh/uv/) are recommended:

```bash
git clone https://github.com/shaun-cccs/threat-hunting-harness.git
cd threat-hunting-harness
uv sync --locked
```

Alternatively, create a Python virtual environment and run `python -m pip install -e .` inside it. Development checks additionally need pytest, pytest-asyncio, mypy, ruff, and types-jsonschema. Commands below use `uv run`; an activated environment can invoke `hunt` directly.

Keep credentials in an ignored `.env` file using the names in [.env.example](.env.example). Provider setup and exact operation allowlists are documented in [providers](docs/providers.md).

## Start a gateway

```bash
uv run hunt --state cases serve
```

The MCP endpoint is `http://127.0.0.1:8765/mcp`. Its bearer token is generated in `cases/gateway.token` with owner-only permissions. Provider lookups are disabled unless the trusted analyst starts the gateway with `--enable-lookups`:

```bash
uv run hunt --state cases serve --enable-lookups --env-file .env
```

Cases and source artifacts stay under `cases/`, outside tracked source. One worker owns each state directory; clients share that worker's jobs and limits. Queries are explicit jobs, and pagination and retries require explicit submissions. A restart records interrupted execution without silently replaying queries.

## Create and inspect a case

```bash
uv run hunt create --hypothesis 'Related service fingerprints during the campaign' \
  --seed 192.0.2.1 --start 2024-01-01 --end 2024-02-01 \
  --limit query_calls=5 --limit api_requests=5
uv run hunt status CASE_ID
uv run hunt export CASE_ID --output artifacts/exports
```

Limits are optional and shared across callers. Unset limits impose no numeric hunt budget. An adapter rejects limits it cannot enforce; unknown upstream requests and credits remain unknown. Creating or reading a case does not query a provider. The documentation IP above is for offline examples.

## Verify connectivity with limited requests

Inspect configuration without any network requests:

```bash
uv run hunt connections
```

Check Shodan account metadata without indicator queries:

```bash
uv run hunt connections --live
```

A cached report is reused unless `--refresh` is specified. For an explicit, single Shodan host retrieval:

```bash
uv run hunt smoke --ip 1.1.1.1
```

The smoke command queries Shodan's existing report, never the IP itself. It uses one query and one API request, with no search, pagination, or retry. It retains its case and sanitized result under `artifacts/live-smoke/`. [Verification results](docs/verification.md) record actual checks separately from offline fixtures.

## Tests

```bash
uv run mypy src
uv run ruff check src tests
uv run pytest
```

Provider adapters, native Codex profiles, and evaluation follow in separate branches.

## Design

- [Domain glossary](CONTEXT.md)
- [Harness design](docs/threat-hunting-design.md)
- [Architectural decisions](docs/adr/)
- [Provider research](docs/research/threat-intelligence-mcp.md)
- [Client research](docs/research/agent-mcp-clients.md)

Historical association, current malicious use, and actor attribution are separate claims. All retrieved candidates survive narrowing, including candidates left outside the expansion subset. Internal catalog integrations await defined tables and backend contracts.
