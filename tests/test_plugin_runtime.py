"""Real stdio processes, auto-started backend, shared jobs and retained state; no live calls."""

import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).parents[1]


@pytest.fixture
def plugin_environment(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".env").write_text("GTI_API_KEY=fixture-only\n")
    helper = tmp_path / "fake-gti"
    helper.write_text(
        f"#!{sys.executable}\nimport os, runpy\nos.environ['FIXTURE_PROVIDER']='gti'\n"
        f"runpy.run_path({str(ROOT / 'tests/fixtures/provider_server.py')!r})\n"
    )
    helper.chmod(0o700)
    paths = tmp_path / "paths.json"
    paths.write_text(
        json.dumps(
            {
                "python": sys.executable,
                "gti": str(helper),
                "node": "/unused-node",
                "greynoise": "/unused-greynoise",
                "runtime": str(tmp_path),
            }
        )
    )
    env = {
        key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "USER", "LANG"}
    }
    env.update(
        HUNT_PLUGIN_TEST_RUNTIME=str(paths),
        HUNT_PLUGIN_DATA=str(tmp_path / "data"),
        HUNT_PLUGIN_CACHE=str(tmp_path / "cache"),
        HUNT_PLUGIN_IDLE_SECONDS="1.5",
    )
    return workspace, env


@asynccontextmanager
async def connected(env, plugin_root=ROOT):
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(plugin_root / "scripts/plugin_stdio.py")],
        cwd=str(plugin_root),
        env=env,
    )
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            yield session


async def call(session, name, arguments=None):
    result = await session.call_tool(name, arguments or {})
    assert not result.isError, result
    return result.structuredContent


async def ready(session, workspace):
    status = await call(session, "hunting_setup", {"workspace": str(workspace)})
    async with asyncio.timeout(20):
        while status["status"] != "ready":
            assert status["status"] in ("preparing", "updating"), status
            await asyncio.sleep(0.05)
            status = await call(session, "hunting_status")
    return status


async def test_claude_bundle_from_another_directory_shares_codex_cases(
    plugin_environment, tmp_path
):
    workspace, env = plugin_environment
    installed = tmp_path / "plugin cache with spaces" / "threat-hunting-harness"
    shutil.copytree(ROOT / "plugins/threat-hunting-harness", installed)
    before = {p.relative_to(installed): p.read_bytes() for p in installed.rglob("*") if p.is_file()}
    manifest = json.loads((installed / ".claude-plugin/plugin.json").read_text())
    server = manifest["mcpServers"]["hunting"]
    params = StdioServerParameters(
        command=server["command"],
        args=[arg.replace("${CLAUDE_PLUGIN_ROOT}", str(installed)) for arg in server["args"]],
        cwd=str(workspace),
        env=env,
    )
    async with stdio_client(params) as streams, connected(env) as codex:
        async with ClientSession(*streams) as claude:
            await claude.initialize()
            one, two = await asyncio.gather(ready(claude, workspace), ready(codex, workspace))
            assert one["state_directory"] == two["state_directory"]
            assert one["configured_providers"] == two["configured_providers"] == ["gti"]
            assert one["live_requests_during_setup"] == two["live_requests_during_setup"] == 0
            case = await call(
                claude,
                "case_create",
                {
                    "spec": {
                        "hypothesis": "Share a retained case across hosts",
                        "seeds": ["seed.example"],
                        "start": "2024-01-01",
                        "end": "2024-02-01",
                        "limits": {"query_calls": 0},
                    }
                },
            )
            assert (await call(codex, "case_read", {"case_id": case["id"]}))["id"] == case["id"]
            exported = await call(claude, "case_export_files", {"case_id": case["id"]})
            assert Path(exported["markdown"]).is_file()
    after = {p.relative_to(installed): p.read_bytes() for p in installed.rglob("*") if p.is_file()}
    assert after == before
    assert (workspace / ".env").read_text() == "GTI_API_KEY=fixture-only\n"


async def test_plugin_stdio_starts_once_shares_queries_and_reopens_after_idle(plugin_environment):
    workspace, env = plugin_environment
    async with connected(env) as first, connected(env) as second:
        one, two = await asyncio.gather(ready(first, workspace), ready(second, workspace))
        assert one["state_directory"] == two["state_directory"]
        assert one["configured_providers"] == ["gti"]
        assert one["live_requests_during_setup"] == 0
        case = await call(
            first,
            "case_create",
            {
                "spec": {
                    "hypothesis": "Fixture historical DNS association",
                    "seeds": ["seed.example"],
                    "start": "2024-01-01",
                    "end": "2024-02-01",
                    "limits": {"query_calls": 1},
                }
            },
        )
        query = {
            "case_id": case["id"],
            "query": {
                "provider": "gti",
                "operation": "get_entities_related_to_a_domain",
                "arguments": {
                    "domain": "seed.example",
                    "relationship_name": "resolutions",
                    "descriptors_only": False,
                    "limit": 1,
                },
                "pivot_from": "seed.example",
                "purpose": "Fixture-only recorded relationship",
            },
        }
        a, b = await asyncio.gather(
            call(first, "query_submit", query), call(second, "query_submit", query)
        )
        assert a["id"] == b["id"]
        async with asyncio.timeout(10):
            while True:
                job = await call(second, "job_read", {"case_id": case["id"], "job_id": a["id"]})
                if job["status"] not in ("queued", "active"):
                    break
                await asyncio.sleep(0.03)
        assert job["status"] == "partial"  # GTI's positive limit does not prove exhaustion.
        retained = await call(first, "case_read", {"case_id": case["id"]})
        assert retained["usage"]["query_calls"] == 1
        assert any(item["indicator"] == "192.0.2.5" for item in retained["candidates"])
        finding = await call(
            first,
            "finding_propose",
            {
                "case_id": case["id"],
                "claim": {
                    "candidate": "192.0.2.5",
                    "kind": "historical_association",
                    "statement": "Fixture dated DNS association",
                    "evidence_ids": [retained["evidence"][0]["id"]],
                    "alternative_explanations": ["Shared hosting does not establish maliciousness"],
                },
            },
        )
        await call(
            second,
            "finding_review",
            {
                "case_id": case["id"],
                "finding_id": finding["id"],
                "review": {
                    "reviewer": "fixture-independent-reviewer",
                    "assessment": "insufficient",
                    "rationale": "DNS association alone does not establish campaign membership",
                },
            },
        )
        decision_args = {
            "case_id": case["id"],
            "finding_id": finding["id"],
            "decision": "needs_work",
            "rationale": "Request independent support",
        }
        refused_decision = await first.call_tool(
            "analyst_decide", {**decision_args, "confirmation": ""}
        )
        assert refused_decision.isError
        decision = await call(
            first,
            "analyst_decide",
            {
                **decision_args,
                "confirmation": "Fixture instruction: mark this finding needs work",
            },
        )
        assert decision["origin"] == "plugin_chat"
        assert decision["confirmation"].startswith("Fixture instruction")
        refused = await second.call_tool(
            "query_submit",
            {
                **query,
                "query": {**query["query"], "refresh": True},
            },
        )
        assert refused.isError
        exported = await call(first, "case_export_files", {"case_id": case["id"]})
        assert Path(exported["markdown"]).is_file()
        assert "fixture-only" not in Path(exported["json"]).read_text()
        await call(second, "hunting_status")
    descriptor = Path(one["state_directory"]) / "service.json"
    async with asyncio.timeout(10):
        while json.loads(descriptor.read_text())["status"] != "stopped":
            await asyncio.sleep(0.1)
    async with connected(env) as reopened:
        await ready(reopened, workspace)
        listed = await call(reopened, "case_list")
        assert [item["id"] for item in listed["cases"]] == [case["id"]]
        saved = await call(reopened, "case_read", {"case_id": case["id"]})
        assert saved["queries"] == retained["queries"]
        assert saved["limits"] == {"query_calls": 1}
        assert saved["decisions"] == [decision]


async def test_plugin_creates_env_without_overwriting_and_reloads_keys(plugin_environment):
    workspace, env = plugin_environment
    (workspace / ".env").unlink()
    async with connected(env) as session:
        status = await ready(session, workspace)
        assert status["configured_providers"] == []
        assert (workspace / ".env").read_text() == (ROOT / ".env.example").read_text()
        (workspace / ".env").write_text("GTI_API_KEY=fixture-only\n")
        status = await call(session, "hunting_status")
        assert status["configured_providers"] == ["gti"]
        await ready(session, workspace)
        assert (workspace / ".env").read_text() == "GTI_API_KEY=fixture-only\n"
        (workspace / ".env").write_bytes(b"\xff")
        broken = await call(session, "hunting_status")
        assert broken["status"] == "configuration_error"
        (workspace / ".env").write_text("GTI_API_KEY=fixture-only\n")
        assert (await call(session, "hunting_status"))["status"] == "ready"


def script_module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_git_release_timestamp_orders_after_legacy_installer():
    key = script_module("plugin_stdio").version_key
    assert key("0.1.0+codex.20260915002728") > key("0.1.0+codex.20260915000026959080")
    assert key("0.1.0+codex.20260915002728") == key("0.1.0+codex.20260915002728000000")
    assert key("0.2.0") > key("0.1.0+codex.20260915002728")


async def test_updated_plugin_replaces_old_backend_without_losing_case(
    plugin_environment, tmp_path
):
    workspace, env = plugin_environment
    installer = script_module("install_plugin")
    installed = Path(installer.prepare(ROOT, tmp_path / "personal")["plugin"])
    async with connected(env) as previous:
        before = await ready(previous, workspace)
        case = await call(
            previous,
            "case_create",
            {
                "spec": {
                    "hypothesis": "Preserve across upgrade",
                    "seeds": ["seed.example"],
                    "start": "2024-01-01",
                    "end": "2024-02-01",
                }
            },
        )
        async with connected(env, installed) as updated:
            after = await ready(updated, workspace)
            assert after["version"] != before["version"]
            assert after["state_directory"] == before["state_directory"]
            assert (await call(updated, "case_read", {"case_id": case["id"]}))["id"] == case["id"]
            assert (await call(previous, "hunting_status"))["status"] == "plugin_updated"
            assert (await call(updated, "hunting_status"))["version"] == after["version"]


async def test_backend_start_failure_stays_failed_until_retry(plugin_environment):
    workspace, env = plugin_environment
    digest = hashlib.sha256(str(workspace).encode()).hexdigest()[:24]
    state = Path(env["HUNT_PLUGIN_DATA"]) / "workspaces" / digest
    database = state / "cases" / "cases.sqlite"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"not a sqlite database")
    async with connected(env) as session:
        status = await call(session, "hunting_setup", {"workspace": str(workspace)})
        async with asyncio.timeout(10):
            while status["status"] == "preparing":
                await asyncio.sleep(0.05)
                status = await call(session, "hunting_status")
        assert status["status"] == "setup_failed"
        stamp = (state / "setup.log").stat().st_mtime_ns
        for _ in range(3):
            assert (await call(session, "hunting_status"))["status"] == "setup_failed"
        assert (state / "setup.log").stat().st_mtime_ns == stamp
        database.unlink()
        assert (await ready(session, workspace))["status"] == "ready"


async def test_connection_checks_share_cache_and_changed_credentials_recheck(tmp_path, monkeypatch):
    from hunting_harness import plugin_runtime
    from hunting_harness.connections import write_report

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".env").write_text("SHODAN_API_KEY=first-fixture-value\n")
    runtime = plugin_runtime.Runtime(workspace, tmp_path / "state", {})
    calls = []

    async def validate(keys, output):
        calls.append(keys)
        await asyncio.sleep(0.02)
        report = {"providers": {"shodan": {"status": "authenticated", "requests": 1}}}
        write_report(output / "connections.json", report)
        return report

    monkeypatch.setattr(plugin_runtime, "validate_connections", validate)
    await asyncio.gather(
        *[runtime.mcp.call_tool("provider_connections", {"live": True}) for _ in range(3)]
    )
    assert len(calls) == 1
    (workspace / ".env").write_text("SHODAN_API_KEY=second-fixture-value\n")
    await runtime.mcp.call_tool("provider_connections", {"live": True})
    assert len(calls) == 2


def test_failed_health_cannot_report_stale_ready(plugin_environment, monkeypatch):
    workspace, env = plugin_environment
    module = script_module("plugin_stdio")
    for key, value in env.items():
        if key.startswith("HUNT_PLUGIN_"):
            monkeypatch.setenv(key, value)
    plugin = module.Plugin()
    try:
        plugin.workspace = workspace
        monkeypatch.setattr(plugin, "descriptor", lambda: {"status": "ready"})
        monkeypatch.setattr(module, "locked", lambda _: True)

        def failed(_):
            raise TimeoutError

        monkeypatch.setattr(plugin, "health", failed)
        assert plugin.status()["status"] == "backend_unavailable"
    finally:
        plugin.stopped.set()


async def test_bundled_tool_catalog_matches_backend_and_initializes_without_dependencies():
    spec = importlib.util.spec_from_file_location(
        "build_plugin_tools", ROOT / "scripts/build_plugin_tools.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = await module.catalog()
    assert json.loads((ROOT / "assets/plugin-tools.json").read_text()) == expected
    # -S disables site-packages: initial discovery must work before bootstrap installs anything.
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "fixture", "version": "1"},
        },
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-S",
        str(ROOT / "scripts/plugin_stdio.py"),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await asyncio.wait_for(
        process.communicate(json.dumps(request).encode() + b"\n"), 3
    )
    assert process.returncode == 0, errors
    assert json.loads(output)["result"]["serverInfo"]["name"] == "threat-hunting-harness"
