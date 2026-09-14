import json
import tomllib

from hunting_harness.clients import prepare_client


def test_both_clients_use_the_same_gateway_with_only_hunt_tools_and_no_provider_keys(tmp_path):
    for client in ("codex", "claude"):
        profile = prepare_client(client, tmp_path / client, "http://127.0.0.1:8765/mcp")
        assert profile["client"] == client
        assert profile["endpoint"] == "http://127.0.0.1:8765/mcp"
    codex = tomllib.loads((tmp_path / "codex/.codex/config.toml").read_text())
    assert codex["features"]["shell_tool"] is False
    assert codex["mcp_servers"]["hunting"]["bearer_token_env_var"] == "HUNT_GATEWAY_TOKEN"
    claude = json.loads((tmp_path / "claude/.mcp.json").read_text())
    assert set(claude["mcpServers"]) == {"hunting"}
    assert "HUNT_GATEWAY_TOKEN" in claude["mcpServers"]["hunting"]["headers"]["Authorization"]
    assert (tmp_path / "codex/.codex/agents/investigator.toml").exists()
    assert (tmp_path / "claude/.claude/agents/evidence-reviewer.md").exists()


def test_preparing_a_profile_cannot_overwrite_personal_client_configuration(tmp_path, monkeypatch):
    from pathlib import Path

    import pytest

    personal = tmp_path / ".codex/config.toml"
    personal.parent.mkdir()
    personal.write_text('model = "personal-model"\n')
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(ValueError, match="dedicated"):
        prepare_client("codex", tmp_path, "http://127.0.0.1:8765/mcp")
    assert personal.read_text() == 'model = "personal-model"\n'


async def test_both_client_replays_share_reviewed_state_across_restart(tmp_path):
    from hunting_harness.clients import fixture_workflow

    for client in ("codex", "claude"):
        output = tmp_path / client
        result = await fixture_workflow(client, output)
        assert result["validation"] == "offline_mcp_sdk_replay"
        assert result["native_model_workflow"] == "not_exercised"
        assert result["runtime_enforcement"] == "not_verified"
        assert result["retained_usage"]["query_calls"] == 1
        assert result["limits"] == {"query_calls": 2}
        assert result["reopened_settled"]["status"] == "completed"
        assert result["active_status"]["status_summary"]["branch_states"]["active"] == 1
        case = json.loads((output / "case.json").read_text())
        assert case["id"] == result["case_id"]
        assert len(case["queries"]) == 1
        assert len(case["candidates"]) == 2
        assert [finding["status"] for finding in case["findings"]] == ["accepted", "rejected"]
        assert case["resumptions"][0]["refresh"] is True
        transcript = json.loads((output / "transcript.json").read_text())
        assert {entry["role"] for entry in transcript} == {
            "coordinator",
            "investigator",
            "evidence-reviewer",
            "scripted-analyst",
        }
        assert all(
            entry["role"] == "evidence-reviewer"
            for entry in transcript
            if entry["tool"] == "finding_review"
        )
        assert all(
            entry["role"] == "scripted-analyst"
            for entry in transcript
            if entry["tool"] == "analyst_decide"
        )
        assert not list((output / "profile").rglob("case.json"))
        assert (output / "report.md").exists()
        assert (output / "candidates.csv").exists()


def test_codex_native_roles_have_standalone_transport_and_a_working_tool_host(tmp_path):
    from hunting_harness.clients import command

    prepare_client("codex", tmp_path, "http://127.0.0.1:8765/mcp")
    for path in (tmp_path / ".codex/agents").glob("*.toml"):
        role = tomllib.loads(path.read_text())
        transport = role["mcp_servers"]["hunting"]
        assert transport.get("url") == "http://127.0.0.1:8765/mcp"
        assert transport.get("bearer_token_env_var") == "HUNT_GATEWAY_TOKEN"
        assert "analyst_decide" not in transport["enabled_tools"]
    config = tomllib.loads((tmp_path / ".codex/config.toml").read_text())
    assert config["features"]["code_mode_host"] is True
    args = command("codex", tmp_path, "http://127.0.0.1:8765/mcp")
    assert "features.code_mode_host=false" not in args


def test_preflight_reports_ignored_controls_without_claiming_runtime_enforcement(
    tmp_path, monkeypatch
):
    import os
    import sys
    from pathlib import Path

    from hunting_harness.clients import preflight

    executable = tmp_path / "bin/codex"
    executable.parent.mkdir()
    fixture = Path(__file__).parent / "fixtures/client_cli.py"
    executable.write_text(f"#!{sys.executable}\n" + fixture.read_text())
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(executable.parent) + os.pathsep + os.environ["PATH"])
    workdir = tmp_path / "profile"
    prepare_client("codex", workdir, "http://127.0.0.1:8765/mcp")
    result = preflight("codex", workdir, "http://127.0.0.1:8765/mcp", "secret-test-token")
    assert result["configuration"] == "validated"
    assert result["unsupported_controls"] == ["unified_exec"]
    assert result["effective_runtime_enforcement"] == "not_verified"
    assert result["model_workflow"] == "not_exercised"
    assert "secret-test-token" not in json.dumps(result)


def test_codex_automatic_approval_is_scoped_to_named_gateway_tools(tmp_path):
    from hunting_harness.clients import command

    prepare_client("codex", tmp_path, "http://127.0.0.1:8765/mcp")
    paths = [tmp_path / ".codex/config.toml", *(tmp_path / ".codex/agents").glob("*.toml")]
    for path in paths:
        config = tomllib.loads(path.read_text())
        hunting = config["mcp_servers"]["hunting"]
        assert hunting.get("default_tools_approval_mode") == "prompt"
        assert set(hunting.get("tools", {})) == set(hunting["enabled_tools"])
        assert all(tool["approval_mode"] == "approve" for tool in hunting["tools"].values())
        assert "analyst_decide" not in hunting["tools"]
    args = command("codex", tmp_path, "http://127.0.0.1:8765/mcp")
    assert 'mcp_servers.hunting.tools.case_read.approval_mode="approve"' in args
    assert 'mcp_servers.hunting.tools.query_submit.approval_mode="approve"' in args
    assert "--dangerously-bypass-approvals-and-sandbox" not in args
