"""Opt-in installed-plugin fixture: zero queries and one native shared-state reader.

Requires an installed plugin and existing Codex login. This verifies native wiring,
shared state and exports, not intelligence quality, evidence review or human acceptance.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any, cast

Record = dict[str, Any]
HYPOTHESIS = "Installed plugin native workflow fixture"
REASON = "Fixture intentionally excludes provider queries"
PROVIDER_KEYS = {
    "SHODAN_API_KEY", "CENSYS_API_KEY", "CENSYS_ORG_ID", "GTI_API_KEY", "VT_APIKEY",
    "GREYNOISE_API_KEY",
}


def records(path: Path) -> list[Record]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def structured(item: Record) -> Record:
    result = item.get("result") or {}
    return cast(Record, result.get("structured_content") or result.get("structuredContent") or {})


def successful(item: Record) -> bool:
    return bool(
        item.get("status") == "completed" and not item.get("error")
        and not (item.get("result") or {}).get("isError")
    )


def delegation(thread_id: str, sessions: Path) -> Record:
    """Retain only relevant native events; never copy prompts or encrypted messages."""
    result: Record = {"parent_thread_id": thread_id, "spawn_calls": [], "children": []}
    parents = list(sessions.rglob(f"*{thread_id}.jsonl")) if thread_id else []
    if len(parents) != 1:
        return result
    parent = records(parents[0])
    calls = [
        row["payload"] for row in parent if row.get("type") == "response_item"
        and row.get("payload", {}).get("type") == "function_call"
        and row["payload"].get("name") == "spawn_agent"
    ]
    outputs = {
        row["payload"]["call_id"]: row["payload"].get("output")
        for row in parent if row.get("type") == "response_item"
        and row.get("payload", {}).get("type") == "function_call_output"
    }
    for call in calls:
        raw = outputs.get(call["call_id"])
        try:
            response = json.loads(raw) if isinstance(raw, str) else {}
        except ValueError:
            response = {}
        result["spawn_calls"].append({
            "call_id": call["call_id"],
            "result": {k: response[k] for k in ("task_name", "agent_id") if k in response},
        })
    # Only first-line metadata is inspected to locate children; unrelated content is not read.
    for path in sessions.rglob("*.jsonl"):
        try:
            with path.open() as stream:
                meta = json.loads(stream.readline()).get("payload", {})
        except (OSError, ValueError):
            continue
        if meta.get("parent_thread_id") != thread_id:
            continue
        child_id = meta["id"]
        child_rows = records(path)
        items = [
            row["payload"]["item"] for row in child_rows
            if row.get("type") == "event_msg"
            and row.get("payload", {}).get("type") == "item_completed"
            and row["payload"].get("thread_id") == child_id
            and row["payload"].get("item", {}).get("type") == "McpToolCall"
        ]
        result["children"].append({
            "thread_id": child_id,
            "parent_thread_id": thread_id,
            "completed": any(
                row.get("type") == "event_msg"
                and row.get("payload", {}).get("type") == "task_complete" for row in child_rows
            ),
            "further_delegations": sum(
                row.get("type") == "response_item"
                and row.get("payload", {}).get("type") == "function_call"
                and row["payload"].get("name") == "spawn_agent" for row in child_rows
            ),
            "mcp_calls": [{
                "server": item.get("server"), "tool": item.get("tool"),
                "arguments": item.get("arguments", {}), "successful": successful(item),
                "result": structured(item),
            } for item in items],
        })
    return result


def zero_case(case: Record, case_id: str) -> bool:
    return bool(
        case.get("id") == case_id and case.get("limits") == {"query_calls": 0}
        and all(case.get(key) == [] for key in ("queries", "evidence", "findings", "decisions"))
        and case.get("usage")
        and all(value == 0 for value in case["usage"].values())
    )


def analyze(root: Path, sessions: Path | None = None) -> Record:
    """Analyze an existing run without invoking Codex, providers or the plugin."""
    events = records(root / "events.jsonl")
    items = [row["item"] for row in events if row.get("type") == "item.completed"]
    mcp = [item for item in items if item.get("type") == "mcp_tool_call"]
    thread_id = next(
        (row["thread_id"] for row in events if row.get("type") == "thread.started"), ""
    )
    sessions = sessions or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "sessions"
    evidence = delegation(thread_id, sessions)
    (root / "delegation-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def results(tool: str) -> list[Record]:
        return [structured(item) for item in mcp if item.get("server") == "hunting"
                and item.get("tool") == tool and successful(item)]

    created = results("case_create")
    case_id = str(created[0].get("id", "")) if len(created) == 1 else ""
    ready = [r for r in results("hunting_setup") + results("hunting_status")
             if r.get("status") == "ready"]
    exported = results("case_export_files")
    retained: Record = {}
    exported_files: Record = {}
    for key in ("markdown", "json", "csv"):
        if not exported or not isinstance(exported[-1].get(key), str):
            continue
        source = Path(exported[-1][key])
        if source.is_file():
            (root / "exports").mkdir(exist_ok=True)
            copied = root / "exports" / source.name
            shutil.copyfile(source, copied)
            exported_files[key] = str(copied)
            if key == "json":
                retained = json.loads(copied.read_text())
    children = evidence["children"]
    child_calls = [item for child in children for item in child["mcp_calls"]]
    child_reads = [item["result"] for item in child_calls
                   if item["tool"] == "case_read" and item["successful"]]
    child_setups = [item["result"] for item in child_calls
                    if item["tool"] in ("hunting_setup", "hunting_status") and item["successful"]]
    forbidden = [item.get("tool") for item in mcp + child_calls
                 if item.get("tool") == "query_submit" or (
                     item.get("tool") == "provider_connections"
                     and item.get("arguments", {}).get("live")
                 )]
    command = json.loads((root / "command.json").read_text())
    checks = {
        "process_completed": (root / "exit-code").read_text().strip() == "0",
        "no_cli_configuration_overrides": not any(arg in ("-c", "--config") for arg in command),
        "plugin_ready_without_providers": bool(ready) and all(
            r.get("configured_providers") == [] and r.get("live_requests_during_setup") == 0
            for r in ready
        ),
        "exactly_one_zero_limit_case": bool(case_id) and created[0].get("limits") == {
            "query_calls": 0
        } and created[0].get("hypothesis") == HYPOTHESIS,
        "parent_read_zero_usage": any(zero_case(case, case_id) for case in results("case_read")),
        "exactly_one_native_child": len(evidence["spawn_calls"]) == len(children) == 1
        and bool(evidence["spawn_calls"][0]["result"]) and children[0]["completed"],
        "child_read_shared_zero_usage": any(zero_case(case, case_id) for case in child_reads),
        "child_joined_same_workspace": bool(ready) and any(
            result.get("status") == "ready"
            and result.get("workspace") == ready[-1].get("workspace")
            and result.get("state_directory") == ready[-1].get("state_directory")
            for result in child_setups
        ),
        "child_did_not_create_case": not any(i["tool"] == "case_create" for i in child_calls),
        "child_did_not_delegate": all(child["further_delegations"] == 0 for child in children),
        "only_hunting_mcp_calls": all(i.get("server") == "hunting" for i in mcp + child_calls),
        "no_provider_query_attempts": not forbidden,
        "no_shell_commands": not any(item.get("type") == "command_execution" for item in items),
        "waiting_branch_retained": any(
            branch.get("status") == "waiting" and branch.get("reason") == REASON
            for branch in retained.get("branches", [])
        ),
        "settled_as_paused": any(r.get("status") == "paused" for r in results("hunt_settle")),
        "exports_retained": len(exported_files) == 3 and zero_case(retained, case_id)
        and retained.get("status") == "paused",
    }
    report = {
        "workflow_verified": all(checks.values()), "checks": checks,
        "unmet_checks": [name for name, passed in checks.items() if not passed],
        "thread_id": thread_id, "case_id": case_id, "native_children": len(children),
        "status": retained.get("status"), "usage": retained.get("usage"),
        "plugin_version": ready[-1].get("version") if ready else None,
        "exports": exported_files, "delegation_evidence": str(root / "delegation-evidence.json"),
        "scope": "Installed plugin wiring, shared case access and exports; zero-query fixture",
        "evidence_review": "not_exercised", "analyst_acceptance": "not_exercised",
        "runtime_egress_enforcement": "not_verified",
    }
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def verify(root: Path, timeout: int) -> Record:
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / ".env").write_text("# Native fixture: deliberately no provider credentials.\n")
    (workspace / ".env").chmod(0o600)
    prompt = f"""Use $hunt from the installed Threat Hunting plugin in this Codex session.
This is a bounded integration fixture, not a live investigation. Workspace: {workspace}.
Call hunting_setup with that exact workspace and poll hunting_status until ready. Let the
installed plugin prepare itself automatically. Do not run shell/network/provider tools,
installers, a gateway/client, or terminals. There are no provider credentials.
Create exactly one case: hypothesis "{HYPOTHESIS}", seed "192.0.2.1", start "2024-01-01",
end "2024-01-31", query_calls limit 0. Never query_submit or call live provider_connections.
Delegate to exactly one native Codex subagent with this workspace and case ID. Have it call
hunting_setup, hunting_status until ready, and case_read through the installed plugin, then
report the same ID and zero-query limit. It must not create cases, invoke providers or
delegate. Wait for its completion. Record a waiting branch on the seed with reason
"{REASON}", call hunt_settle, case_export_files and case_read. Report the retained case,
shared state, zero usage and export paths. Do not invent findings or analyst decisions."""
    (root / "prompt.txt").write_text(prompt)
    command = [
        "codex", "--ask-for-approval", "never", "exec", "--json", "--skip-git-repo-check",
        "--sandbox", "read-only", "-C", str(workspace), prompt,
    ]
    (root / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    env = {key: value for key, value in os.environ.items()
           if key not in PROVIDER_KEYS and not key.startswith(("HERDR_", "HUNT_PLUGIN_"))}
    with (root / "events.jsonl").open("w") as output, (root / "stderr.log").open("w") as errors:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
            env=env, start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            code = 124
    (root / "exit-code").write_text(str(code) + "\n")
    return analyze(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=360)
    parser.add_argument("--analyze-only", action="store_true", help="Inspect an existing run")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    root = args.output.resolve()
    if not args.analyze_only and root.exists():
        parser.error("--output must be a new directory; use --analyze-only to inspect an old run")
    try:
        report = analyze(root) if args.analyze_only else verify(root, args.timeout)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report = {"workflow_verified": False, "error": str(error)}
        if root.is_dir():
            (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["workflow_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
