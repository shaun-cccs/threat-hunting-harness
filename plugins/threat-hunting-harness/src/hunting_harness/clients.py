"""Dedicated client profiles and installed-client configuration checks.

Configuration checks never imply verification of model tools or operating-system egress.
"""

import json
import os
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from .models import Record
from .playbooks import ROLES, WORKFLOW

TOOLS = [
    "case_create",
    "case_read",
    "provider_operations",
    "playbooks",
    "query_submit",
    "job_read",
    "candidate_select",
    "candidate_defer",
    "coverage_record",
    "finding_propose",
    "finding_review",
    "branch_record",
    "hunt_settle",
    "case_resume",
    "case_export",
]
DISABLED_FEATURES = [
    "shell_tool",
    "unified_exec",
    "code_mode",
    "apps",
    "plugins",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "view_image",
    "image_generation",
    "hooks",
    "in_app_browser",
    "standalone_web_search",
    "workspace_dependencies",
    "skill_mcp_dependency_install",
]
PROVIDER_VARIABLES = {
    "SHODAN_API_KEY",
    "CENSYS_API_KEY",
    "CENSYS_ORG_ID",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "GTI_API_KEY",
    "VT_APIKEY",
    "VT_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "GREYNOISE_API_KEY",
}
# These are public role contracts, not an authentication boundary at the MCP endpoint.
ROLE_TOOLS = {
    "coordinator": [tool for tool in TOOLS if tool != "finding_review"],
    "investigator": [
        "case_read",
        "provider_operations",
        "playbooks",
        "query_submit",
        "job_read",
        "candidate_select",
        "candidate_defer",
        "coverage_record",
        "finding_propose",
        "branch_record",
    ],
    "evidence-reviewer": ["case_read", "playbooks", "job_read", "finding_review"],
}
GUIDANCE = (
    WORKFLOW
    + """
Delegate investigation to the investigator role and independent review to evidence-reviewer.
Pass the same case ID and a bounded branch hypothesis to each delegate. Delegation does not create
another case or reset limits. Propose findings as investigator; request finding_review from a
separate reviewer session. Present challenged findings and alternatives alongside supported ones.
Only the separate trusted analyst CLI records human decisions with analyst_decide.
For each continuation, copy the returned arguments and supply QuerySpec.continuation_of with the
previous job ID. A later empty page does not erase earlier observations. Link branch_record to its
supporting evidence_ids and query_ids when available. Use case_read.status_summary when present.
Reopen by reading the existing case ID. Use case_resume for new seeds or explicit refresh.
"""
)
LIMITATIONS = [
    "Installed-client checks inspect configuration and advertised controls; no model session ran.",
    "Shell/tool removal and OS network egress have not been exercised in a model session.",
    "Codex Code Mode host remains enabled to route MCP tools. Its code execution and network "
    "capabilities require runtime verification; this profile does not claim OS egress confinement.",
    "Managed settings, plugins, new tools and client upgrades require renewed validation.",
    "Filtering removes known provider variable names; it cannot prove absence of secrets "
    "in files, aliases, subprocess helpers or an already running client.",
    "Role tool lists guide client behavior; the shared token is not a role identity.",
]


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _validate(client: str, endpoint: str) -> None:
    if client not in ("codex", "claude"):
        raise ValueError("Choose codex or claude")
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("The hunting gateway must be an HTTP loopback URL without credentials")
    # Force validation of malformed ports before writing a profile.
    _ = parsed.port


def _codex_config(endpoint: str) -> str:
    config = 'sandbox_mode = "read-only"\napproval_policy = "never"\nweb_search = "disabled"\n'
    config += "developer_instructions = " + json.dumps(GUIDANCE + ROLES["coordinator"]) + "\n"
    config += "\n[features]\nmulti_agent = true\ncode_mode_host = true\n"
    config += "".join(f"{key} = false\n" for key in DISABLED_FEATURES)
    for role, instruction in ROLES.items():
        config += f"\n[agents.{json.dumps(role)}]\ndescription = {json.dumps(instruction)}\n"
        config += f'config_file = "agents/{role}.toml"\n'
    config += "\n[mcp_servers.hunting]\nurl = " + json.dumps(endpoint) + "\n"
    config += 'bearer_token_env_var = "HUNT_GATEWAY_TOKEN"\n'
    config += "enabled_tools = " + json.dumps(TOOLS) + "\n"
    config += _gateway_approvals(TOOLS)
    return config


def _gateway_approvals(tool_names: list[str]) -> str:
    # Keep newly introduced tools gated; only the explicit gateway allowlist is preapproved.
    result = 'default_tools_approval_mode = "prompt"\n'
    for tool in tool_names:
        result += f'\n[mcp_servers.hunting.tools.{tool}]\napproval_mode = "approve"\n'
    return result


def _claude_roles() -> Record:
    return {
        role: {
            "description": instruction,
            "prompt": GUIDANCE + instruction,
            "tools": ["mcp__hunting__" + tool for tool in ROLE_TOOLS[role]]
            + (["Agent"] if role == "coordinator" else []),
        }
        for role, instruction in ROLES.items()
    }


def prepare_client(client: str, workdir: Path, endpoint: str) -> Record:
    """Generate a dedicated workspace without changing personal client configuration."""
    _validate(client, endpoint)
    workdir = workdir.resolve()
    personal_roots = {
        Path.home().resolve(),
        Path.home().resolve() / ".codex",
        Path.home().resolve() / ".claude",
    }
    if workdir in personal_roots:
        raise ValueError(
            "Choose a dedicated hunting workspace outside personal client configuration"
        )
    _write(workdir / "HUNTING.md", GUIDANCE)
    if client == "codex":
        _write(workdir / ".codex/config.toml", _codex_config(endpoint))
        for role, instruction in ROLES.items():
            _write(
                workdir / f".codex/agents/{role}.toml",
                f"name = {json.dumps(role)}\ndescription = {json.dumps(instruction)}\n"
                'sandbox_mode = "read-only"\ndeveloper_instructions = '
                + json.dumps(GUIDANCE + instruction)
                + "\n\n[mcp_servers.hunting]\nurl = "
                + json.dumps(endpoint)
                + '\nbearer_token_env_var = "HUNT_GATEWAY_TOKEN"\nenabled_tools = '
                + json.dumps(ROLE_TOOLS[role])
                + "\n"
                + _gateway_approvals(ROLE_TOOLS[role]),
            )
        skill = workdir / ".agents/skills/hunt/SKILL.md"
    else:
        _write(
            workdir / ".mcp.json",
            json.dumps(
                {
                    "mcpServers": {
                        "hunting": {
                            "type": "http",
                            "url": endpoint,
                            "headers": {"Authorization": "Bearer ${HUNT_GATEWAY_TOKEN}"},
                        }
                    }
                },
                indent=2,
            )
            + "\n",
        )
        _write(
            workdir / ".claude/settings.json",
            json.dumps(
                {
                    "permissions": {
                        "allow": ["mcp__hunting__" + tool for tool in TOOLS] + ["Agent"],
                        "deny": [
                            "Bash",
                            "Read",
                            "Write",
                            "Edit",
                            "WebFetch",
                            "WebSearch",
                            "NotebookEdit",
                        ],
                    }
                },
                indent=2,
            )
            + "\n",
        )
        for role, definition in _claude_roles().items():
            _write(
                workdir / f".claude/agents/{role}.md",
                f"---\nname: {role}\ndescription: {json.dumps(definition['description'])}\n"
                "tools: " + ", ".join(definition["tools"]) + "\n"
                "---\n\n" + definition["prompt"] + "\n",
            )
        # Explicit --agents works even when restricted mode ignores project auto-discovery.
        _write(workdir / ".claude/hunting-agents.json", json.dumps(_claude_roles(), indent=2))
        skill = workdir / ".claude/skills/hunt/SKILL.md"
    _write(
        skill,
        "---\nname: hunt\ndescription: Run an analyst-guided hunt through the shared gateway.\n"
        "disable-model-invocation: true\n---\n\n" + GUIDANCE,
    )
    return {
        "client": client,
        "workdir": str(workdir),
        "endpoint": endpoint,
        "provider_credentials": "excluded_from_generated_files",
        "runtime_enforcement": "not_verified",
        "limitations": LIMITATIONS,
    }


def command(client: str, workdir: Path, endpoint: str) -> list[str]:
    _validate(client, endpoint)
    workdir = workdir.resolve()
    if client == "claude":
        return [
            "claude",
            "--restricted",
            "--strict-mcp-config",
            "--mcp-config",
            str(workdir / ".mcp.json"),
            "--settings",
            str(workdir / ".claude/settings.json"),
            "--setting-sources",
            "",
            "--tools",
            "Agent",
            "--allowedTools",
            ",".join(["mcp__hunting__" + tool for tool in TOOLS] + ["Agent"]),
            "--agents",
            json.dumps(_claude_roles()),
            "--agent",
            "coordinator",
            "--append-system-prompt",
            GUIDANCE + ROLES["coordinator"],
        ]
    args = [
        "codex",
        "-C",
        str(workdir),
        "-c",
        'sandbox_mode="read-only"',
        "-c",
        'approval_policy="never"',
        "-c",
        'web_search="disabled"',
        "-c",
        "developer_instructions=" + json.dumps(GUIDANCE + ROLES["coordinator"]),
    ]
    # Do not copy personal server credentials; override only names of configured servers.
    personal = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml"
    if personal.exists():
        config = tomllib.loads(personal.read_text())
        for name in config.get("mcp_servers", {}):
            if name != "hunting":
                args += ["-c", f"mcp_servers.{json.dumps(name)}.enabled=false"]
    for feature in DISABLED_FEATURES:
        args += ["-c", f"features.{feature}=false"]
    args += ["-c", "features.multi_agent=true", "-c", "features.code_mode_host=true"]
    for role, instruction in ROLES.items():
        args += [
            "-c",
            f"agents.{json.dumps(role)}.description=" + json.dumps(instruction),
            "-c",
            f"agents.{json.dumps(role)}.config_file="
            + json.dumps(str(workdir / f".codex/agents/{role}.toml")),
        ]
    args += [
        "-c",
        "mcp_servers.hunting.url=" + json.dumps(endpoint),
        "-c",
        "mcp_servers.hunting.enabled=true",
        "-c",
        'mcp_servers.hunting.bearer_token_env_var="HUNT_GATEWAY_TOKEN"',
        "-c",
        "mcp_servers.hunting.enabled_tools=" + json.dumps(TOOLS),
    ]
    args += ["-c", 'mcp_servers.hunting.default_tools_approval_mode="prompt"']
    for tool in TOOLS:
        args += ["-c", f'mcp_servers.hunting.tools.{tool}.approval_mode="approve"']
    return args


def client_environment(token: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in PROVIDER_VARIABLES}
    env["HUNT_GATEWAY_TOKEN"] = token
    return env


def _run(args: list[str], env: dict[str, str], workdir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, env=env, cwd=workdir, capture_output=True, text=True, timeout=30, check=False
    )


def preflight(client: str, workdir: Path, endpoint: str, token: str) -> Record:
    """Inspect installed flags and effective MCP configuration without provider/model requests."""
    _validate(client, endpoint)
    report: Record = {
        "client": client,
        "provider_credentials_in_environment": False,
        "effective_runtime_enforcement": "not_verified",
        "model_workflow": "not_exercised",
        "live_provider_calls": 0,
        "limitations": list(LIMITATIONS),
    }
    try:
        args = command(client, workdir, endpoint)
        env = client_environment(token)
        version = _run([client, "--version"], env, workdir)
        report["version"] = version.stdout.strip() if version.returncode == 0 else None
        if version.returncode:
            report["configuration"] = "version_check_failed"
            return report
        if client == "codex":
            check = _run(args + ["mcp", "list", "--json"], env, workdir)
            if check.returncode:
                report["configuration"] = "client_rejected_configuration"
                return report
            servers = json.loads(check.stdout)
            enabled = [s for s in servers if s.get("enabled")]
            report["enabled_mcp_servers"] = [s["name"] for s in enabled]
            detail = _run(args + ["mcp", "get", "hunting", "--json"], env, workdir)
            hunting: Record = json.loads(detail.stdout) if detail.returncode == 0 else {}
            transport = hunting.get("transport", {})
            correct = (
                len(enabled) == 1
                and transport.get("url") == endpoint
                and transport.get("bearer_token_env_var") == "HUNT_GATEWAY_TOKEN"
                and set(hunting.get("enabled_tools") or []) == set(TOOLS)
            )
            report["configuration"] = "validated" if correct else "unexpected_configuration"
            features = _run(args + ["features", "list"], env, workdir)
            states = {
                parts[0]: parts[-1]
                for line in features.stdout.splitlines()
                if len(parts := line.split()) >= 3
            }
            report["unsupported_controls"] = [
                name for name in DISABLED_FEATURES if states.get(name) != "false"
            ]
            report["native_roles"] = list(ROLES)
        else:
            check = _run(["claude", "--help"], env, workdir)
            required = [
                "--restricted",
                "--strict-mcp-config",
                "--tools",
                "--setting-sources",
                "--agents",
                "--agent",
                "--settings",
            ]
            report["unsupported_controls"] = [name for name in required if name not in check.stdout]
            mcp = json.loads((workdir / ".mcp.json").read_text())
            settings = json.loads((workdir / ".claude/settings.json").read_text())
            correct = (
                set(mcp.get("mcpServers", {})) == {"hunting"}
                and mcp["mcpServers"]["hunting"]["url"] == endpoint
                and mcp["mcpServers"]["hunting"]["headers"]["Authorization"]
                == "Bearer ${HUNT_GATEWAY_TOKEN}"
                and "Bash" in settings["permissions"]["deny"]
            )
            report["configuration"] = (
                "supported_cli_flags_and_parsed_files"
                if correct and not report["unsupported_controls"]
                else "unsupported_or_invalid_configuration"
            )
            report["native_roles"] = list(_claude_roles())
            report["limitations"].append(
                "Claude help and JSON parsing do not show its effective runtime tool inventory."
            )
    except FileNotFoundError:
        report["configuration"] = "client_or_profile_not_found"
    except subprocess.TimeoutExpired:
        report["configuration"] = "client_check_timed_out"
    except (ValueError, KeyError, TypeError, OSError):
        # Never retain subprocess stderr or arbitrary config data: either may contain credentials.
        report["configuration"] = "configuration_check_failed"
    return report
