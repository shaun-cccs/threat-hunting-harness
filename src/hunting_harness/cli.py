"""Trusted analyst commands. Live lookups require an explicit server option."""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import uvicorn

from .config import gateway_token, providers
from .connections import credentials, validate_connections
from .gateway import Gateway
from .models import CaseSpec
from .server import create_app
from .smoke import shodan_smoke


def query_limit(value: str) -> tuple[str, int]:
    name, separator, count = value.partition("=")
    if not separator or name not in ("query_calls", "api_requests", "mcp_calls"):
        raise argparse.ArgumentTypeError("Use query_calls=N, api_requests=N, or mcp_calls=N")
    try:
        amount = int(count)
    except ValueError:
        raise argparse.ArgumentTypeError("A limit must be a nonnegative integer") from None
    if amount < 0:
        raise argparse.ArgumentTypeError("A limit must be a nonnegative integer")
    return name, amount


def _run() -> None:
    parser = argparse.ArgumentParser(prog="hunt")
    parser.add_argument("--state", type=Path, default=Path("cases"))
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Run an authenticated loopback MCP gateway")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--env-file", type=Path, default=Path(".env"))
    serve.add_argument(
        "--enable-lookups",
        action="store_true",
        help="Enable existing-observation provider queries; off by default",
    )
    probe = commands.add_parser(
        "connections", help="Inspect configuration or validate authentication"
    )
    probe.add_argument("--env-file", type=Path, default=Path(".env"))
    probe.add_argument("--live", action="store_true")
    probe.add_argument("--refresh", action="store_true")
    probe.add_argument("--output", type=Path, default=Path("artifacts/connection-validation"))
    smoke = commands.add_parser("smoke", help="Make exactly one existing Shodan host lookup")
    smoke.add_argument(
        "--ip", required=True, help="IP to retrieve from Shodan, never contacted directly"
    )
    smoke.add_argument("--env-file", type=Path, default=Path(".env"))
    smoke.add_argument("--output", type=Path, default=Path("artifacts/live-smoke"))
    create = commands.add_parser("create")
    create.add_argument("--hypothesis", required=True)
    create.add_argument("--seed", action="append", required=True)
    create.add_argument("--start", required=True)
    create.add_argument("--end", required=True)
    create.add_argument(
        "--limit",
        action="append",
        type=query_limit,
        default=[],
        help="Optional shared limit, e.g. query_calls=5; repeat per measure",
    )
    status = commands.add_parser("status")
    status.add_argument("case_id")
    export = commands.add_parser("export")
    export.add_argument("case_id")
    export.add_argument("--output", type=Path, default=Path("artifacts/exports"))
    decision = commands.add_parser("decide", help="Record a human analyst decision after review")
    decision.add_argument("case_id")
    decision.add_argument("finding_id")
    decision.add_argument("decision", choices=["accept", "reject", "needs_work"])
    decision.add_argument("--rationale", required=True)
    args = parser.parse_args()
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)
    if args.command == "serve":
        selected = providers(credentials(args.env_file), Path.cwd()) if args.enable_lookups else {}
        app = create_app(args.state, gateway_token(args.state), selected)
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", access_log=False)
    elif args.command == "connections":
        cached = args.output / "connections.json"
        if not args.live:
            print(
                json.dumps(
                    {
                        "configured_variables": sorted(credentials(args.env_file)),
                        "requests": 0,
                        "cached_report": str(cached) if cached.exists() else None,
                    }
                )
            )
        elif cached.exists() and not args.refresh:
            print(cached.read_text())
        else:
            print(
                json.dumps(
                    asyncio.run(validate_connections(credentials(args.env_file), args.output)),
                    indent=2,
                )
            )
    elif args.command == "smoke":
        print(
            json.dumps(
                asyncio.run(shodan_smoke(credentials(args.env_file), args.ip, args.output)),
                indent=2,
            )
        )
    else:
        gateway = Gateway(args.state)
        if args.command == "create":
            result = gateway.case_create(
                CaseSpec.model_validate(
                    {
                        "hypothesis": args.hypothesis,
                        "seeds": args.seed,
                        "start": args.start,
                        "end": args.end,
                        "limits": dict(args.limit),
                    }
                )
            )
        elif args.command == "status":
            result = gateway.case_read(args.case_id)
        elif args.command == "decide":
            result = gateway.analyst_decide(
                args.case_id, args.finding_id, args.decision, args.rationale
            )
        else:
            exported = gateway.case_export(args.case_id)
            args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
            for extension, key in [("md", "markdown"), ("json", "json"), ("csv", "csv")]:
                value = exported[key]
                descriptor = os.open(
                    args.output / f"{args.case_id}.{extension}",
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    os.fchmod(output.fileno(), 0o600)
                    output.write(json.dumps(value, indent=2) + "\n" if key == "json" else value)
            result = {"exported_to": str(args.output)}
        print(json.dumps(result, indent=2))


def main() -> None:
    try:
        _run()
    except (ValueError, FileExistsError, FileNotFoundError) as error:
        print(f"hunt: {error}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
