"""Reproducible offline campaign replay against an enrichment-only baseline.

The supplied corpus uses cited campaign indicators and explicitly synthetic Shodan
responses. This measures pipeline behavior, not model quality or live source coverage.
Ground truth is read only after both investigator workflows have finished.
"""

import hashlib
import json
import platform
import re
import time
from pathlib import Path
from typing import cast

import httpx
from starlette.applications import Starlette

from .exports import write_exports
from .models import CaseSpec, Record, indicator
from .providers.shodan import Shodan
from .replay import ReplaySession, replay_session
from .server import create_app


class EvaluationError(ValueError):
    """Invalid or incomparable benchmark input."""


def _json(path: Path) -> Record:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise EvaluationError("Benchmark documents must contain JSON objects")
    return cast(Record, value)


def _save(path: Path, value: Record | list[Record]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_campaigns(benchmark_root: Path) -> list[Record]:
    """Return seed-only manifests. Withheld truth and provider responses remain separate."""
    campaigns = []
    for path in sorted((benchmark_root / "campaigns").glob("*.json")):
        campaign = _json(path)
        case_id = campaign.get("id", "")
        if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", case_id):
            raise EvaluationError("Campaign IDs must be safe lowercase names")
        if path.stem != case_id or campaign.get("schema_version") != 1:
            raise EvaluationError("Campaign identity or schema version is invalid")
        if "withheld" in campaign or "truth" in campaign:
            raise EvaluationError("Investigator manifests must not contain withheld answers")
        CaseSpec.model_validate(
            {k: campaign[k] for k in ("hypothesis", "seeds", "start", "end", "limits")}
        )
        if not campaign.get("sources"):
            raise EvaluationError("Campaigns must cite their evidence sources")
        fixture = benchmark_root / campaign["observation_fixture"]
        if not fixture.resolve().is_relative_to((benchmark_root / "observations").resolve()):
            raise EvaluationError("Observation fixtures must stay in the observations directory")
        if not fixture.is_file():
            raise EvaluationError("Campaign observation fixture is missing")
        campaigns.append(campaign)
    if not campaigns:
        raise EvaluationError("No campaign manifests found")
    return campaigns


def _provider(fixture: Record) -> Shodan:
    if fixture.get("kind") != "synthetic_shodan" or fixture.get("schema_version") != 1:
        raise EvaluationError("Only versioned synthetic Shodan replay is supported")

    def respond(request: httpx.Request) -> httpx.Response:
        if request.method != "GET" or request.url.host != "api.shodan.io":
            raise EvaluationError("Unexpected replay transport request")
        if request.url.path == "/shodan/host/search":
            query = request.url.params["query"]
            result = fixture["searches"].get(query)
            if result is None or request.url.params.get("page", "1") != "1":
                return httpx.Response(400, json={"error": "unrecorded_fixture_query"})
            return httpx.Response(200, json=result)
        if request.url.path.startswith("/shodan/host/"):
            ip = request.url.path.removeprefix("/shodan/host/")
            if ip in fixture.get("fail_hosts", {}):
                return httpx.Response(fixture["fail_hosts"][ip])
            return httpx.Response(200, json=fixture["hosts"].get(ip, {"data": []}))
        return httpx.Response(400, json={"error": "unsupported_fixture_operation"})

    return Shodan("fixture-only", transport=httpx.MockTransport(respond))


def _fingerprint(evidence: Record) -> str | None:
    value = evidence["raw"].get("ssl", {}).get("cert", {}).get("fingerprint", {}).get("sha256")
    return value if isinstance(value, str) else None


def _in_window(evidence: Record, campaign: Record) -> bool:
    observed = evidence["observed_at"]
    return bool(observed and campaign["start"] <= observed[:10] <= campaign["end"])


async def _query(
    session: ReplaySession, case_id: str, pivot: str, operation: str, arguments: Record
) -> Record:
    job = await session.call(
        "query_submit",
        {
            "case_id": case_id,
            "query": {
                "provider": "shodan",
                "operation": operation,
                "arguments": arguments,
                "pivot_from": pivot,
                "purpose": "Existing synthetic observations for benchmark replay",
            },
        },
    )
    return await session.finished(case_id, job)


async def _run(campaign: Record, fixture: Record, output: Path, mode: str) -> Record:
    output.mkdir(parents=True, exist_ok=False)
    _save(output / "investigator-input.json", campaign)
    transcript: list[Record] = []
    started = time.perf_counter()
    app = create_app(output / "cases", "fixture-token-" * 4, {"shodan": _provider(fixture)})
    transport = cast(Starlette, app.app)
    findings: list[Record] = []
    async with transport.router.lifespan_context(transport):
        async with replay_session(cast(Starlette, app), "coordinator", transcript) as coordinator:
            case = await coordinator.call(
                "case_create",
                {
                    "spec": {
                        key: campaign[key]
                        for key in ("hypothesis", "seeds", "start", "end", "limits")
                    }
                },
            )
            case_id = case["id"]
            await coordinator.call("playbooks")
            await coordinator.call("provider_operations")
            async with replay_session(
                cast(Starlette, app), "investigator", transcript
            ) as investigator:
                for seed in campaign["seeds"]:
                    branch = await coordinator.call(
                        "branch_record",
                        {
                            "case_id": case_id,
                            "pivot": seed,
                            "hypothesis": campaign["hypothesis"],
                            "status": "active",
                            "reason": f"{mode}: assigned seed history branch",
                        },
                    )
                    job = await _query(investigator, case_id, seed, "host", {"ip": seed})
                    if mode == "coordinated" and job["status"] in ("completed", "partial"):
                        state = await investigator.call("case_read", {"case_id": case_id})
                        fingerprints = sorted(
                            {
                                fingerprint
                                for evidence in state["evidence"]
                                if seed in evidence["indicators"]
                                and (fingerprint := _fingerprint(evidence))
                                and _in_window(evidence, campaign)
                            }
                        )
                        for fingerprint in fingerprints:
                            await _query(
                                investigator,
                                case_id,
                                seed,
                                "search",
                                {
                                    "query": f'ssl.cert.fingerprint:"{fingerprint}"',
                                    "page": 1,
                                },
                            )
                        await _investigate(investigator, campaign, case_id, fingerprints, findings)
                    state = await investigator.call("case_read", {"case_id": case_id})
                    seed_jobs = [q for q in state["queries"] if q["pivot_from"] == seed]
                    waiting = any(q["status"] in ("failed", "partial") for q in seed_jobs)
                    await investigator.call(
                        "branch_record",
                        {
                            "case_id": case_id,
                            "pivot": seed,
                            "hypothesis": campaign["hypothesis"],
                            "status": "waiting" if waiting else "completed",
                            "branch_id": branch["id"],
                            "reason": "Source gap remains"
                            if waiting
                            else "Planned seed work retained",
                            "query_ids": [q["id"] for q in seed_jobs],
                        },
                    )
            async with replay_session(
                cast(Starlette, app), "evidence-reviewer", transcript
            ) as reviewer:
                evidence_state = await reviewer.call("case_read", {"case_id": case_id})
                for finding in findings:
                    evidence = [
                        e for e in evidence_state["evidence"] if e["id"] in finding["evidence_ids"]
                    ]
                    supported = any(_in_window(e, campaign) and _fingerprint(e) for e in evidence)
                    await reviewer.call(
                        "finding_review",
                        {
                            "case_id": case_id,
                            "finding_id": finding["id"],
                            "review": {
                                "reviewer": "scripted-independent-evidence-reviewer",
                                "assessment": "supported" if supported else "challenged",
                                "rationale": (
                                    "Dated synthetic fingerprint supports relatedness only. "
                                    "Fixture availability after the window is retrospective "
                                    "leakage; no current-use or actor-ownership claim."
                                ),
                            },
                        },
                    )
            await coordinator.call("hunt_settle", {"case_id": case_id})
            exported = await coordinator.call("case_export", {"case_id": case_id})
    elapsed = time.perf_counter() - started
    write_exports(output, exported)
    _save(output / "transcript.json", transcript)
    case = exported["json"]
    return {
        "mode": mode,
        "case": case,
        "elapsed_seconds": elapsed,
        "gateway_mcp_tool_calls": len(transcript),
        "artifact_directory": str(output),
    }


async def _investigate(
    session: ReplaySession,
    campaign: Record,
    case_id: str,
    fingerprints: list[str],
    findings: list[Record],
) -> None:
    state = await session.call("case_read", {"case_id": case_id})
    for candidate in state["candidates"]:
        value = candidate["indicator"]
        if value in campaign["seeds"] or candidate.get("assessment") or candidate.get("expansion"):
            continue
        evidence = [
            e
            for e in state["evidence"]
            if e["id"] in candidate["evidence_ids"]
            and _in_window(e, campaign)
            and _fingerprint(e) in fingerprints
        ]
        if not evidence:
            await session.call(
                "candidate_defer",
                {
                    "case_id": case_id,
                    "candidate": value,
                    "rationale": "No distinctive dated fingerprint linking to seed observations",
                },
            )
            continue
        ids = [e["id"] for e in evidence]
        await session.call(
            "candidate_select",
            {
                "case_id": case_id,
                "selection": {
                    "candidate": value,
                    "evidence_ids": ids,
                    "hypothesis": campaign["hypothesis"],
                    "rationale": "Matching distinctive synthetic fingerprint inside campaign dates",
                    "relationship": "certificate",
                    "distinctive": True,
                },
            },
        )
        branch = await session.call(
            "branch_record",
            {
                "case_id": case_id,
                "pivot": value,
                "hypothesis": campaign["hypothesis"],
                "status": "active",
                "reason": "Validate selected candidate using recorded host history",
                "evidence_ids": ids,
            },
        )
        job = await _query(session, case_id, value, "host", {"ip": value})
        findings.append(
            await session.call(
                "finding_propose",
                {
                    "case_id": case_id,
                    "claim": {
                        "candidate": value,
                        "kind": "historical_association",
                        "statement": "Dated synthetic fingerprint links candidate and seed.",
                        "evidence_ids": ids,
                        "alternative_explanations": [
                            "Shared certificate",
                            "Copied service configuration",
                            "Reassignment after the reported period",
                        ],
                    },
                },
            )
        )
        await session.call(
            "branch_record",
            {
                "case_id": case_id,
                "pivot": value,
                "hypothesis": campaign["hypothesis"],
                "status": "completed" if job["status"] == "completed" else "waiting",
                "reason": "Recorded fixture history retained"
                if job["status"] == "completed"
                else "Host history unavailable; retain search observations and source gap",
                "branch_id": branch["id"],
                "evidence_ids": ids,
                "query_ids": [job["id"]],
            },
        )


def _traceable(case: Record, finding: Record, *, contemporaneous: bool = False) -> bool:
    """Follow retained paths to seeds, checking each edge's query and observation IDs."""
    evidence = {e["id"]: e for e in case["evidence"]}
    queries = {q["id"]: q for q in case["queries"]}
    reached = set(case["seeds"])
    linked_finding = False
    while True:
        before = len(reached)
        for candidate in case["candidates"]:
            for path in candidate["pivot_paths"]:
                observation = evidence.get(path["evidence_id"])
                query = queries.get(path["query_id"])
                if contemporaneous and observation:
                    available = observation["raw"].get("fixture", {}).get("available_at")
                    if not available or available[:10] > case["end"]:
                        continue
                    if not _in_window(observation, case):
                        continue
                if (
                    path["from"] in reached
                    and observation
                    and query
                    and query["pivot_from"] == path["from"]
                    and query["id"] in observation["query_ids"]
                    and candidate["indicator"] in observation["indicators"]
                ):
                    reached.add(candidate["indicator"])
                    if (
                        candidate["indicator"] == finding["candidate"]
                        and observation["id"] in finding["evidence_ids"]
                    ):
                        linked_finding = True
        if len(reached) == before:
            break
    return (
        finding["candidate"] in reached
        and linked_finding
        and bool(finding["evidence_ids"])
        and all(
            eid in evidence and finding["candidate"] in evidence[eid]["indicators"]
            for eid in finding["evidence_ids"]
        )
    )


def score_run(case: Record, truth: Record) -> Record:
    """Score reviewed, traceable discoveries; never turn missing assessments into acceptance."""
    seeds = set(case["seeds"])
    withheld = {indicator(value) for value in truth["withheld"]} - seeds
    credited: set[str] = set()
    eligible_in_window: set[str] = set()
    rejected_paths = []
    for finding in case["findings"]:
        if finding["candidate"] in seeds or not finding.get("reviews"):
            continue
        if finding["reviews"][-1]["assessment"] != "supported":
            continue
        if not _traceable(case, finding):
            rejected_paths.append(finding["id"])
            continue
        credited.add(finding["candidate"])
        if _traceable(case, finding, contemporaneous=True):
            eligible_in_window.add(finding["candidate"])
    additional = credited - withheld
    assessments = truth.get("analyst_assessments")
    accepted = assessed = None
    if assessments is not None:
        reviewed = {indicator(k): v for k, v in assessments.items() if indicator(k) in additional}
        if any(v not in ("accept", "reject", "needs_work") for v in reviewed.values()):
            raise EvaluationError("Invalid analyst assessment")
        assessed = len(reviewed)
        accepted = sum(v == "accept" for v in reviewed.values())
    temporal = []
    for evidence in case["evidence"]:
        available = evidence["raw"].get("fixture", {}).get("available_at")
        temporal.append(
            {
                "evidence_id": evidence["id"],
                "observed_at": evidence["observed_at"],
                "available_at": available,
                "retrieved_at": evidence["retrieved_at"],
                "observed_within_window": _in_window(evidence, case),
                "availability": "unknown"
                if not available
                else ("post_window" if available[:10] > case["end"] else "by_window_end"),
                "synthetic": bool(evidence["raw"].get("fixture", {}).get("synthetic")),
            }
        )
    return {
        "withheld_total": len(withheld),
        "withheld_recovered": len(credited & withheld),
        "withheld_recall": len(credited & withheld) / len(withheld) if withheld else None,
        "credited_discoveries": sorted(credited),
        "additional_candidates": sorted(additional),
        "in_window_available_withheld_recovered": len(eligible_in_window & withheld),
        "untraceable_findings_excluded": rejected_paths,
        "analyst_assessed_additional": assessed,
        "analyst_accepted_additional": accepted,
        "analyst_acceptance_rate": accepted / assessed
        if assessed and accepted is not None
        else None,
        "usage": case["usage"],
        "provider_credit_cost": case["usage"].get("credits"),
        "monetary_cost": None,
        "model_tokens": None,
        "temporal_evidence": temporal,
        "source_gaps": case["source_gaps"],
        "status": case["status"],
        "findings_awaiting_analyst": sum(
            f["status"] == "awaiting_analyst" for f in case["findings"]
        ),
    }


async def evaluate(
    benchmark_root: Path, output_dir: Path, case_ids: list[str] | None = None
) -> Record:
    """Run both policies with identical source fixtures, then score against withheld truth."""
    campaigns = load_campaigns(benchmark_root)
    known = {campaign["id"] for campaign in campaigns}
    if case_ids is not None and (not case_ids or not set(case_ids) <= known):
        raise EvaluationError("Requested benchmark case is unknown or the selection is empty")
    selected = [c for c in campaigns if case_ids is None or c["id"] in case_ids]
    output_dir.mkdir(parents=True, exist_ok=False)
    results = []
    for campaign in selected:
        case_id = campaign["id"]
        source = benchmark_root / campaign["observation_fixture"]
        fixture = _json(source)
        # Both runs see the same fixture object and public seed-only input. Neither receives truth.
        baseline = await _run(campaign, fixture, output_dir / case_id / "baseline", "baseline")
        coordinated = await _run(
            campaign, fixture, output_dir / case_id / "coordinated", "coordinated"
        )
        truth_path = benchmark_root / "truth" / f"{case_id}.json"
        truth = _json(truth_path)
        if truth.get("id") != case_id or truth.get("schema_version") != 1:
            raise EvaluationError("Truth identity or schema version does not match campaign")
        _save(output_dir / case_id / "evaluator-only-truth.json", truth)
        _save(output_dir / case_id / "source-fixture.json", fixture)
        modes = {}
        for run in (baseline, coordinated):
            scored = {
                **score_run(run["case"], truth),
                "elapsed_seconds": run["elapsed_seconds"],
                "gateway_mcp_tool_calls": run["gateway_mcp_tool_calls"],
                "artifact_directory": run["artifact_directory"],
            }
            _save(Path(run["artifact_directory"]) / "metrics.json", scored)
            modes[run["mode"]] = scored
        results.append(
            {
                "campaign_id": case_id,
                "modes": modes,
                "input_sha256": _digest(benchmark_root / "campaigns" / f"{case_id}.json"),
                "observations_sha256": _digest(source),
                "truth_sha256": _digest(truth_path),
                "conditions": campaign["conditions"],
            }
        )
    report: Record = {
        "schema_version": 1,
        "validation": "synthetic_campaign_pipeline_replay",
        "python_version": platform.python_version(),
        "results": results,
        "live_provider_calls": 0,
        "models_launched": False,
        "acceptance_thresholds": {
            "status": "not_established",
            "values": None,
            "reason": "Synthetic replay is not empirical discovery performance. "
            "Set targets only after real coverage and analyst assessment.",
        },
    }
    _save(output_dir / "evaluation.json", report)
    lines = [
        "# Offline campaign evaluation",
        "",
        "Synthetic Shodan observations; scripted MCP roles; no model or live provider calls.",
        "",
        "| Campaign | Mode | Withheld recovery | Query calls | Seconds | Credits |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for result in results:
        for mode, metrics in result["modes"].items():
            credit_cost = metrics["provider_credit_cost"]
            credit_cost = "unknown" if credit_cost is None else credit_cost
            lines.append(
                f"| {result['campaign_id']} | {mode} | "
                f"{metrics['withheld_recovered']}/{metrics['withheld_total']} | "
                f"{metrics['usage']['query_calls']} | {metrics['elapsed_seconds']:.4f} | "
                f"{credit_cost} |"
            )
    lines += [
        "",
        "Analyst acceptance and monetary/model costs are unmeasured. "
        "Temporal leakage is recorded per observation in metrics.json. "
        "Elapsed time measures local replay, not analyst or live hunt duration. "
        "No empirical performance thresholds have been established.",
        "",
    ]
    (output_dir / "report.md").write_text("\n".join(lines))
    return report
