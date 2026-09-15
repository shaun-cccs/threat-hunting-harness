"""Reports and structured exports preserve candidate and review state."""

import csv
import html
import io
import json
import os
from copy import deepcopy
from pathlib import Path

from .models import Record


def write_exports(output_dir: Path, exported: Record) -> None:
    """Write a replay's report and structured case beside its retained artifacts."""
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {
        "report.md": exported["markdown"],
        "case.json": json.dumps(exported["json"], indent=2) + "\n",
        "candidates.csv": exported["csv"],
    }
    for name, content in files.items():
        descriptor = os.open(output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(content)


def escaped(value: object) -> str:
    return html.escape(str(value))


def details(value: object) -> list[str]:
    return ["    " + escaped(line) for line in json.dumps(value, indent=2).splitlines()]


def render(case: Record) -> Record:
    case = deepcopy(case)
    lines = [
        f"# Hunt {case['id']}",
        "",
        escaped(case["hypothesis"]),
        "",
        f"Campaign window: {case['start']} to {case['end']}",
        f"Status: {case['status']}",
        "",
        "Stopping/waiting reason: " + escaped(case.get("stopping_reason") or "None recorded"),
        "",
        "Seeds: " + ", ".join(case["seeds"]),
        "",
        "## Findings",
        "",
    ]
    if not case["findings"]:
        lines += [
            "No findings recorded. This does not establish absence of malicious activity.",
            "",
        ]
    for finding in case["findings"]:
        lines += [
            f"### {finding['candidate']}: {finding['kind']}",
            "",
            escaped(finding["statement"]),
            "",
            "Hypothesis: " + escaped(finding.get("hypothesis") or case["hypothesis"]),
            "",
            f"Review state: {finding['status']}",
            "",
            "Evidence: " + ", ".join(finding["evidence_ids"]),
            "",
            "Alternative explanations:",
            "",
        ]
        lines += ["- " + escaped(value) for value in finding["alternative_explanations"]]
        if finding["kind"] == "current_malicious_use":
            lines += [
                "",
                f"Case-specific freshness window: {finding['freshness_start']} "
                f"to {finding['freshness_end']}",
            ]
        if finding["kind"] == "attribution":
            lines += ["", "Attribution basis: " + escaped(finding.get("attribution_basis"))]
        lines += ["", "Evidence-backed pivot paths:", ""]
        for path in finding["pivot_paths"]:
            lines += [
                f"- {path['from']} → {path.get('to', finding['candidate'])}; "
                f"evidence {path['evidence_id']}; query {path['query_id']}"
            ]
        lines += ["", "Reviewer assessments:", ""]
        for review in finding["reviews"]:
            lines += [
                "- "
                + escaped(review["reviewer"])
                + ": "
                + escaped(review["assessment"])
                + " — "
                + escaped(review["rationale"])
            ]
            lines += ["  - Flag: " + escaped(flag) for flag in review.get("flags", [])]
            lines += [
                "  - Alternative: " + escaped(value)
                for value in review.get("alternative_explanations", [])
            ]
        lines += [""]

    lines += ["## Retained candidates", ""]
    table = io.StringIO()
    fields = [
        "indicator",
        "selected",
        "review_states",
        "claim_kinds",
        "observed_at",
        "evidence_ids",
        "query_ids",
        "historical_association",
        "current_malicious_use",
        "attribution",
        "analyst_decisions",
        "narrowing_rationale",
    ]
    writer = csv.DictWriter(table, fieldnames=fields)
    writer.writeheader()
    for candidate in case["candidates"]:
        evidence = [e for e in case["evidence"] if e["id"] in candidate["evidence_ids"]]
        findings = [f for f in case["findings"] if f["candidate"] == candidate["indicator"]]
        finding_ids = {f["id"] for f in findings}
        decisions = [d for d in case["decisions"] if d["finding_id"] in finding_ids]
        rationale = candidate.get("assessment", {}).get("rationale", "")
        row = {
            "indicator": candidate["indicator"],
            "selected": candidate["selected"],
            "review_states": ";".join(f["status"] for f in findings) or "candidate",
            "claim_kinds": ";".join(f["kind"] for f in findings),
            "observed_at": ";".join(e["observed_at"] or "unknown" for e in evidence),
            "evidence_ids": ";".join(candidate["evidence_ids"]),
            "query_ids": ";".join(sorted({q for e in evidence for q in e["query_ids"]})),
            "analyst_decisions": json.dumps(decisions),
            "narrowing_rationale": rationale,
        }
        for kind in ("historical_association", "current_malicious_use", "attribution"):
            row[kind] = ";".join(f["status"] for f in findings if f["kind"] == kind) or "unassessed"
        # Preserve text when CSV is opened in a spreadsheet.
        writer.writerow(
            {
                key: "'" + value
                if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                else value
                for key, value in row.items()
            }
        )
        lines.append(
            f"- {candidate['indicator']}: "
            + ("selected for expansion" if candidate["selected"] else "retained")
        )
        if rationale:
            lines += ["  - Narrowing rationale: " + escaped(rationale)]
        assessment = candidate.get("assessment") or {}
        if assessment:
            basis = assessment.get("basis", "uninspected")
            lines += [
                "  - Deferral basis: "
                + escaped(basis)
                + (" (open lead: deferred without inspection)" if basis == "uninspected" else "")
            ]
            if assessment.get("reopen_if"):
                lines += ["  - Reopen if: " + escaped(assessment["reopen_if"])]
            if assessment.get("zone_authority_signals"):
                lines += [
                    "  - Zone authority evidence retained: this candidate serves DNS or is named "
                    "as a nameserver, so it is operator infrastructure rather than an answer "
                    "inside a zone"
                ]
        if candidate.get("expansion"):
            lines += [
                "  - Expansion: "
                + escaped(candidate["expansion"]["hypothesis"])
                + "; "
                + escaped(candidate["expansion"]["rationale"])
            ]
        lines += ["  - Evidence: " + ", ".join(candidate["evidence_ids"])]

    for heading, value in (
        ("Investigation branches", case["branches"]),
        ("Coverage statements", case.get("coverage_statements", [])),
        ("Source gaps", case["source_gaps"]),
        ("Export gaps", case.get("export_gaps", [])),
        ("Analyst decisions", case["decisions"]),
    ):
        lines += ["", "## " + heading, "", *details(value)]
    lines += [
        "",
        "## Usage and limits",
        "",
        "Unknown accounting is null; a failed lookup is not a negative result.",
        "",
        *details(
            {
                "usage": case["usage"],
                "reservations": case.get("reservations", {}),
                "limits": case["limits"],
            }
        ),
        "",
        "## Query history",
        "",
    ]
    for query in case["queries"]:
        lines += [f"### Query {query['id']}", "", *details(query), ""]
    lines += [
        "",
        "## Source observations",
        "",
        "Observation dates are distinct from retrieval times. Missing dates remain unknown.",
        "Raw records are retained in structured JSON source_records and evidence fields.",
        "",
    ]
    for evidence in case["evidence"]:
        lines += [
            f"- {evidence['id']}: {evidence['provider']}; "
            f"observed {evidence['observed_at'] or 'unknown'}; "
            f"retrieved {evidence['retrieved_at']}; source "
            + escaped(evidence.get("source_id") or "unknown")
            + "; queries "
            + ", ".join(evidence["query_ids"])
        ]
        lines += [""] + details(evidence["raw"]) + [""]
    return {"markdown": "\n".join(lines) + "\n", "json": case, "csv": table.getvalue()}
