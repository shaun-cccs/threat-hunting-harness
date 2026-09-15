"""Evidence-linked narrowing and review invariants."""

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime
from typing import cast
from uuid import uuid4

from .models import Claim, Expansion, Record, Review, now

NAMESERVER = re.compile(r"^(?:ns|dns|nameserver)[0-9]*\.", re.IGNORECASE)


def candidate(case: Record, value: str) -> Record:
    for item in case["candidates"]:
        if item["indicator"] == value:
            return cast(Record, item)
    raise ValueError("Unknown candidate in this case")


def evidence_for(case: Record, value: str, ids: list[str]) -> list[Record]:
    retained = candidate(case, value)
    if not ids or not set(ids) <= set(retained["evidence_ids"]):
        raise ValueError("Evidence must belong to this candidate and case")
    return [e for e in case["evidence"] if e["id"] in ids]


def zone_authority_evidence(case: Record, value: str) -> list[Record]:
    """Retained signals that a candidate *serves* a zone rather than merely resolving under one.

    A host answering DNS, or named as a nameserver, is operator-controlled infrastructure. A
    host that only appears as an answer inside a zone may be a wildcard artefact. The two must
    never share a disposition, so this is checked before any narrowing is allowed to stand.
    """
    retained = candidate(case, value)
    ids = set(retained["evidence_ids"])
    signals: list[Record] = []

    def walk(node: object, evidence_id: str) -> None:
        if isinstance(node, dict):
            port, protocol = node.get("port"), str(node.get("protocol", "")).upper()
            if port == 53 or protocol == "DNS":
                signals.append({"evidence_id": evidence_id, "signal": "serves_dns", "port": port})
            for name in node.get("names", []) or []:
                if isinstance(name, str) and NAMESERVER.match(name):
                    signals.append(
                        {"evidence_id": evidence_id, "signal": "nameserver_name", "name": name}
                    )
            for child in node.values():
                walk(child, evidence_id)
        elif isinstance(node, list):
            for child in node:
                walk(child, evidence_id)

    for item in case["evidence"]:
        if item["id"] in ids:
            walk(item.get("raw"), item["id"])
    return signals


def observed_date(evidence: Record) -> str | None:
    """Only a parseable source observation date can support a temporal claim."""
    value = evidence.get("observed_at")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def independent_origins(evidence: list[Record]) -> int:
    """Collapse copied records, shared source identities, and records from one provider call.

    Several records returned by a single query are one origin, not several: they share the
    provider, the call and its coverage. Counting them separately inflates corroboration.
    """
    groups: list[set[str]] = []
    for item in evidence:
        keys = {
            "raw:" + hashlib.sha256(json.dumps(item["raw"], sort_keys=True).encode()).hexdigest()
        }
        if item.get("source_id"):
            keys.add("source:" + item["source_id"])
        keys |= {"query:" + query_id for query_id in item.get("query_ids", [])}
        overlapping = [group for group in groups if group & keys]
        for group in overlapping:
            groups.remove(group)
            keys |= group
        groups.append(keys)
    return len(groups)


def pivot_paths(case: Record, value: str, ids: list[str]) -> list[Record]:
    """Retain the supporting route back to a seed, without following graph cycles."""
    paths: list[Record] = []
    visited: set[str] = set()

    def visit(current: str, evidence_ids: list[str] | None = None) -> None:
        if current in visited:
            return
        visited.add(current)
        item = next((c for c in case["candidates"] if c["indicator"] == current), None)
        if item is None:
            return
        for path in item["pivot_paths"]:
            if evidence_ids is not None and path["evidence_id"] not in evidence_ids:
                continue
            paths.append({**path, "to": current})
            if path["from"] not in case["seeds"]:
                visit(path["from"])

    visit(value, ids)
    return paths


def select(case: Record, selection: Expansion) -> Record:
    if selection.relationship.strip().lower().replace(" ", "_") in (
        "asn",
        "hosting",
        "cdn",
        "shared_asn",
        "hosting_provider",
        "shared_hosting",
        "shared_cdn",
    ):
        raise ValueError("Shared infrastructure alone does not justify expansion")
    evidence = evidence_for(case, selection.candidate, selection.evidence_ids)
    dated = [
        e for e in evidence if (value := observed_date(e)) and case["start"] <= value <= case["end"]
    ]
    if not dated:
        raise ValueError("Expansion requires observations aligned with campaign dates")
    if not selection.distinctive and independent_origins(dated) < 2:
        raise ValueError("Expansion needs a distinctive relationship or independent sources")
    item = candidate(case, selection.candidate)
    expansion = {**selection.model_dump(), "recorded_at": now()}
    item.setdefault("selection_history", []).append(expansion)
    item.update(
        selected=True,
        expansion=expansion,
        needs_assessment=False,
        assessed_evidence_ids=list(item["evidence_ids"]),
    )
    return item


def propose(case: Record, claim: Claim) -> Record:
    evidence = evidence_for(case, claim.candidate, claim.evidence_ids)
    if claim.kind == "current_malicious_use":
        if not claim.freshness_start or not claim.freshness_end:
            raise ValueError(
                "Current-use claims require an explicit case-specific freshness window"
            )
        if claim.freshness_start > claim.freshness_end or not any(
            observed_date(e)
            and str(claim.freshness_start) <= str(observed_date(e)) <= str(claim.freshness_end)
            for e in evidence
        ):
            raise ValueError("No source evidence in the specified freshness window")
    if claim.kind == "historical_association" and not any(
        observed_date(e) and case["start"] <= str(observed_date(e)) <= case["end"] for e in evidence
    ):
        raise ValueError("Historical association requires evidence in the campaign window")
    if claim.kind == "attribution" and not (claim.attribution_basis or "").strip():
        raise ValueError(
            "Actor attribution requires an explicit basis beyond infrastructure relatedness"
        )
    paths = pivot_paths(case, claim.candidate, claim.evidence_ids)
    finding: Record = {
        **claim.model_dump(mode="json"),
        "id": uuid4().hex,
        "created_at": now(),
        "status": "awaiting_review",
        "reviews": [],
        "hypothesis": claim.hypothesis or case["hypothesis"],
        "observations": [
            {
                "evidence_id": e["id"],
                "provider": e["provider"],
                "source_id": e.get("source_id"),
                "observed_at": e.get("observed_at"),
                "date_status": "known" if observed_date(e) else "unknown",
                "retrieved_at": e["retrieved_at"],
                "query_ids": list(e["query_ids"]),
            }
            for e in evidence
        ],
        "independent_source_count": independent_origins(evidence),
        "pivot_paths": deepcopy(paths),
    }
    case["findings"].append(finding)
    return finding


def finding(case: Record, finding_id: str) -> Record:
    for item in case["findings"]:
        if item["id"] == finding_id:
            return cast(Record, item)
    raise ValueError("Unknown finding in this case")


def review(case: Record, finding_id: str, assessment: Review) -> Record:
    item = finding(case, finding_id)
    item["reviews"].append({**assessment.model_dump(), "recorded_at": now()})
    item["status"] = "awaiting_analyst"
    return item


def decide(case: Record, finding_id: str, decision: str, rationale: str) -> Record:
    if decision not in ("accept", "reject", "needs_work") or not rationale.strip():
        raise ValueError("An analyst decision and rationale are required")
    item = finding(case, finding_id)
    if not item["reviews"]:
        raise ValueError("Evidence review is required before an analyst decision")
    record: Record = {
        "finding_id": finding_id,
        "decision": decision,
        "rationale": rationale,
        "recorded_at": now(),
        "origin": "analyst_cli",
    }
    case["decisions"].append(record)
    item["status"] = {"accept": "accepted", "reject": "rejected", "needs_work": "needs_work"}[
        decision
    ]
    return record
