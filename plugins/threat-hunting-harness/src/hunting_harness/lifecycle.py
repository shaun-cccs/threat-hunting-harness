"""Natural stopping and explicit resumption without replaying provider work."""

from uuid import uuid4

from .analysis import candidate, evidence_for, zone_authority_evidence
from .models import Deferral, Record, indicator, now


def defer(case: Record, deferral: Deferral) -> Record:
    """Narrowing states a class, its evidence, and what would reopen it.

    An unstructured deferral is recorded as `uninspected`: a backlog item, not a disposition.
    Settling reports such a candidate as an open lead rather than treating it as explained.
    """
    item = candidate(case, indicator(deferral.candidate))
    if deferral.basis_evidence_ids:
        evidence_for(case, item["indicator"], deferral.basis_evidence_ids)
    authority = zone_authority_evidence(case, item["indicator"])
    assessment = {
        "rationale": deferral.rationale,
        "basis": deferral.basis,
        "basis_evidence_ids": list(deferral.basis_evidence_ids),
        "reopen_if": deferral.reopen_if,
        "zone_authority_signals": authority,
        "recorded_at": now(),
    }
    item.setdefault("selection_history", []).append({"selected": False, **assessment})
    item.update(
        selected=False,
        assessment=assessment,
        needs_assessment=False,
        assessed_evidence_ids=list(item["evidence_ids"]),
    )
    return item


def branch(
    case: Record,
    pivot: str,
    hypothesis: str,
    status: str,
    reason: str,
    branch_id: str | None,
    evidence_ids: list[str] | None = None,
    query_ids: list[str] | None = None,
) -> Record:
    pivot = indicator(pivot)
    if status not in ("queued", "active", "waiting", "completed") or not reason.strip():
        raise ValueError("A valid branch status and reason are required")
    if pivot not in case["seeds"] and not candidate(case, pivot)["selected"]:
        raise ValueError("A branch must start from a seed or selected candidate")
    if not hypothesis.strip():
        raise ValueError("A branch needs a hypothesis")
    item = None
    if branch_id:
        item = next((b for b in case["branches"] if b["id"] == branch_id), None)
        if item is None or item["pivot"] != pivot:
            raise ValueError("Unknown branch for this pivot")
        if item.get("explicit_query_scope") and query_ids is None:
            query_ids = item["query_ids"]
        if item.get("explicit_evidence_scope") and evidence_ids is None:
            evidence_ids = item.get("evidence_ids")
    explicit_query_scope = query_ids is not None
    explicit_evidence_scope = evidence_ids is not None
    jobs = {q["id"]: q for q in case["queries"] if q["pivot_from"] == pivot}
    if query_ids is not None:
        if not set(query_ids) <= jobs.keys():
            raise ValueError("Branch queries must belong to this case and pivot")
        jobs = {key: jobs[key] for key in query_ids}
    if evidence_ids is not None and not set(evidence_ids) <= {
        e["id"]
        for e in case["evidence"]
        if pivot in e["indicators"] or set(e["query_ids"]) & jobs.keys()
    }:
        raise ValueError("Branch evidence must belong to this case and pivot")
    if status == "completed" and (
        any(q["status"] in ("queued", "active") for q in jobs.values())
        or any(g["query_id"] in jobs and not g.get("resolved_by") for g in case["source_gaps"])
    ):
        raise ValueError("The branch still has active work or unresolved source gaps")
    if item is None:
        item = {"id": uuid4().hex, "pivot": pivot, "hypothesis": hypothesis, "history": []}
        case["branches"].append(item)
    retained = next((c for c in case["candidates"] if c["indicator"] == pivot), None)
    covered = list(retained["evidence_ids"]) if retained else []
    item.update(
        status=status,
        reason=reason,
        hypothesis=hypothesis,
        query_ids=list(jobs),
        explicit_query_scope=explicit_query_scope,
        explicit_evidence_scope=explicit_evidence_scope,
        evidence_ids=evidence_ids
        if evidence_ids is not None
        else list(
            dict.fromkeys(
                covered + [e["id"] for e in case["evidence"] if set(e["query_ids"]) & jobs.keys()]
            )
        ),
    )
    if status == "completed":
        item["completed_evidence_ids"] = [
            value for value in covered if value in item["evidence_ids"]
        ]
    item["history"].append(
        {
            "status": status,
            "reason": reason,
            "recorded_at": now(),
            "hypothesis": hypothesis,
            "query_ids": list(jobs),
            "evidence_ids": list(item["evidence_ids"]),
        }
    )
    if status in ("queued", "active"):
        case.update(status="active", stopping_reason=None)
    return dict(item)


def settle(case: Record) -> Record:
    pending_queries = any(q["status"] in ("queued", "active") for q in case["queries"])
    pending_branches = any(b["status"] in ("queued", "active") for b in case["branches"])
    unassessed = any(
        c["indicator"] not in case["seeds"]
        and (c.get("needs_assessment") or (not c.get("expansion") and not c.get("assessment")))
        for c in case["candidates"]
    )
    unexpanded = any(
        c["selected"]
        and not set(c["evidence_ids"])
        <= {
            evidence_id
            for b in case["branches"]
            if b["pivot"] == c["indicator"] and b["status"] == "completed"
            for evidence_id in b.get("completed_evidence_ids", b.get("evidence_ids", []))
        }
        for c in case["candidates"]
    )
    open_leads = [
        c["indicator"]
        for c in case["candidates"]
        if not c["selected"]
        and (c.get("assessment") or {}).get("basis", "uninspected") == "uninspected"
    ]
    contradicted = [
        c["indicator"]
        for c in case["candidates"]
        if not c["selected"] and (c.get("assessment") or {}).get("zone_authority_signals")
    ]
    waiting = (
        any(not g.get("resolved_by") for g in case["source_gaps"])
        or any(b["status"] == "waiting" for b in case["branches"])
        or bool(open_leads)
        or bool(contradicted)
    )
    if pending_queries or pending_branches or unassessed:
        status, reason = (
            "active",
            "Queries, investigation branches, or candidate assessments remain",
        )
    elif unexpanded:
        independent = any(
            c["selected"]
            and not any(
                b["pivot"] == c["indicator"] and b["status"] in ("waiting", "completed")
                for b in case["branches"]
            )
            for c in case["candidates"]
        )
        status = "active" if independent or not waiting else "paused"
        reason = "Selected candidates still need completed investigation branches"
    elif contradicted:
        status, reason = (
            "paused",
            "Deferred candidates carry zone-authority evidence and need a disposition",
        )
    elif open_leads:
        status, reason = (
            "paused",
            "Candidates were deferred without being inspected; they remain open leads",
        )
    elif waiting:
        status, reason = (
            "paused",
            "Remaining work depends on unavailable or incomplete observations",
        )
    else:
        status, reason = (
            "completed",
            "No further candidates meet expansion criteria; no work is waiting",
        )
    case.update(status=status, stopping_reason=reason)
    return {
        "status": status,
        "reason": reason,
        "open_questions": {
            "uninspected_deferrals": open_leads,
            "zone_authority_deferrals": contradicted,
            "unresolved_source_gaps": [
                g["reason"] for g in case["source_gaps"] if not g.get("resolved_by")
            ],
        },
    }


def resume(case: Record, new_seeds: list[str], refresh: bool) -> Record:
    seeds = [indicator(seed) for seed in new_seeds]
    if not refresh and not any(seed not in case["seeds"] for seed in seeds):
        raise ValueError("Resume requires new inputs or an explicit refresh")
    case["seeds"] = list(dict.fromkeys(case["seeds"] + seeds))
    case.update(status="active", stopping_reason=None)
    case.setdefault("resumptions", []).append(
        {"new_seeds": seeds, "refresh": refresh, "recorded_at": now()}
    )
    return {"id": case["id"], "status": "active", "seeds": case["seeds"]}
