"""Case-oriented public interface used by MCP, the analyst CLI, and replay."""

import asyncio
import fcntl
import hashlib
import json
import os
import re
from copy import deepcopy
from pathlib import Path
from types import TracebackType
from typing import IO, Self, cast
from uuid import uuid4

from . import analysis, exports, lifecycle
from .models import (
    CaseSpec,
    Claim,
    Deferral,
    Expansion,
    QuerySpec,
    Record,
    Review,
    indicator,
    now,
)
from .providers.base import Page, Provider, SourceGap, observation_time
from .store import Store


class Gateway:
    def __init__(self, root: Path, providers: dict[str, Provider] | None = None):
        self.store = Store(root)
        self.providers = providers or {}
        self.tasks: set[asyncio.Task[None]] = set()
        self.worker_lock: IO[str] | None = None

    async def __aenter__(self) -> Self:
        lock = (self.store.root / "worker.lock").open("w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            raise ValueError("A gateway worker already owns this case directory") from None
        self.worker_lock = lock
        for case_id in self.store.case_ids():
            self.store.change(case_id, self._recover)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for case_id in self.store.case_ids():

            def interrupted(case: Record) -> None:
                for job in case["queries"]:
                    if job["status"] in ("queued", "active"):
                        self._fail(case, job["id"], "interrupted", "gateway_shutdown")

            self.store.change(case_id, interrupted)
        if self.worker_lock:
            self.worker_lock.close()
            self.worker_lock = None

    @staticmethod
    def _recover(case: Record) -> None:
        for job in case["queries"]:
            if job["status"] in ("queued", "active"):
                job.update(
                    status="interrupted",
                    gap="execution_uncertain_after_restart",
                    finished_at=now(),
                    accounting_status="uncertain_after_restart",
                )
                for measure in ("api_requests", "mcp_calls"):
                    job.setdefault("usage", {})[measure] = None
                case["source_gaps"].append({"query_id": job["id"], "reason": job["gap"]})
        for branch in case["branches"]:
            if branch["status"] == "active":
                branch.update(status="waiting", reason="Investigation interrupted by restart")
                branch["history"].append(
                    {"status": "waiting", "reason": branch["reason"], "recorded_at": now()}
                )

    def case_create(self, spec: CaseSpec) -> Record:
        return self.store.create(
            {
                **spec.model_dump(mode="json"),
                "id": uuid4().hex,
                "created_at": now(),
                "status": "active",
                "queries": [],
                "candidates": [],
                "evidence": [],
                "findings": [],
                "branches": [],
                "decisions": [],
                "source_gaps": [],
                "coverage_statements": [],
            }
        )

    SECTIONS = ("queries", "candidates", "evidence", "findings", "branches")
    FULL_LIMIT = 2_000_000

    def case_read(
        self,
        case_id: str,
        view: str = "summary",
        section: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> Record:
        """Read retained case state. Defaults to a digest; whole records are opt-in.

        A hunt accumulates every provider payload it retained, so the full record outgrows any
        single response. `view="summary"` omits raw evidence, `section` pages one list, and
        `view="full"` is refused past a size ceiling rather than failing mid-transfer.
        """
        if view not in ("summary", "full"):
            raise ValueError("View must be 'summary' or 'full'")
        case = self.store.read(case_id)
        case["usage"] = self._usage(case)
        case["reservations"] = {
            measure: self._reserved(case, measure) for measure in ("mcp_calls", "api_requests")
        }
        case["status_summary"] = self._status_summary(case)
        if section is not None:
            if section not in self.SECTIONS:
                raise ValueError(f"Section must be one of {', '.join(self.SECTIONS)}")
            if offset < 0 or limit < 1:
                raise ValueError("Offset must be positive and limit at least one")
            items = case[section][offset : offset + limit]
            if section == "evidence" and view == "full":
                self._hydrate(case_id, items)
            return {
                "case_id": case["id"],
                "section": section,
                "offset": offset,
                "limit": limit,
                "total": len(case[section]),
                "returned": len(items),
                "next_offset": (
                    offset + len(items) if offset + len(items) < len(case[section]) else None
                ),
                "items": items if view == "full" else [self._digest(section, i) for i in items],
                "status_summary": case["status_summary"],
            }
        if view == "full":
            self._hydrate(case_id, case["evidence"])
            size = len(json.dumps(case))
            if size > self.FULL_LIMIT:
                raise ValueError(
                    f"Retained case is {size} bytes, above the {self.FULL_LIMIT} response ceiling. "
                    "Read it a section at a time with section= and offset=, or use the default view"
                )
            return case
        for name in self.SECTIONS:
            case[name] = [self._digest(name, item) for item in case[name]]
        return case

    def _hydrate(self, case_id: str, evidence: list[Record]) -> list[Record]:
        """Attach retained payloads to these evidence records in one batched fetch.

        Payloads live outside the case document, so anything that actually reads `raw` asks for
        exactly the records it returns. Fetching per record instead would turn a paged read into
        one query per item.
        """
        if not evidence:
            return evidence
        payloads = self.store.read_raw(case_id, [item["id"] for item in evidence])
        for item in evidence:
            item["raw"] = payloads.get(item["id"])
        return evidence

    def _whole_case(self, case_id: str) -> Record:
        """Every retained field, for writers that are not bound by a response size ceiling."""
        case = self.store.read(case_id)
        self._hydrate(case_id, case["evidence"])
        case["usage"] = self._usage(case)
        case["reservations"] = {
            measure: self._reserved(case, measure) for measure in ("mcp_calls", "api_requests")
        }
        case["status_summary"] = self._status_summary(case)
        return case

    @staticmethod
    def _digest(section: str, item: Record) -> Record:
        """Drop retained provider payloads only.

        Everything a disposition or a continuation depends on stays: only `evidence[].raw`,
        which is the bulk of a grown case, is withheld until asked for.
        """
        if section == "evidence":
            return {k: v for k, v in item.items() if k != "raw"}
        return item

    @staticmethod
    def _status_summary(case: Record) -> Record:
        deferred = [c for c in case["candidates"] if not c["selected"] and c.get("assessment")]
        return {
            "retained_candidates": len(case["candidates"]),
            "selected_candidates": sum(bool(c["selected"]) for c in case["candidates"]),
            "deferral_bases": {
                basis: sum(
                    (c.get("assessment") or {}).get("basis", "uninspected") == basis
                    for c in deferred
                )
                for basis in ("prevalence", "out_of_scope", "uninspected")
            },
            "zone_authority_deferrals": [
                c["indicator"]
                for c in deferred
                if (c.get("assessment") or {}).get("zone_authority_signals")
            ],
            "findings_awaiting_review": sum(
                f["status"] == "awaiting_review" for f in case["findings"]
            ),
            "findings_awaiting_analyst": sum(
                f["status"] == "awaiting_analyst" for f in case["findings"]
            ),
            "analyst_decisions": len(case["decisions"]),
            "coverage_statements": len(case.get("coverage_statements", [])),
            "query_states": {
                state: sum(q["status"] == state for q in case["queries"])
                for state in ("queued", "active", "completed", "partial", "failed", "interrupted")
            },
            "branch_states": {
                state: sum(b["status"] == state for b in case["branches"])
                for state in ("queued", "active", "waiting", "completed")
            },
            "unresolved_source_gaps": sum(not g.get("resolved_by") for g in case["source_gaps"]),
        }

    @staticmethod
    def _reserved(case: Record, measure: str) -> int | None:
        values = [
            q.get("reservation", {}).get(measure)
            for q in case["queries"]
            if q["status"] == "queued"
        ]
        return None if any(value is None for value in values) else sum(values)

    @staticmethod
    def _usage(case: Record) -> Record:
        usage: Record = {"query_calls": len(case["queries"])}
        for measure in ("mcp_calls", "api_requests", "returned_records", "credits"):
            values = [q.get("usage", {}).get(measure) for q in case["queries"]]
            usage[measure] = None if any(v is None for v in values) else sum(values)
        return usage

    def provider_operations(self) -> Record:
        """List configured providers and their supported query operations."""
        return {name: provider.operations() for name, provider in self.providers.items()}

    def candidate_select(self, case_id: str, selection: Expansion) -> Record:
        """Select a retained candidate for expansion using evidence aligned with campaign dates."""
        return self.store.change(
            case_id,
            lambda c: analysis.select(c, selection),
            lambda c: list(selection.evidence_ids),
        )

    def finding_propose(self, case_id: str, claim: Claim) -> Record:
        """Propose a finding linked to retained evidence for subsequent review."""
        return self.store.change(
            case_id,
            lambda c: analysis.propose(c, claim),
            lambda c: list(claim.evidence_ids),
        )

    def finding_review(self, case_id: str, finding_id: str, review: Review) -> Record:
        """Record an evidence review of a finding before the analyst's decision."""
        return self.store.change(case_id, lambda c: analysis.review(c, finding_id, review))

    def analyst_decide(
        self, case_id: str, finding_id: str, decision: str, rationale: str
    ) -> Record:
        return self.store.change(
            case_id, lambda c: analysis.decide(c, finding_id, decision, rationale)
        )

    def candidate_defer(self, case_id: str, deferral: Deferral) -> Record:
        """Defer a candidate with its class, that class's evidence, and what would reopen it.

        A deferral without cited evidence is recorded as `uninspected` and reported as an open
        lead at settle: narrowing an unread candidate postpones the question, it does not answer it.
        """
        return self.store.change(
            case_id,
            lambda c: lifecycle.defer(c, deferral),
            lambda c: self._candidate_evidence_ids(c, indicator(deferral.candidate)),
        )

    @staticmethod
    def _candidate_evidence_ids(case: Record, value: str) -> list[str]:
        """The candidate's evidence, for a change that has to inspect retained payloads.

        An unknown candidate yields nothing so the change itself still raises, keeping the error
        the caller sees unchanged.
        """
        item = next((c for c in case["candidates"] if c["indicator"] == value), None)
        return list(item["evidence_ids"]) if item else []

    def coverage_record(
        self,
        case_id: str,
        subject: str,
        question: str,
        looked_at: list[str],
        not_covered: list[str],
    ) -> Record:
        """Record what a source could and could not answer, without asserting a finding.

        Non-detection belongs here. A provider that held no record of the subject supplies no
        evidence about it, so this states which providers, fields and dates were actually
        covered instead of letting silence read as a negative observation.
        """
        if not question.strip() or not looked_at:
            raise ValueError("A coverage statement needs a question and the sources consulted")
        statement: Record = {
            "id": uuid4().hex,
            "subject": indicator(subject),
            "question": question,
            "looked_at": list(looked_at),
            "not_covered": list(not_covered),
            "recorded_at": now(),
        }

        def append(case: Record) -> Record:
            case.setdefault("coverage_statements", []).append(statement)
            return statement

        return self.store.change(case_id, append)

    def branch_record(
        self,
        case_id: str,
        pivot: str,
        hypothesis: str,
        status: str,
        reason: str,
        branch_id: str | None = None,
        evidence_ids: list[str] | None = None,
        query_ids: list[str] | None = None,
    ) -> Record:
        """Create or update an investigation branch with its status, reason, and evidence scope."""
        return self.store.change(
            case_id,
            lambda c: lifecycle.branch(
                c, pivot, hypothesis, status, reason, branch_id, evidence_ids, query_ids
            ),
        )

    def hunt_settle(self, case_id: str) -> Record:
        """Assess remaining work and record whether the hunt is active, paused, or completed."""
        return self.store.change(case_id, lifecycle.settle)

    def case_resume(
        self, case_id: str, new_seeds: list[str] | None = None, refresh: bool = False
    ) -> Record:
        """Resume with new seeds or an explicit refresh without replaying provider queries."""
        return self.store.change(case_id, lambda c: lifecycle.resume(c, new_seeds or [], refresh))

    def case_export(self, case_id: str) -> Record:
        """Render retained case evidence and source records as Markdown, JSON, and CSV content."""
        case = self._whole_case(case_id)
        case["source_records"] = {}
        case["export_gaps"] = []
        for job in case["queries"]:
            if job.get("artifact"):
                artifact = self.store.root / case_id / f"{job['id']}.jsonl"
                try:
                    case["source_records"][job["id"]] = [
                        json.loads(line) for line in artifact.read_text().splitlines()
                    ]
                except (OSError, ValueError):
                    case["export_gaps"].append(
                        {"query_id": job["id"], "reason": "source_artifact_unavailable"}
                    )
        return exports.render(case)

    def job_read(self, case_id: str, job_id: str) -> Record:
        """Read a submitted query job's status, usage, and retained result metadata."""
        return self._job(self.case_read(case_id), job_id)

    @staticmethod
    def _job(case: Record, job_id: str) -> Record:
        for job in case["queries"]:
            if job["id"] == job_id:
                return cast(Record, job)
        raise ValueError("Unknown query in this case")

    async def query_submit(self, case_id: str, query: QuerySpec) -> Record:
        """Submit a provider query within shared case limits and return a job to poll with job_read.

        Matching submissions reuse retained jobs unless refresh is explicitly requested.
        Pagination requires a separate submission; results are retained before narrowing.
        """
        query = QuerySpec.model_validate(deepcopy(query.model_dump()))
        if self.worker_lock is None:
            raise ValueError("Start the gateway before submitting queries")
        provider = self.providers.get(query.provider)
        if provider is None:
            raise ValueError("Provider is not configured")
        provider.validate(query.operation, query.arguments)
        fingerprint = hashlib.sha256(
            json.dumps(
                [
                    query.provider,
                    provider.version,
                    query.operation,
                    query.arguments,
                    query.pivot_from,
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        reservation = {
            "api_requests": provider.api_requests_per_call,
            "mcp_calls": provider.mcp_calls_per_call,
        }
        job: Record = {
            **query.model_dump(),
            "id": uuid4().hex,
            "status": "queued",
            "created_at": now(),
            "provider_version": provider.version,
            "fingerprint": fingerprint,
            "reservation": reservation,
            "accounting_status": "reserved",
            "usage": {"api_requests": 0, "mcp_calls": 0, "returned_records": 0, "credits": None},
        }

        def insert(case: Record) -> Record:
            if case["status"] != "active":
                raise ValueError("Resume the case before submitting more queries")
            if query.pivot_from not in case["seeds"] and not any(
                c["indicator"] == query.pivot_from and c["selected"] for c in case["candidates"]
            ):
                raise ValueError("Queries must pivot from a seed or selected candidate")
            parent = self._continuation_parent(case, query)
            job["continuation_of"] = parent["id"] if parent else None
            job["pagination_root"] = (
                parent.get("pagination_root", parent["id"]) if parent else job["id"]
            )
            previous = [
                q
                for q in case["queries"]
                if q.get("fingerprint") == fingerprint
                and (not parent or q.get("continuation_of") == parent["id"])
            ]
            if previous and not query.refresh:
                if previous[-1]["status"] in ("failed", "interrupted"):
                    raise ValueError("An explicit refresh is required to retry this query")
                return cast(Record, previous[-1])
            usage = self._usage(case)
            for measure, limit in case["limits"].items():
                cost = 1 if measure == "query_calls" else reservation[measure]
                reserved = 0 if measure == "query_calls" else self._reserved(case, measure)
                if cost is None or usage[measure] is None or reserved is None:
                    raise ValueError(f"Cannot enforce {measure} limit for this provider")
                if usage[measure] + reserved + cost > limit:
                    raise ValueError(f"{measure} limit reached")
            job["refresh_of"] = [q["id"] for q in previous] if query.refresh else []
            case["queries"].append(job)
            return job

        retained = self.store.change(case_id, insert)
        if retained["id"] != job["id"]:
            return retained
        task = asyncio.create_task(self._execute(case_id, job["id"], query, provider))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    @staticmethod
    def _continuation_parent(case: Record, query: QuerySpec) -> Record | None:
        parents = [
            q
            for q in case["queries"]
            if q.get("continuation") == query.arguments
            and q["provider"] == query.provider
            and q["operation"] == query.operation
            and q["pivot_from"] == query.pivot_from
            and q["status"] == "partial"
        ]
        if query.continuation_of:
            parents = [q for q in parents if q["id"] == query.continuation_of]
            if not parents:
                raise ValueError("Continuation must match a retained query and its exact arguments")
        return cast(Record, parents[-1]) if parents else None

    async def _execute(
        self, case_id: str, job_id: str, query: QuerySpec, provider: Provider
    ) -> None:
        try:

            def started(case: Record) -> None:
                job = self._job(case, job_id)
                job.update(status="active", started_at=now(), accounting_status="dispatched")
                job["usage"].update(job["reservation"])
                job["usage"]["returned_records"] = None

            self.store.change(case_id, started)
            page = await provider.fetch(query.operation, query.arguments)
            artifact_dir = self.store.root / case_id
            artifact_dir.mkdir(mode=0o700, exist_ok=True)
            artifact = artifact_dir / f"{job_id}.jsonl"
            with artifact.open("x", encoding="utf-8") as output:
                os.chmod(artifact, 0o600)
                output.write(json.dumps(page.raw) + "\n")
                output.flush()
                os.fsync(output.fileno())
            self.store.change(case_id, lambda c: self._retain(c, job_id, query, page))
        except asyncio.CancelledError:
            self.store.change(
                case_id, lambda c: self._fail(c, job_id, "interrupted", "execution_interrupted")
            )
            raise
        except SourceGap as error:
            code = str(error)
            failure_usage = error.usage
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", code):
                code = "provider_unavailable"
            self.store.change(
                case_id, lambda c: self._fail(c, job_id, "failed", code, failure_usage)
            )
        except Exception:
            # Provider exceptions can contain request URLs or credentials. Keep them out of cases.
            self.store.change(
                case_id, lambda c: self._fail(c, job_id, "failed", "execution_or_retention_failed")
            )

    def _retain(self, case: Record, job_id: str, query: QuerySpec, page: Page) -> None:
        retrieved = now()
        new_evidence = 0
        new_candidates = 0
        for observation in page.records:
            values = list(dict.fromkeys(indicator(value) for value in observation.indicators))
            observed_at = observation_time(observation.observed_at)
            evidence_id = hashlib.sha256(
                json.dumps(
                    [
                        query.provider,
                        observation.raw,
                        observed_at,
                        observation.source_id,
                        sorted(values),
                    ],
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            evidence = next((e for e in case["evidence"] if e["id"] == evidence_id), None)
            if evidence is None:
                evidence = {
                    "id": evidence_id,
                    "provider": query.provider,
                    "observed_at": observed_at,
                    "retrieved_at": retrieved,
                    "date_status": "known" if observed_at else "unknown",
                    "raw": observation.raw,
                    "source_id": observation.source_id,
                    "query_ids": [],
                    "indicators": values,
                }
                case["evidence"].append(evidence)
                new_evidence += 1
            if job_id not in evidence["query_ids"]:
                evidence["query_ids"].append(job_id)
            for value in values:
                candidate = next((c for c in case["candidates"] if c["indicator"] == value), None)
                if candidate is None:
                    candidate = {
                        "indicator": value,
                        "selected": False,
                        "evidence_ids": [],
                        "pivot_paths": [],
                    }
                    case["candidates"].append(candidate)
                    new_candidates += 1
                if evidence_id not in candidate["evidence_ids"]:
                    candidate["evidence_ids"].append(evidence_id)
                    candidate["needs_assessment"] = True
                path = {"from": query.pivot_from, "query_id": job_id, "evidence_id": evidence_id}
                if path not in candidate["pivot_paths"]:
                    candidate["pivot_paths"].append(path)
        job = self._job(case, job_id)
        job.update(
            status="completed" if page.complete and not page.gap else "partial",
            finished_at=retrieved,
            complete=page.complete,
            continuation=page.continuation,
            gap=page.gap,
            artifact=f"{case['id']}/{job_id}.jsonl",
            usage={
                "api_requests": page.api_requests,
                "mcp_calls": page.mcp_calls,
                "returned_records": len(page.records),
                "credits": page.credits,
            },
            metadata=page.metadata,
        )
        job.update(
            accounting_status="reported",
            new_evidence_count=new_evidence,
            new_candidate_count=new_candidates,
            evidence_ids=[e["id"] for e in case["evidence"] if job_id in e["query_ids"]],
            candidate_indicators=[
                c["indicator"]
                for c in case["candidates"]
                if any(p["query_id"] == job_id for p in c["pivot_paths"])
            ],
        )
        parent_id = job.get("continuation_of")
        if parent_id:
            parent = self._job(case, parent_id)
            parent.setdefault("continued_by", []).append(job_id)
            for gap in case["source_gaps"]:
                if gap["query_id"] == parent_id and gap["reason"] == "incomplete_retrieval":
                    gap["resolved_by"] = job_id
        if page.gap or not page.complete:
            case["source_gaps"].append(
                {"query_id": job_id, "reason": page.gap or "incomplete_retrieval"}
            )
        else:
            recovered = job
            while True:
                for gap in case["source_gaps"]:
                    if gap["query_id"] in recovered.get("refresh_of", []):
                        gap["resolved_by"] = job_id
                parent_id = recovered.get("continuation_of")
                if not parent_id:
                    break
                parent = self._job(case, parent_id)
                # A final page recovers earlier refresh attempts only through
                # pages whose sole missing coverage was their continuation.
                if parent.get("gap") not in (None, "incomplete_retrieval"):
                    break
                recovered = parent

    @staticmethod
    def _fail(
        case: Record, job_id: str, status: str, reason: str, usage: Record | None = None
    ) -> None:
        job = Gateway._job(case, job_id)
        job.update(status=status, gap=reason, finished_at=now())
        if usage is not None:
            for measure in ("mcp_calls", "api_requests", "returned_records", "credits"):
                if measure in usage:
                    job["usage"][measure] = usage[measure]
            job["accounting_status"] = "reported"
        case["source_gaps"].append({"query_id": job_id, "reason": reason})
