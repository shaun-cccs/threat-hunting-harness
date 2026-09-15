import httpx
import pytest
from test_queries import case_spec, finished

from hunting_harness.gateway import Gateway
from hunting_harness.models import QuerySpec
from hunting_harness.providers.shodan import Shodan
from hunting_harness.shodan_fixture import ShodanFixtureTransport


async def test_source_gap_pauses_hunt_and_explicit_refresh_can_complete_it(tmp_path):
    responses = [httpx.Response(429), httpx.Response(200, json={"data": []})]
    provider = Shodan("fixture", transport=ShodanFixtureTransport(lambda r: responses.pop(0)))
    async with Gateway(tmp_path, {"shodan": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="shodan",
            operation="host",
            arguments={"ip": "192.0.2.1"},
            pivot_from="192.0.2.1",
            purpose="Recorded history",
        )
        job = await gateway.query_submit(case["id"], query)
        await finished(gateway, case["id"], job["id"])
        assert gateway.hunt_settle(case["id"])["status"] == "paused"
        gateway.case_resume(case["id"], refresh=True)
        with pytest.raises(ValueError, match="explicit refresh"):
            await gateway.query_submit(case["id"], query)
        retry = await gateway.query_submit(case["id"], query.model_copy(update={"refresh": True}))
        await finished(gateway, case["id"], retry["id"])
        assert gateway.hunt_settle(case["id"])["status"] == "completed"
        gateway.case_resume(case["id"], new_seeds=["new.example"])
        assert gateway.case_read(case["id"])["seeds"] == ["192.0.2.1", "new.example"]
        assert len(gateway.case_read(case["id"])["queries"]) == 2


async def test_independent_branch_at_same_pivot_keeps_its_query_scope_during_outage(tmp_path):
    def response(request):
        if "history" not in request.url.params:
            return httpx.Response(503)
        return httpx.Response(200, json={"data": []})

    provider = Shodan("fixture", transport=ShodanFixtureTransport(response))
    async with Gateway(tmp_path, {"shodan": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="shodan",
            operation="host",
            arguments={"ip": "192.0.2.1"},
            pivot_from="192.0.2.1",
            purpose="Historical observations",
        )
        success = await gateway.query_submit(case["id"], query)
        failed = await gateway.query_submit(
            case["id"],
            query.model_copy(update={"arguments": {"ip": "192.0.2.1", "history": False}}),
        )
        await finished(gateway, case["id"], success["id"])
        await finished(gateway, case["id"], failed["id"])
        branch = gateway.branch_record(
            case["id"],
            "192.0.2.1",
            "Historical reuse",
            "active",
            "Assess available history",
            query_ids=[success["id"]],
        )
        completed = gateway.branch_record(
            case["id"],
            "192.0.2.1",
            "Historical reuse",
            "completed",
            "Historical branch exhausted",
            branch_id=branch["id"],
        )
        assert completed["query_ids"] == [success["id"]]
        assert gateway.hunt_settle(case["id"])["status"] == "paused"
        assert gateway.case_read(case["id"])["source_gaps"][0]["query_id"] == failed["id"]


async def test_new_observation_requires_reassessment_and_updates_completed_branch_evidence(
    tmp_path,
):
    from test_queries import FixtureSource

    from hunting_harness.models import Expansion
    from hunting_harness.providers.base import Observation, Page

    provider = FixtureSource(
        [
            Page([Observation(["192.0.2.2"], "2024-01-03", {"service": "first"})], {}),
            Page([Observation(["192.0.2.2"], "2024-01-04", {"service": "new"})], {}),
        ]
    )
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="fixture",
            operation="lookup",
            arguments={},
            pivot_from="192.0.2.1",
            purpose="Recorded service",
        )
        first = await gateway.query_submit(case["id"], query)
        await finished(gateway, case["id"], first["id"])
        candidate = gateway.case_read(case["id"])["candidates"][0]
        selection = Expansion(
            candidate="192.0.2.2",
            evidence_ids=candidate["evidence_ids"],
            hypothesis="Service reuse",
            rationale="Distinctive dated service",
            relationship="service",
            distinctive=True,
        )
        gateway.candidate_select(case["id"], selection)
        branch = gateway.branch_record(
            case["id"], "192.0.2.2", "Service reuse", "completed", "No additional pivots"
        )
        assert gateway.hunt_settle(case["id"])["status"] == "completed"
        gateway.case_resume(case["id"], refresh=True)
        second = await gateway.query_submit(case["id"], query.model_copy(update={"refresh": True}))
        await finished(gateway, case["id"], second["id"])
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        candidate = gateway.case_read(case["id"])["candidates"][0]
        gateway.candidate_select(
            case["id"], selection.model_copy(update={"evidence_ids": candidate["evidence_ids"]})
        )
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        updated = gateway.branch_record(
            case["id"],
            "192.0.2.2",
            "Service reuse",
            "completed",
            "New evidence considered; no pivots",
            branch_id=branch["id"],
        )
        assert set(updated["evidence_ids"]) == set(candidate["evidence_ids"])
        assert gateway.hunt_settle(case["id"])["status"] == "completed"


@pytest.mark.parametrize("page_gap", [None, "restricted_records"])
async def test_paginated_refresh_resolves_failure_only_after_complete_recovery(tmp_path, page_gap):
    from test_queries import FixtureSource

    from hunting_harness.providers.base import Page, SourceGap

    class InitiallyUnavailable(FixtureSource):
        async def fetch(self, operation, arguments):
            if self.calls == 0:
                self.calls += 1
                raise SourceGap("provider_rate_limited")
            return await super().fetch(operation, arguments)

    provider = InitiallyUnavailable(
        [
            Page(
                [],
                {"page": 1},
                complete=False,
                continuation={"cursor": "second"},
                gap=page_gap,
                metadata={"coverage_gaps": ["history_bounds_unknown"]},
            ),
            Page([], {"page": 2}, complete=False, continuation={"cursor": "last"}),
            Page([], {"page": 3}),
        ]
    )
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="fixture",
            operation="lookup",
            arguments={},
            pivot_from="192.0.2.1",
            purpose="Recover recorded search",
        )
        failed = await gateway.query_submit(case["id"], query)
        await finished(gateway, case["id"], failed["id"])
        assert gateway.hunt_settle(case["id"])["status"] == "paused"
        gateway.case_resume(case["id"], refresh=True)
        refreshed = await gateway.query_submit(
            case["id"], query.model_copy(update={"refresh": True})
        )
        refreshed = await finished(gateway, case["id"], refreshed["id"])
        next_job = await gateway.query_submit(
            case["id"],
            query.model_copy(
                update={"arguments": refreshed["continuation"], "continuation_of": refreshed["id"]}
            ),
        )
        next_job = await finished(gateway, case["id"], next_job["id"])
        case = gateway.case_read(case["id"])
        failure_gap = next(g for g in case["source_gaps"] if g["query_id"] == failed["id"])
        assert "resolved_by" not in failure_gap
        assert gateway.hunt_settle(case["id"])["status"] == "paused"
    async with Gateway(tmp_path, {"fixture": provider}) as reopened:
        reopened.case_resume(case["id"], refresh=True)
        final = await reopened.query_submit(
            case["id"],
            query.model_copy(
                update={"arguments": next_job["continuation"], "continuation_of": next_job["id"]}
            ),
        )
        await finished(reopened, case["id"], final["id"])
        retained = reopened.case_read(case["id"])
        failure_gap = next(g for g in retained["source_gaps"] if g["query_id"] == failed["id"])
        if page_gap is None:
            assert failure_gap["resolved_by"] == final["id"]
            assert reopened.hunt_settle(case["id"])["status"] == "completed"
        else:
            assert "resolved_by" not in failure_gap
            restricted = next(g for g in retained["source_gaps"] if g["reason"] == page_gap)
            assert "resolved_by" not in restricted
            assert reopened.hunt_settle(case["id"])["status"] == "paused"
        assert retained["queries"][1]["metadata"]["coverage_gaps"] == ["history_bounds_unknown"]


async def test_completed_scoped_branches_jointly_cover_candidate_without_hiding_pending_work(
    tmp_path,
):
    from test_queries import FixtureSource

    from hunting_harness.models import Expansion
    from hunting_harness.providers.base import Observation, Page

    provider = FixtureSource(
        [
            Page(
                [
                    Observation(["192.0.2.2"], "2024-01-03", {"service": "A"}),
                    Observation(["192.0.2.2"], "2024-01-04", {"service": "B"}),
                ],
                {},
            ),
            Page([Observation(["192.0.2.2"], "2024-01-05", {"service": "C"})], {}),
        ]
    )
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="fixture",
            operation="lookup",
            arguments={},
            pivot_from="192.0.2.1",
            purpose="Gather candidate services",
        )
        first = await gateway.query_submit(case["id"], query)
        await finished(gateway, case["id"], first["id"])
        candidate = gateway.case_read(case["id"])["candidates"][0]
        selection = Expansion(
            candidate="192.0.2.2",
            evidence_ids=candidate["evidence_ids"],
            hypothesis="Service reuse",
            rationale="Distinct dated services",
            relationship="service",
            distinctive=True,
        )
        gateway.candidate_select(case["id"], selection)
        first_branch = gateway.branch_record(
            case["id"],
            "192.0.2.2",
            "Service A",
            "completed",
            "Assessed A",
            evidence_ids=[candidate["evidence_ids"][0]],
            query_ids=[],
        )
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        second_branch = gateway.branch_record(
            case["id"],
            "192.0.2.2",
            "Service B",
            "queued",
            "Assess B next",
            evidence_ids=[candidate["evidence_ids"][1]],
            query_ids=[],
        )
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        gateway.branch_record(
            case["id"],
            "192.0.2.2",
            "Service B",
            "waiting",
            "Waiting for B review",
            branch_id=second_branch["id"],
        )
        assert gateway.hunt_settle(case["id"])["status"] == "paused"
        gateway.branch_record(
            case["id"],
            "192.0.2.2",
            "Service B",
            "completed",
            "Assessed B",
            branch_id=second_branch["id"],
        )
        assert gateway.hunt_settle(case["id"])["status"] == "completed"
        gateway.case_resume(case["id"], refresh=True)
        refresh = await gateway.query_submit(case["id"], query.model_copy(update={"refresh": True}))
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        await finished(gateway, case["id"], refresh["id"])
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        candidate = gateway.case_read(case["id"])["candidates"][0]
        gateway.candidate_select(
            case["id"], selection.model_copy(update={"evidence_ids": candidate["evidence_ids"]})
        )
        assert gateway.hunt_settle(case["id"])["status"] == "active"
        gateway.branch_record(
            case["id"],
            "192.0.2.2",
            "Service C",
            "completed",
            "Assessed new C",
            evidence_ids=[candidate["evidence_ids"][2]],
            query_ids=[],
        )
        assert gateway.hunt_settle(case["id"])["status"] == "completed"
        retained = gateway.case_read(case["id"])
        assert retained["branches"][0]["id"] == first_branch["id"]
        assert retained["branches"][0]["completed_evidence_ids"] == [candidate["evidence_ids"][0]]


def _deferrable(tmp_path, raw):
    """A case holding one non-seed candidate with one retained evidence record."""
    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())
    evidence = {
        "id": "e1",
        "raw": raw,
        "provider": "fixture",
        "query_ids": ["q1"],
        "retrieved_at": "2026-01-05T00:00:00+00:00",
        "observed_at": "2026-01-05T00:00:00+00:00",
        "indicators": ["192.0.2.9"],
    }
    candidate = {
        "indicator": "192.0.2.9",
        "selected": False,
        "evidence_ids": ["e1"],
        "pivot_paths": [],
        "needs_assessment": True,
    }

    def seed(record):
        record["evidence"].append(evidence)
        record["candidates"].append(candidate)
        return record

    gateway.store.change(case["id"], seed)
    return gateway, case


def test_uninspected_deferral_is_an_open_lead_rather_than_a_disposition(tmp_path):
    from hunting_harness.models import Deferral

    gateway, case = _deferrable(tmp_path, {"services": [{"port": 443, "protocol": "HTTP"}]})
    gateway.candidate_defer(
        case["id"], Deferral(candidate="192.0.2.9", rationale="Nothing flagged it")
    )
    settled = gateway.hunt_settle(case["id"])
    assert settled["status"] == "paused"
    assert settled["open_questions"]["uninspected_deferrals"] == ["192.0.2.9"]
    assert "deferred without being inspected" in settled["reason"]
    assert gateway.case_read(case["id"])["status_summary"]["deferral_bases"]["uninspected"] == 1


def test_inspected_deferral_with_cited_evidence_lets_a_hunt_complete(tmp_path):
    from hunting_harness.models import Deferral

    gateway, case = _deferrable(tmp_path, {"services": [{"port": 443, "protocol": "HTTP"}]})
    gateway.candidate_defer(
        case["id"],
        Deferral(
            candidate="192.0.2.9",
            rationale="Inspected: default banner, explained by prevalence",
            basis="prevalence",
            basis_evidence_ids=["e1"],
            reopen_if="A distinctive dated observation is retained",
        ),
    )
    settled = gateway.hunt_settle(case["id"])
    assert settled["status"] == "completed"
    assert settled["open_questions"]["uninspected_deferrals"] == []


def test_conclusive_deferral_basis_requires_retained_evidence(tmp_path):
    from hunting_harness.models import Deferral

    with pytest.raises(ValueError, match="conclusive deferral basis needs retained evidence"):
        Deferral(candidate="192.0.2.9", rationale="Common technology", basis="prevalence")


def test_deferring_zone_authority_evidence_cannot_settle_a_hunt(tmp_path):
    from hunting_harness.models import Deferral

    gateway, case = _deferrable(
        tmp_path,
        {
            "services": [{"port": 53, "protocol": "DNS"}],
            "dns": {"names": ["ns1.example.com"]},
        },
    )
    gateway.candidate_defer(
        case["id"],
        Deferral(
            candidate="192.0.2.9",
            rationale="Looks like consumer CPE",
            basis="out_of_scope",
            basis_evidence_ids=["e1"],
        ),
    )
    settled = gateway.hunt_settle(case["id"])
    assert settled["status"] == "paused"
    assert settled["open_questions"]["zone_authority_deferrals"] == ["192.0.2.9"]
    assert "zone-authority evidence" in settled["reason"]
    signals = gateway.case_read(case["id"])["candidates"][0]["assessment"]["zone_authority_signals"]
    assert {s["signal"] for s in signals} == {"serves_dns", "nameserver_name"}
