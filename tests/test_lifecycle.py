import httpx
import pytest
from test_queries import case_spec, finished

from hunting_harness.gateway import Gateway
from hunting_harness.models import QuerySpec
from hunting_harness.providers.shodan import Shodan


async def test_source_gap_pauses_hunt_and_explicit_refresh_can_complete_it(tmp_path):
    responses = [httpx.Response(429), httpx.Response(200, json={"data": []})]
    provider = Shodan("fixture", transport=httpx.MockTransport(lambda r: responses.pop(0)))
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
        if request.url.params.get("history") == "false":
            return httpx.Response(503)
        return httpx.Response(200, json={"data": []})

    provider = Shodan("fixture", transport=httpx.MockTransport(response))
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
