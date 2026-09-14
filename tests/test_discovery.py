import httpx
import pytest
from test_queries import case_spec, finished

from hunting_harness.gateway import Gateway
from hunting_harness.models import Expansion, QuerySpec
from hunting_harness.providers.shodan import Shodan


async def test_narrowing_keeps_all_candidates_and_incomplete_retrieval(tmp_path):
    raw = {
        "total": 101,
        "matches": [
            {"ip_str": "192.0.2.2", "timestamp": "2024-01-05", "port": 443, "data": "distinct"},
            {"ip_str": "192.0.2.3", "timestamp": "2024-01-06", "port": 443, "data": "common"},
        ]
        + [
            {"ip_str": f"198.51.100.{n}", "timestamp": "2024-01-06", "port": 443}
            for n in range(1, 99)
        ],
    }
    provider = Shodan(
        "fixture", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=raw))
    )
    async with Gateway(tmp_path, {"shodan": provider}) as gateway:
        case = gateway.case_create(case_spec())
        job = await gateway.query_submit(
            case["id"],
            QuerySpec(
                provider="shodan",
                operation="search",
                arguments={"query": "ssl:distinct"},
                pivot_from="192.0.2.1",
                purpose="Find recorded service reuse",
            ),
        )
        job = await finished(gateway, case["id"], job["id"])
        assert job["continuation"] == {"query": "ssl:distinct", "page": 2}
        case = gateway.case_read(case["id"])
        evidence = case["candidates"][0]["evidence_ids"]
        gateway.candidate_select(
            case["id"],
            Expansion(
                candidate="192.0.2.2",
                evidence_ids=evidence,
                hypothesis="Service reuse",
                rationale="Distinct fingerprint within campaign dates",
                relationship="service_fingerprint",
                distinctive=True,
            ),
        )
        retained = gateway.case_read(case["id"])["candidates"]
        assert [(c["indicator"], c["selected"]) for c in retained[:2]] == [
            ("192.0.2.2", True),
            ("192.0.2.3", False),
        ]
        assert len(retained) == 100
        assert sum(c["selected"] for c in retained) == 1
        with pytest.raises(ValueError, match="Shared infrastructure"):
            gateway.candidate_select(
                case["id"],
                Expansion(
                    candidate="192.0.2.3",
                    evidence_ids=retained[1]["evidence_ids"],
                    hypothesis="Same ASN",
                    rationale="Shared hosting",
                    relationship="asn",
                    distinctive=True,
                ),
            )


async def test_pagination_retains_both_pages_and_resolves_gap_without_duplicate_progress(tmp_path):
    from test_queries import FixtureSource

    from hunting_harness.providers.base import Observation, Page

    first = Observation(["192.0.2.2"], "2024-01-03", {"service": "unique"})
    second = Observation(["192.0.2.3"], None, {"service": "undated"})
    pages = [
        Page(
            [first],
            {"page": 1},
            complete=False,
            continuation={"cursor": "next"},
            api_requests=None,
            mcp_calls=1,
        ),
        Page([second], {"page": 2}, api_requests=None, mcp_calls=1),
        Page([second], {"page": 2}, api_requests=None, mcp_calls=1),
    ]
    async with Gateway(tmp_path, {"fixture": FixtureSource(pages)}) as gateway:
        case = gateway.case_create(case_spec())
        query = QuerySpec(
            provider="fixture",
            operation="lookup",
            arguments={},
            pivot_from="192.0.2.1",
            purpose="Search stored fingerprints",
        )
        first_job = await gateway.query_submit(case["id"], query)
        first_job = await finished(gateway, case["id"], first_job["id"])
        gateway.candidate_defer(case["id"], "192.0.2.2", "Weak service evidence")
        assert gateway.hunt_settle(case["id"])["status"] == "paused"
        gateway.case_resume(case["id"], refresh=True)
        continuation = query.model_copy(
            update={"arguments": first_job["continuation"], "continuation_of": first_job["id"]}
        )
        last = await gateway.query_submit(case["id"], continuation)
        await finished(gateway, case["id"], last["id"])
        gateway.candidate_defer(case["id"], "192.0.2.3", "Missing dates")
        assert gateway.hunt_settle(case["id"])["status"] == "completed"
        gateway.case_resume(case["id"], refresh=True)
        refreshed = await gateway.query_submit(
            case["id"], continuation.model_copy(update={"refresh": True})
        )
        refreshed = await finished(gateway, case["id"], refreshed["id"])
        assert refreshed["new_evidence_count"] == 0
        assert refreshed["new_candidate_count"] == 0
        assert gateway.hunt_settle(case["id"])["status"] == "completed"
    async with Gateway(tmp_path) as reopened:
        retained = reopened.case_read(case["id"])
        assert [c["indicator"] for c in retained["candidates"]] == ["192.0.2.2", "192.0.2.3"]
        assert len(retained["evidence"]) == 2
        assert retained["evidence"][1]["query_ids"] == [last["id"], refreshed["id"]]
        assert retained["source_gaps"][0]["resolved_by"] in (last["id"], refreshed["id"])
        assert retained["queries"][1]["pagination_root"] == first_job["id"]
