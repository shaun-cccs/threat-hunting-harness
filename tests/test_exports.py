import csv
import io

from test_queries import case_spec

from hunting_harness.gateway import Gateway


def test_export_keeps_case_status_and_unknown_costs_without_mutating_case(tmp_path):
    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())
    before = gateway.case_read(case["id"])
    exported = gateway.case_export(case["id"])
    assert exported["json"]["status"] == "active"
    assert "2024-01-01" in exported["markdown"]
    assert "Service reuse" in exported["markdown"]
    assert list(csv.DictReader(io.StringIO(exported["csv"]))) == []
    assert gateway.case_read(case["id"]) == before


async def test_case_export_preserves_narrowed_candidates_history_gaps_and_decisions(tmp_path):
    from test_queries import FixtureSource, finished

    from hunting_harness.models import Claim, Expansion, QuerySpec, Review
    from hunting_harness.providers.base import Observation, Page

    records = [
        Observation(["192.0.2.2"], "2024-01-03", {"banner": "distinct"}),
        Observation(["192.0.2.2"], "2025-01-03", {"banner": "reassigned"}),
        Observation(["192.0.2.3"], None, {"banner": "common"}),
    ]
    provider = FixtureSource(
        [
            Page(
                records,
                {"records": [r.raw for r in records]},
                complete=False,
                gap="provider_rate_limited",
                api_requests=None,
                mcp_calls=1,
            )
        ]
    )
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        case = gateway.case_create(case_spec().model_copy(update={"limits": {"mcp_calls": 5}}))
        job = await gateway.query_submit(
            case["id"],
            QuerySpec(
                provider="fixture",
                operation="lookup",
                arguments={},
                pivot_from="192.0.2.1",
                purpose="Recorded fingerprint search",
            ),
        )
        await finished(gateway, case["id"], job["id"])
        candidate = gateway.case_read(case["id"])["candidates"][0]
        gateway.candidate_select(
            case["id"],
            Expansion(
                candidate="192.0.2.2",
                evidence_ids=candidate["evidence_ids"],
                hypothesis="Service reuse",
                rationale="Distinct dated banner",
                relationship="service_fingerprint",
                distinctive=True,
            ),
        )
        gateway.candidate_defer(case["id"], "192.0.2.3", "Undated common service")
        finding = gateway.finding_propose(
            case["id"],
            Claim(
                candidate="192.0.2.2",
                kind="historical_association",
                statement="Campaign-era association",
                evidence_ids=candidate["evidence_ids"],
                alternative_explanations=["Later reassignment"],
            ),
        )
        gateway.finding_review(
            case["id"],
            finding["id"],
            Review(
                reviewer="reviewer",
                assessment="supported",
                rationale="History only",
                flags=["reassignment"],
            ),
        )
        gateway.analyst_decide(case["id"], finding["id"], "accept", "Accept historical claim only")
        before = gateway.case_read(case["id"])
        exported = gateway.case_export(case["id"])
        assert gateway.case_read(case["id"]) == before
        assert exported["json"]["status"] == "active"
        assert exported["json"]["usage"]["api_requests"] is None
        assert exported["json"]["usage"]["credits"] is None
        assert exported["json"]["source_records"][job["id"]][0]["records"][1] == {
            "banner": "reassigned"
        }
        rows = list(csv.DictReader(io.StringIO(exported["csv"])))
        assert [(row["indicator"], row["selected"]) for row in rows] == [
            ("192.0.2.2", "True"),
            ("192.0.2.3", "False"),
        ]
        assert rows[0]["historical_association"] == "accepted"
        assert rows[0]["current_malicious_use"] == "unassessed"
        assert rows[1]["observed_at"] == "unknown"
        report = exported["markdown"]
        for text in (
            "Service reuse",
            "2024-01-01",
            "192.0.2.1 → 192.0.2.2",
            "Later reassignment",
            "provider_rate_limited",
            "Accept historical claim only",
            "Query history",
            "observed unknown",
            "mcp_calls",
            "reassigned",
            job["id"],
        ):
            assert text in report
