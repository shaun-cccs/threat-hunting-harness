import httpx
import pytest
from test_queries import case_spec, finished

from hunting_harness.gateway import Gateway
from hunting_harness.models import Claim, QuerySpec, Review
from hunting_harness.providers.shodan import Shodan


async def test_review_and_analyst_decision_preserve_historical_claim_and_evidence(tmp_path):
    provider = Shodan(
        "fixture",
        transport=httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "ip_str": "192.0.2.1",
                            "timestamp": "2024-01-03",
                            "data": "historical service",
                        }
                    ]
                },
            )
        ),
    )
    async with Gateway(tmp_path, {"shodan": provider}) as gateway:
        case = gateway.case_create(case_spec())
        job = await gateway.query_submit(
            case["id"],
            QuerySpec(
                provider="shodan",
                operation="host",
                arguments={"ip": "192.0.2.1"},
                pivot_from="192.0.2.1",
                purpose="Historical evidence",
            ),
        )
        await finished(gateway, case["id"], job["id"])
        evidence = gateway.case_read(case["id"])["evidence"][0]
        claim = Claim(
            candidate="192.0.2.1",
            kind="historical_association",
            statement="Service present during campaign",
            evidence_ids=[evidence["id"]],
            alternative_explanations=["Host may have been reassigned since then"],
        )
        finding = gateway.finding_propose(case["id"], claim)
        gateway.finding_review(
            case["id"],
            finding["id"],
            Review(
                reviewer="evidence-reviewer",
                assessment="supported",
                rationale="Dated service; current use remains unknown",
            ),
        )
        gateway.analyst_decide(case["id"], finding["id"], "accept", "Accept historical link only")
        reopened = gateway.case_read(case["id"])
        assert reopened["findings"][0]["kind"] == "historical_association"
        assert reopened["decisions"][0]["decision"] == "accept"
        assert len(reopened["evidence"]) == 1
        with pytest.raises(ValueError, match="freshness"):
            gateway.finding_propose(
                case["id"], claim.model_copy(update={"kind": "current_malicious_use"})
            )
        with pytest.raises(ValueError, match="attribution"):
            gateway.finding_propose(case["id"], claim.model_copy(update={"kind": "attribution"}))


async def test_conflicting_and_undated_observations_survive_review_and_rejection(tmp_path):
    from test_queries import FixtureSource

    from hunting_harness.providers.base import Observation, Page

    records = [
        Observation(["192.0.2.2"], "2024-01-03", {"service": "campaign"}, "report-a"),
        Observation(["192.0.2.2"], "2025-06-01", {"service": "new owner"}, "report-b"),
        Observation(["192.0.2.2"], None, {"service": "unknown date"}, "report-c"),
    ]
    provider = FixtureSource([Page(records, {"observations": [r.raw for r in records]})])
    async with Gateway(tmp_path, {"fixture": provider}) as gateway:
        case = gateway.case_create(case_spec())
        job = await gateway.query_submit(
            case["id"],
            QuerySpec(
                provider="fixture",
                operation="lookup",
                arguments={},
                pivot_from="192.0.2.1",
                purpose="Assess historical association and reassignment",
            ),
        )
        await finished(gateway, case["id"], job["id"])
        evidence = gateway.case_read(case["id"])["evidence"]
        historical = gateway.finding_propose(
            case["id"],
            Claim(
                candidate="192.0.2.2",
                kind="historical_association",
                statement="Historical service reuse",
                evidence_ids=[e["id"] for e in evidence],
                alternative_explanations=["Host reassigned after campaign"],
            ),
        )
        assert historical["observations"][2]["date_status"] == "unknown"
        assert historical["pivot_paths"][0]["from"] == "192.0.2.1"
        review = Review(
            reviewer="separate-reviewer",
            assessment="challenged",
            rationale="New owner contradicts continuing malicious use",
            flags=["reassignment", "conflicting_observations", "missing_dates"],
        )
        gateway.finding_review(case["id"], historical["id"], review)
        gateway.analyst_decide(
            case["id"], historical["id"], "accept", "Historical association only"
        )
        attribution = gateway.finding_propose(
            case["id"],
            Claim(
                candidate="192.0.2.2",
                kind="attribution",
                statement="Possible actor link",
                evidence_ids=[evidence[0]["id"]],
                attribution_basis="Analyst hypothesis from service reuse",
                alternative_explanations=["Unrelated customer on shared infrastructure"],
            ),
        )
        gateway.finding_review(
            case["id"],
            attribution["id"],
            Review(
                reviewer="separate-reviewer",
                assessment="insufficient",
                rationale="Service reuse cannot identify an actor",
                flags=["unsupported_attribution"],
            ),
        )
        gateway.analyst_decide(case["id"], attribution["id"], "reject", "Attribution unsupported")
        with pytest.raises(ValueError, match="No source evidence"):
            gateway.finding_propose(
                case["id"],
                Claim(
                    candidate="192.0.2.2",
                    kind="current_malicious_use",
                    statement="Current malicious use",
                    evidence_ids=[evidence[0]["id"]],
                    freshness_start="2025-01-01",
                    freshness_end="2025-12-31",
                    alternative_explanations=["Stale service"],
                ),
            )
        retained = gateway.case_read(case["id"])
        assert len(retained["evidence"]) == 3
        assert [f["status"] for f in retained["findings"]] == ["accepted", "rejected"]
        assert retained["status_summary"]["analyst_decisions"] == 2
        assert len(retained["candidates"]) == 1


async def test_copied_reports_and_reviewer_agreement_do_not_add_source_independence(tmp_path):
    from test_queries import FixtureSource

    from hunting_harness.models import Expansion
    from hunting_harness.providers.base import Observation, Page

    raw = {"report": "Copied original report"}
    records = [Observation(["192.0.2.2"], "2024-01-03", raw, "original-report")]
    async with Gateway(
        tmp_path,
        {
            "first": FixtureSource([Page(records, raw)]),
            "second": FixtureSource([Page(records, raw)]),
        },
    ) as gateway:
        case = gateway.case_create(case_spec())
        for provider in ("first", "second"):
            job = await gateway.query_submit(
                case["id"],
                QuerySpec(
                    provider=provider,
                    operation="lookup",
                    arguments={},
                    pivot_from="192.0.2.1",
                    purpose="Compare reports",
                ),
            )
            await finished(gateway, case["id"], job["id"])
        evidence = gateway.case_read(case["id"])["evidence"]
        with pytest.raises(ValueError, match="independent"):
            gateway.candidate_select(
                case["id"],
                Expansion(
                    candidate="192.0.2.2",
                    evidence_ids=[e["id"] for e in evidence],
                    hypothesis="Repeated report",
                    rationale="Two providers",
                    relationship="service",
                ),
            )
        finding = gateway.finding_propose(
            case["id"],
            Claim(
                candidate="192.0.2.2",
                kind="relatedness",
                statement="Possible reuse",
                evidence_ids=[e["id"] for e in evidence],
                alternative_explanations=["Copied reports"],
            ),
        )
        for reviewer in ("reviewer-a", "reviewer-b"):
            gateway.finding_review(
                case["id"],
                finding["id"],
                Review(
                    reviewer=reviewer, assessment="supported", rationale="Agreement on same report"
                ),
            )
        retained = gateway.case_read(case["id"])
        assert retained["findings"][0]["independent_source_count"] == 1
        assert len(retained["evidence"]) == 2
