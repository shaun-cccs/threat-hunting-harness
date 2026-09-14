"""Evaluation public APIs: identical observations, withheld truth, and retained metrics."""

import json
from pathlib import Path

from hunting_harness.evaluation import evaluate

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"


async def test_partial_source_coverage_still_permits_evidence_backed_discovery(tmp_path):
    report = await evaluate(BENCHMARKS, tmp_path / "run", ["lazarus-simplextea-2023"])
    result = report["results"][0]
    baseline, hunt = result["modes"]["baseline"], result["modes"]["coordinated"]
    assert baseline["withheld_recovered"] == 0
    assert hunt["withheld_recovered"] == 1
    assert hunt["status"] == "paused"
    assert hunt["usage"]["query_calls"] == 3
    assert hunt["source_gaps"]
    assert hunt["provider_credit_cost"] is None
    assert hunt["analyst_acceptance_rate"] is None
    assert hunt["in_window_available_withheld_recovered"] == 0
    case = json.loads((tmp_path / "run/lazarus-simplextea-2023/coordinated/case.json").read_text())
    assert len(case["candidates"]) == 4
    assert case["findings"][0]["reviews"][0]["assessment"] == "supported"
    assert case["findings"][0]["pivot_paths"]
    assert case["decisions"] == []


def test_scoring_excludes_seeds_duplicates_and_paths_learned_after_the_window():
    from hunting_harness.evaluation import score_run

    case = {
        "seeds": ["192.0.2.1"],
        "start": "2024-01-01",
        "end": "2024-01-31",
        "queries": [
            {"id": "q1", "pivot_from": "192.0.2.1"},
            {"id": "q2", "pivot_from": "192.0.2.2"},
        ],
        "evidence": [
            {
                "id": "e1",
                "indicators": ["192.0.2.2"],
                "query_ids": ["q1"],
                "observed_at": "2024-01-15",
                "retrieved_at": "2024-03-01",
                "raw": {"fixture": {"available_at": "2024-02-15"}},
            },
            {
                "id": "e2",
                "indicators": ["192.0.2.3"],
                "query_ids": ["q2"],
                "observed_at": "2024-01-15",
                "retrieved_at": "2024-03-01",
                "raw": {"fixture": {"available_at": "2024-01-20"}},
            },
        ],
        "candidates": [
            {
                "indicator": "192.0.2.2",
                "pivot_paths": [{"from": "192.0.2.1", "query_id": "q1", "evidence_id": "e1"}],
            },
            {
                "indicator": "192.0.2.3",
                "pivot_paths": [{"from": "192.0.2.2", "query_id": "q2", "evidence_id": "e2"}],
            },
        ],
        "findings": [
            {
                "id": name,
                "candidate": "192.0.2.3",
                "evidence_ids": ["e2"],
                "reviews": [{"assessment": "supported"}],
                "status": "awaiting_analyst",
            }
            for name in ("first", "duplicate")
        ]
        + [
            {
                "id": "seed",
                "candidate": "192.0.2.1",
                "evidence_ids": ["e1"],
                "reviews": [{"assessment": "supported"}],
                "status": "awaiting_analyst",
            }
        ],
        "source_gaps": [],
        "status": "completed",
        "usage": {"credits": None},
    }
    truth = {"withheld": ["192.0.2.3"], "analyst_assessments": None}
    result = score_run(case, truth)
    assert result["credited_discoveries"] == ["192.0.2.3"]
    assert result["withheld_recovered"] == 1
    assert result["in_window_available_withheld_recovered"] == 0
    case["candidates"][0]["pivot_paths"] = []
    assert score_run(case, truth)["withheld_recovered"] == 0


async def test_all_campaigns_retain_comparable_inputs_truth_and_review_artifacts(tmp_path):
    from hunting_harness.evaluation import load_campaigns

    campaigns = load_campaigns(BENCHMARKS)
    assert len(campaigns) == 3
    assert all("withheld" not in campaign and campaign["sources"] for campaign in campaigns)
    report = await evaluate(BENCHMARKS, tmp_path / "run")
    assert report["models_launched"] is False
    assert report["live_provider_calls"] == 0
    assert report["acceptance_thresholds"]["values"] is None
    for result in report["results"]:
        root = tmp_path / "run" / result["campaign_id"]
        assert (root / "baseline/investigator-input.json").read_text() == (
            root / "coordinated/investigator-input.json"
        ).read_text()
        assert (root / "evaluator-only-truth.json").exists()
        assert (root / "source-fixture.json").exists()
        for mode in ("baseline", "coordinated"):
            metrics = result["modes"][mode]
            assert metrics["elapsed_seconds"] >= 0
            assert metrics["provider_credit_cost"] is None
            assert metrics["analyst_assessed_additional"] is None
            assert metrics["temporal_evidence"]
            assert all(e["availability"] == "post_window" for e in metrics["temporal_evidence"])
            assert (root / mode / "report.md").exists()
            assert (root / mode / "candidates.csv").exists()
            assert (root / mode / "transcript.json").exists()
            assert "withheld" not in (root / mode / "investigator-input.json").read_text()
        assert result["modes"]["baseline"]["withheld_recovered"] == 0
        assert result["modes"]["coordinated"]["withheld_recovered"] == 1
