"""Provider public contract, exercised against synthetic external MCP responses."""

import json
import sys
from pathlib import Path

import pytest

from hunting_harness.providers.base import SourceGap
from hunting_harness.providers.mcp_source import McpSource
from hunting_harness.providers.transport import McpTransport


def source(name, payload, *, error=False, changed_schema=False):
    return McpSource(
        name,
        McpTransport(
            command=sys.executable,
            args=[str(Path(__file__).parent / "fixtures/provider_server.py")],
            env={
                "FIXTURE_PROVIDER": name,
                "FIXTURE_PAYLOAD": json.dumps(payload),
                "FIXTURE_ERROR": str(error),
                "FIXTURE_SCHEMA_CHANGED": str(changed_schema),
            },
        ),
    )


async def test_censys_retains_valid_hosts_when_another_certificate_record_is_malformed():
    raw = {
        "result": json.dumps(
            {
                "result": {
                    "hits": [
                        {
                            "host": {
                                "ip": "192.0.2.7",
                                "services": [
                                    {
                                        "observed_at": "2024-01-05T00:00:00Z",
                                        "cert": {"fingerprint_sha256": "a" * 64},
                                    },
                                ],
                            }
                        },
                        {"host": {"ip": "192.0.2.8", "services": [None]}},
                    ],
                    "next_page_token": "next",
                }
            }
        )
    }
    page = await source("censys", raw).fetch("search", {"query": "host.services.cert:a"})
    assert page.records[0].indicators == ["192.0.2.7"]
    assert page.records[0].observed_at == "2024-01-05T00:00:00+00:00"
    assert page.raw == raw
    assert page.complete is False
    assert page.continuation == {"query": "host.services.cert:a", "page_token": "next"}
    assert page.gap == "unrecognized_provider_records"


async def test_empty_gti_relationship_response_is_a_successful_empty_retrieval():
    page = await source("gti", []).fetch(
        "get_entities_related_to_a_domain",
        {
            "domain": "seed.example",
            "relationship_name": "resolutions",
            "descriptors_only": False,
            "limit": 10,
        },
    )
    assert page.records == []
    assert page.complete is True
    assert page.gap is None
    assert page.api_requests is None


async def test_malformed_gti_row_does_not_discard_preceding_dated_resolution():
    raw = [
        {
            "id": "dns-1",
            "type": "resolution",
            "attributes": {
                "ip_address": "192.0.2.5",
                "host_name": "seed.example",
                "date": 1704585600,
            },
        },
        {"id": "dns-2", "type": "resolution", "attributes": "malformed"},
    ]
    page = await source("gti", raw).fetch(
        "get_entities_related_to_a_domain",
        {
            "domain": "seed.example",
            "relationship_name": "resolutions",
            "descriptors_only": False,
            "limit": 10,
        },
    )
    assert page.records[0].indicators == ["192.0.2.5", "seed.example"]
    assert page.records[0].observed_at == "2024-01-07T00:00:00+00:00"
    assert page.raw == raw
    assert page.complete is False
    assert page.gap == "unrecognized_provider_records"


@pytest.mark.parametrize(
    "provider,operation,arguments",
    [
        ("censys", "get_host", {"host_id": "192.0.2.1"}),
        ("gti", "get_domain_report", {"domain": "seed.example"}),
        ("greynoise", "lookup-ip-context", {"ip": "192.0.2.1"}),
    ],
)
async def test_changed_deployed_schema_is_rejected_before_tool_dispatch(
    provider, operation, arguments
):
    adapter = source(provider, {"sensitive": "must-not-be-called"}, changed_schema=True)
    with pytest.raises(SourceGap, match="^provider_tool_schema_changed$"):
        await adapter.fetch(operation, arguments)


@pytest.mark.parametrize(
    "message,code",
    [
        ("Rate limited (429): fixture-secret", "provider_rate_limited"),
        ("Not entitled (403): fixture-secret", "provider_access_denied"),
        ("Authentication failed (401): fixture-secret", "provider_authentication_failed"),
        ("Not found (404): fixture-secret", "provider_record_not_found"),
    ],
)
async def test_mcp_source_errors_are_distinct_and_never_include_upstream_secrets(message, code):
    with pytest.raises(SourceGap) as error:
        await source("greynoise", message, error=True).fetch(
            "lookup-ip-context", {"ip": "192.0.2.1"}
        )
    assert str(error.value) == code
    assert "fixture-secret" not in str(error.value)


async def test_latest_gti_report_does_not_turn_analysis_date_into_dns_association_date():
    page = await source(
        "gti",
        {"type": "domain", "id": "seed.example", "attributes": {"last_analysis_date": 1704585600}},
    ).fetch("get_domain_report", {"domain": "seed.example"})
    assert page.records[0].observed_at is None
    assert page.complete is True and page.gap is None
    assert "historical_association_dates_unavailable" in page.metadata["coverage_gaps"]


async def test_greynoise_context_preserves_benign_service_alternative_and_unknown_date():
    raw = {
        "ip": "192.0.2.1",
        "internet_scanner_intelligence": {"classification": "benign"},
        "business_service_intelligence": {"found": True, "name": "Shared service"},
    }
    page = await source("greynoise", raw).fetch("lookup-ip-context", {"ip": "192.0.2.1"})
    assert page.records[0].raw == raw
    assert page.records[0].indicators == ["192.0.2.1"]
    assert page.records[0].observed_at is None
    assert page.complete is True and page.gap is None
    assert "alternative explanations" in page.metadata["interpretation"]


async def test_greynoise_entitlement_restrictions_preserve_results_and_continuation():
    raw = {
        "data": [
            {
                "ip": "192.0.2.1",
                "internet_scanner_intelligence": {
                    "last_seen": "2024-01-08",
                    "classification": "malicious",
                },
            }
        ],
        "request_metadata": {
            "complete": False,
            "scroll": "page-two",
            "restricted_fields": ["raw_data"],
            "query": "tags:example",
        },
    }
    page = await source("greynoise", raw).fetch("gnql-query", {"query": "tags:example", "size": 1})
    assert page.records[0].observed_at == "2024-01-08T00:00:00+00:00"
    assert page.continuation == {"query": "tags:example", "size": 1, "scroll": "page-two"}
    assert page.gap == "fields_restricted_by_entitlement"
    assert page.raw == raw
    assert page.api_requests is None and page.credits is None


async def test_censys_certificate_names_do_not_inherit_certificate_validity_as_observation_date():
    raw = {
        "result": json.dumps(
            {
                "resource": {
                    "certificate": {
                        "names": ["a.example", "b.example"],
                        "parsed": {"validity_period": {"not_before": "2024-01-01T00:00:00Z"}},
                    }
                }
            }
        )
    }
    page = await source("censys", raw).fetch("get_certificate", {"certificate_id": "a" * 64})
    assert page.records[0].indicators == ["a.example", "b.example"]
    assert page.records[0].observed_at is None
    assert page.complete is True and page.gap is None


@pytest.mark.parametrize(
    "provider,operation",
    [
        ("censys", "scan_host"),
        ("censys", "create_collection"),
        ("censys", "retrieve_cve_details"),
        ("gti", "analyse_file"),
        ("gti", "create_collection"),
        ("gti", "update_iocs_in_collection"),
        ("greynoise", "test-alert-webhook"),
        ("greynoise", "create-alert"),
    ],
)
async def test_operational_or_unreviewed_tools_are_not_exposed(provider, operation):
    adapter = source(provider, {})
    assert operation not in adapter.operations()
    with pytest.raises(ValueError, match="Unsupported"):
        await adapter.fetch(operation, {})


async def test_censys_certificate_search_retains_san_candidates_without_inventing_dates():
    page = await source(
        "censys",
        {
            "hits": [
                {
                    "cert": {
                        "fingerprint_sha256": "a" * 64,
                        "names": ["seed.example", "candidate.example"],
                        "parsed": {"validity_period": {"not_before": "2024-01-01T00:00:00Z"}},
                    }
                }
            ],
            "next_page_token": "",
        },
    ).fetch("search", {"query": "cert.names:seed.example"})
    assert page.records[0].indicators == ["seed.example", "candidate.example"]
    assert page.records[0].observed_at is None
    assert page.complete is True
    assert page.gap is None


async def test_greynoise_hourly_records_keep_distinct_dates_and_history_limits():
    raw = {
        "buckets": {
            "2024-01-08T01:00:00Z": [{"ip": "192.0.2.1"}],
            "2024-01-08T02:00:00Z": [{"ip": "192.0.2.1"}],
        }
    }
    page = await source("greynoise", raw).fetch(
        "gnql-timeseries",
        {
            "query": "ip:192.0.2.1",
            "start_time": "2024-01-08T00:00:00Z",
            "end_time": "2024-01-09T00:00:00Z",
        },
    )
    assert [r.observed_at for r in page.records] == [
        "2024-01-08T01:00:00+00:00",
        "2024-01-08T02:00:00+00:00",
    ]
    assert page.records[0].raw != page.records[1].raw
    assert page.raw == raw
    assert page.complete is False
    assert page.gap == "per_bucket_history_coverage_unverified"


async def test_missing_gti_report_never_falls_back_to_collection():
    with pytest.raises(SourceGap, match="^provider_record_not_found$"):
        await source(
            "gti", {"error": "VirusTotal API Error: NotFoundError - fixture-secret"}
        ).fetch("get_domain_report", {"domain": "seed.example"})


async def test_censys_timeline_preserves_events_and_reports_unverified_completeness():
    raw = {
        "result": json.dumps(
            {
                "events": [
                    {"timestamp": "2024-01-03T00:00:00Z", "type": "service_observed"},
                    {"timestamp": "2024-01-10T00:00:00Z", "type": "service_observed"},
                ]
            }
        )
    }
    page = await source("censys", raw).fetch(
        "get_host_timeline",
        {"host_id": "192.0.2.1", "start_time": "2024-01-01", "end_time": "2024-01-31"},
    )
    assert len(page.records) == 2
    assert page.records[0].observed_at == "2024-01-03T00:00:00+00:00"
    assert page.records[1].observed_at == "2024-01-10T00:00:00+00:00"
    assert page.complete is False and page.continuation is None
    assert page.gap == "history_or_pagination_incomplete"


async def test_provider_capabilities_cannot_be_mutated_to_enable_a_new_operation():
    adapter = source("gti", {})
    exposed = adapter.operations()
    exposed["analyse_file"] = {"type": "object"}
    with pytest.raises(ValueError, match="Unsupported"):
        await adapter.fetch("analyse_file", {})


async def test_censys_bad_certificate_metadata_does_not_erase_other_search_candidates():
    raw = {
        "hits": [
            {"cert": {"names": ["retained.example"]}},
            {"cert": {"names": ["also-retained.example"], "parsed": "invalid"}},
        ],
        "next_page_token": "",
    }
    page = await source("censys", raw).fetch("search", {"query": "cert.names:example"})
    assert [r.indicators for r in page.records] == [["retained.example"], ["also-retained.example"]]
    assert page.complete is False
    assert page.gap == "unrecognized_provider_records"
    assert page.raw == raw


@pytest.mark.parametrize(
    "changed_schema,code,usage",
    [
        (
            True,
            "provider_tool_schema_changed",
            {
                "mcp_calls": 0,
                "api_requests": 0,
                "returned_records": 0,
                "credits": 0,
            },
        ),
        (
            False,
            "provider_rate_limited",
            {
                "mcp_calls": 1,
                "api_requests": None,
                "returned_records": None,
                "credits": None,
            },
        ),
    ],
)
async def test_failed_provider_call_accounts_only_for_dispatched_tools(changed_schema, code, usage):
    adapter = source(
        "greynoise",
        "Rate limited (429): fixture-secret",
        error=True,
        changed_schema=changed_schema,
    )
    with pytest.raises(SourceGap) as error:
        await adapter.fetch("lookup-ip-context", {"ip": "192.0.2.1"})
    assert str(error.value) == code
    assert error.value.usage == usage
    assert "fixture-secret" not in str(error.value)


async def test_provider_session_failure_before_dispatch_reports_zero_usage(tmp_path):
    adapter = McpSource(
        "greynoise", McpTransport(command=str(tmp_path / "missing-provider-executable"))
    )
    with pytest.raises(SourceGap, match="^provider_mcp_unavailable$") as error:
        await adapter.fetch("lookup-ip-context", {"ip": "192.0.2.1"})
    assert error.value.usage == {
        "mcp_calls": 0,
        "api_requests": 0,
        "returned_records": 0,
        "credits": 0,
    }
