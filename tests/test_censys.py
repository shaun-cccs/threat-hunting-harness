"""Censys public provider contract through the real SDK and isolated HTTP transport."""

import json
from datetime import datetime

import httpx
import pytest

from hunting_harness.providers.base import SourceGap
from hunting_harness.providers.censys import Censys

IP = "192.0.2.1"
LOWER = "2026-06-17T00:00:00Z"
UPPER = "2026-09-15T00:00:00Z"
BOUND = "2026-09-12T19:25:11.607695Z"
ARGS = {"host_id": IP, "start_time": LOWER, "end_time": UPPER}


def asset(resource):
    return {"extensions": {}, "resource": resource}


def event(time="2026-09-14T23:19:05.721976640Z", **fields):
    return asset({"event_time": time, **fields})


def source(payload, *, status=200, observe=None, organization="fixture-org", content_type=None):
    calls = []

    def respond(request):
        calls.append(request)
        if observe:
            observe(request)
        kind = "host_timeline_event" if request.url.path.endswith("/timeline") else "host"
        if "/certificate/" in request.url.path:
            kind = "certificate"
        mime = (
            "application/json"
            if "/search/" in request.url.path
            else f"application/vnd.censys.api.v3.{kind}.v1+json"
        )
        return httpx.Response(
            status,
            json=payload,
            headers={
                "Content-Type": content_type
                or (mime if status == 200 else "application/problem+json"),
                "X-Request-ID": "fixture-request-id",
            },
        )

    return Censys("fixture-secret", organization, httpx.MockTransport(respond)), calls


async def test_timeline_preserves_raw_json_unknown_fields_and_exact_continuation():
    raw = {
        "result": {
            "events": [event(future_event={"banner": "HTTP/1.1 200 OK\r\nServer: test"})],
            "scanned_to": BOUND,
            "future_field": "retain",
        }
    }
    provider, calls = source(raw)
    page = await provider.fetch("get_host_timeline", ARGS)
    assert len(calls) == 1
    params = calls[0].url.params
    assert datetime.fromisoformat(params["start_time"]) == datetime.fromisoformat(UPPER)
    assert datetime.fromisoformat(params["end_time"]) == datetime.fromisoformat(LOWER)
    assert params["organization_id"] == "fixture-org"
    assert calls[0].headers["authorization"] == "Bearer fixture-secret"
    assert page.raw == raw
    assert page.records[0].raw == raw["result"]["events"][0]
    assert page.records[0].observed_at == "2026-09-14T23:19:05.721976+00:00"
    assert page.continuation == {**ARGS, "end_time": BOUND}
    assert page.complete is False and page.gap is None
    assert page.api_requests == 1 and page.mcp_calls == 0 and page.credits is None
    assert page.metadata["request_id"] == "fixture-request-id"


@pytest.mark.parametrize("events", [[], [event()]])
async def test_short_timeline_page_is_not_complete_until_boundary_reaches_lower(events):
    provider, _ = source({"result": {"events": events, "scanned_to": BOUND}})
    page = await provider.fetch("get_host_timeline", ARGS)
    assert not page.complete and page.continuation
    provider, _ = source({"result": {"events": [], "scanned_to": LOWER}})
    final = await provider.fetch("get_host_timeline", {**ARGS, "end_time": BOUND})
    assert final.complete and final.continuation is None and final.gap is None
    assert "historical_coverage_depends_on_entitlement" in final.metadata["coverage_gaps"]


@pytest.mark.parametrize("bound", [UPPER, "2026-09-16T00:00:00Z", "bad", None])
async def test_invalid_or_nonprogressing_timeline_cannot_loop_or_claim_completion(bound):
    provider, _ = source({"result": {"events": [event()], "scanned_to": bound}})
    page = await provider.fetch("get_host_timeline", ARGS)
    assert len(page.records) == 1
    assert not page.complete and page.continuation is None and page.gap


async def test_finer_timestamp_boundary_overlaps_instead_of_skipping_events():
    bound = "2026-09-12T19:25:11.607695999Z"
    provider, calls = source({"result": {"events": [], "scanned_to": bound}})
    page = await provider.fetch("get_host_timeline", {**ARGS, "end_time": bound})
    assert datetime.fromisoformat(calls[0].url.params["start_time"]) == datetime.fromisoformat(
        "2026-09-12T19:25:11.607696Z"
    )
    assert page.gap == "provider_pagination_no_progress"
    assert page.continuation is None


async def test_snapshot_preserves_banner_dns_keys_and_scan_date_without_inventing_at_time():
    raw = {
        "result": asset(
            {
                "ip": IP,
                "services": [
                    {
                        "port": 443,
                        "protocol": "HTTP",
                        "scan_time": "2026-09-13T01:09:41Z",
                        "banner": "HTTP\nDate: 1\nDate: 2",
                    },
                    {"port": 22, "protocol": "SSH"},
                ],
                "dns": {"forward_dns": {"seed.example": {"name": "seed.example"}}},
                "future_field": True,
            }
        )
    }
    provider, calls = source(raw)
    page = await provider.fetch("get_host", {"host_id": IP, "at_time": UPPER})
    assert datetime.fromisoformat(calls[0].url.params["at_time"]) == datetime.fromisoformat(UPPER)
    assert page.complete and page.gap is None
    assert len(page.records) == 2
    assert page.records[0].observed_at == "2026-09-13T01:09:41+00:00"
    assert page.records[1].observed_at is None
    assert page.raw == raw
    assert page.records[0].raw["service"]["banner"] == "HTTP\nDate: 1\nDate: 2"


async def test_certificate_names_do_not_inherit_validity_as_observation_date():
    raw = {
        "result": asset(
            {
                "fingerprint_sha256": "a" * 64,
                "names": ["seed.example"],
                "parsed": {"validity_period": {"not_before": "2024-01-01T00:00:00Z"}},
            }
        )
    }
    provider, calls = source(raw)
    page = await provider.fetch("get_certificate", {"certificate_id": "a" * 64})
    assert len(calls) == 1 and calls[0].url.path.endswith("/certificate/" + "a" * 64)
    assert page.complete and page.gap is None
    assert page.records[0].indicators == ["seed.example"]
    assert page.records[0].observed_at is None


def search_result(hits, next_token=""):
    return {
        "result": {
            "hits": hits,
            "next_page_token": next_token,
            "previous_page_token": "",
            "query_duration_millis": 1,
            "total_hits": len(hits),
        }
    }


async def test_search_posts_filters_and_preserves_matched_services_and_certificate_candidates():
    host = asset({"ip": IP})
    host["matched_services"] = [
        {"port": 22, "protocol": "SSH", "scan_time": "2026-09-13T01:09:41Z"}
    ]
    raw = search_result(
        [{"host_v1": host}, {"certificate_v1": asset({"names": ["seed.example"]})}], "next"
    )
    provider, calls = source(raw)
    args = {"query": "host.services.port:22", "fields": ["host.ip"], "page_size": 100}
    page = await provider.fetch("search", args)
    assert calls[0].method == "POST"
    assert json.loads(calls[0].content) == args
    assert page.continuation == {**args, "page_token": "next"}
    assert [r.indicators for r in page.records] == [[IP], ["seed.example"]]
    assert page.records[0].observed_at == "2026-09-13T01:09:41+00:00"
    assert page.raw == raw and not page.complete


async def test_malformed_search_row_does_not_erase_valid_rows_or_original_payload():
    raw = search_result([{"host_v1": asset({"ip": IP})}, {"host_v1": {"resource": "broken"}}])
    provider, _ = source(raw)
    page = await provider.fetch("search", {"query": "host.ip:192.0.2.1"})
    assert page.raw == raw and len(page.records) == 1
    assert page.gap and not page.complete


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "provider_invalid_request"),
        (401, "provider_authentication_failed"),
        (403, "provider_access_denied"),
        (404, "provider_record_not_found"),
        (429, "provider_rate_limited"),
        (503, "provider_http_503"),
    ],
)
async def test_http_errors_have_safe_codes_and_one_request_without_retry(status, code):
    provider, calls = source({"status": status, "detail": "fixture-secret"}, status=status)
    with pytest.raises(SourceGap) as error:
        await provider.fetch("get_host", {"host_id": IP})
    assert str(error.value) == code
    assert len(calls) == 1
    assert error.value.usage == {
        "api_requests": 1,
        "mcp_calls": 0,
        "returned_records": None,
        "credits": None,
    }


async def test_redirect_is_not_followed():
    calls = []

    def redirect(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://unrelated.example/"})

    provider = Censys("fixture-secret", transport=httpx.MockTransport(redirect))
    with pytest.raises(SourceGap, match="provider_http_302"):
        await provider.fetch("get_host", {"host_id": IP})
    assert len(calls) == 1


async def test_unexpected_success_body_is_retained_as_a_partial_response():
    provider, calls = source("unexpected provider text", content_type="text/plain")
    page = await provider.fetch("get_host", {"host_id": IP})
    assert len(calls) == 1
    assert page.raw == "unexpected provider text"
    assert page.records == [] and not page.complete
    assert page.gap == "unrecognized_provider_response"


@pytest.mark.parametrize("error_type", [httpx.ReadTimeout, httpx.ConnectError])
async def test_transport_failure_keeps_dispatched_usage_and_never_retries(error_type):
    calls = []

    def fail(request):
        calls.append(request)
        raise error_type("fixture-secret", request=request)

    provider = Censys("fixture-secret", transport=httpx.MockTransport(fail))
    with pytest.raises(SourceGap) as error:
        await provider.fetch("get_host", {"host_id": IP})
    assert str(error.value) == "provider_transport_unavailable"
    assert len(calls) == 1 and error.value.usage["api_requests"] == 1


async def test_unrelated_sdk_environment_does_not_override_missing_workspace_org(monkeypatch):
    monkeypatch.setenv("ORGANIZATION_ID", "unrelated-organization")
    provider, calls = source({"result": asset({"ip": IP})}, organization=None)
    await provider.fetch("get_host", {"host_id": IP})
    assert "organization_id" not in calls[0].url.params


@pytest.mark.parametrize(
    "operation,args",
    [
        ("scan_host", {}),
        ("get_host", {"host_id": "invalid"}),
        ("get_host_timeline", {**ARGS, "end_time": LOWER}),
        ("get_certificate", {"certificate_id": "invalid"}),
        ("search", {"query": "x", "page_size": 101}),
        ("search", {"query": "x", "page_size": True}),
        ("get_host", {"host_id": IP, "fresh_scan": True}),
    ],
)
async def test_invalid_or_unreviewed_operations_never_dispatch(operation, args):
    provider, calls = source({})
    with pytest.raises(ValueError):
        await provider.fetch(operation, args)
    assert calls == []


async def test_gateway_retains_each_page_counts_api_calls_and_keeps_distinct_same_time_events(
    tmp_path,
):
    import asyncio

    from hunting_harness.gateway import Gateway
    from hunting_harness.models import CaseSpec, QuerySpec

    first = event(BOUND, forward_dns_resolved={"name": "one.example"})
    same_time = event(BOUND, forward_dns_resolved={"name": "two.example"})
    older = event("2026-09-10T00:00:00Z")
    pages = [
        {"result": {"events": [first, same_time], "scanned_to": BOUND}},
        {"result": {"events": [first, older], "scanned_to": LOWER}},
    ]
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            200,
            json=pages[len(calls) - 1],
            headers={"content-type": "application/vnd.censys.api.v3.host_timeline_event.v1+json"},
        )

    provider = Censys("fixture", transport=httpx.MockTransport(respond))
    async with Gateway(tmp_path, {"censys": provider}) as gateway:
        case = gateway.case_create(
            CaseSpec(
                hypothesis="Fixture timeline",
                seeds=[IP],
                start="2026-06-17",
                end="2026-09-15",
                limits={"api_requests": 2, "mcp_calls": 0},
            )
        )
        query = QuerySpec(
            provider="censys",
            operation="get_host_timeline",
            arguments=ARGS,
            pivot_from=IP,
            purpose="Recorded history",
        )
        first_job = await gateway.query_submit(case["id"], query)
        await asyncio.gather(*gateway.tasks)
        first_job = gateway.job_read(case["id"], first_job["id"])
        assert first_job["status"] == "partial" and len(calls) == 1
        assert json.loads((tmp_path / first_job["artifact"]).read_text()) == pages[0]
        next_job = await gateway.query_submit(
            case["id"],
            query.model_copy(
                update={"arguments": first_job["continuation"], "continuation_of": first_job["id"]}
            ),
        )
        await asyncio.gather(*gateway.tasks)
        final = gateway.case_read(case["id"])
        assert gateway.job_read(case["id"], next_job["id"])["status"] == "completed"
        assert final["usage"]["api_requests"] == 2 and final["usage"]["mcp_calls"] == 0
        assert len(final["evidence"]) == 3
        assert all(gap.get("resolved_by") for gap in final["source_gaps"])


@pytest.mark.parametrize("organization", [None, "fixture-org"])
async def test_sdk_connection_check_uses_account_metadata_not_an_indicator(organization):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            200, json={"result": {}}, headers={"content-type": "application/json"}
        )

    provider = Censys("fixture", organization, httpx.MockTransport(respond))
    result = await provider.check_connection()
    expected = (
        "/v3/accounts/users/credits"
        if not organization
        else "/v3/accounts/organizations/fixture-org"
    )
    assert len(calls) == 1 and calls[0].url.path == expected
    assert result["http_status"] == 200 and result["requests"] == 1
