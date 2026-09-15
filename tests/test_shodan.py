import httpx

from hunting_harness.providers.shodan import Shodan
from hunting_harness.shodan_fixture import ShodanFixtureTransport


async def test_host_history_preserves_each_observation_and_raw_response():
    raw = {
        "ip_str": "192.0.2.1",
        "data": [
            {"ip_str": "192.0.2.1", "port": 443, "timestamp": "2024-01-03T12:00:00", "data": "old"},
            {"ip_str": "192.0.2.1", "port": 443, "timestamp": "2024-01-20T12:00:00", "data": "new"},
        ],
    }

    def provider(request: httpx.Request):
        assert request.url.host == "api.shodan.io"
        assert request.url.path == "/shodan/host/192.0.2.1"
        assert request.url.params["history"] == "True"
        return httpx.Response(200, json=raw)

    adapter = Shodan("fixture-key", transport=ShodanFixtureTransport(provider))
    result = await adapter.fetch("host", {"ip": "192.0.2.1", "history": True})
    assert [r.observed_at for r in result.records] == [
        "2024-01-03T12:00:00+00:00",
        "2024-01-20T12:00:00+00:00",
    ]
    assert result.raw == raw
    assert [r.raw["data"] for r in result.records] == ["old", "new"]


async def test_inconsistent_search_page_retains_all_records_without_claiming_complete():
    rows = [
        {"ip_str": "192.0.2.1", "timestamp": "2024-01-03T12:00:00", "port": n} for n in range(101)
    ]
    adapter = Shodan(
        "fixture-key",
        transport=ShodanFixtureTransport(
            lambda request: httpx.Response(200, json={"matches": rows, "total": 100})
        ),
    )
    page = await adapter.fetch("search", {"query": "ssl.cert.fingerprint:example"})
    assert len(page.records) == 101
    assert page.complete is False
    assert page.gap == "inconsistent_provider_pagination"
    assert page.continuation is None


async def test_successful_history_retrieval_does_not_block_completion_for_unknown_coverage():
    adapter = Shodan(
        "fixture-key",
        transport=ShodanFixtureTransport(
            lambda request: httpx.Response(200, json={"data": [{"port": 443}]})
        ),
    )
    page = await adapter.fetch("host", {"ip": "192.0.2.1"})
    assert page.complete is True
    assert page.gap is None
    assert page.records[0].observed_at is None
    assert page.metadata["coverage_gaps"] == [
        "historical_coverage_bounds_unavailable",
        "observation_dates_unavailable",
    ]


async def test_search_pages_are_explicit_and_usage_is_per_request():
    calls = []
    rows = [
        {"ip_str": "192.0.2.1", "timestamp": "2024-01-03T12:00:00", "port": n} for n in range(100)
    ]

    def respond(request):
        calls.append(request.url.params["page"])
        matches = (
            rows
            if request.url.params["page"] == "1"
            else [{"ip_str": "192.0.2.2", "timestamp": "2024-01-04T12:00:00"}]
        )
        return httpx.Response(200, json={"matches": matches, "total": 101})

    adapter = Shodan("fixture-key", transport=ShodanFixtureTransport(respond))
    first = await adapter.fetch("search", {"query": "ssl.cert.fingerprint:example"})
    assert len(first.records) == 100 and first.complete is False
    assert first.continuation == {"query": "ssl.cert.fingerprint:example", "page": 2}
    assert calls == ["1"]
    second = await adapter.fetch("search", first.continuation)
    assert second.complete is True and second.continuation is None
    assert second.records[0].indicators == ["192.0.2.2"]
    assert calls == ["1", "2"]
    assert first.api_requests == second.api_requests == 1
    assert first.credits is None and second.credits is None


async def test_empty_search_and_missing_host_are_distinct():
    import pytest

    from hunting_harness.providers.base import SourceGap

    empty = Shodan(
        "fixture-key",
        transport=ShodanFixtureTransport(
            lambda request: httpx.Response(200, json={"matches": [], "total": 0})
        ),
    )
    page = await empty.fetch("search", {"query": "hostname:nonexistent.example"})
    assert page.complete is True and page.gap is None and page.records == []
    missing = Shodan(
        "fixture-key",
        transport=ShodanFixtureTransport(
            lambda request: httpx.Response(404, json={"error": "No information available"})
        ),
    )
    with pytest.raises(SourceGap, match="^provider_record_not_found$"):
        await missing.fetch("host", {"ip": "192.0.2.1"})


async def test_shodan_rejects_operational_tools_before_network_dispatch():
    import pytest

    def unexpected(request):
        pytest.fail("Forbidden operation reached the network")

    adapter = Shodan("fixture-key", transport=ShodanFixtureTransport(unexpected))
    for operation in ["scan", "dns_lookup", "reverse_dns_lookup", "fetch_url"]:
        assert operation not in adapter.operations()
        with pytest.raises(ValueError, match="Unsupported"):
            await adapter.fetch(operation, {})


async def test_rate_limit_is_safe_and_is_not_retried():
    import pytest

    from hunting_harness.providers.base import SourceGap

    calls = []

    def respond(request):
        calls.append(request.url.path)
        return httpx.Response(429, json={"error": "fixture-key"})

    adapter = Shodan("fixture-key", transport=ShodanFixtureTransport(respond))
    with pytest.raises(SourceGap, match="^provider_rate_limited$"):
        await adapter.fetch("host", {"ip": "192.0.2.1"})
    assert calls == ["/shodan/host/192.0.2.1"]


async def test_short_search_page_is_incomplete_without_inventing_a_cursor():
    adapter = Shodan(
        "fixture-key",
        transport=ShodanFixtureTransport(
            lambda request: httpx.Response(
                200, json={"matches": [{"ip_str": "192.0.2.1"}], "total": 500}
            )
        ),
    )
    page = await adapter.fetch("search", {"query": "hostname:example"})
    assert page.complete is False
    assert page.continuation is None
    assert page.gap == "incomplete_provider_page"
    assert len(page.records) == 1


async def test_sdk_preserves_full_search_banners_and_ignores_environment(monkeypatch):
    import logging

    import requests

    from hunting_harness.providers.shodan import SDK_VERSION

    monkeypatch.setenv("SHODAN_API_URL", "https://unrelated.example")
    monkeypatch.setenv("HTTPS_PROXY", "http://unrelated.example:8080")
    raw = {
        "total": 1,
        "matches": [
            {
                "ip_str": "192.0.2.1",
                "timestamp": "2024-01-03T12:00:00.123456789",
                "_shodan": {"id": "banner-id"},
                "data": "first line\nsecond line",
                "future_field": {"complete": True},
            }
        ],
        "unknown_top_level": "retained",
    }
    calls = []

    def respond(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host == "api.shodan.io"
        assert request.url.params == httpx.QueryParams(
            {
                "query": "http.favicon.hash:-123",
                "minify": "False",
                "page": "1",
                "key": "fixture-secret",
            }
        )
        return httpx.Response(200, json=raw)

    class InspectedTransport(ShodanFixtureTransport):
        def send(self, request, **options):
            assert options["timeout"] == 20
            assert not options["proxies"]
            logging.getLogger("urllib3.connectionpool").debug("credential URL %s", request.url)
            return super().send(request, **options)

    # The SDK uses the real Requests session, with an offline adapter at dispatch.
    adapter = Shodan("fixture-secret", transport=InspectedTransport(respond))
    page = await adapter.fetch("search", {"query": "http.favicon.hash:-123"})
    assert len(calls) == 1
    assert page.raw == raw
    assert page.records[0].raw == raw["matches"][0]
    assert page.records[0].source_id == "banner-id"
    assert page.api_requests == 1 and page.mcp_calls == 0 and page.credits is None
    assert page.metadata["provider_version"] == f"sdk-{SDK_VERSION}-adapter-1"
    assert page.metadata["http_status"] == 200
    assert requests.adapters.HTTPAdapter().max_retries.total == 0


async def test_sdk_does_not_follow_redirects_or_leak_provider_errors(caplog):
    import logging

    import pytest

    from hunting_harness.providers.base import SourceGap

    caplog.set_level(logging.DEBUG)
    calls = []

    def respond(request):
        calls.append(request)
        logging.getLogger("urllib3.connectionpool").debug("%s", request.url)
        return httpx.Response(
            302,
            headers={"location": "https://unrelated.example/?key=fixture-secret"},
            json={"error": "fixture-secret"},
        )

    with pytest.raises(SourceGap, match="^provider_http_302$") as failure:
        await Shodan("fixture-secret", transport=ShodanFixtureTransport(respond)).fetch(
            "host", {"ip": "192.0.2.1"}
        )
    assert len(calls) == 1
    assert failure.value.usage == {
        "api_requests": 1,
        "mcp_calls": 0,
        "returned_records": None,
        "credits": None,
    }
    assert "fixture-secret" not in caplog.text


async def test_sdk_connection_check_uses_only_account_metadata():
    calls = []

    def respond(request):
        calls.append(request.url.path)
        assert dict(request.url.params) == {"key": "fixture-key"}
        return httpx.Response(200, json={"plan": "fixture-plan", "query_credits": 100})

    adapter = Shodan("fixture-key", transport=ShodanFixtureTransport(respond))
    assert await adapter.check_connection() == {
        "status": "authenticated",
        "http_status": 200,
        "requests": 1,
    }
    assert calls == ["/api-info"]
    assert "info" not in adapter.operations()


async def test_sdk_transport_failure_is_counted_once():
    import pytest
    import requests

    from hunting_harness.providers.base import SourceGap

    calls = []

    def respond(request):
        calls.append(request)
        raise requests.ReadTimeout("fixture-secret")

    with pytest.raises(SourceGap, match="^provider_transport_unavailable$") as failure:
        await Shodan("fixture-secret", transport=ShodanFixtureTransport(respond)).fetch(
            "host", {"ip": "192.0.2.1"}
        )
    assert len(calls) == failure.value.usage["api_requests"] == 1


async def test_sdk_initialization_failure_reports_zero_requests(monkeypatch):
    import pytest

    from hunting_harness.providers import shodan
    from hunting_harness.providers.base import SourceGap

    def fail(key):
        raise RuntimeError(key)

    monkeypatch.setattr(shodan, "SDK", fail)
    with pytest.raises(SourceGap, match="^provider_sdk_unavailable$") as failure:
        await Shodan("fixture-secret").fetch("host", {"ip": "192.0.2.1"})
    assert failure.value.usage == {
        "api_requests": 0,
        "mcp_calls": 0,
        "returned_records": 0,
        "credits": 0,
    }


async def test_malformed_success_retains_the_response_as_a_gap():
    for raw in [[], {"error": "provider problem"}, {"data": "unexpected"}, "invalid JSON"]:
        response = (
            httpx.Response(200, text=raw) if isinstance(raw, str) else httpx.Response(200, json=raw)
        )
        adapter = Shodan(
            "fixture-key",
            transport=ShodanFixtureTransport(lambda request, response=response: response),
        )
        page = await adapter.fetch("host", {"ip": "192.0.2.1"})
        assert page.raw == raw
        assert page.complete is False and page.gap is not None
        assert page.api_requests == 1 and page.records == []


async def test_sdk_classifies_http_status_even_without_an_error_body():
    import pytest

    from hunting_harness.providers.base import SourceGap

    for status, code in [
        (400, "provider_invalid_request"),
        (401, "provider_authentication_failed"),
        (403, "provider_access_denied"),
        (404, "provider_record_not_found"),
        (429, "provider_rate_limited"),
        (500, "provider_http_500"),
        (502, "provider_http_502"),
    ]:
        adapter = Shodan(
            "fixture-key",
            transport=ShodanFixtureTransport(
                lambda request, status=status: httpx.Response(status, json={})
            ),
        )
        with pytest.raises(SourceGap, match=f"^{code}$") as failure:
            await adapter.fetch("host", {"ip": "192.0.2.1"})
        assert failure.value.usage["api_requests"] == 1
