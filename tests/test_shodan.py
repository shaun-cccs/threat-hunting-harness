import httpx

from hunting_harness.providers.shodan import Shodan


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
        assert request.url.params["history"] == "true"
        return httpx.Response(200, json=raw)

    adapter = Shodan("fixture-key", transport=httpx.MockTransport(provider))
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
        transport=httpx.MockTransport(
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
        transport=httpx.MockTransport(
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

    adapter = Shodan("fixture-key", transport=httpx.MockTransport(respond))
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
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"matches": [], "total": 0})
        ),
    )
    page = await empty.fetch("search", {"query": "hostname:nonexistent.example"})
    assert page.complete is True and page.gap is None and page.records == []
    missing = Shodan(
        "fixture-key",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(404, json={"error": "No information available"})
        ),
    )
    with pytest.raises(SourceGap, match="^provider_record_not_found$"):
        await missing.fetch("host", {"ip": "192.0.2.1"})


async def test_shodan_rejects_operational_tools_before_network_dispatch():
    import pytest

    def unexpected(request):
        pytest.fail("Forbidden operation reached the network")

    adapter = Shodan("fixture-key", transport=httpx.MockTransport(unexpected))
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

    adapter = Shodan("fixture-key", transport=httpx.MockTransport(respond))
    with pytest.raises(SourceGap, match="^provider_rate_limited$"):
        await adapter.fetch("host", {"ip": "192.0.2.1"})
    assert calls == ["/shodan/host/192.0.2.1"]


async def test_short_search_page_is_incomplete_without_inventing_a_cursor():
    adapter = Shodan(
        "fixture-key",
        transport=httpx.MockTransport(
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
