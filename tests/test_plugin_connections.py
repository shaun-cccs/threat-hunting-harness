"""Bounded account checks use isolated fake transports; no provider is contacted."""

import asyncio
import json
import stat
from pathlib import Path

import httpx
import pytest

from hunting_harness import connections

KEYS = {
    "SHODAN_API_KEY": "fixture-shodan-secret",
    "VT_APIKEY": "fixture-gti-secret",
    "GREYNOISE_API_KEY": "fixture-greynoise-secret",
    "CENSYS_API_KEY": "fixture-censys-secret",
    "CENSYS_ORG_ID": "fixture-organization",
}


async def test_all_checks_start_concurrently_and_each_runs_once(tmp_path, monkeypatch):
    started = []
    metadata = []
    everyone_started = asyncio.Event()

    async def start(name):
        started.append(name)
        if len(started) == 4:
            everyone_started.set()
        await everyone_started.wait()

    class Client:
        def __init__(self, **options):
            assert options == {
                "timeout": connections.METADATA_TIMEOUT,
                "follow_redirects": False,
                "trust_env": False,
            }

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, *, params, headers):
            metadata.append((url, params, headers))
            await start(url)
            return httpx.Response(401 if "greynoise" in url else 200)

    class Censys:
        def __init__(self, *, url, headers):
            assert url == "https://mcp.platform.censys.io/platform/mcp/"
            assert headers == {
                "Authorization": "Bearer " + KEYS["CENSYS_API_KEY"],
                "X-Organization-ID": KEYS["CENSYS_ORG_ID"],
            }

        async def inventory(self):
            await start("censys-inventory")
            return [{"name": "get_host", "inputSchema": {"type": "object"}}]

    monkeypatch.setattr(connections.httpx, "AsyncClient", Client)
    monkeypatch.setattr(connections, "McpTransport", Censys)
    async with asyncio.timeout(2):
        report = await connections.validate_connections(KEYS, tmp_path)
    assert len(started) == len(set(started)) == 4
    assert len(metadata) == 3
    assert dict((url, (params, headers)) for url, params, headers in metadata) == {
        "https://api.shodan.io/api-info": ({"key": KEYS["SHODAN_API_KEY"]}, None),
        "https://www.virustotal.com/api/v3/users/me": (None, {"x-apikey": KEYS["VT_APIKEY"]}),
        "https://api.greynoise.io/v3/user": (None, {"key": KEYS["GREYNOISE_API_KEY"]}),
    }
    providers = report["providers"]
    assert providers["shodan"] == {
        "status": "authenticated", "http_status": 200, "requests": 1
    }
    assert providers["gti"] == providers["shodan"]
    assert providers["greynoise"] == {
        "status": "not_validated", "http_status": 401, "requests": 1
    }
    assert providers["censys"] == {
        "status": "mcp_connected", "tools": 1, "sessions": 1, "tool_calls": 0
    }
    assert report["intelligence_queries"] == 0
    assert json.loads((tmp_path / "connections.json").read_text()) == report
    assert len(json.loads((tmp_path / "censys-inventory.json").read_text())) == 1
    for secret in KEYS.values():
        assert secret not in (tmp_path / "connections.json").read_text()


async def test_hanging_checks_are_bounded_without_retries(tmp_path, monkeypatch):
    metadata_attempts = []
    censys_attempts = []
    monkeypatch.setattr(connections, "METADATA_TIMEOUT", 0.03)
    monkeypatch.setattr(connections, "CENSYS_TIMEOUT", 0.06)

    class Client:
        def __init__(self, **options):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, **options):
            metadata_attempts.append(url)
            await asyncio.Event().wait()

    class Censys:
        def __init__(self, **options):
            pass

        async def inventory(self):
            censys_attempts.append("inventory")
            await asyncio.Event().wait()

    monkeypatch.setattr(connections.httpx, "AsyncClient", Client)
    monkeypatch.setattr(connections, "McpTransport", Censys)
    async with asyncio.timeout(1):
        report = await connections.validate_connections(KEYS, tmp_path)
    assert len(metadata_attempts) == len(set(metadata_attempts)) == 3
    assert censys_attempts == ["inventory"]
    for provider in ("shodan", "gti", "greynoise"):
        assert report["providers"][provider] == {"status": "transport_unavailable", "requests": 1}
    assert report["providers"]["censys"] == {
        "status": "connection_not_validated", "sessions": 1,
        "tool_calls": 0, "organization_id_configured": True,
    }


async def test_no_credentials_creates_no_transports(tmp_path, monkeypatch):
    def unexpected(**options):
        raise AssertionError("An unconfigured provider must not create a transport")

    monkeypatch.setattr(connections.httpx, "AsyncClient", unexpected)
    monkeypatch.setattr(connections, "McpTransport", unexpected)
    report = await connections.validate_connections({}, tmp_path)
    for provider in ("shodan", "gti", "greynoise"):
        assert report["providers"][provider] == {"status": "not_configured", "requests": 0}
    assert report["providers"]["censys"] == {"status": "not_configured", "sessions": 0}


def test_report_publication_is_private_and_atomic(tmp_path, monkeypatch):
    path = tmp_path / "connections.json"
    path.write_text('{"status": "old"}')
    path.chmod(0o644)
    replace = connections.os.replace
    publications = []

    def inspect_before_publication(source, destination):
        assert Path(destination) == path
        assert json.loads(path.read_text()) == {"status": "old"}
        assert json.loads(Path(source).read_text()) == {"status": "new"}
        assert stat.S_IMODE(Path(source).stat().st_mode) == 0o600
        publications.append(destination)
        replace(source, destination)

    monkeypatch.setattr(connections.os, "replace", inspect_before_publication)
    connections.write_report(path, {"status": "new"})
    assert publications == [path]
    assert json.loads(path.read_text()) == {"status": "new"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [path]


def test_failed_publication_preserves_previous_report_and_cleans_temporary(tmp_path, monkeypatch):
    path = tmp_path / "connections.json"
    path.write_text('{"status": "old"}')

    def interrupted(source, destination):
        raise OSError("simulated interrupted publication")

    monkeypatch.setattr(connections.os, "replace", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        connections.write_report(path, {"status": "new"})
    assert json.loads(path.read_text()) == {"status": "old"}
    assert list(tmp_path.iterdir()) == [path]
