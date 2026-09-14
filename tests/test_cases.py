from pathlib import Path

from starlette.testclient import TestClient

from hunting_harness.server import create_app

TOKEN = "test-token-with-at-least-32-characters"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json, text/event-stream"}


def call(client: TestClient, name: str, arguments: dict):
    response = client.post(
        "/mcp",
        headers=HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert not result.get("isError"), result
    return result["structuredContent"]


def test_case_is_available_through_mcp_after_restart(tmp_path: Path):
    with TestClient(create_app(tmp_path, TOKEN), base_url="http://127.0.0.1:8765") as client:
        case = call(
            client,
            "case_create",
            {
                "spec": {
                    "hypothesis": "Certificate reuse during the campaign",
                    "seeds": ["192.0.2.1", "Seed.Example"],
                    "start": "2024-01-01",
                    "end": "2024-02-01",
                }
            },
        )
    with TestClient(create_app(tmp_path, TOKEN), base_url="http://127.0.0.1:8765") as client:
        reopened = call(client, "case_read", {"case_id": case["id"]})
    assert reopened["seeds"] == ["192.0.2.1", "seed.example"]
    assert reopened["hypothesis"] == "Certificate reuse during the campaign"
    assert reopened["queries"] == []
    assert reopened["status"] == "active"


def test_mcp_requires_authentication_and_loopback_host(tmp_path):
    with TestClient(create_app(tmp_path, TOKEN), base_url="http://127.0.0.1:8765") as client:
        assert client.post("/mcp", json={}).status_code == 401
        assert (
            client.post("/mcp", headers={"Authorization": "Bearer wrong"}, json={}).status_code
            == 401
        )
        assert (
            client.post(
                "/mcp", headers={**HEADERS, "Host": "attacker.example"}, json={}
            ).status_code
            == 421
        )


def test_invalid_case_inputs_and_cross_case_job_reads_are_rejected(tmp_path):
    import pytest

    from hunting_harness.gateway import Gateway
    from hunting_harness.models import CaseSpec

    with TestClient(create_app(tmp_path, TOKEN), base_url="http://127.0.0.1:8765") as client:
        for changes in (
            {"seeds": ["https://seed.example/path"]},
            {"seeds": ["999.0.0.1"]},
            {"end": "2023-01-01"},
            {"hypothesis": " "},
            {"limits": {"credits": 2}},
            {"limits": {"query_calls": True}},
        ):
            spec = {
                "hypothesis": "Campaign reuse",
                "seeds": ["seed.example"],
                "start": "2024-01-01",
                "end": "2024-02-01",
                **changes,
            }
            result = client.post(
                "/mcp",
                headers=HEADERS,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "case_create", "arguments": {"spec": spec}},
                },
            ).json()["result"]
            assert result["isError"]
        first = call(
            client,
            "case_create",
            {
                "spec": {
                    "hypothesis": "First case",
                    "seeds": ["first.example"],
                    "start": "2024-01-01",
                    "end": "2024-02-01",
                }
            },
        )
        second = call(
            client,
            "case_create",
            {
                "spec": {
                    "hypothesis": "Second case",
                    "seeds": ["second.example"],
                    "start": "2024-01-01",
                    "end": "2024-02-01",
                }
            },
        )
        assert call(client, "case_read", {"case_id": first["id"]})["seeds"] == ["first.example"]
        assert call(client, "case_read", {"case_id": second["id"]})["seeds"] == ["second.example"]
    gateway = Gateway(tmp_path)
    with pytest.raises(ValueError, match="Unknown query"):
        gateway.job_read(second["id"], first["id"])
    assert CaseSpec(
        hypothesis="IP and IDNA",
        seeds=["2001:db8::1", "EXAMPLE.COM."],
        start="2024-01-01",
        end="2024-01-02",
    ).seeds == ["2001:db8::1", "example.com"]
