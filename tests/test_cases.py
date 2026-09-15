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


def test_grown_case_stays_readable_by_section_and_refuses_an_oversized_full_read(tmp_path):
    """A hunt that retained many payloads must not become unreadable at its own gateway."""
    import pytest
    from test_queries import case_spec

    from hunting_harness.gateway import Gateway

    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())
    bulk = "x" * 4096

    def grow(record):
        record["evidence"].extend(
            {
                "id": f"e{index}",
                "raw": {"payload": bulk},
                "provider": "fixture",
                "query_ids": ["q1"],
                "retrieved_at": "2026-01-05T00:00:00+00:00",
                "indicators": ["192.0.2.1"],
            }
            for index in range(600)
        )
        return record

    gateway.store.change(case["id"], grow)

    summary = gateway.case_read(case["id"])
    assert len(summary["evidence"]) == 600
    assert all("raw" not in item for item in summary["evidence"])

    with pytest.raises(ValueError, match="above the .* response ceiling"):
        gateway.case_read(case["id"], view="full")

    page = gateway.case_read(case["id"], section="evidence", offset=0, limit=50, view="full")
    assert page["total"] == 600
    assert page["returned"] == 50
    assert page["next_offset"] == 50
    assert page["items"][0]["raw"]["payload"] == bulk

    last = gateway.case_read(case["id"], section="evidence", offset=580, limit=50)
    assert last["returned"] == 20
    assert last["next_offset"] is None
    assert "raw" not in last["items"][0]

    with pytest.raises(ValueError, match="Section must be one of"):
        gateway.case_read(case["id"], section="nonsense")
    with pytest.raises(ValueError, match="View must be"):
        gateway.case_read(case["id"], view="everything")


def evidence_record(index: int, payload: object) -> dict:
    return {
        "id": f"e{index}",
        "raw": payload,
        "provider": "fixture",
        "query_ids": ["q1"],
        "retrieved_at": "2026-01-05T00:00:00+00:00",
        "indicators": ["192.0.2.1"],
    }


def stored_case(root: Path, case_id: str) -> dict:
    import json
    import sqlite3

    db = sqlite3.connect(root / "cases.sqlite")
    try:
        row = db.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
        return dict(json.loads(row[0]))
    finally:
        db.close()


def test_retained_payloads_live_outside_the_case_document(tmp_path):
    """The case document is read on every disposition, so payloads must not travel inside it."""
    from test_queries import case_spec

    from hunting_harness.gateway import Gateway

    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())

    def grow(record):
        record["evidence"].extend(evidence_record(i, {"payload": f"p{i}"}) for i in range(5))
        return record

    gateway.store.change(case["id"], grow)

    assert all("raw" not in item for item in stored_case(tmp_path, case["id"])["evidence"])
    assert all("raw" not in item for item in gateway.store.read(case["id"])["evidence"])

    assert gateway.store.read_raw(case["id"], ["e1", "e3"]) == {
        "e1": {"payload": "p1"},
        "e3": {"payload": "p3"},
    }
    assert gateway.store.read_raw(case["id"], ["e1", "e1", "missing"]) == {"e1": {"payload": "p1"}}
    assert gateway.store.read_raw(case["id"], []) == {}
    assert len(gateway.store.read_raw(case["id"])) == 5

    page = gateway.case_read(case["id"], section="evidence", offset=1, limit=2, view="full")
    assert [item["raw"] for item in page["items"]] == [{"payload": "p1"}, {"payload": "p2"}]


def test_a_change_leaves_already_retained_payloads_alone(tmp_path):
    """Only newly appended evidence is written, so a change never rewrites the retained volume."""
    import sqlite3

    from test_queries import case_spec

    from hunting_harness.gateway import Gateway

    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())
    gateway.store.change(
        case["id"], lambda c: c["evidence"].append(evidence_record(0, {"payload": "first"}))
    )

    db = sqlite3.connect(tmp_path / "cases.sqlite")
    try:
        with db:
            db.execute(
                "UPDATE evidence_raw SET raw = ? WHERE case_id = ? AND evidence_id = ?",
                ('{"payload": "sentinel"}', case["id"], "e0"),
            )
    finally:
        db.close()

    gateway.store.change(
        case["id"], lambda c: c["evidence"].append(evidence_record(1, {"payload": "second"}))
    )

    assert gateway.store.read_raw(case["id"]) == {
        "e0": {"payload": "sentinel"},
        "e1": {"payload": "second"},
    }


def test_a_case_written_with_inline_payloads_is_migrated_when_it_is_opened(tmp_path):
    """Cases retained before payloads had their own table must keep reading identically."""
    import json
    import sqlite3

    from test_queries import case_spec

    from hunting_harness.gateway import Gateway
    from hunting_harness.store import Store

    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())
    payloads = {f"e{i}": {"payload": f"p{i}", "nested": {"port": 502 + i}} for i in range(3)}

    document = stored_case(tmp_path, case["id"])
    document["evidence"] = [evidence_record(i, payloads[f"e{i}"]) for i in range(3)]
    db = sqlite3.connect(tmp_path / "cases.sqlite")
    try:
        with db:
            db.execute("UPDATE cases SET data = ? WHERE id = ?", (json.dumps(document), case["id"]))
            db.execute("DELETE FROM evidence_raw")
            db.execute("PRAGMA user_version = 0")
    finally:
        db.close()

    Store(tmp_path)

    assert all("raw" not in item for item in stored_case(tmp_path, case["id"])["evidence"])
    assert Store(tmp_path).read_raw(case["id"]) == payloads
    page = Gateway(tmp_path).case_read(case["id"], section="evidence", limit=3, view="full")
    assert [item["raw"] for item in page["items"]] == [payloads[f"e{i}"] for i in range(3)]


def test_migration_runs_once_and_is_safe_to_repeat(tmp_path):
    """An interrupted upgrade must be re-runnable, and a migrated database not re-scanned."""
    import sqlite3

    from test_queries import case_spec

    from hunting_harness.gateway import Gateway
    from hunting_harness.store import Store

    gateway = Gateway(tmp_path)
    case = gateway.case_create(case_spec())
    gateway.store.change(
        case["id"], lambda c: c["evidence"].append(evidence_record(0, {"payload": "kept"}))
    )

    def user_version() -> int:
        db = sqlite3.connect(tmp_path / "cases.sqlite")
        try:
            return int(db.execute("PRAGMA user_version").fetchone()[0])
        finally:
            db.close()

    assert user_version() == Store.SCHEMA_VERSION

    db = sqlite3.connect(tmp_path / "cases.sqlite")
    try:
        with db:
            db.execute("PRAGMA user_version = 0")
    finally:
        db.close()

    for _ in range(2):
        Store(tmp_path)
        assert user_version() == Store.SCHEMA_VERSION
        assert Store(tmp_path).read_raw(case["id"]) == {"e0": {"payload": "kept"}}
