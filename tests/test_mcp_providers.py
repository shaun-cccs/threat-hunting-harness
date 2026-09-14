import sys
from pathlib import Path

import pytest

from hunting_harness.providers.mcp_source import McpSource
from hunting_harness.providers.transport import McpTransport


@pytest.mark.parametrize(
    "name,operation,args,expected",
    [
        ("censys", "search", {"query": "host.services.cert.fingerprint_sha256:abc"}, "192.0.2.4"),
        (
            "gti",
            "get_entities_related_to_a_domain",
            {
                "domain": "seed.example",
                "relationship_name": "resolutions",
                "descriptors_only": False,
                "limit": 1,
            },
            "192.0.2.5",
        ),
        ("greynoise", "gnql-query", {"query": "last_seen:2024-01-08", "size": 1}, "192.0.2.6"),
    ],
)
async def test_selected_mcp_retrieval_preserves_dated_candidates_and_completeness(
    name, operation, args, expected
):
    transport = McpTransport(
        command=sys.executable,
        args=[str(Path(__file__).parent / "fixtures/provider_server.py")],
        env={"FIXTURE_PROVIDER": name},
    )
    source = McpSource(name, transport)
    page = await source.fetch(operation, args)
    assert expected in page.records[0].indicators
    assert page.records[0].observed_at.startswith("2024-01-")
    assert page.raw
    assert page.complete is False
    assert page.api_requests is None
    with pytest.raises(ValueError, match="Unsupported"):
        await source.fetch("analyse_file", {"path": "anything"})
