"""Evidence-complete page contract for external and future internal sources."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from ..models import Record


def observation_time(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = (
            datetime.fromtimestamp(value, UTC)
            if isinstance(value, (int, float))
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
        return parsed.replace(tzinfo=parsed.tzinfo or UTC).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


@dataclass
class Observation:
    indicators: list[str]
    observed_at: str | None
    raw: Record
    source_id: str | None = None


@dataclass
class Page:
    """One fetch result, retained before any continuation is requested.

    ``complete`` describes retrieval, not exhaustive historical coverage. Coverage
    limitations belong in metadata and ``gap``. Counts describe dispatched API
    requests and MCP tool calls, excluding MCP initialization/inventory messages.
    Unknown upstream requests or credits must stay None, never an assumed zero.
    """

    records: list[Observation]
    raw: Any
    complete: bool = True
    continuation: Record | None = None
    gap: str | None = None
    api_requests: int | None = 1
    mcp_calls: int = 0
    credits: float | None = None
    metadata: Record = field(default_factory=dict)


class SourceGap(Exception):
    """A safe status code, never an upstream exception containing credentials."""


class Provider(Protocol):
    """Common seam for external providers and future catalog adapters.

    fetch performs one explicitly requested operation and never follows a returned
    continuation itself. Reservations must be reliable upper bounds; use None
    when upstream calls cannot be observed or controlled. No internal catalog
    implementation is supplied until its backend, tables and mapping are known.
    """

    name: str
    version: str
    api_requests_per_call: int | None
    mcp_calls_per_call: int

    def operations(self) -> Record: ...
    def validate(self, operation: str, arguments: Record) -> None: ...
    async def fetch(self, operation: str, arguments: Record) -> Page: ...
