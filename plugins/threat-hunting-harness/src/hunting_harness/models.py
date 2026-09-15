"""Validated inputs at the hunting gateway seam."""

import ipaddress
import re
from datetime import UTC, date, datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

Record = dict[str, Any]


def now() -> str:
    return datetime.now(UTC).isoformat()


def indicator(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.encode("idna").decode("ascii")
    if (
        len(value) > 253
        or "." not in value
        or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        )
    ):
        raise ValueError("Expected an IP address or domain, without a URL or path")
    if all(part.isdigit() for part in value.split(".")):
        raise ValueError("Invalid IP address")
    return value


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="after")
    @classmethod
    def nonblank_text(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError("Text values cannot be blank")
        if isinstance(value, list) and any(
            isinstance(item, str) and not item.strip() for item in value
        ):
            raise ValueError("Text entries cannot be blank")
        return value


class CaseSpec(Input):
    hypothesis: str = Field(min_length=1)
    seeds: list[str] = Field(min_length=1)
    start: date
    end: date
    limits: dict[str, StrictInt] = Field(default_factory=dict)

    @field_validator("hypothesis")
    @classmethod
    def hypothesis_valid(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Hypothesis cannot be blank")
        return value.strip()

    @field_validator("limits")
    @classmethod
    def limits_valid(cls, value: dict[str, int]) -> dict[str, int]:
        if any(
            k not in ("query_calls", "mcp_calls", "api_requests") or v < 0 for k, v in value.items()
        ):
            raise ValueError("Limits must name controllable measures and be nonnegative")
        return value

    @field_validator("seeds")
    @classmethod
    def seeds_valid(cls, seeds: list[str]) -> list[str]:
        return list(dict.fromkeys(indicator(seed) for seed in seeds))

    @model_validator(mode="after")
    def dates_valid(self) -> Self:
        if self.end < self.start:
            raise ValueError("Campaign end precedes start")
        return self


class QuerySpec(Input):
    provider: str
    operation: str
    arguments: Record
    pivot_from: str
    purpose: str = Field(min_length=1)
    refresh: bool = False
    continuation_of: str | None = None

    @field_validator("pivot_from")
    @classmethod
    def pivot_valid(cls, value: str) -> str:
        return indicator(value)


class Expansion(Input):
    candidate: str
    evidence_ids: list[str] = Field(min_length=1)
    hypothesis: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    relationship: str
    distinctive: bool = False

    @field_validator("candidate")
    @classmethod
    def candidate_valid(cls, value: str) -> str:
        return indicator(value)


class Claim(Input):
    candidate: str
    kind: Literal["relatedness", "historical_association", "current_malicious_use", "attribution"]
    statement: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    alternative_explanations: list[str] = Field(min_length=1)
    freshness_start: date | None = None
    freshness_end: date | None = None
    attribution_basis: str | None = None
    hypothesis: str | None = None

    @model_validator(mode="after")
    def freshness_valid(self) -> Self:
        if bool(self.freshness_start) != bool(self.freshness_end):
            raise ValueError("Supply both freshness window dates")
        if (
            self.freshness_start
            and self.freshness_end
            and self.freshness_end < self.freshness_start
        ):
            raise ValueError("Freshness end precedes start")
        return self

    @field_validator("candidate")
    @classmethod
    def candidate_valid(cls, value: str) -> str:
        return indicator(value)


class Review(Input):
    reviewer: str = Field(min_length=1)
    assessment: Literal["supported", "challenged", "insufficient"]
    rationale: str = Field(min_length=1)
    flags: list[
        Literal[
            "shared_infrastructure",
            "stale_evidence",
            "conflicting_observations",
            "reassignment",
            "copied_sources",
            "missing_dates",
            "unsupported_attribution",
        ]
    ] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)
