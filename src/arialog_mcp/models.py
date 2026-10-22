"""Typed tool results. Every result carries the exact query that produced it."""

from __future__ import annotations

from pydantic import BaseModel, Field


class QueryInfo(BaseModel):
    endpoint: str = Field(description="VRLI API endpoint used")
    constraints: list[str] = Field(description="Exact constraints sent, for the audit trail")
    window_start: str = Field(description="UTC ISO-8601")
    window_end: str = Field(description="UTC ISO-8601")
    relative_window: bool = Field(
        description="True when the window is 'last N minutes' evaluated on the appliance clock"
    )


class Event(BaseModel):
    time: str = Field(description="UTC ISO-8601")
    host: str | None = None
    text: str
    fields: dict[str, str] = Field(default_factory=dict)


class SearchResult(BaseModel):
    query: QueryInfo
    returned: int
    complete: bool = Field(description="False if VRLI hit its query timeout (partial result)")
    truncated: bool
    truncated_reason: str | None = None
    events: list[Event]
    notes: list[str] = Field(default_factory=list)


class Signature(BaseModel):
    signature_id: str
    template: str = Field(description="Message with ids/IPs/numbers masked")
    count: int
    first_seen: str
    last_seen: str
    top_hosts: dict[str, int] = Field(default_factory=dict)
    samples: list[str] = Field(default_factory=list)


class SignatureResult(BaseModel):
    query: QueryInfo
    scanned: int
    distinct_signatures: int
    scan_truncated: bool = Field(
        description="True: more events matched than were scanned; counts are lower bounds"
    )
    covered_from: str | None = Field(
        default=None, description="Oldest event scanned (newest events are scanned first)"
    )
    complete: bool
    signatures: list[Signature]
    notes: list[str] = Field(default_factory=list)


class Bin(BaseModel):
    start: str = Field(description="UTC ISO-8601 bin start")
    count: int
    zscore: float | None = None
    spike: bool = False


class AggregateResult(BaseModel):
    query: QueryInfo
    bin_seconds: int
    total: int
    peak: Bin | None = None
    spikes: list[Bin] = Field(default_factory=list)
    bins: list[Bin]
    complete: bool
    notes: list[str] = Field(default_factory=list)


class VersionInfo(BaseModel):
    version: str | None = None
    release: str | None = None
    raw: dict[str, object] = Field(default_factory=dict)
