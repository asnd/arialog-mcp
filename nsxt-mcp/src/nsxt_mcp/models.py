"""Typed envelopes preserve unknown NSX fields without inventing missing operational state."""

from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class PolicyObject(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    id: str
    path: str | None = None
    display_name: str | None = None
    scope: list[str] | None = None


class GatewayPolicy(PolicyObject):
    category: str | None = None
    sequence_number: int | None = Field(default=None, ge=0)
    internal_sequence_number: int | None = None
    stateful: bool | None = None


class FirewallRule(PolicyObject):
    sequence_number: int | None = Field(default=None, ge=0)
    action: str | None = None
    disabled: bool | None = None
    logged: bool | None = None
    source_groups: list[str] | None = None
    destination_groups: list[str] | None = None
    services: list[str] | None = None
    sources_excluded: bool | None = None
    destinations_excluded: bool | None = None
    direction: str | None = None
    service_entries: list[dict[str, Any]] | None = None


class Evidence(BaseModel):
    target: str
    source: str
    selection: dict[str, str | int] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    notes: list[str] = Field(default_factory=list)


class Detail(Evidence, Generic[T]):
    data: T


class Collection(Evidence, Generic[T]):
    items: list[T]
    complete: bool
    next_cursor: str | None
    pages: int


class Observation(Evidence):
    data: dict[str, Any]
    complete: bool = True
