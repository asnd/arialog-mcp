"""Time windows and VRLI constraint-path building.

VRLI v2 encodes constraints in the URL path: ``/events/<field>/<OP value>/...``.
Pitfalls handled here:
* a query with no timestamp constraint only returns the last minute -> we always add one;
* the space between operator and value must be ``%20`` (not ``/``);
* values are percent-encoded so user text can never inject extra path segments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from urllib.parse import quote

from pydantic import BaseModel, Field, model_validator

from .errors import InvalidInputError

FIELD_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
MAX_VALUE_LEN = 200
MAX_TEXT_TERMS = 10
MAX_FILTERS = 10


class Op(StrEnum):
    EQ = "="
    NE = "!="
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    MATCHES = "MATCHES"
    EXISTS = "EXISTS"


class Filter(BaseModel):
    """One field constraint, e.g. ``hostname = esx-02`` or ``appname CONTAINS vmkernel``."""

    field: str = Field(description="VRLI field name, e.g. hostname, appname, source")
    op: Op = Field(description="=, !=, CONTAINS, NOT_CONTAINS, MATCHES (regex) or EXISTS")
    value: str | None = Field(default=None, max_length=MAX_VALUE_LEN, description="Omit for EXISTS")

    @model_validator(mode="after")
    def _check(self) -> Filter:
        if not FIELD_RE.match(self.field):
            raise ValueError("field must match [A-Za-z0-9_.-]{1,64}")
        if self.field == "timestamp":
            raise ValueError("use the time-window parameters instead of a timestamp filter")
        if self.op is Op.EXISTS:
            if self.value is not None:
                raise ValueError("EXISTS takes no value")
        elif not self.value:
            raise ValueError(f"{self.op.value} needs a value")
        return self


@dataclass(frozen=True)
class Window:
    start: datetime  # UTC
    end: datetime  # UTC
    last_ms: int | None = None  # set -> relative to the *appliance* clock via LAST

    @property
    def seconds(self) -> int:
        return int((self.end - self.start).total_seconds())


def _parse_aware(label: str, value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise InvalidInputError(f"{label} is not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        # Never guess a timezone: a wrong guess silently queries the wrong hour.
        raise InvalidInputError(f"{label} needs a timezone offset (e.g. 2026-10-07T12:00:00Z)")
    return parsed.astimezone(UTC)


def resolve_window(
    last_minutes: int | None,
    start: str | None,
    end: str | None,
    *,
    now: datetime,
    max_hours: int,
) -> Window:
    if last_minutes is not None and (start or end):
        raise InvalidInputError("give either last_minutes or start/end, not both")
    if last_minutes is not None:
        if last_minutes < 1:
            raise InvalidInputError("last_minutes must be >= 1")
        win = Window(now - timedelta(minutes=last_minutes), now, last_ms=last_minutes * 60_000)
    else:
        if not start:
            raise InvalidInputError("give last_minutes, or start (and optionally end)")
        s = _parse_aware("start", start)
        e = _parse_aware("end", end) if end else now
        win = Window(s, e)
    if win.end <= win.start:
        raise InvalidInputError("end must be after start")
    if win.seconds > max_hours * 3600:
        raise InvalidInputError(f"window exceeds the {max_hours}h limit; narrow it")
    return win


def _seg(field: str, op: str, value: str | None) -> str:
    expr = op if value is None else f"{op} {value}"
    return f"{quote(field, safe='')}/{quote(expr, safe='')}"


def build_constraints(
    window: Window, text_contains: list[str] | None, filters: list[Filter] | None
) -> tuple[str, list[str]]:
    """Return (encoded path suffix, human-readable constraint list for the audit trail)."""
    texts = text_contains or []
    flts = filters or []
    if len(texts) > MAX_TEXT_TERMS or len(flts) > MAX_FILTERS:
        raise InvalidInputError(
            f"at most {MAX_TEXT_TERMS} text terms and {MAX_FILTERS} filters per query"
        )
    segs: list[str] = []
    human: list[str] = []
    if window.last_ms is not None:
        segs.append(_seg("timestamp", "LAST", str(window.last_ms)))
        human.append(f"timestamp LAST {window.last_ms}")
    else:
        s_ms = int(window.start.timestamp() * 1000)
        e_ms = int(window.end.timestamp() * 1000)
        segs.append(_seg("timestamp", ">=", str(s_ms)))
        segs.append(_seg("timestamp", "<", str(e_ms)))
        human += [f"timestamp >= {s_ms}", f"timestamp < {e_ms}"]
    for term in texts:
        if not term or len(term) > MAX_VALUE_LEN:
            raise InvalidInputError(f"text term must be 1-{MAX_VALUE_LEN} characters")
        segs.append(_seg("text", "CONTAINS", term))
        human.append(f"text CONTAINS {term!r}")
    for f in flts:
        segs.append(_seg(f.field, f.op.value, f.value))
        human.append(f"{f.field} {f.op.value}" + (f" {f.value!r}" if f.value is not None else ""))
    return "/".join(segs), human
