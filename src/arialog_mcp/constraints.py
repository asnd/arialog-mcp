"""Time windows and VRLI constraint-path building.

VRLI encodes constraints in the URL path: ``/events/<field>/<operator><value>/...``.
Pitfalls handled here (Log Insight query API docs, "Specifying constraints"):
* a query with no timestamp constraint only returns the last minute -> we always add one;
* word operators are separated from the value by a space (``CONTAINS%20error``), symbolic
  operators are followed by the value directly (``%3E%3D1451606400000``);
* constraints sharing field AND operator are ORed by VRLI, everything else is ANDed;
* values are percent-encoded so user text can never inject extra path segments.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from urllib.parse import quote

from pydantic import BaseModel, Field, model_validator

from .errors import InvalidInputError

FIELD_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")  # ':' for content-pack fields (ns:field)
NUMBER_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
MAX_VALUE_LEN = 200
MAX_TEXT_TERMS = 10
MAX_FILTERS = 10
REGEX_HINT = (
    "regex operators are disabled on VRLI unless the internal option "
    "api-server.regex-query-enabled is set (Broadcom KB 2123058)"
)
ENCODING_HINT = (
    "values containing '/' or '%' may be rejected by the appliance's URL handling; "
    "match on a shorter token without those characters"
)


class Op(StrEnum):
    EQ = "="
    NE = "!="
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    HAS = "HAS"
    NOT_HAS = "NOT_HAS"
    MATCHES_REGEX = "=~"
    NOT_MATCHES_REGEX = "!=~"
    EXISTS = "EXISTS"


SYMBOLIC = {Op.EQ, Op.NE, Op.MATCHES_REGEX, Op.NOT_MATCHES_REGEX}
REGEX = {Op.MATCHES_REGEX, Op.NOT_MATCHES_REGEX}


class Filter(BaseModel):
    """One field constraint, e.g. ``hostname CONTAINS esx-02`` or ``appname = vmkernel``."""

    field: str = Field(description="VRLI field name, e.g. hostname, appname, source")
    op: Op = Field(
        description=(
            "CONTAINS (phrase, case-insensitive), NOT_CONTAINS, HAS (all words, any order), "
            "NOT_HAS, = and != (documented for numeric fields), =~ and !=~ (regex; disabled "
            "on the appliance by default), EXISTS. Filters sharing field and op are ORed."
        )
    )
    value: str | None = Field(default=None, max_length=MAX_VALUE_LEN, description="Omit for EXISTS")

    @model_validator(mode="after")
    def _check(self) -> Filter:
        if not FIELD_RE.match(self.field):
            raise ValueError("field must match [A-Za-z0-9_.:-]{1,128}")
        if self.field == "timestamp":
            raise ValueError("use the time-window parameters instead of a timestamp filter")
        if self.op is Op.EXISTS:
            if self.value is not None:
                raise ValueError("EXISTS takes no value")
            return self
        if not self.value or not self.value.strip():
            raise ValueError(f"{self.op.value} needs a value")
        if self.op in SYMBOLIC and self.value[0] in "=~<>! \t":
            # The value follows a symbolic operator directly; these would change the operator.
            raise ValueError(f"a {self.op.value} value must not start with = ~ < > ! or space")
        return self


@dataclass(frozen=True)
class Window:
    start: datetime  # UTC
    end: datetime  # UTC
    last_ms: int | None = None  # set -> relative to the *appliance* clock via LAST

    @property
    def seconds(self) -> int:
        return int((self.end - self.start).total_seconds())


@dataclass(frozen=True)
class Constraints:
    path: str  # encoded path suffix
    human: list[str]  # readable form for the audit trail
    notes: list[str]  # caveats the caller should see in the result
    error_hint: str | None  # appended to the message if VRLI rejects the query


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
    if value is None:
        expr = op
    elif op[0].isalpha():
        expr = f"{op} {value}"  # word operator: space-separated
    else:
        expr = f"{op}{value}"  # symbolic operator: value follows directly
    return f"{quote(field, safe='')}/{quote(expr, safe='')}"


def _terms(label: str, terms: list[str] | None) -> list[str]:
    out = [t.strip() for t in terms or []]
    if len(out) > MAX_TEXT_TERMS:
        raise InvalidInputError(f"at most {MAX_TEXT_TERMS} {label} terms per query")
    if any(not t or len(t) > MAX_VALUE_LEN for t in out):
        raise InvalidInputError(f"{label} terms must be 1-{MAX_VALUE_LEN} characters")
    return out


def build_constraints(
    window: Window,
    text_all: list[str] | None,
    text_any: list[str] | None,
    filters: list[Filter] | None,
) -> Constraints:
    every = _terms("text_all", text_all)
    anyof = _terms("text_any", text_any)
    flts = filters or []
    if len(flts) > MAX_FILTERS:
        raise InvalidInputError(f"at most {MAX_FILTERS} filters per query")
    segs: list[str] = []
    human: list[str] = []
    notes: list[str] = []
    if window.last_ms is not None:
        segs.append(_seg("timestamp", "LAST", str(window.last_ms)))
        human.append(f"timestamp LAST {window.last_ms}")
    else:
        s_ms = int(window.start.timestamp() * 1000)
        e_ms = int(window.end.timestamp() * 1000)
        segs += [_seg("timestamp", ">=", str(s_ms)), _seg("timestamp", "<", str(e_ms))]
        human += [f"timestamp >= {s_ms}", f"timestamp < {e_ms}"]
    if every:
        # One HAS constraint: every whitespace-delimited word must occur, in any order.
        joined = " ".join(every)
        segs.append(_seg("text", Op.HAS.value, joined))
        human.append(f"text HAS {joined!r}")
    for phrase in anyof:  # repeated CONTAINS on one field -> VRLI ORs them
        segs.append(_seg("text", Op.CONTAINS.value, phrase))
        human.append(f"text CONTAINS {phrase!r}" + (" (OR)" if len(anyof) > 1 else ""))
    for f in flts:
        segs.append(_seg(f.field, f.op.value, f.value))
        human.append(f"{f.field} {f.op.value}" + (f" {f.value!r}" if f.value is not None else ""))
    # A filter sharing field+operator with another filter or a text term is ORed, not ANDed.
    taken: Counter[tuple[str, str]] = Counter((f.field, f.op.value) for f in flts)
    taken[("text", Op.CONTAINS.value)] += 1 if anyof else 0
    taken[("text", Op.HAS.value)] += 1 if every else 0
    for field, op in sorted({(f.field, f.op.value) for f in flts}):
        if taken[(field, op)] > 1:
            notes.append(f"VRLI ORs constraints that share field and operator: {field} {op}")
    if any(f.op in (Op.EQ, Op.NE) and not NUMBER_RE.match(f.value or "") for f in flts):
        notes.append(
            "= and != are documented as numeric operators; if a text field returns nothing, "
            "retry with CONTAINS"
        )
    hints: list[str] = []
    if any(f.op in REGEX for f in flts):
        hints.append(REGEX_HINT)
    if any(c in v for v in [*every, *anyof, *(f.value or "" for f in flts)] for c in "/%"):
        hints.append(ENCODING_HINT)
    return Constraints("/".join(segs), human, notes, "; ".join(hints) or None)
