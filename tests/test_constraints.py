from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from arialog_mcp.constraints import Filter, Op, build_constraints, resolve_window
from arialog_mcp.errors import InvalidInputError

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


def win(**kw):
    return resolve_window(kw.get("last"), kw.get("start"), kw.get("end"), now=NOW, max_hours=72)


def test_relative_window_uses_last():
    path, human = build_constraints(win(last=60), None, None)
    assert path == "timestamp/LAST%203600000" and human == ["timestamp LAST 3600000"]


def test_absolute_window_encodes_operators_with_percent20():
    path, _ = build_constraints(
        win(start="2026-10-07T10:00:00Z", end="2026-10-07T11:00:00Z"), None, None
    )
    lo = int(datetime(2026, 10, 7, 10, tzinfo=UTC).timestamp() * 1000)
    hi = lo + 3_600_000
    assert path == f"timestamp/%3E%3D%20{lo}/timestamp/%3C%20{hi}"


def test_values_cannot_inject_path_segments():
    path, _ = build_constraints(
        win(last=5), ["a/b/timestamp/LAST 1"], [Filter(field="hostname", op=Op.EQ, value="x/y")]
    )
    assert path.count("/") == 5  # timestamp/<e>, text/<e>, hostname/<e> -> exactly 3 pairs
    assert "%2F" in path


@pytest.mark.parametrize(
    "kw,msg",
    [
        (dict(start="2026-10-07T10:00:00"), "timezone"),
        (dict(start="garbage"), "ISO-8601"),
        (dict(last=5, start="2026-10-07T10:00:00Z"), "either"),
        (dict(), "last_minutes"),
        (dict(start="2026-10-07T12:00:00Z", end="2026-10-07T11:00:00Z"), "after start"),
        (dict(start="2026-10-01T00:00:00Z", end="2026-10-07T00:00:00Z"), "72h"),
        (dict(last=0), ">= 1"),
    ],
)
def test_window_validation(kw, msg):
    with pytest.raises(InvalidInputError, match=msg):
        win(**kw)


def test_filter_validation():
    with pytest.raises(ValidationError):
        Filter(field="bad field!", op=Op.EQ, value="x")
    with pytest.raises(ValidationError):
        Filter(field="timestamp", op=Op.EQ, value="1")
    with pytest.raises(ValidationError):
        Filter(field="host", op=Op.EXISTS, value="x")
    with pytest.raises(ValidationError):
        Filter(field="host", op=Op.EQ)
    assert Filter(field="host", op=Op.EXISTS).value is None


def test_too_many_terms():
    with pytest.raises(InvalidInputError):
        build_constraints(win(last=5), ["t"] * 11, None)


def test_empty_or_oversized_text_term_rejected():
    with pytest.raises(InvalidInputError, match="1-200"):
        build_constraints(win(last=5), [""], None)
    with pytest.raises(InvalidInputError, match="1-200"):
        build_constraints(win(last=5), ["x" * 201], None)
