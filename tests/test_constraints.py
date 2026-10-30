from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from arialog_mcp.constraints import (
    ENCODING_HINT,
    REGEX_HINT,
    Filter,
    Op,
    build_constraints,
    resolve_window,
)
from arialog_mcp.errors import InvalidInputError

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


def win(**kw):
    return resolve_window(kw.get("last"), kw.get("start"), kw.get("end"), now=NOW, max_hours=72)


def build(window, text_all=None, text_any=None, filters=None):
    return build_constraints(window, text_all, text_any, filters)


def test_relative_window_uses_last_with_space():
    c = build(win(last=60))
    assert c.path == "timestamp/LAST%203600000" and c.human == ["timestamp LAST 3600000"]
    assert c.notes == [] and c.error_hint is None


def test_absolute_window_symbolic_operators_take_the_value_directly():
    c = build(win(start="2026-10-07T10:00:00Z", end="2026-10-07T11:00:00Z"))
    lo = int(datetime(2026, 10, 7, 10, tzinfo=UTC).timestamp() * 1000)
    assert c.path == f"timestamp/%3E%3D{lo}/timestamp/%3C{lo + 3_600_000}"


def test_text_all_is_one_has_constraint_and_text_any_repeats_contains():
    c = build(win(last=5), text_all=["Lost access", "datastore"], text_any=["SCSI", "APD"])
    assert c.path.split("/")[2:] == [
        "text",
        "HAS%20Lost%20access%20datastore",
        "text",
        "CONTAINS%20SCSI",
        "text",
        "CONTAINS%20APD",
    ]
    assert "text CONTAINS 'SCSI' (OR)" in c.human
    assert c.notes == []  # text_any ORing is the documented intent, no warning


@pytest.mark.parametrize(
    "op,value,expr",
    [
        (Op.EQ, "5", "%3D5"),
        (Op.NE, "5", "%21%3D5"),
        (Op.MATCHES_REGEX, "ERR.*", "%3D~ERR.%2A"),
        (Op.NOT_MATCHES_REGEX, "x", "%21%3D~x"),
        (Op.CONTAINS, "a b", "CONTAINS%20a%20b"),
        (Op.NOT_HAS, "a", "NOT_HAS%20a"),
        (Op.EXISTS, None, "EXISTS"),
    ],
)
def test_operator_encoding(op, value, expr):
    c = build(win(last=5), filters=[Filter(field="f", op=op, value=value)])
    assert c.path.endswith(f"/f/{expr}")


def test_values_cannot_inject_path_segments():
    c = build(
        win(last=5),
        text_any=["a/b/timestamp/LAST 1"],
        filters=[Filter(field="hostname", op=Op.CONTAINS, value="x/y")],
    )
    assert c.path.count("/") == 5  # timestamp/<e>, text/<e>, hostname/<e> -> exactly 3 pairs
    assert "%2F" in c.path and c.error_hint == ENCODING_HINT


def test_same_field_and_operator_filters_are_flagged_as_or():
    c = build(
        win(last=5),
        filters=[
            Filter(field="hostname", op=Op.CONTAINS, value="esx-01"),
            Filter(field="hostname", op=Op.CONTAINS, value="esx-02"),
            Filter(field="appname", op=Op.CONTAINS, value="vmkernel"),
        ],
    )
    assert c.notes == ["VRLI ORs constraints that share field and operator: hostname CONTAINS"]


def test_text_filter_colliding_with_text_any_is_flagged():
    c = build(
        win(last=5), text_any=["a"], filters=[Filter(field="text", op=Op.CONTAINS, value="b")]
    )
    assert any("text CONTAINS" in n for n in c.notes)


def test_string_equality_gets_a_note_numbers_do_not():
    c = build(win(last=5), filters=[Filter(field="hostname", op=Op.EQ, value="esx-02")])
    assert any("numeric" in n for n in c.notes)
    assert build(win(last=5), filters=[Filter(field="size", op=Op.EQ, value="10")]).notes == []


def test_regex_filter_carries_the_disabled_hint():
    c = build(win(last=5), filters=[Filter(field="text", op=Op.MATCHES_REGEX, value="x")])
    assert c.error_hint == REGEX_HINT


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
    with pytest.raises(ValidationError):
        Filter(field="host", op=Op.CONTAINS, value="  ")
    assert Filter(field="host", op=Op.EXISTS).value is None
    assert Filter(field="com.vmware.vsphere:vmw_user", op=Op.CONTAINS, value="x")


@pytest.mark.parametrize("value", ["~x", "=x", ">1", " x", "!x"])
def test_symbolic_value_cannot_change_the_operator(value):
    with pytest.raises(ValidationError, match="must not start"):
        Filter(field="f", op=Op.EQ, value=value)
    assert Filter(field="f", op=Op.CONTAINS, value=value)  # word operators are space-separated


def test_too_many_terms_or_filters():
    with pytest.raises(InvalidInputError, match="text_all"):
        build(win(last=5), text_all=["t"] * 11)
    with pytest.raises(InvalidInputError, match="text_any"):
        build(win(last=5), text_any=["t"] * 11)
    with pytest.raises(InvalidInputError, match="filters"):
        build(win(last=5), filters=[Filter(field="f", op=Op.EXISTS)] * 11)


def test_empty_or_oversized_text_term_rejected():
    with pytest.raises(InvalidInputError, match="1-200"):
        build(win(last=5), text_any=[" "])
    with pytest.raises(InvalidInputError, match="1-200"):
        build(win(last=5), text_all=["x" * 201])
