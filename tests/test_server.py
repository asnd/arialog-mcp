from __future__ import annotations

import inspect
import logging

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from arialog_mcp.client import RawEvents, VRLIClient
from arialog_mcp.reduce import RawEvent
from arialog_mcp.server import create_server
from arialog_mcp.service import ArialogService
from conftest import ANCHOR, END, START, FakeClock, Stub, make_settings, no_sleep

WINDOW = {"start": START, "end": END}


@pytest.fixture
def make_mcp(stub: Stub, clock: FakeClock):
    clients: list[VRLIClient] = []

    def _make(**over):
        s = make_settings(**over)
        c = VRLIClient(s, transport=httpx.ASGITransport(app=stub.app), sleep=no_sleep, clock=clock)
        clients.append(c)
        return create_server(s, c)

    yield _make


async def call(mcp, tool, args):
    async with Client(mcp) as c:
        return (await c.call_tool(tool, args)).structured_content


async def test_exposes_only_the_four_read_only_tools(make_mcp):
    async with Client(make_mcp()) as c:
        tools = await c.list_tools()
    assert {t.name for t in tools} == {"version", "log_aggregate", "log_signatures", "log_search"}
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)


async def test_aggregate_finds_the_burst(make_mcp):
    r = await call(make_mcp(), "log_aggregate", {**WINDOW, "bin_seconds": 120})
    assert r["bin_seconds"] == 120 and r["total"] == 1564 and r["complete"]
    spikes = r["spikes"]
    assert spikes
    starts = {s["start"][11:16] for s in spikes}
    assert starts <= {"11:28", "11:30", "11:32", "11:34"} and "11:30" in starts
    assert r["peak"]["count"] > 400
    assert r["query"]["constraints"][0].startswith("timestamp >=")


async def test_aggregate_bin_width_never_exceeds_cap(make_mcp):
    r = await call(make_mcp(max_bins=24), "log_aggregate", {**WINDOW, "bin_seconds": 1})
    assert r["bin_seconds"] >= 300 and len(r["bins"]) <= 24
    assert any("raised" in n for n in r["notes"])


async def test_signatures_group_and_rank(make_mcp):
    r = await call(make_mcp(), "log_signatures", WINDOW)
    top, second = r["signatures"][0], r["signatures"][1]
    assert top["template"].startswith("ScsiDeviceIO") and top["count"] == 1200
    assert top["top_hosts"] == {"esx-02": 1200} and len(top["samples"]) == 2
    assert second["template"].startswith("Accepted password") and second["count"] == 360
    assert r["distinct_signatures"] == 3 and r["scanned"] == 1564 and not r["scan_truncated"]
    assert r["signatures"][2]["count"] == 4  # four VMFS ids collapse into one template


async def test_signatures_flag_truncated_scan(make_mcp):
    r = await call(make_mcp(signature_scan_limit=100), "log_signatures", WINDOW)
    assert r["scan_truncated"] and r["scanned"] == 100
    assert any("lower bounds" in n for n in r["notes"])
    assert r["covered_from"] is not None


async def test_search_filters_and_orders_newest_first(make_mcp):
    r = await call(
        make_mcp(),
        "log_search",
        {
            **WINDOW,
            "text_contains": ["Lost access"],
            "filters": [{"field": "hostname", "op": "=", "value": "esx-02"}],
            "limit": 10,
        },
    )
    assert r["returned"] == 4 and not r["truncated"]
    times = [e["time"] for e in r["events"]]
    assert times == sorted(times, reverse=True) and r["events"][0]["host"] == "esx-02"


async def test_search_caps_limit_and_reports_it(make_mcp):
    r = await call(make_mcp(max_events=20), "log_search", {**WINDOW, "limit": 1000})
    assert r["returned"] == 20 and r["truncated"]
    assert any("server cap of 20" in n for n in r["notes"])


async def test_search_byte_budget(make_mcp):
    r = await call(make_mcp(max_bytes=1_000), "log_search", {**WINDOW, "limit": 200})
    assert r["truncated"] and "byte budget" in r["truncated_reason"] and r["returned"] < 20


async def test_relative_window(make_mcp):
    r = await call(make_mcp(), "log_search", {"last_minutes": 120, "limit": 1})
    assert r["returned"] == 1 and r["query"]["relative_window"]


async def test_text_term_cannot_escape_into_other_constraints(make_mcp):
    r = await call(make_mcp(), "log_search", {**WINDOW, "text_contains": ["x/timestamp/LAST 1"]})
    assert r["returned"] == 0  # no 400, no widened window


async def test_naive_timestamp_is_a_clear_tool_error(make_mcp):
    with pytest.raises(ToolError, match="timezone"):
        await call(make_mcp(), "log_search", {"start": "2026-10-07T10:00:00"})


async def test_unavailable_is_a_tool_error_without_secrets(make_mcp, stub: Stub):
    await stub.faults(unavailable_next=999)
    with pytest.raises(ToolError) as ei:
        await call(make_mcp(), "log_search", {**WINDOW})
    assert "unavailable" in str(ei.value).lower() and "placeholder" not in str(ei.value)


async def test_partial_result_is_surfaced(make_mcp, stub: Stub):
    await stub.faults(partial=True)
    r = await call(make_mcp(), "log_search", {**WINDOW, "limit": 100})
    assert r["complete"] is False and any("partial" in n for n in r["notes"])


async def test_version(make_mcp):
    r = await call(make_mcp(), "version", {})
    assert r["version"].startswith("8.18")


async def test_aggregate_notes_partial_and_too_few_bins(make_mcp, stub: Stub):
    await stub.faults(partial=True)
    r = await call(
        make_mcp(),
        "log_aggregate",
        {"start": "2026-10-07T11:00:00Z", "end": "2026-10-07T11:05:00Z", "bin_seconds": 120},
    )
    assert r["complete"] is False
    assert any("partial" in n for n in r["notes"])
    assert any("spike detection skipped" in n for n in r["notes"])
    assert r["spikes"] == []


async def test_signatures_note_partial(make_mcp, stub: Stub):
    await stub.faults(partial=True)
    r = await call(make_mcp(), "log_signatures", WINDOW)
    assert r["complete"] is False and any("partial" in n for n in r["notes"])


async def test_signatures_empty_window(make_mcp):
    r = await call(
        make_mcp(),
        "log_signatures",
        {"start": "2026-10-06T00:00:00Z", "end": "2026-10-06T01:00:00Z"},
    )
    assert r["scanned"] == 0 and r["signatures"] == [] and r["covered_from"] is None


async def test_audit_log_records_calls_without_secrets(make_mcp, caplog):
    caplog.set_level(logging.INFO, logger="arialog_mcp.audit")
    await call(
        make_mcp(),
        "log_search",
        {**WINDOW, "limit": 1, "text_contains": ["audit-secret-value"]},
    )
    with pytest.raises(ToolError):
        await call(make_mcp(), "log_search", {"start": "2026-10-07T10:00:00"})
    recs = [r for r in caplog.records if r.name == "arialog_mcp.audit"]
    assert [r.getMessage() for r in recs] == ["tool ok", "tool failed"]
    assert recs[0].tool == "log_search" and recs[0].ms >= 0
    assert not hasattr(recs[0], "tool_args")
    assert "placeholder" not in caplog.text and "Bearer" not in caplog.text
    assert "audit-secret-value" not in caplog.text


async def test_unexpected_exception_is_logged_and_surfaced(make_mcp, caplog):
    mcp = make_mcp()

    async def boom(*a, **k):
        raise RuntimeError("kaboom")

    for cell in inspect.unwrap((await mcp.get_tool("log_search")).fn).__closure__ or ():
        if isinstance(cell.cell_contents, ArialogService):
            cell.cell_contents.client.events = boom  # type: ignore[method-assign]
    with caplog.at_level(logging.ERROR, logger="arialog_mcp.audit"), pytest.raises(ToolError):
        await call(mcp, "log_search", WINDOW)
    assert any(r.getMessage() == "tool crashed" for r in caplog.records)


async def test_healthz_does_not_touch_vrli(make_mcp, stub: Stub):
    app = make_mcp().http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/healthz")
    assert r.status_code == 200 and r.text == "ok"
    assert (await stub.stats())["request_count"] == 0


async def test_server_closes_client_it_created(monkeypatch):
    closed: list[bool] = []

    async def fake_close(self) -> None:
        closed.append(True)

    monkeypatch.setattr(VRLIClient, "aclose", fake_close)
    mcp = create_server(make_settings())  # no client injected -> server owns it
    async with Client(mcp) as c:
        await c.list_tools()
    assert closed == [True]


async def test_injected_client_is_not_closed_by_server(make_mcp, monkeypatch):
    closed: list[bool] = []

    async def fake_close(self) -> None:
        closed.append(True)

    monkeypatch.setattr(VRLIClient, "aclose", fake_close)
    async with Client(make_mcp()) as c:
        await c.list_tools()
    assert closed == []


async def test_invalid_arguments_are_audited_as_rejected(make_mcp, caplog):
    caplog.set_level(logging.INFO, logger="arialog_mcp.audit")
    with pytest.raises(ToolError):
        await call(make_mcp(), "log_search", {**WINDOW, "limit": 0})  # violates ge=1
    recs = [r for r in caplog.records if r.name == "arialog_mcp.audit"]
    assert [r.getMessage() for r in recs] == ["tool rejected"]
    assert recs[0].exc_info is None  # no traceback noise for caller mistakes


async def test_unexpected_exception_details_are_masked(make_mcp):
    mcp = make_mcp()

    async def boom(*a, **k):
        raise RuntimeError("internal detail /etc/secret")

    for cell in inspect.unwrap((await mcp.get_tool("log_search")).fn).__closure__ or ():
        if isinstance(cell.cell_contents, ArialogService):
            cell.cell_contents.client.events = boom  # type: ignore[method-assign]
    with pytest.raises(ToolError) as ei:
        await call(mcp, "log_search", WINDOW)
    assert "internal detail" not in str(ei.value)


async def test_search_and_signature_outputs_redact_sensitive_log_content(make_mcp):
    mcp = make_mcp()

    async def events(*args, **kwargs):
        return RawEvents(
            [
                RawEvent(
                    ANCHOR,
                    'password="log-secret" Authorization: Bearer token-value',
                    {"hostname": "node-a", "api_key": "field-secret"},
                )
            ],
            complete=True,
        )

    for cell in inspect.unwrap((await mcp.get_tool("log_search")).fn).__closure__ or ():
        if isinstance(cell.cell_contents, ArialogService):
            cell.cell_contents.client.events = events  # type: ignore[method-assign]
    search = await call(mcp, "log_search", WINDOW)
    signatures = await call(mcp, "log_signatures", WINDOW)
    rendered = str(search) + str(signatures)
    assert "log-secret" not in rendered
    assert "token-value" not in rendered
    assert "field-secret" not in rendered
    assert "[redacted]" in rendered


async def test_too_many_text_terms_rejected_by_schema(make_mcp):
    with pytest.raises(ToolError):
        await call(make_mcp(), "log_search", {**WINDOW, "text_contains": ["a"] * 11})


async def test_readyz_reflects_breaker_without_touching_vrli(make_mcp, stub: Stub):
    mcp = make_mcp()
    app = mcp.http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/readyz")).status_code == 200
        await stub.faults(unavailable_next=999)
        for _ in range(2):  # breaker_failures=2
            with pytest.raises(ToolError):
                await call(mcp, "log_search", WINDOW)
        before = (await stub.stats())["request_count"]
        r = await c.get("/readyz")
        assert r.status_code == 503 and "circuit open" in r.text
        assert (await stub.stats())["request_count"] == before


async def test_http_auth_token_guards_mcp_but_not_probes(make_mcp):
    token = "s" * 32
    app = make_mcp(http_auth_token=token).http_app()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c,
    ):
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 200
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        hdrs = {"accept": "application/json, text/event-stream"}
        assert (await c.post("/mcp", json=body, headers=hdrs)).status_code == 401
        bad = {**hdrs, "authorization": "Bearer " + "x" * 32}
        assert (await c.post("/mcp", json=body, headers=bad)).status_code == 401
        good = {**hdrs, "authorization": f"Bearer {token}"}
        assert (await c.post("/mcp", json=body, headers=good)).status_code != 401


async def test_http_tool_calls_are_rate_limited_per_authenticated_caller(make_mcp):
    token = "r" * 32
    app = make_mcp(http_auth_token=token, caller_burst=1).http_app(
        stateless_http=True, json_response=True
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "version", "arguments": {}},
    }
    headers = {
        "authorization": f"Bearer {token}",
        "accept": "application/json, text/event-stream",
    }
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client,
    ):
        first = await client.post("/mcp", json=body, headers=headers)
        second = await client.post("/mcp", json=body, headers=headers)
    assert first.status_code == second.status_code == 200
    assert not first.json()["result"].get("isError")
    assert second.json()["result"]["isError"]
    assert "request budget" in second.json()["result"]["content"][0]["text"]
