"""End-to-end checks against a running arialog-mcp (HTTP) + vrli-stub. Run inside a container.

usage: e2e_client.py <mcp_url> <stub_url> <badcreds_mcp_url>
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.request
from datetime import UTC, datetime

from fastmcp import Client
from fastmcp.exceptions import ToolError

MCP, STUB, BAD = sys.argv[1:4]
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def stub(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        STUB + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json"},
    )
    return json.load(OPENER.open(req, timeout=5))


def ok(name: str) -> None:
    print(f"PASS {name}", flush=True)


async def call(url: str, tool: str, args: dict):
    async with Client(url) as c:
        return (await c.call_tool(tool, args)).structured_content


async def expect_error(url: str, tool: str, args: dict, needle: str) -> None:
    try:
        await call(url, tool, args)
    except ToolError as exc:
        assert needle in str(exc).lower(), f"expected {needle!r} in {exc}"
        assert "placeholder" not in str(exc) and "wrong" not in str(exc), "secret leaked"
        return
    raise AssertionError(f"{tool} should have failed with {needle!r}")


async def main() -> None:
    anchor = stub("GET", "/_stub/stats")["anchor_ms"]
    # The stub's "now" is its start time; use absolute windows around its dataset.
    end = datetime.fromtimestamp((anchor + 60_000) / 1000, tz=UTC).isoformat()
    start = datetime.fromtimestamp((anchor - 125 * 60_000) / 1000, tz=UTC).isoformat()
    window = {"start": start, "end": end}

    async with Client(MCP) as c:
        names = {t.name for t in await c.list_tools()}
    assert names == {"version", "log_aggregate", "log_signatures", "log_search"}, names
    ok("tools listed")

    v = await call(MCP, "version", {})
    assert v["version"].startswith("8.18")
    ok("version")

    agg = await call(MCP, "log_aggregate", {**window, "bin_seconds": 120})
    assert agg["spikes"] and agg["total"] == 1564, agg["total"]
    ok("aggregate finds the SCSI burst")

    sig = await call(MCP, "log_signatures", window)
    assert "ScsiDeviceIO" in sig["signatures"][0]["template"]
    assert sig["signatures"][0]["count"] == 1200 and not sig["scan_truncated"]
    ok("signatures group + rank")

    srch = await call(MCP, "log_search", {**window, "text_any": ["Lost access"], "limit": 5})
    assert srch["returned"] == 4 and srch["events"][0]["host"] == "esx-02"
    assert srch["events"][0]["fields"]["appname"] == "vmkernel"
    ok("search with filter; hostname/appname read from text offsets")

    both = await call(MCP, "log_search", {**window, "text_all": ["volume", "lost"], "limit": 10})
    none = await call(MCP, "log_search", {**window, "text_all": ["volume", "ScsiDeviceIO"]})
    assert both["returned"] == 4 and none["returned"] == 0
    ok("text_all keeps AND semantics")

    sparse = await call(
        MCP, "log_aggregate", {**window, "text_any": ["ScsiDeviceIO"], "bin_seconds": 300}
    )
    # The stub anchors at container start, so the 5-minute burst may straddle two 300 s bins;
    # then only the bigger part is a spike. Empty bins (omitted by the stub) must be zero-filled.
    nonzero = [b for b in sparse["bins"] if b["count"]]
    assert sparse["total"] == 1200 and 1 <= len(nonzero) <= 2, nonzero
    assert sparse["spikes"] and sparse["spikes"][0]["start"] == sparse["peak"]["start"], sparse
    assert len(sparse["bins"]) - len(nonzero) >= 20  # gaps were zero-filled
    ok("aggregate zero-fills sparse bins")

    # --- failure paths ---
    await expect_error(MCP, "log_search", {"start": "2026-10-07T10:00:00"}, "timezone")
    ok("naive timestamp rejected")

    stub("POST", "/_stub/faults", {"expire_sessions": True})
    assert (await call(MCP, "log_search", {**window, "limit": 1}))["returned"] == 1
    ok("expired session -> transparent re-login")

    stub("POST", "/_stub/faults", {"timeout_sessions": True})
    assert (await call(MCP, "log_search", {**window, "limit": 1}))["returned"] == 1
    ok("440 session timeout -> transparent re-login")

    stub("POST", "/_stub/faults", {"unavailable_next": 3})
    assert (await call(MCP, "log_search", {**window, "limit": 1}))["returned"] == 1
    ok("503 while appliance starting -> retried")

    stub("POST", "/_stub/faults", {"partial": True})
    part = await call(MCP, "log_search", {**window, "limit": 100})
    assert part["complete"] is False and any("partial" in n for n in part["notes"])
    stub("DELETE", "/_stub/faults")
    ok("partial result surfaced")

    stub("POST", "/_stub/faults", {"bad_json": True})
    await expect_error(MCP, "log_search", {**window}, "non-json")
    stub("DELETE", "/_stub/faults")
    ok("non-JSON body -> clean error")

    await expect_error(BAD, "log_search", {**window}, "credentials")
    await expect_error(BAD, "log_search", {**window}, "locking")
    stats = stub("GET", "/_stub/stats")
    assert stats["login_failures"] == 1, stats  # second call blocked by cooldown, not sent
    ok("bad credentials -> one login attempt only (AD lockout guard)")


asyncio.run(main())
print("E2E OK")
