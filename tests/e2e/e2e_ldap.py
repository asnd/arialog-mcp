"""LDAP-mode end-to-end checks: arialog-mcp (ldaps -> OpenLDAP) + vrli-stub. Run in a container.

usage: e2e_ldap.py <ldap_mcp_url> <stub_url>
Directory users (tests/e2e/ldap/10-seed.ldif): alice (ops, VRLI user), bob (no mapped group),
carol (mapped, but not a VRLI user).
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

MCP, STUB = sys.argv[1:3]
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def ok(name: str) -> None:
    print(f"PASS {name}", flush=True)


def stats() -> dict:
    return json.load(OPENER.open(STUB + "/_stub/stats", timeout=5))


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def raw_status(auth: str | None) -> tuple[int, str]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    if auth:
        headers["authorization"] = auth
    req = urllib.request.Request(MCP, data=body, headers=headers, method="POST")
    try:
        with OPENER.open(req, timeout=10) as r:
            return r.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("www-authenticate", "")


async def call(user: str, password: str, tool: str, args: dict):
    transport = StreamableHttpTransport(MCP, headers={"Authorization": basic(user, password)})
    async with Client(transport) as c:
        return (await c.call_tool(tool, args)).structured_content


async def main() -> None:
    anchor = stats()["anchor_ms"]
    window = {
        "start": datetime.fromtimestamp((anchor - 125 * 60_000) / 1000, tz=UTC).isoformat(),
        "end": datetime.fromtimestamp((anchor + 60_000) / 1000, tz=UTC).isoformat(),
    }

    code, challenge = raw_status(None)
    assert code == 401 and challenge.startswith("Basic"), (code, challenge)
    ok("no credentials -> 401 with Basic challenge")

    for label, auth in (
        ("wrong password", basic("alice", "nope")),
        ("unmapped user", basic("bob", "pw-bob")),
        ("bearer token", "Bearer " + "x" * 32),
    ):
        code, _ = raw_status(auth)
        assert code == 401, (label, code)
        ok(f"{label} -> 401")

    before = stats()
    srch = await call("alice", "pw-alice", "log_search", {**window, "limit": 3})
    agg = await call("alice", "pw-alice", "log_aggregate", {**window, "bin_seconds": 120})
    assert srch["returned"] == 3 and agg["total"] == 1564, (srch["returned"], agg["total"])
    after = stats()
    alice = after["requests_by_user"].get("alice", 0) - before["requests_by_user"].get("alice", 0)
    assert alice == 2, after
    assert after["logins_by_user"].get("svc-test", 0) == before["logins_by_user"].get(
        "svc-test", 0
    ), "LDAP mode must never log in with a service account"
    ok("alice (ops) queries VRLI as herself over LDAPS")

    try:
        await call("carol", "pw-carol", "log_search", {**window, "limit": 1})
    except ToolError as exc:
        assert "credentials" in str(exc).lower() and "pw-carol" not in str(exc), exc
        ok("carol (mapped, no VRLI account) -> clean VRLI credentials error")
    else:
        raise AssertionError("carol should be rejected by VRLI")

    assert (await call("alice", "pw-alice", "log_search", {**window, "limit": 1}))["returned"] == 1
    ok("other users unaffected by carol's rejection")


asyncio.run(main())
print("E2E LDAP OK")
