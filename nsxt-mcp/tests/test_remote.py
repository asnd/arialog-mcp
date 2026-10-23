import asyncio
import base64
import socket
from contextlib import asynccontextmanager

import httpx
import httpx2
import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from pydantic import ValidationError
from stub_nsx import NSXStub

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import RemoteSettings, Settings
from nsxt_mcp.credentials import current_caller
from nsxt_mcp.remote import CallerLimits, create_remote_app


def basic(username, password="pw"):
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def remote_settings(settings, mode="per_user", **overrides):
    remote = {
        "realm": "lab",
        "authentication_target": "a",
        "targets": ["a", "b"],
        "grants": {"alice@test": {"targets": ["a"]}} if mode == "shared" else {},
        "burst": 100,
        **overrides,
    }
    return Settings.model_validate({**settings.model_dump(), "mode": mode, "remote": remote})


@asynccontextmanager
async def remote_client(settings, mode="per_user", **overrides):
    config = remote_settings(settings, mode, **overrides)
    stub = NSXStub()
    registry = TargetRegistry(config, transport=httpx.MockTransport(stub))
    app = create_remote_app(registry)
    async with (
        app.app.router.lifespan_context(app.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://mcp.test"
        ) as client,
    ):
        yield client, registry, stub, app


async def rpc(client, username, name="nsx_list_targets", arguments=None, **kwargs):
    return await client.post(
        "/mcp",
        headers={
            "Authorization": basic(username),
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
        **kwargs,
    )


@pytest.mark.parametrize("mode", ["shared", "per_user"])
async def test_remote_execution_identity(settings, mode):
    async with remote_client(settings, mode) as (client, registry, stub, app):
        response = await rpc(
            client,
            "alice@test",
            "nsx_get_gateway_firewall_policy",
            {"target": "a", "policy_id": "policy-1"},
        )
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["structuredContent"]["data"]["scope"] == ["/infra/tier-1s/app"]
        probe, operation = stub.requests
        assert probe.headers["authorization"] == basic("alice@test")
        expected = (
            basic("reader@example.test", "synthetic-password")
            if mode == "shared"
            else basic("alice@test")
        )
        assert operation.headers["authorization"] == expected
        assert response.headers["cache-control"] == "no-store"
        assert "mcp-session-id" not in response.headers
        assert current_caller.get() is None
        assert app.limits.states["lab/alice@test"].active == 0


async def test_shared_user_must_have_explicit_grant(settings):
    async with remote_client(settings, "shared") as (client, registry, stub, app):
        assert (await rpc(client, "unmapped@test")).status_code == 403
        assert len(stub.requests) == 1  # Authenticated, no service-account read.
        denied = await rpc(client, "alice@test", "nsx_get_version", {"target": "b"})
        assert denied.json()["result"]["isError"]
        assert all(r.url.host == "a.example.test" for r in stub.requests)
        targets = await rpc(client, "alice@test")
        assert targets.json()["result"]["structuredContent"]["result"] == ["a"]


async def test_tool_group_grant_checked_before_read(settings):
    grants = {"alice@test": {"targets": ["a"], "tool_groups": ["metadata"]}}
    async with remote_client(settings, "shared", grants=grants) as (client, _, stub, _):
        denied = await rpc(
            client, "alice@test", "nsx_get_group", {"target": "a", "group_id": "web"}
        )
        assert denied.json()["result"]["isError"]
        assert len(stub.requests) == 1


async def test_per_user_nsx_permission_denial_and_reauthentication(settings):
    async with remote_client(settings) as (client, registry, stub, app):
        denied = await rpc(client, "alice@test", "nsx_get_version", {"target": "b"})
        assert denied.json()["result"]["isError"]
        assert "NSX denied read permission" in str(denied.json())
        assert (await rpc(client, "bad")).status_code == 401
        allowed = await rpc(client, "bob@test", "nsx_get_version", {"target": "b"})
        assert not allowed.json()["result"].get("isError", False)
        assert not registry.shared_clients
        assert registry.breakers["b"].failures == 0
        assert len([r for r in stub.requests if r.url.host == "a.example.test"]) == 3


@pytest.mark.parametrize("authorization", [None, "Bearer token", "Basic !!!", "Basic dXNlcg=="])
async def test_bad_authorization_never_reaches_nsx(settings, authorization):
    async with remote_client(settings) as (client, _, stub, _):
        response = await client.post(
            "/mcp", headers={"Authorization": authorization} if authorization else {}, json={}
        )
        assert response.status_code == 401
        assert "Basic realm=" in response.headers["www-authenticate"]
        assert not stub.requests


async def test_duplicate_auth_header_and_origins_rejected(settings):
    async with remote_client(settings) as (client, _, stub, _):
        duplicate = await client.post(
            "/mcp",
            headers=[
                ("Authorization", basic("alice@test")),
                ("Authorization", basic("bob@test")),
            ],
        )
        assert duplicate.status_code == 401
        origin = await client.post(
            "/mcp",
            headers={
                "Authorization": basic("alice@test"),
                "Origin": "https://untrusted.test",
            },
        )
        assert origin.status_code == 403
        assert not stub.requests


async def test_https_required_and_forwarded_header_not_blindly_trusted(settings):
    async with remote_client(settings) as (client, _, stub, _):
        response = await client.post(
            "http://mcp.test/mcp",
            headers={
                "Authorization": basic("alice@test"),
                "X-Forwarded-Proto": "https",
            },
        )
        assert response.status_code == 400
        assert not stub.requests


async def test_persistent_session_ids_rejected_for_every_user(settings):
    async with remote_client(settings) as (client, _, stub, _):
        for username in ("alice@test", "bob@test"):
            response = await client.post(
                "/mcp",
                headers={
                    "Authorization": basic(username),
                    "Mcp-Session-Id": "other-users-session",
                },
            )
            assert response.status_code == 400
        assert len(stub.requests) == 2  # Session ID cannot bypass either user's authentication.
        assert current_caller.get() is None


async def test_remote_request_size_cap(settings):
    async with remote_client(settings, max_request_bytes=20) as (client, _, stub, app):
        response = await client.post(
            "/mcp", headers={"Authorization": basic("alice@test")}, content=b"x" * 21
        )
        assert response.status_code == 413
        assert app.limits.states["lab/alice@test"].active == 0


async def test_public_liveness_does_not_query_nsx(settings):
    async with remote_client(settings) as (client, _, stub, _):
        response = await client.get("/healthz")
        assert response.status_code == 200 and response.json() == {"status": "ok"}
        assert not stub.requests


async def test_auth_outage_is_not_unauthorized_or_empty_success(settings):
    async with remote_client(settings) as (client, _, stub, _):
        stub.overrides["/api/v1/aaa/user-info"] = (503, {"secret": "do not expose"})
        response = await rpc(client, "alice@test")
        assert response.status_code == 503
        assert "secret" not in response.text


@pytest.mark.parametrize("payload", [{}, [], {"user_name": ""}, {"user_name": "bad\nname"}])
async def test_invalid_identity_payload_fails_closed(settings, payload):
    async with remote_client(settings) as (client, _, stub, app):
        stub.overrides["/api/v1/aaa/user-info"] = (200, payload)
        response = await rpc(client, "alice@test")
        assert response.status_code == 503
        assert len(stub.requests) == 1
        assert all(state.active == 0 for state in app.limits.states.values())


async def test_canonical_nsx_identity_drives_grants_and_alias_budgets(settings):
    async with remote_client(settings, "shared", burst=2) as (client, _, stub, app):
        stub.overrides["/api/v1/aaa/user-info"] = (
            200,
            {"user_name": "alice@test", "roles": [{"role": "auditor"}]},
        )
        alias = await rpc(client, "ALICE@test")
        assert alias.status_code == 200
        assert alias.json()["result"]["structuredContent"]["result"] == ["a"]
        assert (await rpc(client, "Alice@test")).status_code == 200
        assert (await rpc(client, "alice@test")).status_code == 429
        assert current_caller.get() is None
        assert all(state.active == 0 for state in app.limits.states.values())


async def test_request_rate_budget_returns_429_before_nsx(settings):
    async with remote_client(settings, burst=1) as (client, _, stub, _):
        assert (await rpc(client, "alice@test")).status_code == 200
        response = await rpc(client, "alice@test")
        assert response.status_code == 429
        assert response.headers["retry-after"] == "1"
        assert len(stub.requests) == 1


async def test_concurrent_authentication_budget_and_cancel_cleanup(settings):
    config = remote_settings(settings, caller_concurrency=1)
    entered = asyncio.Event()

    async def blocked_nsx(request):
        entered.set()
        await asyncio.Event().wait()

    registry = TargetRegistry(config, transport=httpx.MockTransport(blocked_nsx))
    app = create_remote_app(registry)
    async with (
        app.app.router.lifespan_context(app.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://mcp.test"
        ) as client,
    ):
        pending = asyncio.create_task(rpc(client, "alice@test"))
        await asyncio.wait_for(entered.wait(), 2)
        second = await rpc(client, "alice@test")
        assert second.status_code == 429
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert app.limits.states["lab/alice@test"].active == 0
        assert current_caller.get() is None
        assert registry.global_limit._value == config.global_concurrency


async def test_authentication_deadline_is_bounded(settings):
    config = remote_settings(settings, authentication_timeout=0.02)

    async def blocked_nsx(request):
        await asyncio.Event().wait()

    registry = TargetRegistry(config, transport=httpx.MockTransport(blocked_nsx))
    app = create_remote_app(registry)
    async with (
        app.app.router.lifespan_context(app.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://mcp.test"
        ) as client,
    ):
        response = await asyncio.wait_for(rpc(client, "alice@test"), 2)
        assert response.status_code == 503
        assert app.limits.states["lab/alice@test"].active == 0


def test_caller_limits_refill_capacity_and_expiration():
    config = RemoteSettings(
        realm="test",
        authentication_target="a",
        targets={"a"},
        burst=2,
        requests_per_minute=60,
        caller_concurrency=1,
        max_callers=1,
        caller_idle_seconds=10,
    )
    now = [0.0]
    limits = CallerLimits(config, clock=lambda: now[0])
    assert limits.enter("one")
    assert not limits.enter("one")  # Concurrent request rejected.
    assert not limits.enter("two")  # Bounded table; active user cannot be evicted.
    limits.exit("one")
    assert limits.enter("one")
    limits.exit("one")
    assert not limits.enter("one")  # Burst exhausted.
    now[0] = 1
    assert limits.enter("one")
    limits.exit("one")
    now[0] = 12
    assert limits.enter("two")
    assert set(limits.states) == {"two"}


@pytest.mark.parametrize(
    "changes",
    [
        {"authentication_target": "unknown"},
        {"targets": ["unknown"]},
        {"grants": {"user": {"targets": ["unknown"]}}},
    ],
)
def test_invalid_remote_grants(settings, changes):
    with pytest.raises(ValidationError):
        remote_settings(settings, **changes)


@asynccontextmanager
async def live_app(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


@pytest.mark.parametrize("mode", ["shared", "per_user"])
async def test_real_remote_clients_concurrent_identity_isolation(settings, mode, caplog):
    config = remote_settings(
        settings,
        mode,
        require_https=False,
        grants={"alice@test": {"targets": ["a"]}, "bob@test": {"targets": ["b"]}},
    )
    stub = NSXStub()
    registry = TargetRegistry(config, transport=httpx.MockTransport(stub))
    app = create_remote_app(registry)
    caplog.set_level("INFO", logger="nsxt_mcp.audit")
    async with live_app(app) as url:

        async def run(username, target):
            transport = StreamableHttpTransport(
                url,
                headers={"Authorization": basic(username)},
                httpx_client_factory=lambda **kw: httpx2.AsyncClient(trust_env=False, **kw),
            )
            async with Client(transport) as client:
                result = await client.call_tool("nsx_list_targets")
                assert result.structured_content["result"] == [target]
                policy = await client.call_tool(
                    "nsx_get_gateway_firewall_policy",
                    {
                        "target": target,
                        "policy_id": "policy-1",
                    },
                )
                assert policy.structured_content["target"] == target
                denied = await client.call_tool(
                    "nsx_get_version",
                    {
                        "target": "b" if target == "a" else "a",
                    },
                    raise_on_error=False,
                )
                assert denied.is_error

        await asyncio.gather(run("alice@test", "a"), run("bob@test", "b"))
    operations = [r for r in stub.requests if "gateway-policies" in r.url.path]
    assert len(operations) == 2
    if mode == "per_user":
        assert {r.url.host: r.headers["authorization"] for r in operations} == {
            "a.example.test": basic("alice@test"),
            "b.example.test": basic("bob@test"),
        }
    else:
        assert {r.headers["authorization"] for r in operations} == {
            basic("reader@example.test", "synthetic-password")
        }
    records = [r for r in caplog.records if r.name == "nsxt_mcp.audit"]
    assert {r.caller for r in records} == {"lab/alice@test", "lab/bob@test"}
    assert all(r.execution_mode == mode for r in records)
    assert "synthetic-password" not in caplog.text
    assert current_caller.get() is None
    assert all(value.active == 0 for value in app.limits.states.values())
