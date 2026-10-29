from __future__ import annotations

import asyncio

import httpx
import pytest

from arialog_mcp.client import VRLIClient
from arialog_mcp.errors import AuthError, BreakerOpenError, QueryError, UnavailableError
from conftest import ANCHOR, FakeClock, Stub, make_settings, no_sleep

HOUR = f"timestamp/%3E%3D%20{ANCHOR - 3_600_000}/timestamp/%3C%20{ANCHOR}"


def make(stub: Stub, clock: FakeClock, **over) -> VRLIClient:
    return VRLIClient(
        make_settings(**over),
        transport=httpx.ASGITransport(app=stub.app),
        sleep=no_sleep,
        clock=clock,
    )


async def test_login_once_and_session_reused(client: VRLIClient, stub: Stub):
    await client.events(HOUR, limit=5)
    await client.events(HOUR, limit=5)
    assert (await stub.stats())["login_count"] == 1


async def test_expired_session_triggers_one_relogin(client: VRLIClient, stub: Stub):
    await client.events(HOUR, limit=5)
    await stub.faults(expire_sessions=True)
    res = await client.events(HOUR, limit=5)
    assert res.events and (await stub.stats())["login_count"] == 2


async def test_session_refreshed_before_ttl(client: VRLIClient, stub: Stub, clock: FakeClock):
    await client.events(HOUR, limit=1)
    clock.advance(1800)  # past 90% of the 1800s ttl
    await client.events(HOUR, limit=1)
    assert (await stub.stats())["login_count"] == 2


async def test_503_during_login_and_request_is_retried(client: VRLIClient, stub: Stub):
    await stub.faults(unavailable_next=2)  # appliance still starting: login 503, then 503 again
    res = await client.events(HOUR, limit=5)
    assert len(res.events) == 5


async def test_retries_exhausted_raises_unavailable(client: VRLIClient, stub: Stub):
    await stub.faults(unavailable_next=99)
    with pytest.raises(UnavailableError):
        await client.events(HOUR, limit=5)


async def test_breaker_opens_then_half_opens(client: VRLIClient, stub: Stub, clock: FakeClock):
    await stub.faults(unavailable_next=999)
    for _ in range(2):  # breaker_failures=2
        with pytest.raises(UnavailableError):
            await client.events(HOUR, limit=1)
    before = (await stub.stats())["request_count"]
    with pytest.raises(BreakerOpenError):
        await client.events(HOUR, limit=1)
    assert (await stub.stats())["request_count"] == before  # appliance not touched
    await stub.faults(unavailable_next=0)
    clock.advance(31)
    assert (await client.events(HOUR, limit=1)).events


async def test_breaker_allows_only_one_half_open_probe(clock: FakeClock):
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503)
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"version": "8.18"})

    client = VRLIClient(
        make_settings(retries=0, breaker_failures=1),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
        clock=clock,
    )
    with pytest.raises(UnavailableError):
        await client.version()
    clock.advance(31)
    probe = asyncio.create_task(client.version())
    await entered.wait()
    with pytest.raises(BreakerOpenError, match="already in progress"):
        await client.version()
    release.set()
    assert await probe == {"version": "8.18"}
    assert calls == 2
    await client.aclose()


async def test_bad_credentials_do_not_hammer_ad(stub: Stub, clock: FakeClock):
    c = make(stub, clock, password="wrong")
    for _ in range(3):
        with pytest.raises(AuthError):
            await c.events(HOUR, limit=1)
    assert (await stub.stats())["login_failures"] == 1  # cooldown prevents repeated attempts
    clock.advance(61)
    with pytest.raises(AuthError):
        await c.events(HOUR, limit=1)
    assert (await stub.stats())["login_failures"] == 2
    await c.aclose()


async def test_bad_query_is_query_error_and_does_not_trip_breaker(client: VRLIClient, stub: Stub):
    for _ in range(4):
        with pytest.raises(QueryError, match="400"):
            await client.events("timestamp", limit=1)  # odd segment count -> HTTP 400
    assert (await client.events(HOUR, limit=1)).events


async def test_non_json_response_is_unavailable(client: VRLIClient, stub: Stub):
    await stub.faults(bad_json=True)
    with pytest.raises(UnavailableError, match="non-JSON"):
        await client.events(HOUR, limit=1)


async def test_partial_result_flag_propagates(client: VRLIClient, stub: Stub):
    await stub.faults(partial=True)
    assert (await client.events(HOUR, limit=500)).complete is False
    assert (await client.aggregated(HOUR, bin_width_ms=600_000)).complete is False


async def test_connect_error_is_unavailable(clock: FakeClock):
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    c = VRLIClient(
        make_settings(), transport=httpx.MockTransport(boom), sleep=no_sleep, clock=clock
    )
    with pytest.raises(UnavailableError, match="ConnectError"):
        await c.version()
    await c.aclose()


async def test_version_needs_no_login(client: VRLIClient, stub: Stub):
    assert (await client.version())["version"].startswith("8.18")
    assert (await stub.stats())["login_count"] == 0


async def test_no_timestamp_constraint_only_returns_last_minute(client: VRLIClient):
    """Documents the VRLI pitfall the MCP guards against by always sending a timestamp."""
    assert (await client.events("text/CONTAINS%20ScsiDeviceIO", limit=50)).events == []


async def test_session_acquired_once_for_parallel_calls(client: VRLIClient, stub: Stub):
    """Mirrors ariaops-mcp's parallel-token test: no login stampede on a cold start."""
    import asyncio

    results = await asyncio.gather(*(client.events(HOUR, limit=1) for _ in range(12)))
    assert all(r.events for r in results)
    assert (await stub.stats())["login_count"] == 1


async def test_concurrency_is_capped(stub: Stub, clock: FakeClock):
    import asyncio

    active = peak = 0
    real = httpx.ASGITransport(app=stub.app)

    class Counting(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            try:
                return await real.handle_async_request(request)
            finally:
                active -= 1

    c = VRLIClient(
        make_settings(max_concurrency=3), transport=Counting(), sleep=no_sleep, clock=clock
    )
    await asyncio.gather(*(c.events(HOUR, limit=1) for _ in range(15)))
    assert 1 < peak <= 3
    await c.aclose()


def test_backoff_is_jittered_capped_and_honours_retry_after(clock: FakeClock):
    s = make_settings(backoff_base_s=1.0, backoff_max_s=5.0)
    lo = VRLIClient(s, sleep=no_sleep, clock=clock, jitter=lambda: 0.0)
    hi = VRLIClient(s, sleep=no_sleep, clock=clock, jitter=lambda: 1.0)
    assert (lo._backoff(1, None), hi._backoff(1, None)) == (0.5, 1.0)
    assert (lo._backoff(3, None), hi._backoff(3, None)) == (2.0, 4.0)
    assert hi._backoff(10, None) == 5.0  # capped
    assert lo._backoff(1, 3.0) == 3.0  # Retry-After wins over a shorter backoff
    assert lo._backoff(1, 600.0) == 5.0  # but is capped too


async def test_retry_after_header_drives_the_wait(clock: FakeClock):
    calls = {"n": 0}
    slept: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, headers={"Retry-After": "2"})
        if calls["n"] == 2:
            return httpx.Response(429, headers={"Retry-After": "soon"})  # unparsable -> ignored
        return httpx.Response(200, json={"version": "8.18.0"})

    async def record(d: float) -> None:
        slept.append(d)

    c = VRLIClient(
        make_settings(backoff_base_s=0.0),
        transport=httpx.MockTransport(handler),
        sleep=record,
        clock=clock,
    )
    assert (await c.version())["version"] == "8.18.0"
    assert slept == [2.0, 0.0]
    await c.aclose()


async def test_breaker_open_property(client: VRLIClient, stub: Stub, clock: FakeClock):
    assert client.breaker_open is False
    await stub.faults(unavailable_next=999)
    for _ in range(2):
        with pytest.raises(UnavailableError):
            await client.events(HOUR, limit=1)
    assert client.breaker_open is True
    clock.advance(31)
    assert client.breaker_open is False  # cooldown over: half-open


# ------------------------------------------------------------------ per-user sessions (LDAP)
from pydantic import SecretStr  # noqa: E402

from arialog_mcp.client import Credentials  # noqa: E402
from vrli_stub.app import create_app  # noqa: E402


def creds(user: str, pw: str) -> Credentials:
    return Credentials(user, SecretStr(pw))


@pytest.fixture
async def users_stub():
    s = Stub(create_app(anchor_ms=ANCHOR, users={"alice": "pa", "carol": "pc"}))
    yield s
    await s.http.aclose()


async def test_each_user_gets_and_reuses_their_own_session(users_stub: Stub, clock: FakeClock):
    c = make(users_stub, clock)
    for _ in range(2):
        await c.events(HOUR, limit=1, creds=creds("alice", "pa"))
        await c.events(HOUR, limit=1, creds=creds("carol", "pc"))
    st = await users_stub.stats()
    assert st["logins_by_user"] == {"alice": 1, "carol": 1}
    assert st["requests_by_user"] == {"alice": 2, "carol": 2}


async def test_changed_password_never_reuses_the_old_session(users_stub: Stub, clock: FakeClock):
    c = make(users_stub, clock)
    await c.events(HOUR, limit=1, creds=creds("alice", "pa"))
    with pytest.raises(AuthError, match="rejected the credentials"):
        await c.events(HOUR, limit=1, creds=creds("alice", "stale"))


async def test_user_sessions_are_bounded_lru(users_stub: Stub, clock: FakeClock):
    c = make(users_stub, clock, max_user_sessions=1)
    for who, pw in (("alice", "pa"), ("carol", "pc"), ("alice", "pa")):
        await c.events(HOUR, limit=1, creds=creds(who, pw))
    assert (await users_stub.stats())["logins_by_user"] == {"alice": 2, "carol": 1}


async def test_user_lockout_guard_survives_session_eviction(users_stub: Stub, clock: FakeClock):
    c = make(users_stub, clock, max_user_sessions=1)
    with pytest.raises(AuthError):
        await c.events(HOUR, limit=1, creds=creds("bob", "x"))
    await c.events(HOUR, limit=1, creds=creds("alice", "pa"))  # evicts bob's session
    with pytest.raises(AuthError, match="not retrying"):
        await c.events(HOUR, limit=1, creds=creds("BOB", "x"))
    assert (await users_stub.stats())["login_failures"] == 1


async def test_without_service_account_a_credential_is_mandatory(users_stub: Stub, clock):
    c = make(
        users_stub,
        clock,
        username=None,
        password=None,
        transport="http",
        http_auth_mode="ldap",
        ldap_server_uri="ldaps://l",
        ldap_user_dn_template="{username}",
        ldap_user_search_base="dc=x",
        default_role="ops",
    )
    with pytest.raises(AuthError, match="no VRLI credentials"):
        await c.events(HOUR, limit=1)
    assert (await users_stub.stats())["request_count"] == 0
    assert (await c.version())["version"].startswith("8.18")  # unauthenticated probe still works
