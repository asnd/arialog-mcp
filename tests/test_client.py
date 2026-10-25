from __future__ import annotations

import httpx
import pytest

from arialog_mcp.client import VRLIClient
from arialog_mcp.errors import AuthError, BreakerOpenError, QueryError, UnavailableError
from conftest import ANCHOR, FakeClock, Stub, make_settings, no_sleep

HOUR = f"timestamp/%3E%3D{ANCHOR - 3_600_000}/timestamp/%3C{ANCHOR}"


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
    assert (await client.aggregated(HOUR, bin_width_ms=600_000, limit=10)).complete is False


async def test_connect_error_is_unavailable(clock: FakeClock):
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    c = VRLIClient(
        make_settings(), transport=httpx.MockTransport(boom), sleep=no_sleep, clock=clock
    )
    with pytest.raises(UnavailableError, match="ConnectError"):
        await c.version()
    await c.aclose()


async def test_version_uses_a_session(client: VRLIClient, stub: Stub):
    """/api/v2/version requires authentication (API docs); an anonymous call gets 401."""
    assert (await client.version())["version"].startswith("8.18")
    assert (await stub.stats())["login_count"] == 1


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


async def test_session_timeout_440_triggers_one_relogin(client: VRLIClient, stub: Stub):
    await client.events(HOUR, limit=1)
    await stub.faults(timeout_sessions=True)  # VRLI answers 440 "Login Timeout"
    assert (await client.events(HOUR, limit=1)).events
    assert (await stub.stats())["login_count"] == 2


async def test_aggregated_sends_limit_and_sorts_bins(client: VRLIClient, stub: Stub):
    res = await client.aggregated(HOUR, bin_width_ms=600_000, limit=10)
    starts = [b.start_ms for b in res.bins]
    assert starts == sorted(starts) and len(starts) == 6  # stub answers newest first
    assert not res.limit_reached
    q = (await stub.stats())["last_query"]
    assert q["limit"] == "10" and q["bin-width"] == "600000" and q["timeout"] == "30000"


async def test_aggregated_flags_limit_reached(client: VRLIClient):
    res = await client.aggregated(HOUR, bin_width_ms=60_000, limit=5)
    assert res.limit_reached and len(res.bins) == 5


async def test_regex_disabled_on_appliance_is_query_error(client: VRLIClient):
    with pytest.raises(QueryError, match="disabled"):
        await client.events(HOUR + "/text/%3D~ERROR", limit=1)


async def test_unknown_operator_is_rejected_by_vrli(client: VRLIClient):
    with pytest.raises(QueryError, match="400"):
        await client.events(HOUR + "/text/MATCHES%20x", limit=1)


async def test_read_timeout_is_not_retried(stub: Stub, clock: FakeClock):
    calls = {"get": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/sessions":
            return httpx.Response(200, json={"sessionId": "tok", "ttl": 100})
        calls["get"] += 1
        raise httpx.ReadTimeout("slow query")

    c = VRLIClient(
        make_settings(retries=3),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
        clock=clock,
    )
    with pytest.raises(UnavailableError, match="did not answer in time"):
        await c.events(HOUR, limit=1)
    assert calls["get"] == 1  # the heavy query is not re-sent
    await c.aclose()


async def test_query_read_timeout_exceeds_vrli_query_timeout(clock: FakeClock):
    seen: list[dict[str, float | None]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.extensions["timeout"])
        if req.url.path == "/api/v2/sessions":
            return httpx.Response(200, json={"sessionId": "tok", "ttl": 100})
        return httpx.Response(200, json={"events": []})

    c = VRLIClient(
        make_settings(request_timeout_s=10, query_timeout_ms=30_000, query_timeout_margin_s=15),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
        clock=clock,
    )
    await c.events(HOUR, limit=1)
    login, query = seen
    assert login["read"] == 10 and query["read"] == 45 and query["connect"] == 10
    await c.aclose()


async def test_retry_after_header_is_honoured(clock: FakeClock):
    delays: list[float] = []
    answers = iter([httpx.Response(503, headers={"Retry-After": "7"})])

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/sessions":
            return httpx.Response(200, json={"sessionId": "tok", "ttl": 100})
        return next(answers, httpx.Response(200, json={"events": []}))

    async def record(d: float) -> None:
        delays.append(d)

    c = VRLIClient(
        make_settings(backoff_base_s=0.5),
        transport=httpx.MockTransport(handler),
        sleep=record,
        clock=clock,
    )
    await c.events(HOUR, limit=1)
    assert delays == [7.0]
    await c.aclose()


async def test_half_open_breaker_lets_a_single_probe_through(stub: Stub, clock: FakeClock):
    import asyncio

    c = make(stub, clock, retries=0)
    await stub.faults(unavailable_next=2)
    for _ in range(2):
        with pytest.raises(UnavailableError):
            await c.events(HOUR, limit=1)
    clock.advance(31)
    await stub.faults(latency_s=0.05)
    results = await asyncio.gather(
        *(c.events(HOUR, limit=1) for _ in range(5)), return_exceptions=True
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1
    assert sum(isinstance(r, BreakerOpenError) for r in results) == 4
    assert (await c.events(HOUR, limit=1)).events  # probe succeeded -> closed again
    await c.aclose()


async def test_probe_ending_in_auth_error_releases_the_probe(stub: Stub, clock: FakeClock):
    c = make(stub, clock, retries=0)
    await stub.faults(unavailable_next=2)
    for _ in range(2):
        with pytest.raises(UnavailableError):
            await c.events(HOUR, limit=1)
    clock.advance(31)
    await stub.faults(unavailable_next=0)
    c._s.password = type(c._s.password)("wrong")  # login now rejected -> AuthError
    with pytest.raises(AuthError):
        await c.events(HOUR, limit=1)
    c._s.password = type(c._s.password)("placeholder")
    clock.advance(61)  # past the login cooldown
    assert (await c.events(HOUR, limit=1)).events  # next caller may probe again
    await c.aclose()
