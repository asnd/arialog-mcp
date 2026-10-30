"""Client behaviour against malformed / unusual VRLI responses (httpx.MockTransport)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from arialog_mcp.client import VRLIClient
from arialog_mcp.errors import AuthError, QueryError, UnavailableError
from conftest import FakeClock, make_settings, no_sleep

Handler = Callable[[httpx.Request], httpx.Response]
LOGIN_OK = httpx.Response(200, json={"sessionId": "tok", "ttl": 100})
PATH = "timestamp/LAST%2060000"


def build(clock: FakeClock, handler: Handler, **over: Any) -> VRLIClient:
    return VRLIClient(
        make_settings(**over),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
        clock=clock,
    )


def with_login(get: Callable[[httpx.Request], httpx.Response]) -> Handler:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/sessions":
            return LOGIN_OK
        return get(req)

    return handler


async def test_upstream_response_is_bounded_before_json_parsing(clock: FakeClock):
    client = build(
        clock,
        lambda req: httpx.Response(200, content=b"x" * 1001),
        max_response_bytes=1000,
    )
    with pytest.raises(UnavailableError, match="byte limit"):
        await client.version()
    await client.aclose()


@pytest.mark.parametrize(
    "login,exc,match",
    [
        (httpx.Response(200, json={"nope": 1}), UnavailableError, "unexpected payload"),
        (httpx.Response(200, text="<html>"), UnavailableError, "unexpected payload"),
        (httpx.Response(500), UnavailableError, "login unavailable"),
        (httpx.Response(404), AuthError, "refused"),
        (httpx.Response(403), AuthError, "rejected the credentials"),
    ],
)
async def test_login_failure_variants(clock, login, exc, match):
    c = build(clock, lambda req: login)
    with pytest.raises(exc, match=match):
        await c.events(PATH, limit=1)
    await c.aclose()


async def test_login_transport_error(clock):
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    c = build(clock, boom)
    with pytest.raises(UnavailableError, match=r"login failed \(ConnectTimeout\)"):
        await c.events(PATH, limit=1)
    await c.aclose()


async def test_login_without_ttl_uses_default(clock):
    calls = {"login": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/sessions":
            calls["login"] += 1
            return httpx.Response(200, json={"sessionId": "tok"})  # no ttl
        return httpx.Response(200, json={"events": [], "complete": True})

    c = build(clock, handler)
    await c.events(PATH, limit=1)
    clock.advance(1500)  # < 90% of the 1800s default
    await c.events(PATH, limit=1)
    assert calls["login"] == 1
    clock.advance(200)  # now past 1620s
    await c.events(PATH, limit=1)
    assert calls["login"] == 2
    await c.aclose()


async def test_forbidden_after_login_is_auth_error(clock):
    c = build(clock, with_login(lambda r: httpx.Response(403)))
    with pytest.raises(AuthError, match="refused the session"):
        await c.events(PATH, limit=1)
    await c.aclose()


async def test_persistent_401_relogs_once_then_fails(clock):
    logins = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/sessions":
            logins["n"] += 1
            return LOGIN_OK
        return httpx.Response(401)

    c = build(clock, handler)
    with pytest.raises(AuthError):
        await c.events(PATH, limit=1)
    assert logins["n"] == 2  # initial + exactly one re-login
    await c.aclose()


async def test_http_500_is_unavailable(clock):
    c = build(clock, with_login(lambda r: httpx.Response(500)), retries=1)
    with pytest.raises(UnavailableError, match="HTTP 500"):
        await c.events(PATH, limit=1)
    await c.aclose()


@pytest.mark.parametrize(
    "body",
    [{"events": [{"nope": 1}]}, {"events": [{"timestamp": "x"}]}, [], {"events": 5}],
)
async def test_events_unexpected_shape(clock, body):
    c = build(clock, with_login(lambda r: httpx.Response(200, json=body)), retries=0)
    with pytest.raises(UnavailableError, match="unexpected shape"):
        await c.events(PATH, limit=1)
    await c.aclose()


@pytest.mark.parametrize("body", [{"bins": [{"x": 1}]}, [], {"bins": [{"minTimestamp": "a"}]}])
async def test_aggregated_unexpected_shape(clock, body):
    c = build(clock, with_login(lambda r: httpx.Response(200, json=body)), retries=0)
    with pytest.raises(UnavailableError, match="unexpected shape"):
        await c.aggregated(PATH, bin_width_ms=1000, limit=10)
    await c.aclose()


async def test_event_field_parsing_keeps_first_duplicate(clock):
    body = {
        "events": [
            {
                "timestamp": 5,
                "text": "t",
                "fields": [
                    {"name": "hostname", "content": "a"},
                    {"name": "hostname", "content": "b"},
                    {"content": "no-name"},
                ],
            }
        ]
    }
    c = build(clock, with_login(lambda r: httpx.Response(200, json=body)))
    ev = (await c.events(PATH, limit=1)).events[0]
    assert ev.fields == {"hostname": "a"} and ev.host == "a"
    await c.aclose()


async def test_query_error_detail_json_and_plain(clock):
    c = build(
        clock, with_login(lambda r: httpx.Response(400, json={"errorMessage": "bad field foo"}))
    )
    with pytest.raises(QueryError, match="bad field foo"):
        await c.events(PATH, limit=1)
    await c.aclose()
    c = build(clock, with_login(lambda r: httpx.Response(400, text="plain failure")))
    with pytest.raises(QueryError, match="plain failure"):
        await c.events(PATH, limit=1)
    await c.aclose()


async def test_version_non_dict_payload(clock):
    c = build(clock, with_login(lambda r: httpx.Response(200, json=["8.18"])))
    assert await c.version() == {"raw": ["8.18"]}
    await c.aclose()


async def test_request_carries_bearer_and_constraint_path_is_not_double_encoded(clock):
    seen: list[httpx.Request] = []

    def get(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"events": []})

    c = build(clock, with_login(get))
    await c.events("timestamp/LAST%2060000/text/CONTAINS%20a%2Fb", limit=7)
    req = seen[0]
    assert req.headers["authorization"] == "Bearer tok"
    assert req.url.raw_path.startswith(
        b"/api/v2/events/timestamp/LAST%2060000/text/CONTAINS%20a%2Fb?"
    )
    assert req.url.params["limit"] == "7" and req.url.params["order-by-direction"] == "DESC"
    await c.aclose()


async def test_event_fields_given_as_text_offsets(clock):
    text = "\U0001f600 esx-02 vmkernel: x"  # emoji = 2 UTF-16 code units, as in Java
    body = {
        "events": [
            {
                "timestamp": 5,
                "text": text,
                "fields": [
                    {"name": "hostname", "startPosition": 3, "length": 6},
                    {"name": "appname", "startPosition": 10, "length": 8},
                    {"name": "source", "content": "10.0.0.12"},
                    {"name": "outside", "startPosition": 40, "length": 3},
                    {"name": "negative", "startPosition": -1, "length": 3},
                    {"name": "nothing"},
                    "not-a-dict",
                ],
            }
        ]
    }
    c = build(clock, with_login(lambda r: httpx.Response(200, json=body)))
    ev = (await c.events(PATH, limit=1)).events[0]
    assert ev.fields == {"hostname": "esx-02", "appname": "vmkernel", "source": "10.0.0.12"}
    assert ev.host == "esx-02"
    await c.aclose()
