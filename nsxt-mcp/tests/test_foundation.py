import asyncio
import base64
from collections import Counter

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import CredentialProfile, Target
from nsxt_mcp.credentials import Caller, Credentials
from nsxt_mcp.errors import (
    AccessDenied,
    AuthenticationFailed,
    ContractError,
    LimitExceeded,
    ResourceNotFound,
    Unavailable,
)


def basic(user, password="synthetic-password"):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def user(name):
    return Caller(
        f"realm/{name}",
        frozenset({"a", "b"}),
        Credentials(SecretStr(name), SecretStr("synthetic-password")),
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://host",
        "https://u:p@host",
        "https://host/api",
        "https://host?x=y",
        "https://host/#x",
        "https://",
    ],
)
def test_invalid_origins(url):
    with pytest.raises(ValidationError):
        Target(url=url)


def test_secret_sources():
    with pytest.raises(ValidationError):
        CredentialProfile(username_env="U")
    with pytest.raises(ValidationError):
        CredentialProfile(username_env="U", password_env="P", password_file="secret")


async def test_lazy_targets_and_shared_auth(settings, caller):
    requests = []

    def stub(request):
        requests.append(request)
        return httpx.Response(200, json={"product_version": "4.2.1.0.0"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    assert not registry.shared_clients
    assert registry.list_targets(caller) == ["a", "b"]
    assert await registry.discover_version("a", caller) == "4.2.1.0.0"
    assert set(registry.shared_clients) == {"a"}
    assert requests[0].headers["authorization"] == basic("reader@example.test")
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/api/v1/node/version"
    await registry.aclose()
    assert not registry.shared_clients


async def test_invalid_requests_never_reach_transport(settings, caller):
    def stub(request):
        pytest.fail("Rejected request reached network")

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    cases = [
        ("https://evil.test", {}, {}),
        ("node_version", {}, {"action": "restart"}),
        ("gateway_policies", {"domain_id": "../default"}, {}),
        ("gateway_policies", {"domain_id": "%2fadmin"}, {}),
        ("gateway_policies", {"domain_id": ".."}, {}),
        ("tier0s", {}, {"page_size": 1001}),
        ("tier0s", {}, {"page_size": True}),
    ]
    for endpoint, parameters, query in cases:
        with pytest.raises(ContractError):
            await registry.get("a", endpoint, caller, parameters=parameters, query=query)
    with pytest.raises(AccessDenied):
        await registry.get("a", "node_version", Caller("denied", frozenset()))


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, AuthenticationFailed),
        (403, AccessDenied),
        (404, ResourceNotFound),
        (307, ContractError),
        (400, ContractError),
    ],
)
async def test_status_errors_no_retry_no_breaker(settings, caller, status, error):
    calls = 0

    def stub(request):
        nonlocal calls
        calls += 1
        return httpx.Response(status, text="sensitive upstream details")

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(error) as exc:
        await registry.get("a", "node_version", caller)
    assert "sensitive" not in str(exc.value)
    assert calls == 1
    assert registry.breakers["a"].failures == 0
    await registry.aclose()


async def test_retry_after(settings, caller):
    calls = 0
    delays = []

    async def sleep(delay):
        delays.append(delay)

    def stub(request):
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(429 if calls == 1 else 503, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"ok": True})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub), sleep=sleep)
    assert await registry.get("a", "node_version", caller) == {"ok": True}
    assert calls == 3
    assert delays == [2, 2]
    await registry.aclose()


async def test_breaker_and_recovery(settings, caller):
    settings.attempts = 1
    settings.breaker_threshold = 1
    now = [0.0]
    status = [503]
    calls = []

    def stub(request):
        calls.append(request)
        return httpx.Response(status[0], json={})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub), clock=lambda: now[0])
    for _ in range(2):
        with pytest.raises(Unavailable):
            await registry.get("a", "node_version", caller)
    assert len(calls) == 1
    now[0] = 31
    status[0] = 200
    await registry.get("a", "node_version", caller)
    assert registry.breakers["a"].opened_at is None
    await registry.aclose()


async def test_user_isolation_and_no_service_fallback(settings):
    settings.mode = "per_user"
    requests = []

    async def stub(request):
        await asyncio.sleep(0)
        requests.append(request)
        return httpx.Response(200, json={"product_version": "4.1.2"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    await asyncio.gather(
        *[registry.discover_version("a", user(name)) for name in ("local-reader", "ldap@test")]
    )
    assert {r.headers["authorization"] for r in requests} == {
        basic("local-reader"),
        basic("ldap@test"),
    }
    assert not registry.shared_clients
    with pytest.raises(AuthenticationFailed):
        await registry.get("a", "node_version", Caller("missing", frozenset({"a"})))
    assert len(requests) == 2
    assert "synthetic-password" not in repr(user("ldap@test"))


async def test_auth_probe_uses_caller_not_service(settings):
    requests = []

    def stub(request):
        requests.append(request)
        return httpx.Response(200, json={"user_name": "human@test"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    assert await registry.authenticate("a", user("human@test")) == "human@test"
    assert requests[0].url.path == "/api/v1/aaa/user-info"
    assert requests[0].headers["authorization"] == basic("human@test")
    assert not registry.shared_clients


async def test_pagination_continuation_and_repeated_cursor(settings, caller):
    def stub(request):
        if "cursor" not in request.url.params:
            return httpx.Response(200, json={"results": [{"id": "one"}], "cursor": "opaque"})
        assert request.url.params["cursor"] == "opaque"
        return httpx.Response(200, json={"results": [{"id": "two"}]})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    settings.max_pages = 1
    first = await registry.list_pages("a", "tier0s", caller)
    assert not first.complete and first.next_cursor == "opaque"
    second = await registry.list_pages("a", "tier0s", caller, cursor=first.next_cursor)
    assert second.complete and second.items == [{"id": "two"}]
    await registry.aclose()
    settings.max_pages = 3
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"results": [], "cursor": "loop"})
        ),
    )
    with pytest.raises(ContractError, match="Repeated"):
        await registry.list_pages("a", "tier0s", caller)
    await registry.aclose()


@pytest.mark.parametrize("payload", [[], "bad json", {"results": "bad"}])
async def test_malformed_results(settings, caller, payload):
    registry = TargetRegistry(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    )
    with pytest.raises(ContractError):
        await registry.list_pages("a", "tier0s", caller)
    await registry.aclose()


async def test_byte_and_item_caps(settings, caller):
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"results": [{"id": 1}, {"id": 2}]})
        ),
    )
    settings.max_items = 1
    with pytest.raises(LimitExceeded):
        await registry.list_pages("a", "tier0s", caller)
    settings.max_response_bytes = 1
    with pytest.raises(LimitExceeded):
        await registry.get("a", "node_version", caller)
    await registry.aclose()


async def test_fleet_limits_over_50_targets(settings):
    settings.targets = {
        f"target-{i}": Target(url=f"https://manager-{i}.test", credential_profile="service")
        for i in range(55)
    }
    settings.global_concurrency = 3
    settings.target_concurrency = 2
    caller = Caller("fleet", frozenset(settings.targets))
    active = Counter()
    peaks = Counter()

    async def stub(request):
        host = request.url.host
        active["global"] += 1
        active[host] += 1
        peaks["global"] = max(peaks["global"], active["global"])
        peaks[host] = max(peaks[host], active[host])
        await asyncio.sleep(0.001)
        active["global"] -= 1
        active[host] -= 1
        return httpx.Response(200, json={})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    assert len(registry.list_targets(caller)) == 55
    assert not registry.shared_clients
    await asyncio.gather(
        *[
            registry.get(target, "node_version", caller)
            for target in ["target-0"] * 6 + list(settings.targets)[1:]
        ]
    )
    assert peaks["global"] == 3
    assert peaks["manager-0.test"] <= 2
    assert not any(active.values())
    await registry.aclose()


async def test_deadline_and_cancellation_release_limits(settings, caller):
    settings.timeout = 0.03

    async def stub(request):
        await asyncio.sleep(10)
        return httpx.Response(200, json={})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(Unavailable, match="deadline"):
        await registry.get("a", "node_version", caller)
    task = asyncio.create_task(registry.get("a", "node_version", caller))
    await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert registry.breakers["a"].failures == 1
    assert registry.global_limit._value == settings.global_concurrency
    assert registry.target_limits["a"]._value == settings.target_concurrency
    await registry.aclose()


@pytest.mark.parametrize("version", ["4.0.1", "4.1.2.0.0", "4.2.4.0.0"])
async def test_synthetic_version_contracts(settings, caller, version):
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"product_version": version})
        ),
    )
    assert await registry.discover_version("a", caller) == version
    await registry.aclose()
