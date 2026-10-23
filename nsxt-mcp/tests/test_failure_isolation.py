import asyncio

import httpx
import pytest
from pydantic import SecretStr

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import CredentialProfile
from nsxt_mcp.credentials import Caller, Credentials
from nsxt_mcp.errors import (
    AccessDenied,
    AuthenticationFailed,
    ContractError,
    Unavailable,
)


async def test_distinct_target_credentials(settings, caller, monkeypatch):
    monkeypatch.setenv("SECOND_USER", "local-reader")
    monkeypatch.setenv("SECOND_PASSWORD", "other-synthetic-secret")
    settings.credential_profiles["second"] = CredentialProfile(
        username_env="SECOND_USER", password_env="SECOND_PASSWORD"
    )
    settings.targets["b"].credential_profile = "second"
    seen = {}

    def stub(request):
        seen[request.url.host] = request.headers["authorization"]
        return httpx.Response(200, json={})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    await asyncio.gather(*[registry.get(target, "node_version", caller) for target in ("a", "b")])
    assert seen["a.example.test"] != seen["b.example.test"]
    await registry.aclose()


async def test_file_secret_and_missing_secret(settings, caller, tmp_path, monkeypatch):
    secret = tmp_path / "password"
    secret.write_text("file-secret\n")
    settings.credential_profiles["service"] = CredentialProfile(
        username_env="TEST_NSX_USER", password_file=secret
    )
    seen = []

    def stub(request):
        seen.append(request)
        return httpx.Response(200, json={})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    await registry.get("a", "node_version", caller)
    monkeypatch.delenv("TEST_NSX_USER")
    with pytest.raises(AuthenticationFailed, match="unavailable"):
        await registry.get("a", "node_version", caller)
    assert len(seen) == 1
    await registry.aclose()


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, AuthenticationFailed),
        (403, AccessDenied),
        (503, Unavailable),
        (307, Unavailable),
    ],
)
async def test_authentication_probe_failures(settings, caller, status, error):
    caller = Caller(
        caller.identity,
        caller.allowed_targets,
        Credentials(SecretStr("user@test"), SecretStr("private-password")),
    )
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(lambda r: httpx.Response(status, text="private-password")),
    )
    with pytest.raises(error) as exc:
        await registry.authenticate("a", caller)
    assert "private-password" not in str(exc.value)
    assert not registry.shared_clients
    assert not registry.breakers


async def test_bad_user_does_not_disable_target(settings):
    settings.mode = "per_user"
    settings.breaker_threshold = 1

    def stub(request):
        status = 401 if request.headers["authorization"] == "Basic YmFkOnB3" else 200
        return httpx.Response(status, json={"product_version": "4.2.0"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    bad = Caller("bad", frozenset({"a"}), Credentials(SecretStr("bad"), SecretStr("pw")))
    good = Caller("good", frozenset({"a"}), Credentials(SecretStr("good"), SecretStr("pw")))
    with pytest.raises(AuthenticationFailed):
        await registry.discover_version("a", bad)
    assert await registry.discover_version("a", good) == "4.2.0"
    # Even after another caller populated version metadata, a bad user must reauthenticate.
    with pytest.raises(AuthenticationFailed):
        await registry.discover_version("a", bad)
    assert registry.breakers["a"].failures == 0


async def test_transport_failure_is_sanitized_and_target_scoped(settings, caller):
    settings.attempts = 1
    settings.breaker_threshold = 1

    def stub(request):
        if request.url.host == "a.example.test":
            raise httpx.ConnectError("private transport detail")
        return httpx.Response(200, json={})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(Unavailable) as exc:
        await registry.get("a", "node_version", caller)
    assert "private" not in str(exc.value)
    assert await registry.get("b", "node_version", caller) == {}
    assert registry.breakers["a"].opened_at is not None
    await registry.aclose()


async def test_invalid_json_not_empty_success(settings, caller):
    registry = TargetRegistry(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"not JSON"))
    )
    with pytest.raises(ContractError, match="JSON"):
        await registry.get("a", "node_version", caller)
    await registry.aclose()


@pytest.mark.parametrize("version", ["3.2.0", "9.0.0", "4.bad", None])
async def test_unsupported_or_malformed_version(settings, caller, version):
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"product_version": version})
        ),
    )
    with pytest.raises(ContractError):
        await registry.discover_version("a", caller)
    assert not registry.versions
    await registry.aclose()


async def test_pagination_total_deadline(settings, caller):
    settings.timeout = 0.04
    calls = 0

    async def stub(request):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.025)
        return httpx.Response(200, json={"results": [], "cursor": f"next-{calls}"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(Unavailable, match="deadline"):
        await registry.list_pages("a", "tier0s", caller)
    assert calls < settings.max_pages
    await registry.aclose()


async def test_no_session_cookies_or_redirect_following(settings, caller):
    requests = []

    def stub(request):
        requests.append(request)
        return httpx.Response(200, json={}, headers={"Set-Cookie": "JSESSIONID=unwanted; Path=/"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    await registry.get("a", "node_version", caller)
    await registry.get("a", "node_version", caller)
    assert all(not request.headers.get("cookie") for request in requests)
    assert not registry.shared_clients["a"].cookies
    assert registry.shared_clients["a"].follow_redirects is False
    await registry.aclose()
