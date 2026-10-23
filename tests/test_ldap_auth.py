from __future__ import annotations

import base64
import logging
from typing import Any

import httpx
import pytest
from ldap3 import MOCK_SYNC, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from arialog_mcp.client import VRLIClient
from arialog_mcp.ldap_auth import (
    LDAPAuthenticator,
    UserAccessToken,
    _parse_basic,
    map_groups_to_claims,
)
from arialog_mcp.server import create_server
from conftest import ANCHOR, END, START, FakeClock, Stub, make_settings, no_sleep
from vrli_stub.app import create_app

BASE = "ou=people,dc=example,dc=org"
OPS = "cn=arialog-ops,ou=groups,dc=example,dc=org"
SE = "cn=vrops-se,ou=groups,dc=example,dc=org"
OTHER = "cn=wiki-users,ou=groups,dc=example,dc=org"
GROUP_MAP = {"arialog-ops": {"role": "ops"}, SE: {"role": "country", "country": "SE"}}
PASSWORDS = {"alice": "pw-alice", "bob": "pw-bob", "carol": "pw-carol"}

LDAP_SETTINGS: dict[str, Any] = dict(
    username=None,
    password=None,
    transport="http",
    http_auth_mode="ldap",
    ldap_server_uri="ldaps://ldap.example.org",
    ldap_user_dn_template=f"uid={{username}},{BASE}",
    ldap_user_search_base="dc=example,dc=org",
    ldap_group_role_map=GROUP_MAP,
)


# ------------------------------------------------------------------ mock directory
class Directory:
    """ldap3 MOCK_SYNC directory; counts binds so tests can prove what was (not) sent."""

    def __init__(self, *, down: bool = False) -> None:
        self.server = Server("mock")
        self.binds = 0
        self.down = down
        seed = Connection(self.server, user="cn=admin", password="x", client_strategy=MOCK_SYNC)
        for uid, groups in (("alice", [OPS, OTHER]), ("bob", [OTHER]), ("carol", [SE])):
            seed.strategy.add_entry(
                f"uid={uid},{BASE}",
                {
                    "uid": uid,
                    "userPassword": PASSWORDS[uid],
                    "objectClass": "inetOrgPerson",
                    "memberOf": groups,
                },
            )

    def connect(self, bind_dn: str, password: str) -> Any:
        self.binds += 1
        if self.down:
            raise LDAPSocketOpenError("unreachable")
        conn = Connection(self.server, user=bind_dn, password=password, client_strategy=MOCK_SYNC)
        # MOCK_SYNC ignores auto_bind; bind explicitly with the same failure semantics.
        if not conn.bind():
            raise LDAPBindError("invalid credentials")
        return conn


def make_authn(directory: Directory, clock: FakeClock | None = None, **over: Any):
    kw: dict[str, Any] = dict(
        server_uri="ldaps://ldap.example.org",
        user_dn_template=f"uid={{username}},{BASE}",
        user_search_base="dc=example,dc=org",
        group_role_map=GROUP_MAP,
        max_failed_binds=3,
        failed_bind_cooldown_s=300,
        cache_ttl=300,
        connector=directory.connect,
    )
    if clock is not None:
        kw["clock"] = clock
    kw.update(over)
    return LDAPAuthenticator(**kw)


# ------------------------------------------------------------------ group mapping
def test_ops_mapping_wins_over_country():
    claims = map_groups_to_claims([SE, OPS], GROUP_MAP)
    assert claims == {"role": "ops"}


def test_country_mapping_keeps_country_and_instance():
    m = {"vrops-se": {"role": "country", "country": "SE", "instance": "se"}}
    assert map_groups_to_claims([SE], m) == {"role": "country", "country": "SE", "instance": "se"}


def test_bare_cn_matches_any_ou_but_full_dn_only_that_dn():
    assert map_groups_to_claims(["cn=arialog-ops,ou=elsewhere,dc=x"], GROUP_MAP) is not None
    # SE is keyed by full DN: a same-named group in another OU must not match.
    assert map_groups_to_claims(["cn=vrops-se,ou=elsewhere,dc=x"], GROUP_MAP) is None


def test_unmapped_groups_and_custom_roles():
    assert map_groups_to_claims([OTHER], GROUP_MAP) is None
    assert map_groups_to_claims(["cn=x"], {"x": {"role": "auditor"}}) == {"role": "auditor"}


# ------------------------------------------------------------------ authenticator
async def test_valid_mapped_user_gets_claims_and_is_cached():
    d = Directory()
    a = make_authn(d)
    assert await a.authenticate("alice", "pw-alice") == {"role": "ops"}
    assert await a.authenticate("carol", "pw-carol") == {"role": "country", "country": "SE"}
    assert await a.authenticate("alice", "pw-alice") == {"role": "ops"}
    assert d.binds == 2  # third call served from cache


async def test_cache_expires_with_the_clock(clock: FakeClock):
    d = Directory()
    a = make_authn(d, clock, cache_ttl=10)
    await a.authenticate("alice", "pw-alice")
    clock.advance(11)
    await a.authenticate("alice", "pw-alice")
    assert d.binds == 2


async def test_wrong_password_and_unmapped_user_are_denied():
    d = Directory()
    a = make_authn(d)
    assert await a.authenticate("alice", "nope") is None
    assert await a.authenticate("bob", "pw-bob") is None  # binds, but no mapped group
    assert await a.authenticate("nobody", "x") is None


async def test_empty_password_never_binds():
    d = Directory()
    assert await make_authn(d).authenticate("alice", "") is None
    assert d.binds == 0


async def test_failed_binds_are_throttled_per_username(clock: FakeClock):
    d = Directory()
    a = make_authn(d, clock)
    for _ in range(3):
        assert await a.authenticate("alice", "nope") is None
    assert d.binds == 3
    # Throttled: neither a wrong nor the right password reaches the directory...
    assert await a.authenticate("ALICE", "nope") is None
    assert await a.authenticate("alice", "pw-alice") is None
    assert d.binds == 3
    # ...other users are unaffected, and the block lifts after the cooldown.
    assert await a.authenticate("carol", "pw-carol") is not None
    clock.advance(301)
    assert await a.authenticate("alice", "pw-alice") == {"role": "ops"}


async def test_cached_login_survives_a_throttle(clock: FakeClock):
    d = Directory()
    a = make_authn(d, clock)
    assert await a.authenticate("alice", "pw-alice")
    for _ in range(3):
        await a.authenticate("alice", "attacker-guess")
    assert await a.authenticate("alice", "pw-alice") == {"role": "ops"}  # no DoS via throttle


async def test_success_resets_the_failure_counter(clock: FakeClock):
    d = Directory()
    a = make_authn(d, clock)
    for _ in range(2):
        await a.authenticate("alice", "nope")
    await a.authenticate("alice", "pw-alice")
    for _ in range(2):
        await a.authenticate("alice", "nope")
    assert await a.authenticate(
        "alice",
        "pw-alice",
    ) == {"role": "ops"}  # cached anyway
    assert d.binds == 5


async def test_directory_down_denies_without_counting_failures(caplog):
    d = Directory(down=True)
    a = make_authn(d, max_failed_binds=1)
    with caplog.at_level(logging.ERROR, logger="arialog_mcp.ldap"):
        assert await a.authenticate("alice", "pw-alice") is None
        assert await a.authenticate("alice", "pw-alice") is None
    assert d.binds == 2  # never throttled: an outage is not a bad password
    assert any(getattr(r, "event", "") == "ldap_unavailable" for r in caplog.records)


async def test_default_role_when_no_map_is_configured():
    d = Directory()
    a = make_authn(d, group_role_map={}, default_role="ops")
    assert await a.authenticate("bob", "pw-bob") == {"role": "ops"}


async def test_search_filter_is_escaped():
    seen: dict[str, str] = {}

    class FakeConn:
        entries: list[Any] = []

        def search(self, *, search_base: str, search_filter: str, attributes: list[str]) -> None:
            seen["filter"] = search_filter

        def unbind(self) -> None:
            raise RuntimeError("ignored")

    a = make_authn(Directory(), connector=lambda dn, pw: FakeConn())
    assert await a.authenticate("x)(uid=*", "pw") is None  # bound, but no entry -> unmapped
    assert "(uid=x\\29\\28uid=\\2a)" in seen["filter"]


def test_password_is_never_serialised():
    tok = UserAccessToken(token="ldap", client_id="alice", scopes=[])
    tok._password = __import__("pydantic").SecretStr("pw-alice")
    assert "pw-alice" not in repr(tok) and "pw-alice" not in tok.model_dump_json()
    assert tok.password.get_secret_value() == "pw-alice"


@pytest.mark.parametrize(
    "header,expected",
    [
        (
            "Basic " + base64.b64encode(b"alice:pw:with:colons").decode(),
            ("alice", "pw:with:colons"),
        ),
        ("basic " + base64.b64encode(b" alice :pw").decode(), ("alice", "pw")),
        ("Bearer abc", None),
        ("Basic", None),
        ("Basic !!!notbase64", None),
        ("Basic " + base64.b64encode(b"alice").decode(), None),
        ("Basic " + base64.b64encode(b"alice:").decode(), None),
        ("Basic " + base64.b64encode(b":pw").decode(), None),
        ("Basic " + base64.b64encode(b"\xff\xfe:pw").decode(), None),
    ],
)
def test_parse_basic(header, expected):
    assert _parse_basic(header) == expected


# ------------------------------------------------------------------ HTTP end to end (in-process)
def basic(user: str, password: str) -> dict[str, str]:
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"authorization": f"Basic {raw}"}


HDRS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }


@pytest.fixture
async def multi_stub():
    # VRLI knows alice and carol@corp (template test); bob is not a VRLI user at all.
    s = Stub(create_app(anchor_ms=ANCHOR, users={"alice": "pw-alice", "carol@corp": "pw-carol"}))
    yield s
    await s.http.aclose()


@pytest.fixture
def ldap_app(multi_stub: Stub, clock: FakeClock):
    made: list[VRLIClient] = []

    def _make(**over: Any):
        settings = make_settings(**{**LDAP_SETTINGS, **over})
        client = VRLIClient(
            settings,
            transport=httpx.ASGITransport(app=multi_stub.app),
            sleep=no_sleep,
            clock=clock,
        )
        made.append(client)
        mcp = create_server(settings, client, authenticator=make_authn(Directory()))
        return mcp.http_app(stateless_http=True, json_response=True)

    return _make


async def post(app, body: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c,
    ):
        return await c.post("/mcp", json=body, headers={**HDRS, **headers})


SEARCH = tool_call("log_search", {"start": START, "end": END, "limit": 2})


async def test_ldap_mode_challenges_with_basic(ldap_app):
    app = ldap_app()
    r = await post(app, SEARCH, {})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="arialog-mcp"'
    for bad in (basic("alice", "nope"), basic("bob", "pw-bob"), {"authorization": "Bearer x"}):
        r = await post(app, SEARCH, bad)
        assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Basic")


async def test_probes_stay_open_in_ldap_mode(ldap_app):
    app = ldap_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/healthz")).status_code == 200


async def test_vrli_is_queried_as_the_ldap_user(ldap_app, multi_stub: Stub, caplog):
    caplog.set_level(logging.INFO, logger="arialog_mcp.audit")
    r = await post(ldap_app(), SEARCH, basic("alice", "pw-alice"))
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert not result.get("isError") and result["structuredContent"]["returned"] == 2
    stats = await multi_stub.stats()
    assert stats["requests_by_user"] == {"alice": 1}
    assert stats["logins_by_user"] == {"alice": 1}  # no service-account login at all
    line = next(x for x in caplog.records if x.getMessage() == "tool ok")
    assert line.user == "alice" and line.role == "ops"  # type: ignore[attr-defined]
    assert all("pw-alice" not in x.getMessage() + str(x.__dict__) for x in caplog.records)


async def test_vrli_username_template_and_per_user_lockout_guard(ldap_app, multi_stub: Stub):
    # carol is "carol@corp" in VRLI; without the template VRLI rejects her.
    app = ldap_app()
    r = await post(app, SEARCH, basic("carol", "pw-carol"))
    assert r.json()["result"]["isError"]
    assert "credentials" in r.json()["result"]["content"][0]["text"]
    r = await post(app, SEARCH, basic("carol", "pw-carol"))
    assert "locking" in r.json()["result"]["content"][0]["text"]  # cooldown, not resent
    assert (await multi_stub.stats())["login_failures"] == 1
    # A rejected user does not affect anyone else.
    r = await post(app, SEARCH, basic("alice", "pw-alice"))
    assert not r.json()["result"].get("isError")

    templated = ldap_app(ldap_vrli_username_template="{username}@corp")
    r = await post(templated, SEARCH, basic("carol", "pw-carol"))
    assert not r.json()["result"].get("isError"), r.text
    assert (await multi_stub.stats())["requests_by_user"].get("carol@corp") == 1


async def test_ldap_mode_never_falls_back_to_a_service_account(multi_stub: Stub, clock):
    # Even with a service account configured, an LDAP-mode tool call without an LDAP user
    # (e.g. in-memory transport) must fail rather than run as the service account.
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    settings = make_settings(**{**LDAP_SETTINGS, "username": "svc-test", "password": "placeholder"})
    client = VRLIClient(
        settings, transport=httpx.ASGITransport(app=multi_stub.app), sleep=no_sleep, clock=clock
    )
    mcp = create_server(settings, client, authenticator=make_authn(Directory()))
    async with Client(mcp) as c:
        with pytest.raises(ToolError, match="LDAP-authenticated"):
            await c.call_tool("log_search", {"start": START, "end": END})
    assert (await multi_stub.stats())["login_count"] == 0


async def test_real_ldap3_path_recovers_after_an_outage(caplog):
    # Real ldap3 against a closed local port: every attempt must report the actual
    # connection error. ldap3 caches failed addresses on its Server object, which (unfixed)
    # turns all later attempts into "invalid server address" until the process restarts.
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]  # closed again once the block exits
    a = LDAPAuthenticator(
        server_uri=f"ldap://127.0.0.1:{port}",
        user_dn_template="uid={username},dc=x",
        user_search_base="dc=x",
        group_role_map=GROUP_MAP,
        verify_tls=False,
        bind_timeout=2,
    )
    with caplog.at_level(logging.ERROR, logger="arialog_mcp.ldap"):
        for _ in range(3):
            assert await a.authenticate("alice", "pw-alice") is None
    errors = [r.error for r in caplog.records if getattr(r, "event", "") == "ldap_unavailable"]
    assert len(errors) == 3
    assert all("invalid server address" not in e for e in errors), errors
    assert all("pw-alice" not in e for e in errors)


async def test_group_search_failure_is_an_operator_error_not_unmapped(caplog):
    from ldap3.core.exceptions import LDAPAttributeError

    class BrokenSearch:
        def search(self, **_: Any) -> None:
            raise LDAPAttributeError("invalid attribute type in filter")

        def unbind(self) -> None:
            return None

    a = make_authn(Directory(), connector=lambda dn, pw: BrokenSearch(), max_failed_binds=1)
    with caplog.at_level(logging.INFO, logger="arialog_mcp.ldap"):
        assert await a.authenticate("alice", "pw-alice") is None
        assert await a.authenticate("alice", "pw-alice") is None  # not throttled
    events = [getattr(r, "event", "") for r in caplog.records]
    assert events == ["ldap_unavailable", "ldap_unavailable"]
    assert "group search failed" in caplog.records[0].error  # type: ignore[attr-defined]
