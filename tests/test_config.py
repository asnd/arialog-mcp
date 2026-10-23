from __future__ import annotations

import pytest
from pydantic import ValidationError

from arialog_mcp.config import Settings

BASE = dict(host="vrli.example.local", username="svc", password="pw")


def mk(**over):
    return Settings(_env_file=None, **{**BASE, **over})  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "host",
    ["https://vrli.local", "http://vrli.local", "vrli.local:9543", "vrli.local/api", "", " "],
)
def test_host_must_be_bare(host):
    with pytest.raises(ValidationError, match="bare hostname"):
        mk(host=host)


def test_host_trimmed_and_base_url():
    s = mk(host=" vrli.local ", port=9543)
    assert s.base_url == "https://vrli.local:9543"
    assert mk(use_tls=False).base_url == "http://vrli.example.local:9543"


def test_invalid_transport_and_provider_rejected():
    with pytest.raises(ValidationError):
        mk(transport="websocket")
    with pytest.raises(ValidationError):
        mk(provider="LDAP")


def test_log_level_normalised_and_validated():
    assert mk(log_level="debug").log_level == "DEBUG"
    with pytest.raises(ValidationError, match="log_level"):
        mk(log_level="chatty")


def test_defaults_are_safe():
    s = mk()
    assert s.verify_ssl is True and s.trust_env is False and s.transport == "stdio"
    assert s.provider == "ActiveDirectory" and s.http_host == "127.0.0.1"
    assert "pw" not in repr(s) and "pw" not in str(s.model_dump())


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("ARIALOG_HOST", "from-env.local")
    monkeypatch.setenv("ARIALOG_USERNAME", "u")
    monkeypatch.setenv("ARIALOG_PASSWORD", "p")
    monkeypatch.setenv("ARIALOG_MAX_EVENTS", "7")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.host == "from-env.local" and s.max_events == 7


@pytest.mark.parametrize("field,val", [("max_concurrency", 0), ("retries", -1), ("max_events", 0)])
def test_numeric_bounds(field, val):
    with pytest.raises(ValidationError):
        mk(**{field: val})


def test_http_on_non_loopback_requires_a_token():
    with pytest.raises(ValidationError, match="token or ldap is required"):
        mk(transport="http", http_host="0.0.0.0")
    assert mk(transport="http", http_host="0.0.0.0", http_auth_token="x" * 16).http_auth_token
    assert mk(transport="http", http_host="0.0.0.0", http_allow_unauthenticated=True)
    assert mk(transport="http", http_host="127.0.0.1").http_auth_token is None
    assert mk(transport="http", http_host="localhost").http_auth_token is None
    assert mk(transport="http", http_host="::1").http_auth_token is None


def test_short_token_rejected_and_never_echoed():
    with pytest.raises(ValidationError, match="at least 16") as ei:
        mk(http_auth_token="short-tok")
    assert "short-tok" not in str(ei.value).split("input_value")[0]
    assert "x" * 16 not in repr(mk(http_auth_token="x" * 16))


def test_request_timeout_must_outlast_query_timeout():
    with pytest.raises(ValidationError, match="request_timeout_s must be longer"):
        mk(request_timeout_s=30, query_timeout_ms=30_000)
    assert mk(request_timeout_s=31, query_timeout_ms=30_000)


@pytest.mark.parametrize("field,val", [("port", 0), ("http_port", 70_000), ("retries", 11)])
def test_more_numeric_bounds(field, val):
    with pytest.raises(ValidationError):
        mk(**{field: val})


LDAP = dict(
    username=None,
    password=None,
    transport="http",
    http_auth_mode="ldap",
    ldap_server_uri="ldaps://ldap.example.local",
    ldap_user_dn_template="{username}@example.local",
    ldap_user_search_base="dc=example,dc=local",
    ldap_group_role_map={"arialog-ops": {"role": "ops"}},
)


def test_ldap_mode_needs_no_service_account():
    s = mk(**LDAP)
    assert s.auth_mode == "ldap" and s.username is None


def test_other_modes_still_need_the_service_account():
    with pytest.raises(ValidationError, match="service account"):
        mk(username=None, password=None)


def test_token_alone_keeps_enabling_token_auth():
    assert mk(http_auth_token="t" * 32).auth_mode == "token"
    with pytest.raises(ValidationError, match="requires http_auth_token"):
        mk(http_auth_mode="token")


@pytest.mark.parametrize(
    "over,needle",
    [
        ({"transport": "stdio"}, "needs transport=http"),
        ({"ldap_server_uri": None}, "requires ldap_server_uri"),
        ({"ldap_user_search_base": ""}, "requires ldap_user_search_base"),
        ({"ldap_user_dn_template": "cn=fixed"}, "must contain {username}"),
        ({"ldap_server_uri": "ldap://ldap.example.local"}, "must use ldaps://"),
        ({"ldap_group_role_map": {}}, "requires default_role"),
        ({"ldap_vrli_username_template": "svc"}, "must contain {username}"),
        ({"ldap_group_role_map": '{"a": "ops"}'}, "ldap_group_role_map must be"),
        ({"ldap_group_role_map": "{not json"}, "must be valid JSON"),
    ],
)
def test_ldap_validation(over, needle):
    with pytest.raises(ValidationError, match=needle):
        mk(**{**LDAP, **over})


def test_ldap_plain_ldap_allowed_only_without_tls_verification():
    s = mk(**{**LDAP, "ldap_server_uri": "ldap://ldap.test", "ldap_verify_tls": False})
    assert s.ldap_server_uri == "ldap://ldap.test"


def test_ldap_default_role_without_map():
    assert mk(**{**LDAP, "ldap_group_role_map": {}, "default_role": "ops"}).default_role == "ops"


def test_ldap_settings_load_from_env_with_ariaops_compatible_map(monkeypatch):
    env = {
        "ARIALOG_HOST": "vrli.example.local",
        "ARIALOG_TRANSPORT": "http",
        "ARIALOG_HTTP_AUTH_MODE": "ldap",
        "ARIALOG_LDAP_SERVER_URI": "ldaps://ldap.example.local",
        "ARIALOG_LDAP_USER_DN_TEMPLATE": "{username}@example.local",
        "ARIALOG_LDAP_USER_SEARCH_BASE": "dc=example,dc=local",
        # Copied verbatim from an ARIAOPS_LDAP_GROUP_ROLE_MAP value.
        "ARIALOG_LDAP_GROUP_ROLE_MAP": '{"vrops-ops": {"role": "ops"}, '
        '"vrops-se": {"role": "country", "country": "SE"}}',
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.ldap_group_role_map["vrops-se"] == {"role": "country", "country": "SE"}
    monkeypatch.setenv("ARIALOG_LDAP_GROUP_ROLE_MAP", "")
    with pytest.raises(ValidationError, match="requires default_role"):
        Settings(_env_file=None)  # type: ignore[call-arg]
