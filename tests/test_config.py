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
