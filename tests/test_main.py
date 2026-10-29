from __future__ import annotations

import json
import logging
import sys

import pytest

from arialog_mcp import __main__ as entry

ENV = {
    "ARIALOG_HOST": "vrli.test",
    "ARIALOG_USERNAME": "svc",
    "ARIALOG_PASSWORD": "s3cret-pw",
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for k in list(__import__("os").environ):
        if k.startswith("ARIALOG_"):
            monkeypatch.delenv(k)
    monkeypatch.chdir(tmp_path)  # no stray .env


@pytest.fixture
def restore_logging():
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    httpx_level = logging.getLogger("httpx").level
    yield
    root.handlers[:], root.level = handlers, level
    logging.getLogger("httpx").setLevel(httpx_level)


def test_json_formatter_includes_extras_and_exception():
    fmt = entry.JsonFormatter()
    rec = logging.LogRecord(
        "arialog_mcp.audit", logging.WARNING, "f", 1, "tool failed %s", ("x",), None
    )
    rec.tool = "log_search"
    rec.ms = 12
    out = json.loads(fmt.format(rec))
    assert out["msg"] == "tool failed x" and out["level"] == "WARNING"
    assert out["tool"] == "log_search" and out["ms"] == 12 and "args" not in out
    try:
        raise ValueError("boom")
    except ValueError:
        rec2 = logging.LogRecord("n", logging.ERROR, "f", 1, "m", (), sys.exc_info())
    assert "ValueError: boom" in json.loads(fmt.format(rec2))["exc"]


def test_configure_logging_goes_to_stderr_and_quiets_httpx(restore_logging):
    entry.configure_logging("debug")
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert isinstance(root.handlers[0], logging.StreamHandler)
    assert root.handlers[0].stream is sys.stderr  # stdout is the MCP channel
    assert logging.getLogger("httpx").level == logging.WARNING


def test_main_missing_config_exits_2_without_leaking(monkeypatch, capsys):
    monkeypatch.setenv("ARIALOG_PASSWORD", "s3cret-pw")  # host/username missing
    with pytest.raises(SystemExit) as ei:
        entry.main()
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "host" in err and ".env.example" in err
    assert "s3cret-pw" not in err


class FakeServer:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple, dict]] = []

    def run(self, *a, **kw) -> None:
        self.calls.append((a, kw))


@pytest.mark.parametrize(
    "extra,expected",
    [
        ({}, ((), {})),
        (
            {
                "ARIALOG_TRANSPORT": "http",
                "ARIALOG_HTTP_HOST": "0.0.0.0",
                "ARIALOG_HTTP_PORT": "9000",
                "ARIALOG_HTTP_AUTH_TOKEN": "t" * 32,
                "ARIALOG_HTTP_BEHIND_TLS_PROXY": "true",
            },
            ((), {"transport": "http", "host": "0.0.0.0", "port": 9000}),
        ),
    ],
)
def test_main_selects_transport(monkeypatch, restore_logging, extra, expected):
    for k, v in {**ENV, **extra}.items():
        monkeypatch.setenv(k, v)
    fake = FakeServer()
    seen = {}
    monkeypatch.setattr(entry, "create_server", lambda s: seen.setdefault("s", s) and fake)
    entry.main()
    assert fake.calls == [expected]
    assert seen["s"].password.get_secret_value() == "s3cret-pw"
    assert "s3cret-pw" not in repr(seen["s"])  # SecretStr never prints


def test_main_reports_model_level_config_error(monkeypatch, capsys):
    for k, v in {
        **ENV,
        "ARIALOG_TRANSPORT": "http",
        "ARIALOG_HTTP_HOST": "0.0.0.0",
        "ARIALOG_HTTP_BEHIND_TLS_PROXY": "true",
    }.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(SystemExit) as ei:
        entry.main()
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "token or ldap is required" in err and "s3cret-pw" not in err


def test_main_warns_when_http_is_unauthenticated(monkeypatch, restore_logging, caplog):
    for k, v in {**ENV, "ARIALOG_TRANSPORT": "http"}.items():  # loopback: allowed
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(entry, "create_server", lambda s: FakeServer())
    monkeypatch.setattr(entry, "configure_logging", lambda level: None)
    with caplog.at_level(logging.WARNING, logger="arialog_mcp"):
        entry.main()
    assert any(getattr(r, "event", None) == "http_no_auth" for r in caplog.records)
