"""Entrypoint: ``arialog-mcp`` (stdio by default; ARIALOG_TRANSPORT=http for streamable HTTP)."""

from __future__ import annotations

import json
import logging
import sys

from pydantic import ValidationError

from .config import Settings
from .server import create_server

_STD = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        out.update({k: v for k, v in record.__dict__.items() if k not in _STD})
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stderr)  # stdout is the MCP channel in stdio mode
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    logging.getLogger("httpx").setLevel(logging.WARNING)  # never log request URLs/headers


def main() -> None:
    try:
        settings = Settings()  # type: ignore[call-arg]
    except ValidationError as exc:
        # loc names the setting; model-level checks have no loc, so show their message.
        # Never print e["input"]: it can hold the password.
        problems = "; ".join(
            ".".join(map(str, e["loc"])) or e["msg"].removeprefix("Value error, ")
            for e in exc.errors()
        )
        print(f"arialog-mcp: invalid configuration ({problems}); see .env.example", file=sys.stderr)
        raise SystemExit(2) from None
    configure_logging(settings.log_level)
    if settings.transport == "http":
        log = logging.getLogger("arialog_mcp")
        if settings.auth_mode == "none":
            log.warning("HTTP transport is unauthenticated", extra={"event": "http_no_auth"})
        else:
            log.info("HTTP auth enabled", extra={"event": "http_auth", "mode": settings.auth_mode})
        if settings.auth_mode == "ldap" and not settings.ldap_verify_tls:
            log.warning("LDAP TLS verification is disabled", extra={"event": "ldap_no_tls"})
    mcp = create_server(settings)
    if settings.transport == "http":
        mcp.run(transport="http", host=settings.http_host, port=settings.http_port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
