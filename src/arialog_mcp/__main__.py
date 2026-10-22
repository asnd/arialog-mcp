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
        missing = ", ".join(".".join(map(str, e["loc"])) for e in exc.errors())
        print(f"arialog-mcp: invalid configuration ({missing}); see .env.example", file=sys.stderr)
        raise SystemExit(2) from None
    configure_logging(settings.log_level)
    mcp = create_server(settings)
    if settings.transport == "http":
        mcp.run(transport="http", host=settings.http_host, port=settings.http_port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
