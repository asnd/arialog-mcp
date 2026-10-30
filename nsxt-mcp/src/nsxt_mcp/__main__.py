"""Local stdio launcher. Per-user identity is supplied by the local process owner."""

import argparse
import os
from pathlib import Path

import uvicorn
from pydantic import SecretStr

from .client import TargetRegistry
from .config import Settings
from .credentials import Caller, Credentials
from .remote import create_remote_app
from .server import configure_audit_logging, create_server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--ssl-certfile")
    parser.add_argument("--ssl-keyfile")
    parser.add_argument(
        "--forwarded-allow-ips",
        default="",
        help="Explicit trusted TLS proxy IPs; forwarded headers ignored by default",
    )
    args = parser.parse_args()
    settings = Settings.model_validate_json(args.config.read_text())
    configure_audit_logging()
    if args.transport == "http":
        if settings.remote is None:
            parser.error("HTTP transport requires remote configuration")
        if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
            parser.error("Specify both TLS certificate and key")
        if settings.remote.require_https and not args.ssl_certfile and not args.forwarded_allow_ips:
            parser.error("HTTPS requires a certificate/key or explicitly trusted TLS proxy IPs")
        uvicorn.run(
            create_remote_app(TargetRegistry(settings)),
            host=args.host,
            port=args.port,
            ssl_certfile=args.ssl_certfile,
            ssl_keyfile=args.ssl_keyfile,
            proxy_headers=bool(args.forwarded_allow_ips),
            forwarded_allow_ips=args.forwarded_allow_ips,
            access_log=False,
        )
        return
    credentials = None
    if settings.mode == "per_user":
        credentials = Credentials(
            SecretStr(os.environ["NSXT_USER"]), SecretStr(os.environ["NSXT_PASSWORD"])
        )
    caller = Caller("local-process", frozenset(settings.targets), credentials)
    create_server(TargetRegistry(settings), caller).run(transport="stdio")


if __name__ == "__main__":
    main()
