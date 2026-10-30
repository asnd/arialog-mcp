"""Run a bounded read-only MCP query over stdio or verified remote HTTPS.

Run from this package with uv; see examples/USAGE.md. Never pass passwords as CLI arguments.
"""

import argparse
import asyncio
import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2
from fastmcp import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport


def report(message: str) -> None:
    if sys.stderr.isatty():
        print(message, file=sys.stderr, flush=True)


async def mcp_progress(progress: float, total: float | None, message: str | None) -> None:
    report(f"  server progress: {progress}/{total if total is not None else '?'} {message or ''}")


async def collect(
    client: Client,
    tool: str,
    arguments: dict[str, Any],
    max_calls: int = 1,
) -> dict[str, Any]:
    """Continue only collection cursors, with an explicit call bound and cycle detection."""
    if not 1 <= max_calls <= 100:
        raise ValueError("max_calls must be between 1 and 100")
    arguments = dict(arguments)
    seen: set[str] = set()
    if arguments.get("cursor"):
        seen.add(arguments["cursor"])
    responses: list[dict[str, Any]] = []
    for number in range(1, max_calls + 1):
        report(f"[{number}/{max_calls}] Calling {tool}")
        result = await client.call_tool(tool, arguments)
        payload = result.structured_content
        if not isinstance(payload, dict):
            raise ValueError("Expected structured MCP object output")
        responses.append(payload)
        if payload.get("complete") is not False or "items" not in payload:
            break
        cursor = payload.get("next_cursor")
        if not isinstance(cursor, str) or not cursor or cursor in seen:
            raise ValueError("Incomplete collection has no usable, advancing cursor")
        seen.add(cursor)
        arguments["cursor"] = cursor
    last = responses[-1]
    return {
        "tool": tool,
        "responses": responses,
        "complete": last.get("complete", True),
        "next_cursor": last.get("next_cursor"),
    }


def arguments_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transport", choices=["stdio", "remote"])
    parser.add_argument("--config", type=Path, help="stdio server configuration JSON")
    parser.add_argument("--url", help="Remote HTTPS MCP URL, including /mcp")
    parser.add_argument("--ca-bundle", type=Path, help="CA for the remote MCP server, not NSX")
    parser.add_argument("--password-file", type=Path, help="Remote caller password file")
    parser.add_argument("--tool", default="nsx_list_targets")
    parser.add_argument("--arguments", default="{}", help="Tool arguments as a JSON object")
    parser.add_argument("--max-calls", type=int, default=1, help="Bound continuation calls (1–100)")
    return parser


async def run(args: argparse.Namespace) -> dict[str, Any]:
    arguments = json.loads(args.arguments)
    if not isinstance(arguments, dict):
        raise ValueError("--arguments must be a JSON object")
    if args.transport == "stdio":
        if args.config is None:
            raise ValueError("stdio requires --config")
        transport: StdioTransport | StreamableHttpTransport = StdioTransport(
            command=sys.executable, args=["-m", "nsxt_mcp", "--config", str(args.config.resolve())]
        )
    else:
        url = urlsplit(args.url or "")
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
        ):
            raise ValueError("remote requires an HTTPS --url without embedded credentials")
        username = os.environ.get("MCP_USERNAME", "")
        password = (
            args.password_file.read_text().rstrip("\r\n")
            if args.password_file
            else os.environ.get("MCP_PASSWORD", "")
        )
        if not username or not password or ":" in username:
            raise ValueError("Set MCP_USERNAME and MCP_PASSWORD, or supply --password-file")
        tls = ssl.create_default_context(cafile=str(args.ca_bundle) if args.ca_bundle else None)

        def http_client(
            headers: dict[str, str] | None = None,
            timeout: httpx2.Timeout | None = None,
            auth: httpx2.Auth | None = None,
            **kwargs: Any,
        ) -> httpx2.AsyncClient:
            kwargs["follow_redirects"] = False
            return httpx2.AsyncClient(
                headers=headers,
                timeout=timeout or httpx2.Timeout(30, read=60),
                auth=auth,
                verify=tls,
                trust_env=False,
                **kwargs,
            )

        transport = StreamableHttpTransport(
            args.url,
            auth=httpx2.BasicAuth(username, password),
            httpx_client_factory=http_client,
        )
    report("Connecting to MCP server…")
    async with Client(transport, progress_handler=mcp_progress) as client:
        return await collect(client, args.tool, arguments, args.max_calls)


def main() -> None:
    parser = arguments_parser()
    args = parser.parse_args()
    if not 1 <= args.max_calls <= 100:
        parser.error("--max-calls must be between 1 and 100")
    try:
        result = asyncio.run(run(args))
    except (ValueError, OSError) as exc:
        # No argument values, credential values or local file contents in error output.
        parser.exit(
            2, f"Configuration or input error ({type(exc).__name__}); see examples/USAGE.md\n"
        )
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
