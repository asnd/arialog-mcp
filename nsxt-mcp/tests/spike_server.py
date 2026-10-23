"""Subprocess-only MCP fixture: no real NSX requests or credentials."""

import httpx
from pydantic import SecretStr
from stub_nsx import NSXStub

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import Settings, Target
from nsxt_mcp.credentials import Caller, Credentials
from nsxt_mcp.server import create_server

if __name__ == "__main__":
    settings = Settings(mode="per_user", targets={"stub": Target(url="https://stub.test")})
    caller = Caller(
        "stub-user", frozenset({"stub"}), Credentials(SecretStr("stub"), SecretStr("stub"))
    )
    stub = NSXStub()
    stub.version = "4.2.0.0.0"
    transport = httpx.MockTransport(stub)
    create_server(TargetRegistry(settings, transport=transport), caller).run(transport="stdio")
