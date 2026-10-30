import asyncio
import socket
import sys
from pathlib import Path

import httpx
import httpx2
import uvicorn
from fastmcp import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.server import create_server


async def test_in_process_schema_and_structured_output(settings, caller):
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"product_version": "4.2.1"})
        ),
    )
    async with Client(create_server(registry, caller)) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        version = tools["nsx_get_version"]
        assert version.input_schema["required"] == ["target"]
        assert version.output_schema
        assert version.annotations.read_only_hint
        assert not version.annotations.destructive_hint
        result = await client.call_tool("nsx_get_version", {"target": "a"})
        assert result.structured_content["version"] == "4.2.1"
        denied = await client.call_tool(
            "nsx_get_version", {"target": "denied"}, raise_on_error=False
        )
        assert denied.is_error


async def test_real_stdio_subprocess():
    transport = StdioTransport(
        command=sys.executable, args=[str(Path(__file__).with_name("spike_server.py"))]
    )
    async with Client(transport) as client:
        result = await client.call_tool("nsx_get_version", {"target": "stub"})
        assert result.structured_content["version"] == "4.2.0.0.0"
        rules = await client.call_tool(
            "nsx_list_gateway_firewall_rules", {"target": "stub", "policy_id": "policy-1"}
        )
        assert [rule["id"] for rule in rules.structured_content["items"]] == ["early", "late"]


async def test_streamable_http_custom_basic_header(settings, caller):
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"product_version": "4.1.2"})
        ),
    )
    mcp_app = create_server(registry, caller).http_app()
    seen = []

    async def test_gate(scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            seen.append(headers.get(b"authorization"))
            if headers.get(b"authorization") != b"Basic c3R1YjpzdHVi":
                await send({"type": "http.response.start", "status": 401, "headers": []})
                await send({"type": "http.response.body", "body": b"Unauthorized"})
                return
        await mcp_app(scope, receive, send)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(test_gate, log_level="error", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        url = f"http://127.0.0.1:{port}/mcp"
        async with httpx.AsyncClient(trust_env=False) as http:
            assert (await http.post(url)).status_code == 401
        transport = StreamableHttpTransport(
            url,
            headers={"Authorization": "Basic c3R1YjpzdHVi"},
            httpx_client_factory=lambda **kwargs: httpx2.AsyncClient(trust_env=False, **kwargs),
        )
        async with Client(transport) as client:
            result = await client.call_tool("nsx_get_version", {"target": "a"})
            assert result.structured_content["version"] == "4.1.2"
        assert b"Basic c3R1YjpzdHVi" in seen
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()
