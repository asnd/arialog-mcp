"""Exercise the production container over real TLS/MCP, including failure paths."""

import asyncio
import json
import os
import ssl
import subprocess
import sys

import httpx
import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

EP = "/infra/sites/default/enforcement-points/default"
EDGE = EP + "/edge-clusters/ec/edge-nodes/edge-1"


async def check(host):
    context = ssl.create_default_context(cafile="/config/ca.crt")
    async with httpx.AsyncClient(verify=context, trust_env=False) as http:
        assert (await http.get(f"https://{host}:8443/healthz")).status_code == 200
        assert (await http.post(f"https://{host}:8443/mcp")).status_code == 401
        bad = await http.post(f"https://{host}:8443/mcp", auth=("bad", "wrong"), json={})
        assert bad.status_code == 401
    transport = StreamableHttpTransport(
        f"https://{host}:8443/mcp",
        headers={"Authorization": "Basic YWxpY2VAdGVzdDpwdw=="},
        httpx_client_factory=lambda **kw: httpx2.AsyncClient(verify=context, trust_env=False, **kw),
    )
    async with Client(transport) as client:
        rules = await client.call_tool(
            "nsx_list_gateway_firewall_rules", {"target": "primary", "policy_id": "policy-1"}
        )
        assert len(rules.structured_content["items"]) == 2
        routes = await client.call_tool(
            "nsx_get_routing_table",
            {
                "target": "primary",
                "tier0_id": "t0",
                "edge_path": EDGE,
                "enforcement_point_path": EP,
            },
        )
        assert routes.structured_content["items"][0]["route_entries"]
        tunnels = await client.call_tool(
            "nsx_list_transport_node_tunnels", {"target": "primary", "node_id": "edge-1"}
        )
        assert tunnels.structured_content["pages"] == 2
        fleet = await client.call_tool(
            "nsx_get_fleet_health", {"targets": ["primary", "unavailable"]}
        )
        assert not fleet.structured_content["complete"]
        assert fleet.structured_content["targets"][1]["error_type"] == "Unavailable"
        denied = await client.call_tool(
            "nsx_get_cluster_health", {"target": "not-authorized"}, raise_on_error=False
        )
        assert denied.is_error
    print(f"PASS {host}: TLS, caller auth, Gateway FW, routing, tunnels, fleet partial failures")
    environment = {**os.environ, "MCP_USERNAME": "alice@test"}
    command = [
        sys.executable,
        "/examples/mcp_client.py",
        "remote",
        "--url",
        f"https://{host}:8443/mcp",
        "--ca-bundle",
        "/config/ca.crt",
    ]
    if host == "mcp-per-user":
        environment.pop("MCP_PASSWORD", None)
        command.extend(["--password-file", "/config/client.password"])
    else:
        environment["MCP_PASSWORD"] = "pw"
    example = await asyncio.to_thread(
        subprocess.run,
        command,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(example.stdout)["responses"][0]["result"] == ["primary", "unavailable"]
    print(f"PASS {host}: documented Python client with env/password-file credentials")


async def main():
    await check("mcp-shared")
    await check("mcp-per-user")


if __name__ == "__main__":
    asyncio.run(main())
