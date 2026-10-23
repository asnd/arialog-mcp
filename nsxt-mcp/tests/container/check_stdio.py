"""Host-side MCP client launches the production container over stdio."""

import asyncio
import sys
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


async def main():
    image, network, directory, env_file = sys.argv[1:]
    transport = StdioTransport(
        command="podman",
        args=[
            "run",
            "--rm",
            "-i",
            "--http-proxy=false",
            "--network",
            network,
            "--env-file",
            str(Path(env_file)),
            "-v",
            f"{directory}:/config:ro,z",
            image,
            "--config",
            "/config/stdio.json",
        ],
    )
    async with Client(transport) as client:
        result = await client.call_tool(
            "nsx_get_transport_node_status", {"target": "primary", "node_id": "edge-1"}
        )
        assert result.structured_content["data"]["status"] == "DEGRADED"
    print("PASS packaged stdio: real TLS NSX read and structured transport-node status")


if __name__ == "__main__":
    asyncio.run(main())
