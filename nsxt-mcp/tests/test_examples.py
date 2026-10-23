import importlib.util
import json
from pathlib import Path

import httpx
import pytest
from fastmcp import Client, FastMCP
from stub_nsx import NSXStub

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import Settings
from nsxt_mcp.server import create_server

EXAMPLES = Path(__file__).parents[1] / "examples"
spec = importlib.util.spec_from_file_location("example_client", EXAMPLES / "mcp_client.py")
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


async def test_example_client_follows_pages_and_retains_incomplete_cursor(settings, caller):
    settings.max_pages = 1
    registry = TargetRegistry(settings, transport=httpx.MockTransport(NSXStub()))
    async with Client(create_server(registry, caller)) as client:
        first = await example.collect(
            client,
            "nsx_list_gateway_firewall_rules",
            {
                "target": "a",
                "policy_id": "policy-1",
            },
        )
        assert not first["complete"] and first["next_cursor"] == "rule-page-2"
        all_pages = await example.collect(
            client,
            "nsx_list_gateway_firewall_rules",
            {
                "target": "a",
                "policy_id": "policy-1",
            },
            max_calls=3,
        )
        assert all_pages["complete"] and len(all_pages["responses"]) == 2
        assert [p["items"][0]["id"] for p in all_pages["responses"]] == ["early", "late"]


async def test_example_client_stops_on_broken_remote_cursor():
    server = FastMCP("broken-cursor-fixture")
    calls = []

    @server.tool
    async def broken(cursor: str | None = None) -> dict:
        calls.append(cursor)
        return {"items": [], "complete": False, "next_cursor": "same"}

    async with Client(server) as client:
        with pytest.raises(ValueError, match="advancing cursor"):
            await example.collect(client, "broken", {}, max_calls=100)
    assert calls == [None, "same"]


async def test_example_client_does_not_paginate_partial_fleet_results(settings, caller):
    stub = NSXStub()
    stub.overrides["/api/v1/cluster/status"] = (403, {"error": "denied"})
    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    async with Client(create_server(registry, caller)) as client:
        result = await example.collect(
            client, "nsx_get_fleet_health", {"targets": ["a"]}, max_calls=10
        )
        assert not result["complete"] and len(result["responses"]) == 1
        assert len(stub.requests) == 1


def test_password_file_config_and_mcp_host_templates():
    settings = Settings.model_validate_json((EXAMPLES / "shared-password-file.json").read_text())
    profile = settings.credential_profiles["network-reader"]
    assert profile.password_file and profile.password_env is None
    for name in ("mcp-host-stdio.json", "mcp-host-podman.json"):
        host = json.loads((EXAMPLES / name).read_text())["mcpServers"]["nsxt"]
        assert host["command"].startswith("/absolute/")
        assert "--env-file" in host["args"]
        assert "PASSWORD" not in str(host)


@pytest.mark.parametrize("arguments", ["[]", '"not-an-object"'])
async def test_example_rejects_non_object_arguments_before_connecting(arguments):
    args = example.arguments_parser().parse_args(["stdio", "--arguments", arguments])
    with pytest.raises(ValueError, match="JSON object"):
        await example.run(args)
