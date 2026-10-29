import asyncio

import httpx
import pytest
from fastmcp import Client
from stub_nsx import NSXStub

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import Target
from nsxt_mcp.credentials import Caller
from nsxt_mcp.errors import AccessDenied, ContractError
from nsxt_mcp.operations import OperationsService
from nsxt_mcp.server import create_server

EP = "/infra/sites/default/enforcement-points/default"
EDGE = EP + "/edge-clusters/ec/edge-nodes/edge-1"


@pytest.fixture
def ops(settings):
    stub = NSXStub()
    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    return registry, stub


async def test_routing_scope_nested_routes_bgp_and_secrets(ops, caller):
    registry, stub = ops
    async with Client(create_server(registry, caller)) as client:
        arguments = {
            "target": "a",
            "tier0_id": "t0",
            "enforcement_point_path": EP,
            "edge_path": EDGE,
        }
        routes = await client.call_tool("nsx_get_routing_table", arguments)
        rows = routes.structured_content["items"]
        assert len(rows) == 2
        assert rows[0]["route_entries"][0]["next_hop"] == "192.0.2.2"
        assert routes.structured_content["selection"]["edge_path"] == EDGE
        bgp = await client.call_tool(
            "nsx_get_bgp_neighbor_status", {**arguments, "locale_service_id": "ls"}
        )
        assert bgp.structured_content["items"][0]["connection_status"] == "DISCONNECTED"
        config = await client.call_tool(
            "nsx_get_bgp_config", {"target": "a", "tier0_id": "t0", "locale_service_id": "ls"}
        )
        assert config.structured_content["data"]["password"] == "[redacted]"
        assert config.structured_content["data"]["access_token"] == "[redacted]"
        assert "secret-bgp" not in str(config.content)
        assert "secret-token" not in str(config.content)
    assert all(r.method == "GET" for r in stub.requests)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("nsx_list_gateways", {"gateway_type": "tier-0s"}),
        ("nsx_get_gateway", {"gateway_type": "tier-0s", "gateway_id": "t0"}),
        ("nsx_list_locale_services", {"gateway_type": "tier-0s", "gateway_id": "t0"}),
        (
            "nsx_list_gateway_interfaces",
            {"gateway_type": "tier-0s", "gateway_id": "t0", "locale_service_id": "ls"},
        ),
        ("nsx_list_bgp_neighbors", {"tier0_id": "t0", "locale_service_id": "ls"}),
        ("nsx_list_static_routes", {"gateway_type": "tier-0s", "gateway_id": "t0"}),
        ("nsx_list_nat_rules", {"gateway_type": "tier-1s", "gateway_id": "t1", "nat_id": "USER"}),
        (
            "nsx_get_nat_rule_statistics",
            {
                "gateway_type": "tier-1s",
                "gateway_id": "t1",
                "nat_id": "USER",
                "rule_id": "nat-1",
                "enforcement_point_path": EP,
            },
        ),
        ("nsx_list_segments", {}),
        ("nsx_list_segments", {"fixed_tier1_id": "t1"}),
        ("nsx_get_segment", {"segment_id": "seg"}),
        ("nsx_list_segment_ports", {"segment_id": "seg"}),
        ("nsx_get_cluster_health", {}),
        ("nsx_list_alarms", {"status": "OPEN", "severity": "HIGH"}),
        ("nsx_list_edge_clusters", {}),
        ("nsx_get_edge_cluster_status", {"edge_cluster_id": "ec"}),
        ("nsx_list_transport_nodes", {}),
        ("nsx_get_transport_node_status", {"node_id": "edge-1"}),
        ("nsx_list_transport_node_tunnels", {"node_id": "edge-1", "status": "DOWN"}),
        ("nsx_list_node_interfaces", {"node_id": "edge-1"}),
        ("nsx_get_node_interface_statistics", {"node_id": "edge-1", "interface_id": "eth0"}),
    ],
)
async def test_operational_catalog_contracts(ops, caller, tool, arguments):
    registry, stub = ops
    async with Client(create_server(registry, caller)) as client:
        result = await client.call_tool(tool, {"target": "a", **arguments})
        payload = result.structured_content
        assert payload["target"] == "a" and payload["source"].startswith("/")
        assert payload.get("items") or payload.get("data")
        assert payload["notes"]
    assert all(request.method == "GET" for request in stub.requests)


async def test_tunnels_native_field_and_nonpaginated_interface_contract(ops, caller):
    registry, stub = ops
    service = OperationsService(registry)
    result = await service.listing(
        "a", caller, "transport_node_tunnels", parameters={"node_id": "edge-1"}, runtime=True
    )
    assert result.pages == 2 and result.complete
    assert result.items[0]["bfd"]["diagnostic"] == "PATH_DOWN"
    interfaces = await service.read(
        "a", caller, "node_interfaces", parameters={"node_id": "edge-1"}, runtime=True
    )
    assert interfaces.data["results"][0]["interface_id"] == "eth0"
    assert not stub.requests[-1].url.query
    await registry.aclose()


@pytest.mark.parametrize(
    ("endpoint", "parameters", "query"),
    [
        (
            "routing_table",
            {"gateway_id": "t0"},
            {"edge_path": EDGE, "enforcement_point_path": EP + "-other"},
        ),
        ("routing_table", {"gateway_id": "t0"}, {"network_prefix": "not-an-ip"}),
        ("routing_table", {"gateway_id": "t0"}, {"route_source": "invented"}),
        ("gateway", {"gateway_type": "../../evil", "gateway_id": "t0"}, {}),
        ("transport_node_tunnels", {"node_id": "edge-1"}, {"status": "RESET"}),
        ("node_interfaces", {"node_id": "edge-1"}, {"page_size": 100}),
        (
            "nat_statistics",
            {"gateway_type": "tier-1s", "gateway_id": "t1", "nat_id": "USER", "rule_id": "x"},
            {"action": "reset"},
        ),
    ],
)
async def test_operational_query_rejections_precede_network(
    ops, caller, endpoint, parameters, query
):
    registry, stub = ops
    with pytest.raises(ContractError):
        await registry.get("a", endpoint, caller, parameters=parameters, query=query)
    assert not stub.requests


async def test_fleet_55_targets_bounded_fanout_partial_failure_and_progress(settings):
    settings.targets = {
        f"t{i}": Target(url=f"https://m{i}.test", credential_profile="service") for i in range(55)
    }
    settings.attempts = 1
    settings.fleet_concurrency = 3
    active = peak = 0

    async def stub(request):
        nonlocal active, peak
        active += 1
        peak = max(active, peak)
        try:
            await asyncio.sleep(0.002)
            if request.url.host == "m7.test":
                return httpx.Response(503)
            return httpx.Response(200, json={"mgmt_cluster_status": {"status": "DEGRADED"}})
        finally:
            active -= 1

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    caller = Caller("fleet", frozenset(settings.targets))
    progress = []

    async def report(done, total):
        progress.append((done, total))

    result = await OperationsService(registry).fleet_health(list(settings.targets), caller, report)
    assert len(result.targets) == 55 and not result.complete
    assert result.targets[7].error_type == "Unavailable"
    assert (
        result.targets[0].readable
        and result.targets[0].data["mgmt_cluster_status"]["status"] == "DEGRADED"
    )
    assert peak == 3 and active == 0
    assert progress[-1] == (55, 55)
    await registry.aclose()


async def test_fleet_authorizes_all_targets_before_any_read(ops):
    registry, stub = ops
    caller = Caller("limited", frozenset({"a"}))
    with pytest.raises(AccessDenied):
        await OperationsService(registry).fleet_health(["a", "b"], caller)
    assert not stub.requests


async def test_fleet_deadline_cancels_workers_and_returns_per_target_errors(settings, caller):
    settings.timeout = 0.04
    settings.fleet_concurrency = 1

    async def blocked(request):
        await asyncio.Event().wait()

    registry = TargetRegistry(settings, transport=httpx.MockTransport(blocked))
    result = await OperationsService(registry).fleet_health(["a", "b"], caller)
    assert not result.complete and all(not item.readable for item in result.targets)
    assert registry.global_limit._value == settings.global_concurrency
    await registry.aclose()


@pytest.mark.parametrize("allowed", ["metadata", "gateway_firewall"])
async def test_new_tool_groups_do_not_inherit_old_grants(ops, allowed):
    registry, stub = ops
    caller = Caller("restricted", frozenset({"a"}), tool_groups=frozenset({allowed}))
    async with Client(create_server(registry, caller)) as client:
        for name, args in [
            ("nsx_list_gateways", {"gateway_type": "tier-0s"}),
            ("nsx_get_cluster_health", {}),
        ]:
            result = await client.call_tool(name, {"target": "a", **args}, raise_on_error=False)
            assert result.is_error
    assert not stub.requests
