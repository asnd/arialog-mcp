import httpx
import pytest
from fastmcp import Client
from stub_nsx import NSXStub

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.errors import ContractError
from nsxt_mcp.gateway import GatewayService
from nsxt_mcp.server import create_server

EP = "/infra/sites/default/enforcement-points/default"


@pytest.fixture
def gateway(settings):
    stub = NSXStub()
    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    return GatewayService(registry), registry, stub


async def test_policies_scope_and_rules_order(gateway, caller):
    service, registry, stub = gateway
    policies = await service.policies("a", caller, "default")
    assert policies.items[0].category == "LocalGatewayRules"
    assert policies.items[0].scope == ["/infra/tier-1s/app"]
    detail = await service.policy("a", caller, "default", "policy-1")
    assert detail.data.sequence_number == 20
    progress = []

    async def report(done, total):
        progress.append((done, total))

    rules = await service.rules("a", caller, "default", "policy-1", progress=report)
    assert [rule.id for rule in rules.items] == ["early", "late"]
    assert rules.items[0].disabled is True
    assert rules.items[0].logged is False
    assert rules.items[0].sources_excluded is True
    assert rules.items[1].disabled is None  # Missing is not silently translated to False.
    assert rules.items[0].services == ["/infra/services/HTTPS"]
    assert rules.complete and rules.pages == 2 and len(progress) == 2
    assert rules.source.endswith("/policy-1/rules")
    assert all(request.method == "GET" for request in stub.requests)
    await registry.aclose()


async def test_partial_rule_pages_not_effective_ruleset(gateway, caller):
    service, registry, _ = gateway
    registry.settings.max_pages = 1
    first = await service.rules("a", caller, "default", "policy-1")
    assert not first.complete and first.next_cursor == "rule-page-2"
    second = await service.rules("a", caller, "default", "policy-1", cursor=first.next_cursor)
    assert second.complete and second.items[0].id == "late"
    assert any("partial pages" in note for note in first.notes)
    await registry.aclose()


async def test_members_are_type_specific_and_references_preserve_details(gateway, caller):
    service, registry, _ = gateway
    group = await service.reference("a", caller, "/infra/domains/default/groups/web")
    assert group.data.model_dump()["expression"][0]["value"] == "web"
    svc = await service.reference("a", caller, "/infra/services/HTTPS")
    assert svc.data.model_dump()["service_entries"][0]["destination_ports"] == ["443"]
    ips = await service.group_members(
        "a", caller, "default", "web", "ip-addresses", enforcement_point_path=EP
    )
    assert ips.items == ["192.0.2.1", "192.0.2.0/24"]
    vms = await service.group_members("a", caller, "default", "web", "virtual-machines")
    assert vms.items == [{"external_id": "vm-1"}]
    await registry.aclose()


async def test_statistics_scope_and_realization_errors(gateway, caller):
    service, registry, stub = gateway
    stats = await service.statistics("a", caller, "default", "policy-1", "early", EP)
    assert stats.data["results"][0]["statistics"]["packet_count"] == 42
    assert stats.selection["enforcement_point_path"] == EP
    status = await service.realization(
        "a", caller, "/infra/domains/default/gateway-policies/policy-1"
    )
    assert status.data["publish_status"] == "ERROR"
    assert "edge unavailable" in str(status.data)
    assert "include_enforced_status=true" in str(stub.requests[-1].url)
    path = "/policy/api/v1/infra/domains/default/gateway-policies/policy-1/rules/early/statistics"
    stub.overrides[path] = (200, {"results": [], "cursor": 1})
    partial = await service.statistics("a", caller, "default", "policy-1", "early", EP)
    assert not partial.complete and partial.data["cursor"] == 1
    await registry.aclose()


@pytest.mark.parametrize(
    "path",
    [
        "ANY",
        "https://evil.test/infra/services/x",
        "/infra/services/../x",
        "/global-infra/services/x",
        "/infra/services/%2e%2e",
        "/infra/services/x?x=y",
        "/infra/tier-1s/x/groups/legacy",
    ],
)
async def test_untrusted_reference_never_reaches_nsx(gateway, caller, path):
    service, registry, stub = gateway
    with pytest.raises(ContractError):
        await service.reference("a", caller, path)
    assert not stub.requests
    await registry.aclose()


async def test_malformed_policy_is_error_not_empty_success(gateway, caller):
    service, registry, stub = gateway
    stub.overrides["/policy/api/v1/infra/domains/default/gateway-policies"] = (
        200,
        {"results": [{"id": "bad", "sequence_number": "wrong-type"}]},
    )
    with pytest.raises(ContractError, match="policy object"):
        await service.policies("a", caller, "default")
    await registry.aclose()


async def test_gateway_tools_through_mcp(gateway, caller):
    _, registry, stub = gateway
    async with Client(create_server(registry, caller)) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        assert "nsx_list_gateway_firewall_rules" in tools
        assert "credentials" not in str(tools["nsx_list_gateway_firewall_rules"].input_schema)
        result = await client.call_tool(
            "nsx_list_gateway_firewall_rules", {"target": "a", "policy_id": "policy-1"}
        )
        assert result.structured_content["items"][0]["disabled"] is True
        reference = await client.call_tool(
            "nsx_resolve_firewall_reference", {"target": "a", "path": "/infra/services/HTTPS"}
        )
        assert reference.structured_content["data"]["service_entries"]
        denied = await client.call_tool(
            "nsx_get_gateway_firewall_policy",
            {"target": "a", "policy_id": "../bad"},
            raise_on_error=False,
        )
        assert denied.is_error
        assert "Invalid resource identifier" in str(denied.content)
