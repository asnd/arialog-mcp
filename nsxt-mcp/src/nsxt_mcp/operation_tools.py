"""Curated routing/fabric tool schemas. API methods and paths are never caller inputs."""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from pydantic import Field

from .client import TargetRegistry
from .credentials import Caller
from .endpoints import validate_edge_scope
from .models import Collection, Observation
from .operations import FleetHealth, OperationsService

GatewayType = Literal["tier-0s", "tier-1s"]
PageSize = Annotated[int, Field(ge=1, le=1000)]
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def register_operation_tools(
    server: FastMCP, registry: TargetRegistry, identity: Callable[[], Caller]
) -> dict[str, str]:
    service = OperationsService(registry)
    groups: dict[str, str] = {}

    def tool(group: str) -> Callable[[Callable[..., Any]], Any]:
        def register(function: Callable[..., Any]) -> Any:
            groups[function.__name__] = group
            return server.tool(annotations=READ_ONLY, timeout=registry.settings.timeout)(function)

        return register

    @tool("routing")
    async def nsx_list_gateways(
        target: str,
        gateway_type: GatewayType,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List configured Tier-0 or Tier-1 gateways; select the tier explicitly."""
        return await service.listing(
            target,
            identity(),
            "gateways",
            parameters={"gateway_type": gateway_type},
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_get_gateway(
        target: str, gateway_type: GatewayType, gateway_id: str
    ) -> Observation:
        """Read gateway configuration, connectivity references and HA mode."""
        return await service.read(
            target,
            identity(),
            "gateway",
            parameters={"gateway_type": gateway_type, "gateway_id": gateway_id},
        )

    @tool("routing")
    async def nsx_list_locale_services(
        target: str,
        gateway_type: GatewayType,
        gateway_id: str,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List locale-service IDs and Edge placement; do not select an arbitrary service."""
        return await service.listing(
            target,
            identity(),
            "locale_services",
            parameters={"gateway_type": gateway_type, "gateway_id": gateway_id},
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_list_gateway_interfaces(
        target: str,
        gateway_type: GatewayType,
        gateway_id: str,
        locale_service_id: str,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List configured gateway interfaces for the explicit locale service."""
        return await service.listing(
            target,
            identity(),
            "gateway_interfaces",
            parameters={
                "gateway_type": gateway_type,
                "gateway_id": gateway_id,
                "locale_service_id": locale_service_id,
            },
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_get_bgp_config(target: str, tier0_id: str, locale_service_id: str) -> Observation:
        """Read Tier-0 BGP configuration; secret fields are redacted."""
        return await service.read(
            target,
            identity(),
            "bgp_config",
            parameters={"gateway_id": tier0_id, "locale_service_id": locale_service_id},
        )

    @tool("routing")
    async def nsx_list_bgp_neighbors(
        target: str,
        tier0_id: str,
        locale_service_id: str,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List configured BGP neighbors for an explicit Tier-0 locale service."""
        return await service.listing(
            target,
            identity(),
            "bgp_neighbors",
            parameters={"gateway_id": tier0_id, "locale_service_id": locale_service_id},
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_get_bgp_neighbor_status(
        target: str,
        tier0_id: str,
        locale_service_id: str,
        enforcement_point_path: str,
        edge_path: str,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """Read BGP runtime neighbor state for one explicit enforcement-point/Edge scope."""
        validate_edge_scope(enforcement_point_path, edge_path)
        return await service.listing(
            target,
            identity(),
            "bgp_status",
            parameters={"gateway_id": tier0_id, "locale_service_id": locale_service_id},
            query={"enforcement_point_path": enforcement_point_path, "edge_path": edge_path},
            runtime=True,
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_get_routing_table(
        target: str,
        tier0_id: str,
        enforcement_point_path: str,
        edge_path: str,
        ctx: Context,
        network_prefix: str | None = None,
        route_source: Literal["BGP", "STATIC", "CONNECTED", "OSPF"] | None = None,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """Read Tier-0 runtime routes for an explicit Edge. Preserve nested route_entries,
        next hops, route types and native timestamps. This is not configured static intent.
        """
        validate_edge_scope(enforcement_point_path, edge_path)
        query = {"enforcement_point_path": enforcement_point_path, "edge_path": edge_path}
        if network_prefix:
            query["network_prefix"] = network_prefix
        if route_source:
            query["route_source"] = route_source
        return await service.listing(
            target,
            identity(),
            "routing_table",
            parameters={"gateway_id": tier0_id},
            query=query,
            runtime=True,
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_list_static_routes(
        target: str,
        gateway_type: GatewayType,
        gateway_id: str,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List configured static routes; use runtime routing-table reads for observed routes."""
        return await service.listing(
            target,
            identity(),
            "static_routes",
            parameters={"gateway_type": gateway_type, "gateway_id": gateway_id},
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_list_nat_rules(
        target: str,
        gateway_type: GatewayType,
        gateway_id: str,
        nat_id: str,
        ctx: Context,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List configured rules in an explicit NAT section (e.g. USER, INTERNAL, DEFAULT)."""
        return await service.listing(
            target,
            identity(),
            "nat_rules",
            parameters={"gateway_type": gateway_type, "gateway_id": gateway_id, "nat_id": nat_id},
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_get_nat_rule_statistics(
        target: str,
        gateway_type: GatewayType,
        gateway_id: str,
        nat_id: str,
        rule_id: str,
        enforcement_point_path: str,
    ) -> Observation:
        """Read NAT counters for the selected enforcement point without aggregating/resetting."""
        return await service.read(
            target,
            identity(),
            "nat_statistics",
            parameters={
                "gateway_type": gateway_type,
                "gateway_id": gateway_id,
                "nat_id": nat_id,
                "rule_id": rule_id,
            },
            query={"enforcement_point_path": enforcement_point_path},
            runtime=True,
        )

    @tool("routing")
    async def nsx_list_segments(
        target: str,
        ctx: Context,
        fixed_tier1_id: str | None = None,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List flexible infra segments, or ONLY fixed segments under an explicit Tier-1.
        Flexible segments connected to that Tier-1 are not included in its fixed-segment list.
        """
        return await service.listing(
            target,
            identity(),
            "fixed_segments" if fixed_tier1_id else "segments",
            parameters={"gateway_id": fixed_tier1_id} if fixed_tier1_id else {},
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("routing")
    async def nsx_get_segment(
        target: str, segment_id: str, fixed_tier1_id: str | None = None
    ) -> Observation:
        """Read flexible or fixed segment configuration, retaining connectivity_path."""
        return await service.read(
            target,
            identity(),
            "fixed_segment" if fixed_tier1_id else "segment",
            parameters={
                "segment_id": segment_id,
                **({"gateway_id": fixed_tier1_id} if fixed_tier1_id else {}),
            },
        )

    @tool("routing")
    async def nsx_list_segment_ports(
        target: str,
        segment_id: str,
        ctx: Context,
        fixed_tier1_id: str | None = None,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List configured ports and attachment references on a flexible or fixed segment."""
        return await service.listing(
            target,
            identity(),
            "fixed_segment_ports" if fixed_tier1_id else "segment_ports",
            parameters={
                "segment_id": segment_id,
                **({"gateway_id": fixed_tier1_id} if fixed_tier1_id else {}),
            },
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("fabric")
    async def nsx_get_cluster_health(target: str) -> Observation:
        """Read native Manager cluster status; retain component failures/unknown state."""
        return await service.read(target, identity(), "cluster_status", runtime=True)

    @tool("fabric")
    async def nsx_list_alarms(
        target: str,
        ctx: Context,
        status: Literal["OPEN", "ACKNOWLEDGED", "SUPPRESSED", "RESOLVED"] = "OPEN",
        severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """List system alarms using read-only status/severity filters; never acknowledge them."""
        query: dict[str, str] = {"status": status}
        if severity:
            query["severity"] = severity
        return await service.listing(
            target,
            identity(),
            "alarms",
            query=query,
            runtime=True,
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("fabric")
    async def nsx_list_edge_clusters(
        target: str, ctx: Context, cursor: str | None = None, page_size: PageSize = 100
    ) -> Collection[dict[str, Any]]:
        """List Edge cluster membership and placement configuration."""
        return await service.listing(
            target,
            identity(),
            "edge_clusters",
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("fabric")
    async def nsx_get_edge_cluster_status(target: str, edge_cluster_id: str) -> Observation:
        """Read operational Edge cluster status for one cluster."""
        return await service.read(
            target,
            identity(),
            "edge_cluster_status",
            parameters={"edge_cluster_id": edge_cluster_id},
            runtime=True,
        )

    @tool("fabric")
    async def nsx_list_transport_nodes(
        target: str, ctx: Context, cursor: str | None = None, page_size: PageSize = 100
    ) -> Collection[dict[str, Any]]:
        """List host/Edge transport-node inventory and deployment information."""
        return await service.listing(
            target,
            identity(),
            "transport_nodes",
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("fabric")
    async def nsx_get_transport_node_status(target: str, node_id: str) -> Observation:
        """Read transport-node runtime state without changing node deployment."""
        return await service.read(
            target,
            identity(),
            "transport_node_status",
            parameters={"node_id": node_id},
            runtime=True,
        )

    @tool("fabric")
    async def nsx_list_transport_node_tunnels(
        target: str,
        node_id: str,
        ctx: Context,
        status: Literal["UP", "DOWN"] | None = None,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[dict[str, Any]]:
        """Read tunnel/BFD state; NSX's native tunnels collection is paginated explicitly."""
        return await service.listing(
            target,
            identity(),
            "transport_node_tunnels",
            parameters={"node_id": node_id},
            query={"status": status} if status else {},
            runtime=True,
            cursor=cursor,
            page_size=page_size,
            progress=lambda n, total: ctx.report_progress(n, total),
        )

    @tool("fabric")
    async def nsx_list_node_interfaces(target: str, node_id: str) -> Observation:
        """Read transport-node appliance network interfaces (not gateway logical interfaces)."""
        return await service.read(
            target, identity(), "node_interfaces", parameters={"node_id": node_id}, runtime=True
        )

    @tool("fabric")
    async def nsx_get_node_interface_statistics(
        target: str, node_id: str, interface_id: str
    ) -> Observation:
        """Read appliance interface counters without resetting them."""
        return await service.read(
            target,
            identity(),
            "node_interface_statistics",
            parameters={"node_id": node_id, "interface_id": interface_id},
            runtime=True,
        )

    @tool("fabric")
    async def nsx_get_fleet_health(targets: list[str], ctx: Context) -> FleetHealth:
        """Read Manager status for explicitly selected targets with bounded fan-out.
        Individual failures are returned as errors; readable is not a health verdict.
        """
        return await service.fleet_health(
            targets, identity(), progress=lambda n, total: ctx.report_progress(n, total)
        )

    return groups
