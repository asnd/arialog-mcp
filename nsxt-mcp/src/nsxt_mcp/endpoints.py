"""Closed endpoint manifest; NSX 4.x contracts are provisional until appliance-tested."""

import re
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import quote

from .errors import ContractError


@dataclass(frozen=True)
class Endpoint:
    path: str
    parameters: tuple[str, ...] = ()
    query: frozenset[str] = frozenset()
    permission: str = "read (verify effective NSX role on appliance)"
    coverage: str = "4.x candidate; synthetic contract only"
    cost: str = "single read"
    string_items: bool = False
    list_key: str = "results"

    def build(self, parameters: dict[str, str]) -> str:
        if set(parameters) != set(self.parameters):
            raise ContractError("Invalid endpoint parameters")
        for value in parameters.values():
            if (
                not value
                or value in (".", "..")
                or len(value) > 255
                or any(ord(c) < 32 or c in "/\\%?#" for c in value)
            ):
                raise ContractError("Invalid resource identifier")
        return self.path.format(**{k: quote(v, safe="") for k, v in parameters.items()})


PAGING = frozenset({"cursor", "page_size"})
ORDERED = PAGING | {"sort_by", "sort_ascending"}
POLICY = "/policy/api/v1/infra/domains/{domain_id}/gateway-policies/{policy_id}"
GROUP = "/policy/api/v1/infra/domains/{domain_id}/groups/{group_id}"
GATEWAY = "/policy/api/v1/infra/{gateway_type}/{gateway_id}"
LOCALE = GATEWAY + "/locale-services/{locale_service_id}"
TIER0_LOCALE = "/policy/api/v1/infra/tier-0s/{gateway_id}/locale-services/{locale_service_id}"
NODE = "/api/v1/transport-nodes/{node_id}"
ENDPOINTS = MappingProxyType(
    {
        "node_version": Endpoint("/api/v1/node/version", permission="none; discovery only"),
        "current_user": Endpoint("/api/v1/aaa/user-info", permission="authenticated current user"),
        "cluster_status": Endpoint("/api/v1/cluster/status"),
        "tier0s": Endpoint("/policy/api/v1/infra/tier-0s", query=PAGING),
        "tier1s": Endpoint("/policy/api/v1/infra/tier-1s", query=PAGING),
        "transport_nodes": Endpoint("/api/v1/transport-nodes", query=PAGING),
        "edge_clusters": Endpoint("/api/v1/edge-clusters", query=PAGING),
        "gateway_policies": Endpoint(
            "/policy/api/v1/infra/domains/{domain_id}/gateway-policies",
            ("domain_id",),
            ORDERED,
        ),
        "gateway_policy": Endpoint(POLICY, ("domain_id", "policy_id")),
        "gateway_rules": Endpoint(POLICY + "/rules", ("domain_id", "policy_id"), ORDERED),
        "gateway_rule_statistics": Endpoint(
            POLICY + "/rules/{rule_id}/statistics",
            ("domain_id", "policy_id", "rule_id"),
            frozenset({"enforcement_point_path"}),
        ),
        "group": Endpoint(GROUP, ("domain_id", "group_id")),
        "group_ip_members": Endpoint(
            GROUP + "/members/ip-addresses",
            ("domain_id", "group_id"),
            PAGING | {"enforcement_point_path"},
            string_items=True,
        ),
        "group_vm_members": Endpoint(
            GROUP + "/members/virtual-machines",
            ("domain_id", "group_id"),
            PAGING | {"enforcement_point_path"},
        ),
        "service": Endpoint("/policy/api/v1/infra/services/{service_id}", ("service_id",)),
        "realization_status": Endpoint(
            "/policy/api/v1/infra/realized-state/status",
            query=frozenset({"intent_path", "include_enforced_status"}),
        ),
        "gateways": Endpoint("/policy/api/v1/infra/{gateway_type}", ("gateway_type",), PAGING),
        "gateway": Endpoint(GATEWAY, ("gateway_type", "gateway_id")),
        "locale_services": Endpoint(
            GATEWAY + "/locale-services", ("gateway_type", "gateway_id"), PAGING
        ),
        "gateway_interfaces": Endpoint(
            LOCALE + "/interfaces", ("gateway_type", "gateway_id", "locale_service_id"), PAGING
        ),
        "bgp_config": Endpoint(TIER0_LOCALE + "/bgp", ("gateway_id", "locale_service_id")),
        "bgp_neighbors": Endpoint(
            TIER0_LOCALE + "/bgp/neighbors", ("gateway_id", "locale_service_id"), PAGING
        ),
        "bgp_status": Endpoint(
            TIER0_LOCALE + "/bgp/neighbors/status",
            ("gateway_id", "locale_service_id"),
            PAGING | {"enforcement_point_path", "edge_path"},
        ),
        "routing_table": Endpoint(
            "/policy/api/v1/infra/tier-0s/{gateway_id}/routing-table",
            ("gateway_id",),
            PAGING | {"enforcement_point_path", "edge_path", "network_prefix", "route_source"},
        ),
        "static_routes": Endpoint(
            GATEWAY + "/static-routes", ("gateway_type", "gateway_id"), PAGING
        ),
        "nat_rules": Endpoint(
            GATEWAY + "/nat/{nat_id}/nat-rules", ("gateway_type", "gateway_id", "nat_id"), PAGING
        ),
        "nat_statistics": Endpoint(
            GATEWAY + "/nat/{nat_id}/nat-rules/{rule_id}/statistics",
            ("gateway_type", "gateway_id", "nat_id", "rule_id"),
            frozenset({"enforcement_point_path"}),
        ),
        "segments": Endpoint("/policy/api/v1/infra/segments", query=PAGING),
        "fixed_segments": Endpoint(
            "/policy/api/v1/infra/tier-1s/{gateway_id}/segments", ("gateway_id",), PAGING
        ),
        "segment": Endpoint("/policy/api/v1/infra/segments/{segment_id}", ("segment_id",)),
        "segment_ports": Endpoint(
            "/policy/api/v1/infra/segments/{segment_id}/ports", ("segment_id",), PAGING
        ),
        "fixed_segment": Endpoint(
            "/policy/api/v1/infra/tier-1s/{gateway_id}/segments/{segment_id}",
            ("gateway_id", "segment_id"),
        ),
        "fixed_segment_ports": Endpoint(
            "/policy/api/v1/infra/tier-1s/{gateway_id}/segments/{segment_id}/ports",
            ("gateway_id", "segment_id"),
            PAGING,
        ),
        "alarms": Endpoint("/api/v1/alarms", query=PAGING | {"status", "severity"}),
        "edge_cluster_status": Endpoint(
            "/api/v1/edge-clusters/{edge_cluster_id}/status", ("edge_cluster_id",)
        ),
        "transport_node_status": Endpoint(NODE + "/status", ("node_id",)),
        "transport_node_tunnels": Endpoint(
            NODE + "/tunnels", ("node_id",), PAGING | {"status"}, list_key="tunnels"
        ),
        "node_interfaces": Endpoint(NODE + "/node/network/interfaces", ("node_id",)),
        "node_interface_statistics": Endpoint(
            NODE + "/node/network/interfaces/{interface_id}/stats", ("node_id", "interface_id")
        ),
    }
)


def endpoint_for(name: str, parameters: dict[str, str]) -> tuple[Endpoint, str]:
    if name not in ENDPOINTS:
        raise ContractError("Endpoint is not allowlisted")
    if "gateway_type" in parameters and parameters["gateway_type"] not in ("tier-0s", "tier-1s"):
        raise ContractError("Expected tier-0s or tier-1s")
    endpoint = ENDPOINTS[name]
    return endpoint, endpoint.build(parameters)


def validate_policy_path(path: str, *, enforcement: bool = False) -> str:
    """Policy paths are query values, not arbitrary URLs or API paths."""
    if (
        len(path) > 2048
        or not path.startswith("/infra/")
        or any(c in path for c in "\\%?#")
        or any(not p or p in (".", "..") for p in path.split("/")[1:])
        or any(ord(c) < 32 for c in path)
    ):
        raise ContractError("Invalid local policy path")
    if enforcement and not re.fullmatch(r"/infra/sites/[^/]+/enforcement-points/[^/]+", path):
        raise ContractError("Expected an enforcement-point policy path")
    return path


def validate_edge_scope(enforcement_point: str, edge_path: str) -> None:
    validate_policy_path(enforcement_point, enforcement=True)
    validate_policy_path(edge_path)
    if not re.fullmatch(
        re.escape(enforcement_point) + r"/edge-clusters/[^/]+/edge-nodes/[^/]+", edge_path
    ):
        raise ContractError("Edge path must belong to the selected enforcement point")
