"""Synthetic Policy API fixture; captures origins, credentials, scope and pagination."""

import base64
from urllib.parse import unquote

import httpx


class NSXStub:
    def __init__(self):
        self.requests = []
        self.overrides = {}
        self.version = "4.2.1.0.0"

    def __call__(self, request):
        assert request.method == "GET"
        self.requests.append(request)
        path = unquote(request.url.path)
        if path in self.overrides:
            status, data = self.overrides[path]
            return httpx.Response(status, json=data)
        auth = request.headers.get("authorization", "Basic Og==").split(" ", 1)[1]
        username = base64.b64decode(auth).decode().split(":", 1)[0]
        if username == "bad":
            return httpx.Response(401, json={"error": "private upstream information"})
        if request.url.host == "b.example.test" and username == "alice@test":
            return httpx.Response(403, json={"error": "permission denied"})
        if path == "/api/v1/node/version":
            return httpx.Response(200, json={"product_version": self.version})
        if path == "/api/v1/aaa/user-info":
            return httpx.Response(200, json={"user_name": username, "roles": [{"role": "auditor"}]})
        operation = operation_response(request)
        if operation is not None:
            return operation
        root = "/policy/api/v1/infra/domains/default/gateway-policies"
        policy = {
            "id": "policy-1",
            "path": root.removeprefix("/policy/api/v1") + "/policy-1",
            "category": "LocalGatewayRules",
            "sequence_number": 20,
            "scope": ["/infra/tier-1s/app"],
            "stateful": True,
        }
        rules = [
            {
                "id": "early",
                "sequence_number": 1,
                "action": "DROP",
                "disabled": True,
                "logged": False,
                "scope": ["/infra/tier-1s/app"],
                "sources_excluded": True,
                "source_groups": ["/infra/domains/default/groups/web"],
                "destination_groups": ["ANY"],
                "services": ["/infra/services/HTTPS"],
            },
            {
                "id": "late",
                "sequence_number": 10,
                "action": "ALLOW",
                "logged": True,
                "source_groups": ["ANY"],
                "services": ["ANY"],
            },
        ]
        if path == root:
            return httpx.Response(200, json={"results": [policy]})
        if path == root + "/policy-1":
            return httpx.Response(200, json=policy)
        if path == root + "/policy-1/rules":
            assert request.url.params["sort_by"] == "sequence_number"
            assert request.url.params["sort_ascending"] == "true"
            if "cursor" not in request.url.params:
                return httpx.Response(200, json={"results": rules[:1], "cursor": "rule-page-2"})
            assert request.url.params["cursor"] == "rule-page-2"
            return httpx.Response(200, json={"results": rules[1:]})
        if path.endswith("/rules/early/statistics"):
            assert request.url.params["enforcement_point_path"] == (
                "/infra/sites/default/enforcement-points/default"
            )
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "enforcement_point_path": request.url.params["enforcement_point_path"],
                            "statistics": {"packet_count": 42, "hit_count": 3},
                        }
                    ]
                },
            )
        group = "/policy/api/v1/infra/domains/default/groups/web"
        if path == group:
            return httpx.Response(
                200,
                json={
                    "id": "web",
                    "expression": [{"resource_type": "Condition", "value": "web"}],
                    "tags": [{"scope": "app", "tag": "web"}],
                },
            )
        if path == group + "/members/ip-addresses":
            return httpx.Response(200, json={"results": ["192.0.2.1", "192.0.2.0/24"]})
        if path == group + "/members/virtual-machines":
            return httpx.Response(200, json={"results": [{"external_id": "vm-1"}]})
        if path == "/policy/api/v1/infra/services/HTTPS":
            return httpx.Response(
                200,
                json={
                    "id": "HTTPS",
                    "service_entries": [
                        {
                            "resource_type": "L4PortSetServiceEntry",
                            "l4_protocol": "TCP",
                            "destination_ports": ["443"],
                        }
                    ],
                },
            )
        if path == "/policy/api/v1/infra/realized-state/status":
            return httpx.Response(
                200,
                json={
                    "intent_path": request.url.params["intent_path"],
                    "publish_status": "ERROR",
                    "consolidated_status": {"consolidated_status": "ERROR"},
                    "consolidated_status_per_enforcement_point": [{"error": "edge unavailable"}],
                },
            )
        return httpx.Response(404, json={"error": "unknown synthetic resource"})


def operation_response(request):
    path = unquote(request.url.path)
    root = "/policy/api/v1/infra"
    ep = "/infra/sites/default/enforcement-points/default"
    edge = ep + "/edge-clusters/ec/edge-nodes/edge-1"
    gateway = root + "/tier-0s/t0"
    locale = gateway + "/locale-services/ls"
    lists = {
        root + "/tier-0s": [{"id": "t0", "ha_mode": "ACTIVE_STANDBY"}],
        root + "/tier-1s": [{"id": "t1", "tier0_path": "/infra/tier-0s/t0"}],
        gateway + "/locale-services": [{"id": "ls", "edge_cluster_path": ep + "/edge-clusters/ec"}],
        locale + "/interfaces": [{"id": "uplink", "subnets": [{"ip_addresses": ["192.0.2.1"]}]}],
        locale + "/bgp/neighbors": [
            {"id": "peer", "neighbor_address": "192.0.2.2", "password": "secret-bgp"}
        ],
        gateway + "/static-routes": [{"id": "static-1", "network": "198.51.100.0/24"}],
        root + "/tier-1s/t1/nat/USER/nat-rules": [
            {"id": "nat-1", "action": "SNAT", "translated_network": "203.0.113.1"}
        ],
        root + "/segments": [{"id": "seg", "connectivity_path": "/infra/tier-1s/t1"}],
        root + "/tier-1s/t1/segments": [
            {"id": "fixed", "path": "/infra/tier-1s/t1/segments/fixed"}
        ],
        root + "/segments/seg/ports": [{"id": "port-1", "attachment": {"id": "vif-1"}}],
        "/api/v1/edge-clusters": [{"id": "ec", "members": [{"transport_node_id": "edge-1"}]}],
        "/api/v1/transport-nodes": [
            {"id": "edge-1", "node_deployment_info": {"resource_type": "EdgeNode"}}
        ],
        "/api/v1/alarms": [{"id": "alarm-1", "status": "OPEN", "severity": "HIGH"}],
    }
    objects = {
        gateway: {"id": "t0", "ha_mode": "ACTIVE_STANDBY"},
        root + "/tier-1s/t1": {"id": "t1", "tier0_path": "/infra/tier-0s/t0"},
        locale + "/bgp": {"enabled": True, "local_as_num": "65001", "password": "secret-bgp"},
        root + "/segments/seg": {"id": "seg", "connectivity_path": "/infra/tier-1s/t1"},
        "/api/v1/cluster/status": {
            "mgmt_cluster_status": {"status": "STABLE"},
            "control_cluster_status": {"status": "DEGRADED"},
        },
        "/api/v1/edge-clusters/ec/status": {
            "member_status": [{"transport_node_id": "edge-1", "status": "UP"}]
        },
        "/api/v1/transport-nodes/edge-1/status": {
            "status": "DEGRADED",
            "tunnel_status": {"down_count": 1},
            "last_status_changed_time": 1700000000000,
        },
        "/api/v1/transport-nodes/edge-1/node/network/interfaces": {
            "results": [{"interface_id": "eth0", "link_status": "up"}]
        },
        "/api/v1/transport-nodes/edge-1/node/network/interfaces/eth0/stats": {
            "interface_id": "eth0",
            "rx_errors": 2,
            "tx_dropped": 3,
        },
    }
    if path in lists:
        return httpx.Response(200, json={"results": lists[path]})
    if path in objects:
        return httpx.Response(200, json=objects[path])
    if path == locale + "/bgp/neighbors/status":
        assert request.url.params["enforcement_point_path"] == ep
        assert request.url.params["edge_path"] == edge
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "edge_path": edge,
                        "connection_status": "DISCONNECTED",
                        "neighbor_address": "192.0.2.2",
                        "last_updated_timestamp": 1700000000000,
                    }
                ]
            },
        )
    if path == gateway + "/routing-table":
        assert request.url.params["edge_path"] == edge
        if "cursor" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "edge_node": "edge-1",
                            "route_entries": [
                                {
                                    "network": "198.51.100.0/24",
                                    "next_hop": "192.0.2.2",
                                    "route_type": "b",
                                }
                            ],
                        }
                    ],
                    "cursor": "routes-2",
                },
            )
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "edge_node": "edge-1",
                        "route_entries": [{"network": "192.0.2.0/24", "route_type": "c"}],
                    }
                ]
            },
        )
    if path.endswith("/nat/USER/nat-rules/nat-1/statistics"):
        return httpx.Response(
            200,
            json={
                "results": [
                    {"enforcement_point_path": ep, "rule_statistics": [{"total_packets": 42}]}
                ]
            },
        )
    if path == "/api/v1/transport-nodes/edge-1/tunnels":
        if "cursor" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "tunnels": [
                        {"name": "tun-1", "status": "DOWN", "bfd": {"diagnostic": "PATH_DOWN"}}
                    ],
                    "cursor": "tunnels-2",
                },
            )
        return httpx.Response(200, json={"tunnels": [{"name": "tun-2", "status": "UP"}]})
    return None
