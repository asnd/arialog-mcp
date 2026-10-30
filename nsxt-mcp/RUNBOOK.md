# NSX MCP operations and deployment

## Tool coverage

Every operational tool takes a configured target alias. The server never accepts
arbitrary manager URLs, API methods, or API paths. Existing Gateway Firewall tools
are documented in README.md; these are the routing/fabric additions.

| Group | Tools | Scope / interpretation |
|---|---|---|
| routing | `nsx_list_gateways`, `nsx_get_gateway` | Explicit `tier-0s` or `tier-1s`; configuration |
| routing | `nsx_list_locale_services`, `nsx_list_gateway_interfaces` | Explicit gateway and locale-service placement |
| routing | `nsx_get_bgp_config`, `nsx_list_bgp_neighbors` | Tier-0 configuration; secret fields redacted |
| routing | `nsx_get_bgp_neighbor_status` | Tier-0 + locale service + enforcement point + Edge |
| routing | `nsx_get_routing_table` | Tier-0 observed routes on an explicit Edge; nested `route_entries` retained |
| routing | `nsx_list_static_routes` | Configured Tier-0/Tier-1 routes, not observed forwarding state |
| routing | `nsx_list_nat_rules`, `nsx_get_nat_rule_statistics` | Explicit gateway/NAT section; counters also require enforcement point |
| routing | `nsx_list_segments`, `nsx_get_segment`, `nsx_list_segment_ports` | Flexible infra segments by default; optional fixed Tier-1 scope |
| fabric | `nsx_get_cluster_health`, `nsx_list_alarms` | Native Manager status and filtered read-only alarms |
| fabric | `nsx_list_edge_clusters`, `nsx_get_edge_cluster_status` | Membership configuration versus observed status |
| fabric | `nsx_list_transport_nodes`, `nsx_get_transport_node_status` | Host/Edge inventory and observed status |
| fabric | `nsx_list_transport_node_tunnels` | Native paginated `tunnels` collection and BFD details |
| fabric | `nsx_list_node_interfaces`, `nsx_get_node_interface_statistics` | Appliance interfaces/counters, not logical router interfaces |
| fabric | `nsx_get_fleet_health` | Explicit target list, bounded concurrency and per-target failures |

### Typical investigation

1. Select a target with `nsx_list_targets`.
2. Read cluster status and OPEN alarms. Inspect Edge membership and transport-node status.
3. List the desired gateway tier, locale services and gateway interfaces.
4. Find the relevant Edge path from the returned placement/inventory references.
5. Read BGP configuration and observed peer status for that exact locale-service/Edge scope.
6. Read the Tier-0 routing table, optionally filtering `network_prefix` or `route_source`.
7. Compare configured NAT/Gateway Firewall rules, realized group membership and realization status.
8. Inspect tunnel/BFD and appliance interface counters where needed.

Runtime endpoints may return cached data; returned timestamps remain authoritative.
No tool initiates Traceflow, capture, diagnosis jobs, counter reset, or alarm acknowledgement.
Tier-1 runtime routing-table support is not invented: the current runtime route tool
uses the documented Tier-0 endpoint. Tier-1 static intent/interfaces/NAT are supported.

### Scope and completeness

Use an enforcement-point path such as `/infra/sites/default/enforcement-points/default`
and a matching Edge path:
`/infra/sites/default/enforcement-points/default/edge-clusters/<id>/edge-nodes/<id>`.
An Edge path from a different enforcement point is rejected before network access.

Read `complete`, `next_cursor`, `pages`, `selection`, `source` and `notes` on list responses.
Routing tables retain per-Edge containers instead of flattening routes and losing context.
Fixed Tier-1 segment enumeration excludes flexible segments connected to that Tier-1;
enumerate flexible segments separately and inspect their `connectivity_path`.

Node appliance interface listing has **no documented paging request parameters**.
Its response is preserved as one observation; an unexpected cursor marks it incomplete
instead of causing an undocumented cursor request. Statistics behave similarly where
their documented request contract has no cursor.

### Fleet checks

`nsx_get_fleet_health(targets=[...])` never scans implicitly. All aliases are authorized
before any request is sent. `fleet_concurrency` defaults to 4 and `max_fleet_targets`
to 100. Global and target NSX limits still apply. Workers are cancelled on deadline
or caller cancellation; completed observations are preserved by the service's deadline
handling. The outer MCP/HTTP deadline can still terminate the request sooner.

Each result has `readable`, native `data`, or a sanitized `error_type`/`error`.
`readable=true` means the read succeeded, **not** that the cluster is healthy.
There is a 16 KiB per-target fleet response budget and an aggregate configured output
budget. Select fewer targets when the aggregate budget is exceeded. Full single-target
cluster observations remain available for details.

## Authorization changes

Tool groups are now `metadata`, `gateway_firewall`, `routing`, and `fabric`.
Existing grant defaults remain metadata/Gateway Firewall only. Add `routing` and
`fabric` explicitly to shared-user grants to enable the new tools. Unrestricted
per-user remote mode and local stdio allow the full catalog; NSX still enforces
the execution account's actual permissions. Audit records distinguish caller and
execution mode/profile. A fleet call is authorized as a fabric operation.

## Build and deploy with Podman

The multi-stage image uses Python 3.11, locked uv dependencies, a non-editable
installation and runtime UID **1001** (`appuser`). No test code, credentials,
configuration, TLS keys or developer environment is copied into the image.

```sh
podman build --format docker -t localhost/nsxt-mcp:0.1.0 -f Containerfile .
```

### Local stdio container

Create a local configuration based on `examples/per-user.json`, setting any CA
paths to their in-container mount locations. Provide credentials using a local env
file or a mounted secret reference in shared mode.

```sh
podman run --rm -i --http-proxy=false \
  --env-file /path/to/local-credentials.env \
  -v /path/to/nsxt-config:/config:ro,z \
  localhost/nsxt-mcp:0.1.0 --config /config/config.json
```

Keep stdin attached with `-i`; do not allocate a pseudo-TTY. Configure the MCP host
to launch the `podman run` command. Logs go to stderr; stdout remains MCP traffic.

### Remote TLS container / compose

Prepare a configuration directory containing:

- `config.json`, based on either remote example.
- `server.crt` and `server.key` for the remote HTTPS listener.
- `health-ca.crt`, the issuing CA used to verify the listener's health probe.
- Any NSX CA bundles referenced by `config.json`.
- Any service-account secret files referenced by `config.json`.

The server certificate must include the client-facing hostname and `localhost`
for the supplied compose liveness probe. Alternatively set `NSXT_HEALTH_URL` to
an appropriate certificate hostname reachable inside the container. Ensure UID
1001 can read the mounted configuration and key/secret files; mount them read-only.

Create `.env` for environment-backed service-account secrets (it can be empty in
per-user mode). Then:

```sh
podman compose up -d
podman compose logs -f nsxt-mcp
```

Use `NSXT_CONFIG_DIR` and `NSXT_ENV_FILE` to select other host paths. Compose binds
the HTTPS port to host loopback by default. Its root filesystem is read-only, with
a small tmpfs, no extra capabilities and no privilege escalation. Use separate
instances/ports for shared and per-user execution or distinct authentication realms.

TLS-proxy termination remains supported by the CLI: trust only the actual proxy
addresses via `--forwarded-allow-ips`. Limits are per process; use one worker per
instance so the configured budgets remain predictable.

### Health and audit

`GET /healthz` is unauthenticated **liveness only**, subject to the configured TLS
requirement. It never calls NSX. NSX outages therefore do not cause restart loops.
Use explicit cluster/fleet tools for operational readiness.

The image's health command is `python -m nsxt_mcp.healthcheck`. Without
`NSXT_HEALTH_URL` it checks PID 1 for stdio deployments. With a URL it verifies an
HTTP 200, using `NSXT_HEALTH_CA` for custom trust and ignoring ambient proxies.
Compose sets the URL and CA explicitly. Audit events are JSON lines on stderr.

### Failure interpretation

| Symptom | Interpretation / action |
|---|---|
| HTTP 401 | NSX rejected caller Basic credentials or the client omitted them |
| HTTP 403 | Caller has no grant or identity read was denied |
| HTTP 429 | Caller concurrency/rate budget exhausted; obey Retry-After |
| HTTP 503 during admission | Authentication target unavailable, invalid identity response, or deadline |
| MCP permission error | Operational target denies that user or service account |
| MCP resource-not-found | Check object IDs and release contract; 404 does not establish API incompatibility |
| Incomplete lists | Continue at the returned cursor, or reduce query scope/page size |
| Open circuit breaker | Target suffered transport/transient failures; wait for cooldown |
| Fleet has error entries | Inspect each target independently; other results are still evidence |
| Liveness passes but tools fail | Expected during NSX outage; investigate NSX/connectivity/credentials |

## Validation and reproducibility

Validated locally on 2026-10-23: 167 tests, lint/format/type/syntax checks, Podman
production build, and all TLS/stdio container smoke scenarios passed. The built
image is `localhost/nsxt-mcp:0.1.0` (Python 3.11, runtime UID 1001).
The documented client in `examples/mcp_client.py` passed real HTTPS checks with
environment-backed and standalone password-file credentials. See
`examples/USAGE.md` for connection examples and `TEST_COVERAGE.md` for corner-case
coverage and output-validation limitations.

```sh
bash scripts/validate.sh
bash scripts/validate.sh --container
```

The first command runs lint, formatting, mypy, compilation and stub-backed tests.
The second also builds the production image and runs `scripts/container-smoke.sh`.
The smoke test generates an ephemeral CA and certificates, starts a real HTTPS
NSX stub and both remote credential modes on a private Podman network, and exercises:

- TLS certificate validation, HTTP 200 liveness and failed caller authentication.
- Gateway Firewall rules, runtime routing, native tunnel pagination and partial fleet errors.
- Actual packaged stdio calling the HTTPS NSX stub.
- Non-root execution, read-only remote containers and credential exclusion from audit logs.
- Compose YAML structure.

No real NSX or LDAP service is required. The image is retained for reuse; smoke
containers, network and ephemeral fixture keys are removed on success or failure.
`.env.test` contains synthetic credentials only and is excluded from the image.

## Compatibility evidence

Endpoint paths and parameter shapes were checked against the NSX 4.2 catalog and
method docs. NSX 4.0/4.1 version recognition is synthetic; real release-specific
appliance responses/permissions remain unverified. The current tests do not establish
complete compatibility with every 4.x patch or every MCP desktop client.

Additional sources:

- [Tier-0 runtime routes](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetTier0Routes.html)
- [BGP neighbor status](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetTier0BgpNeighborsStatus.html)
- [Tunnel collection](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_QueryTunnels.html)
- [NAT counters](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetPolicyNatRuleStatisticsFromTier1.html)
- [Alarms](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetAlarms.html)
- [Node interfaces](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_ListNodeInterfaces.html)
- [Node interface counters](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_ReadNetworkInterfaceStatistics.html)
- [Full method catalog](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/api_all_methods.html)
