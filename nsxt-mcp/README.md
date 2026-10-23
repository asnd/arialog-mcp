# NSX 4.x MCP — phases 1–6

Read-only multi-target foundation, using **FastMCP 4.1.3**, async httpx and typed
Pydantic models. Independent package inside the Aria analysis workspace.

## Current scope

- Explicit target aliases, HTTPS/custom CA, environment/file secret references.
- Shared service-account and per-user credential providers; no automatic fallback.
- Trusted caller context with explicit target authorization before network access.
- Lazy target clients, global/per-target concurrency, bounded retry/backoff,
  request deadlines, target circuit breakers and bounded cursor traversal.
- GET-only endpoint manifest; no arbitrary URL, method or action parameter.
- Typed Gateway Firewall, group/service reference, membership and realization tools.
- stdio and authenticated, stateless remote Streamable HTTP.
- NSX-validated Basic caller authentication, canonical identity grants, per-caller
  budgets, and separate shared/per-user execution modes.
- Routing/BGP/NAT/segment tools, fabric/Edge/tunnel observations and explicit fleet health.
- Non-root Podman image, compose example, TLS liveness and hermetic container smoke tests.

No Federation or Projects/VPCs. Operational NSX compatibility remains stub-backed,
with published 4.2 contracts checked and appliance validation pending.

See **[RUNBOOK.md](RUNBOOK.md)** for the full routing/fabric tool catalog,
investigation sequence, deployment, failure interpretation and compatibility evidence.

Start with **[examples/USAGE.md](examples/USAGE.md)** for copyable stdio/remote
client commands, MCP-host configuration, credentials files and bounded pagination.
See **[TEST_COVERAGE.md](TEST_COVERAGE.md)** for tested corner cases and the limits
of output validation.

## Local usage

From this directory:

```sh
uv sync --locked
uv run nsxt-mcp --config examples/shared.json
```

Set `NSXT_SERVICE_USER` and `NSXT_SERVICE_PASSWORD` in the process environment,
or reference a mounted password file using `password_file` instead of
`password_env`. Credentials must have read permission in NSX. A local username
or LDAP username (for example `reader@example.test`) is sent unchanged using
Basic authentication over verified HTTPS. NSX performs credential validation.

For per-user stdio, use `examples/per-user.json`, setting `NSXT_USER` and
`NSXT_PASSWORD`. Each user launches an isolated process. Both examples contain
synthetic manager addresses and must be adapted.

The process owner can access every locally configured target. Remote identity is
constructed only after NSX authentication and local authorization. Caller context
and credentials are never tool arguments.

## Gateway Firewall tools

All NSX-facing tools require an explicit `target`. Domain defaults to `default`.

| Tool | Inputs beyond target | Result |
|---|---|---|
| `nsx_list_targets` | None | Locally configured, authorized aliases |
| `nsx_get_version` | None | NSX product version |
| `nsx_list_gateway_firewall_policies` | Domain, optional cursor/page size | Domain policies, categories, sequence and scope |
| `nsx_get_gateway_firewall_policy` | Policy ID, domain | Full policy including unknown/version-specific fields |
| `nsx_list_gateway_firewall_rules` | Policy ID, domain, optional cursor/page size | Rules requested in sequence order; flags, scope and references retained |
| `nsx_get_gateway_firewall_rule_statistics` | Policy/rule IDs, domain, enforcement-point path | Scoped counters, without resetting them |
| `nsx_get_group` | Group ID, domain | Expressions and tags |
| `nsx_get_group_members` | Group ID, member type, domain, optional enforcement-point path/cursor/page size | IP strings or VM objects |
| `nsx_get_service` | Service ID | Protocol/port and other service entries |
| `nsx_resolve_firewall_reference` | Local group/service policy path | Explicit one-reference resolution |
| `nsx_get_realization_status` | Local intent policy path | Consolidated and enforcement-point status, retaining errors |

Policy lists are domain-wide. Inspect policy and rule scope to determine gateway
applicability. Categories affect precedence, and equal sequence numbers have
nondeterministic order in NSX. Partial results are not an effective ruleset.
Missing flags remain null rather than being guessed. Raw service entries,
exclusions, tags and additional NSX fields are preserved.

Reference resolution accepts `/infra/domains/{id}/groups/{id}` and
`/infra/services/{id}`. Literal ANY/IP addresses are retained on rules and are not
fetched as objects. Gateway-local legacy references are reported as unsupported;
server-supplied links and external URLs are never followed.

Membership covers the requested member type only; an empty IP list does not
prove the group has no members of other types. List calls report page progress.
Statistics preserve a returned cursor and mark the observation incomplete;
Broadcom documents no cursor request parameter for that endpoint, so the server
does not invent one. Configuration, realization and counters are distinct evidence,
not a traffic simulation or proof that a flow is allowed.

## Remote usage

Run separate processes/configurations for shared and per-user execution:

```sh
uv run nsxt-mcp --config examples/remote-shared.json --transport http \
  --host 127.0.0.1 --port 8000 \
  --ssl-certfile /path/to/server.crt --ssl-keyfile /path/to/server.key
```

Use `examples/remote-per-user.json` for user execution. The client connects to
`https://<host>:8000/mcp` and sends `Authorization: Basic <base64(username:password)>`
on **every request**, including initialization/discovery. Usernames/passwords are
UTF-8. The challenge advertises UTF-8. Basic is an explicit compatibility mode,
not an OAuth flow; tested clients use custom headers. Desktop clients must support
custom authorization headers to connect directly.

### Identity and grants

1. Validate the supplied credentials with **GET `/api/v1/aaa/user-info`** on the
   configured authentication target. Parse bounded JSON and require `user_name`.
   The node/version endpoint is not an authentication probe.
2. Use NSX's returned canonical username and configured realm for identity.
3. In **shared mode**, require an exact canonical-username grant, then execute with
   the selected target's service account. An authenticated unmapped user gets 403.
4. In **per-user mode**, forward that request's user credentials to the selected
   configured target; NSX independently enforces permissions there. If grants are
   absent, all `remote.targets` are selectable. If any grants are configured,
   unmapped users are denied and grants restrict targets/tool groups.

Grant keys must match NSX's returned `user_name`, including its domain/case format.
There is no guessed normalization or inferred LDAP group membership. Multiple
identity realms use separate deployments/authentication targets. The authentication
target need not be included in the remote operational target set.

Tool groups are `metadata`, `gateway_firewall`, `routing` and `fabric`.
Existing grant defaults remain metadata/Gateway Firewall only; opt into routing/fabric
explicitly in shared-user grants. Discovery returns the common tool
catalog; tool-group authorization is enforced before invocation. Grants restrict
objects at target/tool-group granularity, not individual policies inside a target.

### Transport and limits

- **Stateless JSON Streamable HTTP**: no stored MCP sessions, credentials, resumable
  event streams or background tools. A supplied `Mcp-Session-Id` is rejected after
  authentication. GET/SSE and DELETE are not supported. Use POST at `/mcp`.
- Each invocation resolves a request-local caller, rather than capturing the first
  client's credentials. The Authorization header is removed from the ASGI scope
  passed to FastMCP; it is not forwarded to unrelated framework dependencies.
- HTTPS is required by default. Direct TLS is supported by the CLI. For TLS offload,
  bind behind the proxy and specify its actual addresses using
  `--forwarded-allow-ips`; forwarded headers are ignored otherwise. There is no
  automatic trust of `X-Forwarded-Proto`. Clear HTTP is configurable for isolated
  loopback tests using `remote.require_https=false`.
- Browser origins are denied unless explicitly listed in `remote.allowed_origins`.
- Per-caller active-request limits and token buckets cover authentication and tool
  execution. The bounded caller table prunes idle entries; login aliases also consume
  the canonical identity's budget so case/domain aliases do not evade that budget.
  Aliases may occupy an additional bounded counter entry. Limits are per process.
- Authentication and whole-request deadlines, request-body limits, and existing
  NSX global/target limits remain in force. Responses use `Cache-Control: no-store`.
- Wrong credentials return 401, admission denial 403, caller budget exhaustion 429,
  and NSX authentication outages/invalid identity payloads 503. NSX operation
  failures are structured MCP tool errors, never successful empty results.
- Audit log records contain caller identity, target, tool, execution mode,
  service-account profile alias, duration and outcome; no credentials/raw arguments.
- `GET /healthz` is public liveness (TLS policy still applies), never an NSX readiness check.

For embedded use, `create_server(registry, caller)` remains appropriate for trusted
stdio/in-process callers. Use `create_remote_app(registry)` for remote clients.

## Credential isolation and connection behavior

Shared execution pools connections per target, with Basic auth supplied on each
request and cookies suppressed. Per-user execution uses operation-scoped clients,
closed after use. There is no cross-user result cache. Version metadata is stored
per target, but discovery always performs an authorized read; it cannot bypass
access checks. Caller-authentication probes always use a fresh client and caller
credentials, never service credentials, and read the current-user identity via
`/api/v1/aaa/user-info`; 403 is an authorization failure, not a session retry.

401/403/404 and contract errors do not trip shared target breakers. Transport,
deadline and exhausted transient failures do. Breakers use a cooldown and bounded
concurrency during recovery. No half-open singleton probe is claimed.

Pagination returns continuation at page boundaries. Repeated cursors and malformed
results fail explicitly. A page that exceeds the item/aggregate byte budget raises
`LimitExceeded` instead of dropping records; retry with a smaller page size.
Exhausting the page count returns `complete=false` and `next_cursor`.

Ambient proxy environment variables are intentionally ignored so configured NSX
credentials go directly to configured origins. Redirects are not followed.

## Endpoint contract / compatibility manifest

All entries are GET-only. Parameters and query keys are closed allowlists.
Routing/fabric additions and their response/scope contracts are described in RUNBOOK.md;
the authoritative closed manifest is `src/nsxt_mcp/endpoints.py`.

| Key | Path | Parameters | Response adapter |
|---|---|---|---|
| `node_version` | `/api/v1/node/version` | None | JSON object; `product_version` for discovery |
| `current_user` | `/api/v1/aaa/user-info` | None | Canonical `user_name` for remote admission |
| `cluster_status` | `/api/v1/cluster/status` | None | JSON object |
| `tier0s` | `/policy/api/v1/infra/tier-0s` | Cursor/page size | `results` + opaque `cursor` |
| `tier1s` | `/policy/api/v1/infra/tier-1s` | Cursor/page size | `results` + opaque `cursor` |
| `transport_nodes` | `/api/v1/transport-nodes` | Cursor/page size | `results` + opaque `cursor` |
| `edge_clusters` | `/api/v1/edge-clusters` | Cursor/page size | `results` + opaque `cursor` |
| `gateway_policies` | `/policy/api/v1/infra/domains/{domain_id}/gateway-policies` | Domain ID + cursor/page size | `results` + opaque `cursor` |
| `gateway_policy` | `…/gateway-policies/{policy_id}` | Domain/policy IDs | Typed policy |
| `gateway_rules` | `…/gateway-policies/{policy_id}/rules` | Domain/policy IDs, paging/order | Typed rules |
| `gateway_rule_statistics` | `…/gateway-policies/{policy_id}/rules/{rule_id}/statistics` | IDs, enforcement-point path | Scoped raw counters |
| `group` | `/policy/api/v1/infra/domains/{domain_id}/groups/{group_id}` | Domain/group IDs | Policy object, expressions retained |
| `group_ip_members` / `group_vm_members` | `…/groups/{group_id}/members/ip-addresses` or `virtual-machines` | IDs, paging, enforcement scope | String or object list |
| `service` | `/policy/api/v1/infra/services/{service_id}` | Service ID | Policy object, entries retained |
| `realization_status` | `/policy/api/v1/infra/realized-state/status` | Intent path, detailed enforcement status | Raw status/error evidence |

Gateway policies are domain-scoped; gateway tools must inspect policy
scope rather than invent gateway-nested policy endpoints.

Source: [Broadcom NSX 4.2 all methods](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/api_all_methods.html),
including `ReadNodeVersion`, `ReadClusterStatus`, `ListTier0s`, `ListTier1`,
`ListTransportNodesWithDeploymentInfo`, `ListEdgeClusters`, and
`ListGatewayPoliciesForDomain`. Basic auth, pagination and rate limits are in the
[4.2 overview](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/).

Phase 3–4 contracts: [rules](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_ListGatewayRules.html),
[rule schema](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/schemas_Rule.html),
[statistics](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetGatewayRuleStatistics.html),
[IP membership](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetGroupIPMembers.html),
[realization](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_ReadIntentStatus.html),
[current user](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_GetCurrentUserInfo.html).

Required access is endpoint-specific read permission, to be verified with the
actual service/user role. Cost is one GET per page, up to the configured page and
retry limits. No speculative fallback on 404 is performed.

| Release family | Contract coverage | Appliance coverage |
|---|---|---|
| 4.0.x | Synthetic version response; common endpoints provisional | Pending |
| 4.1.x | Synthetic version response; common endpoints provisional | Pending |
| 4.2.x | Version response synthetic; paths checked against published 4.2 catalog | Pending |

Fixtures do not establish full NSX 4.x support. Domain tools need appliance-derived
release-specific fixtures to establish verified coverage. Other majors are rejected by
version discovery. Appliance OpenAPI exports can refine the contracts later.

## Validation

Local uv validation on 2026-10-23: **167 tests passed**, Ruff lint/format checks,
mypy and Python compilation passed. This includes real stdio subprocess and
loopback HTTP MCP clients with synthetic NSX responses.

Podman validation also passed: Python 3.11 production image
`localhost/nsxt-mcp:0.1.0`, both remote credential modes over real TLS, packaged
stdio against an HTTPS NSX stub, partial fleet failures, UID 1001/read-only remote
execution, health checks, audit secret exclusion and compose structure. The
documented Python client also passed real TLS checks with environment-backed and
password-file caller credentials. All smoke
containers, the private network and ephemeral TLS fixture keys were cleaned up.

```sh
bash scripts/validate.sh
bash scripts/validate.sh --container
```

The script uses uv for lint, type checks, Python compilation, unit tests and real
MCP transport spikes. External NSX is replaced with deterministic MockTransport
stubs, including a 55-target concurrency scenario and failure paths. Phase 3 tests
exercise Gateway Firewall paths, scope, flags, ordering, membership and references.
Phase 4 tests use the actual authentication boundary, NSX identity stub, and
concurrent real HTTP MCP clients in both credential modes. They verify grants,
caller budgets, identity aliases, cancellation, authentication outages, TLS scheme
checks and session-ID rejection. Desktop-client interoperability and real NSX
appliance coverage remain environment-specific validation work.
