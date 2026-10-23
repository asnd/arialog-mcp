# Corner cases and validation coverage

The tests below execute against synthetic NSX responses. Real MCP clients are used
for in-process, stdio and loopback HTTP checks; Podman smoke tests additionally
exercise the packaged server against a real HTTPS stub with certificate verification.

## Pagination

| Case | Expected behavior | Tests |
|---|---|---|
| Several pages | Preserve records and follow opaque cursor | `test_gateway.py`, `test_operations.py` |
| Short page / empty page with cursor | Continue; page length does not imply completion | `test_boundaries.py` |
| Empty final page | Successful complete empty collection | `test_boundaries.py` |
| Cursor contains `+`, `/`, `=`, `%`, spaces or `?` | Send as one query value, without changing its decoded value | `test_boundaries.py` |
| Immediate repeated cursor or multi-page cycle | Fail explicitly; no infinite traversal | `test_foundation.py`, `test_boundaries.py` |
| Empty, numeric, boolean, object/list or oversized cursor | Reject before the first read, or immediately on a malformed response | `test_boundaries.py` |
| Maximum page count | Return `complete=false` and a page-boundary continuation cursor | `test_foundation.py`, `test_gateway.py` |
| Exact item limit | Stop at the page boundary and retain next cursor | `test_boundaries.py` |
| Page exceeds item limit | Raise `LimitExceeded`; never silently drop part of a page | `test_foundation.py` |
| Individual response byte limit | Reject oversized response | `test_foundation.py` |
| Aggregate bytes across small pages | Apply the traversal byte budget across pages | `test_boundaries.py` |
| Transient failure on a later page | Retry the same cursor; no duplicated or skipped records | `test_boundaries.py` |
| Later page fails permanently | Return a tool error, not a successful partial list | `test_boundaries.py` |
| Traversal deadline / cancellation | Stop work and release request limits | `test_failure_isolation.py`, `test_foundation.py` |
| Native `tunnels` collection | Validate/read that field rather than assuming `results` | `test_operations.py` |
| Statistics/interface API has no cursor request contract | Preserve observation and mark incomplete if needed; do not invent paging arguments | `test_gateway.py`, `test_operations.py` |

The server's cycle set is scoped to a single traversal. Clients continuing across
multiple tool calls should also impose a call limit and detect non-advancing cursors;
the documented Python example does both (`test_examples.py`). Pagination is not
a transactional snapshot: concurrent NSX changes can still move or repeat resources
across pages. The server does not deduplicate them or invent snapshot consistency.

## Output validation

### Validated now

- Invalid JSON syntax, non-object top-level payloads and malformed list containers.
- NaN, Infinity and floating-point overflow, including nested values, are rejected
  before serialization can silently replace them with null.
- Gateway policy/rule models use strict types: string booleans, integer booleans,
  invalid scopes/services, absent IDs and negative sequence numbers are rejected.
- Optional missing flags remain null. Unknown fields are retained for version
  tolerance, including group expressions and service entries.
- Realization reads check the returned intent path and require status information.
- Statistics require a list of objects. IP membership uses a string list, while
  VM membership uses an object list.
- Representative structured MCP responses are validated against the tools'
  advertised JSON Schema using `jsonschema`, in addition to FastMCP's typed outputs.
- Invalid upstream rule fields become MCP tool errors without a misleading
  successful structured result.
- Scope, pagination, unknown/native fields and BGP secret redaction are exercised.

See `test_boundaries.py`, `test_gateway.py`, `test_mcp.py` and `test_operations.py`.

### Boundaries of validation

The server does **not** implement the complete Broadcom schema for every returned
NSX object. Routing/fabric payloads preserve native dictionaries and validate
object/list structure, input scope, budgets and the typed response envelope;
every nested route field, counter enum and release-specific optional property is
not exhaustively checked. A valid MCP output schema is not proof of semantic
correctness or complete appliance compatibility. Those require version-specific
appliance fixtures and integration testing.

Byte limits currently cover NSX response bodies and aggregate list traversal,
plus a serialized fleet result limit. They are not a universal byte limit on the
entire MCP wire frame, which also includes envelopes and compatibility text content.

## Credentials, failures and fleet operations

- Local and LDAP-style usernames, shared/per-user credential isolation and no fallback.
- Password file newline handling, preservation of spaces/Unicode/colons, and
  sanitized missing/empty/invalid-encoding file errors.
- Bad or duplicate Basic headers; NSX caller identity validation; canonical-name grants.
- Target/tool-group denial before operational reads and no cross-user cached access.
- Authentication outages, response size limits, malformed identity JSON, timeouts
  and per-caller rate/concurrency budgets.
- 401/403/404 versus transient retries; target circuit-breaker recovery and isolation.
- TLS scheme/origin checks, session-ID rejection and concurrent real HTTP MCP clients.
- Fifty-five target scenarios, global/target/fleet concurrency, partial fleet failures,
  preauthorization of every selected target and worker cleanup on deadline.
- Real TLS container execution, failed authentication, packaged stdio, UID 1001,
  read-only remote filesystems, liveness and audit-secret exclusion.

See `test_failure_isolation.py`, `test_remote.py`, `test_foundation.py`,
`test_operations.py` and `tests/container/`.

## Reproduce

```sh
bash scripts/validate.sh
bash scripts/validate.sh --container
```

The first command includes example-client type/syntax checks and example tests.
The second also rebuilds the image and runs both remote credential modes over TLS,
including the documented Python client with environment and password-file credentials.
No real LDAP or NSX installation is needed. Appliance load/performance behavior,
all 4.x patch versions, and every third-party desktop client remain unverified.

Latest local result (2026-10-23): **167 tests passed**, including the additional
boundary and example-client tests. Lint, formatting, mypy and compilation passed.
The rebuilt Podman image and all container smoke scenarios passed, including
the documented remote client using both credential-file approaches over real TLS.
