# arialog-mcp — Architecture & Status

Status: **The read-only Aria Operations for Logs MCP server is implemented.**
`log-analyst` remains a future project. Published API shapes have not yet been
verified against a production VRLI 8.18 appliance.

## 1. Goal and boundary

`arialog-mcp` exposes bounded, reduced, read-only VRLI data to MCP-compatible
clients. The current server supports stdio and Streamable HTTP transports and
connects to VRLI 8.18.x using its `/api/v2` API. The HTTP service does not terminate
TLS; put it behind a trusted TLS reverse proxy on remote networks.

This repository contains the MCP server, stubs, tests and container files. The
incident-analysis service described below is planning context and is not included
in this repository. A separate NSX MCP server lives in [`../nsxt-mcp/`](../nsxt-mcp/README.md);
it is an independent package and is not part of the Aria service runtime.

## 2. Current architecture

```text
MCP host
  ├── stdio (local)
  └── Streamable HTTP (/mcp; localhost by default)
          │ optional bearer auth or LDAP Basic auth
          ▼
     FastMCP server
          │ async httpx, API client, bounded reduction
          ▼
     VRLI 8.18.x — HTTPS :9543 /api/v2
```

The HTTP auth modes are `none`, `token`, and `ldap`:

| Mode | MCP caller authentication | VRLI execution identity | Constraints |
|---|---|---|---|
| `none` | None | Configured service account | Loopback only; remote mode requires TLS-proxy acknowledgement and explicit unauthenticated access |
| `token` | Shared bearer token | Configured service account | Token is at least 16 characters; compare in constant time; remote TLS proxy required |
| `ldap` | HTTP Basic checked through LDAPS as the caller | The same caller, per-user passthrough | No service-account fallback; verified LDAPS and remote TLS proxy required |

Any non-loopback HTTP bind requires `ARIALOG_HTTP_BEHIND_TLS_PROXY=true`; this
acknowledges the deployment boundary but does not itself configure TLS.

Setting `ARIALOG_HTTP_AUTH_TOKEN` while `ARIALOG_HTTP_AUTH_MODE=none` retains the
pre-LDAP behavior and enables token mode. Health endpoints remain unauthenticated;
they never call VRLI. `/healthz` is liveness and `/readyz` reports readiness based
on the circuit breaker.

## 3. MCP tools and safety

| Tool | VRLI endpoint / behavior |
|---|---|
| `version` | Read version and reachability probe |
| `log_aggregate` | Aggregate events by time bin; supports grouping and spike detection |
| `log_signatures` | Group and mask message signatures before returning samples |
| `log_search` | Bounded event search; returns completion/truncation metadata |

Tools are read-only by construction. VRLI session login is the only non-GET
operation. Event and byte caps, timeout checks, validation, circuit breaking,
retry/backoff and per-user login protection bound the work. Results include query
constraints and notes so incomplete results are not mistaken for exhaustive data.
Upstream response bodies, event fields, and per-caller request rates are bounded;
search/signature outputs redact common credential material before returning it.

## 4. Authentication and identity

### Service-account modes

With `none` or `token`, the server uses the configured VRLI account (`username`,
`password`, `provider`). Use an account with read-only VRLI access. The bearer token
protects the MCP endpoint; it does not alter the VRLI execution identity.

### LDAP caller passthrough

LDAP usernames are restricted to a DN-safe character set, group lookup is tied to
the authenticated DN/UPN rather than a broad attribute search, and bind attempts
have per-user lockout and process-wide rate limits. Directory outages return
service-unavailable responses rather than being presented as bad credentials.

With `ARIALOG_HTTP_AUTH_MODE=ldap`:

1. The MCP client sends HTTP Basic username/password over the TLS-protected
   connection to the reverse proxy.
2. The MCP server binds to the configured LDAPS endpoint as that user and reads
   direct `memberOf` group values.
3. `ARIALOG_LDAP_GROUP_ROLE_MAP` grants access to users in any mapped group. If no
   group map is configured, an explicit `ARIALOG_DEFAULT_ROLE` is required and is
   granted to every user who can bind.
4. Each VRLI operation authenticates using the same user's credentials, with the
   configured VRLI provider and optional username template. VRLI enforces that
   user's own permissions.

The server has bounded successful-bind caching, a failed-bind lockout guard,
bounded per-user VRLI sessions, and rejected-login cooldowns. It does not fall back
to the service account when a per-user VRLI login fails. Group roles are audit
metadata; VRLI remains the authority for data permissions.

Authentication values and formats intentionally match the `ariaops-mcp`
`ARIAOPS_HTTP_AUTH_MODE=ldap` convention, using the `ARIALOG_` prefix.

## 5. Configuration and secrets

All settings use the `ARIALOG_` prefix; see `.env.example` and
`src/arialog_mcp/config.py`. Invalid configuration exits with code 2 and identifies
the setting without printing its value.

For service-account or token mode, a private `.env` file is supported. For LDAP
mode, directory credentials are caller-supplied and a VRLI service account is not
used. Keep CA files, reverse-proxy TLS keys and env files outside version control.
The application itself does not terminate TLS; the TLS proxy is a security
boundary, especially because LDAP clients send their directory password to it on
every request.

## 6. Planned log-analyst integration

The following architecture is a future goal, not implemented in this repository:

```text
text/file (later alarm adapters) → log-analyst → playbooks → arialog-mcp → VRLI
                                                    ↓
                                      reduce/redact → LLM → report/file/Teams
```

The proposal is a standalone Podman service with deterministic YAML playbooks,
bounded read-only MCP gathering, reduction/redaction before the LLM, structured RCA
reports and file/Teams output. A limited allow-listed tool loop and future alarm
intake remain planned. See the workspace architecture document if this repo is used
as part of a larger operations workspace.

## 7. Testing and validation

- Unit tests use synthetic/stubbed VRLI responses and cover failure paths including
  401/login cooldown, 429/5xx, timeouts, empty/partial responses and output caps.
- `scripts/test-podman.sh` runs hermetic checks in a container without network access.
- `scripts/e2e.sh` runs a VRLI stub and the MCP server. It also starts throwaway
  OpenLDAP over LDAPS with a generated CA to check LDAP authentication and per-user
  VRLI passthrough.
- CI runs Ruff, formatting checks, mypy, pytest on Python 3.11–3.13, and builds the
  container image. The independent NSX package has its own Python 3.11–3.13 CI
  job and a 90% measured line-coverage floor.

Run locally:

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
NO_PROXY=127.0.0.1,localhost uv run pytest
scripts/e2e.sh
```

The tests validate the synthetic contract; payloads and permissions still require
verification against a real VRLI 8.18 deployment.
