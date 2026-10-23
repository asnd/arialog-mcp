# arialog-mcp

Read-only [MCP](https://modelcontextprotocol.io) server for **VMware Aria Operations for Logs
(vRealize Log Insight) 8.18.x**, built with FastMCP (pinned). It reduces logs *on the server*
(counts, spike detection, message signatures, hard caps) so an LLM never receives thousands of raw lines.

| Tool | Purpose |
|---|---|
| `log_aggregate` | event counts per time bin + z-score spike detection — use first |
| `log_signatures` | group events into masked message templates, ranked by count |
| `log_search` | a few raw events (count/byte capped), newest first |
| `version` | appliance version / reachability probe |

Every result carries the exact constraints sent, `complete` (VRLI query timeout?) and `notes`
(e.g. "counts are lower bounds").

## Configure & run
```bash
cp .env.example .env            # placeholders; use a read-only AD service account
uv sync && uv run arialog-mcp                       # stdio
ARIALOG_TRANSPORT=http uv run arialog-mcp           # streamable HTTP on 127.0.0.1:8000/mcp
```
See `.env.example` and `src/arialog_mcp/config.py` for all settings (`ARIALOG_*`). Invalid
configuration exits with code 2 and names the offending setting (never its value).

### HTTP transport
`ARIALOG_HTTP_AUTH_MODE` selects how `/mcp` is protected:

| Mode | Client sends | VRLI is queried as |
|---|---|---|
| `token` | `Authorization: Bearer <ARIALOG_HTTP_AUTH_TOKEN>` (min. 16 chars, constant-time compare; `openssl rand -hex 32`) | the service account |
| `ldap` | `Authorization: Basic <user:password>`, verified by an LDAPS bind | **the caller** (per-user passthrough) |
| `none` | nothing | the service account |

Setting only `ARIALOG_HTTP_AUTH_TOKEN` keeps enabling `token` mode (pre-LDAP behaviour).
Binding a non-loopback address (e.g. `0.0.0.0`, as the container image does) **refuses to start
in `none` mode**, unless `ARIALOG_HTTP_ALLOW_UNAUTHENTICATED=true` is set because an
authenticating reverse proxy sits in front. Running unauthenticated logs a warning.

### LDAP mode (compatible with ariaops-mcp)
Same semantics and value formats as ariaops-mcp's `ARIAOPS_HTTP_AUTH_MODE=ldap`, with the
`ARIALOG_` prefix, so one group map and directory config can serve both servers:

```bash
ARIALOG_TRANSPORT=http
ARIALOG_HTTP_AUTH_MODE=ldap
ARIALOG_LDAP_SERVER_URI=ldaps://dc01.corp.example:636
ARIALOG_LDAP_USER_DN_TEMPLATE={username}@corp.example      # or uid={username},ou=people,...
ARIALOG_LDAP_USER_SEARCH_BASE=dc=corp,dc=example
ARIALOG_LDAP_GROUP_ROLE_MAP='{"vrops-ops": {"role": "ops"}, "vrops-se": {"role": "country", "country": "SE"}}'
# ARIALOG_LDAP_CA_CERT_FILE=/etc/ssl/certs/internal-ca.pem
# ARIALOG_LDAP_VRLI_USERNAME_TEMPLATE={username}           # e.g. {username}@corp.example
```

* **Authentication:** the server binds to LDAPS *as the caller* (no LDAP service account) and
  reads `memberOf` (direct membership only, like ariaops-mcp). `ldaps://` is mandatory
  while `ARIALOG_LDAP_VERIFY_TLS=true` (default).
* **Authorisation:** any group in `ARIALOG_LDAP_GROUP_ROLE_MAP` grants access (there is one VRLI,
  so ariaops-mcp's country→instance scoping does not apply); the mapped role is written to the
  audit log. Matching rules are ariaops-mcp's: a bare CN matches in any OU, a full DN only that
  DN, `ops` wins over `country`. A user in no mapped group gets 401. Without a map,
  `ARIALOG_DEFAULT_ROLE` must be set explicitly and is granted to everyone who can bind.
* **VRLI passthrough:** each tool call logs in to VRLI with the caller's own credentials
  (provider `ARIALOG_PROVIDER`, default `ActiveDirectory`), so VRLI enforces that user's own
  permissions. Sessions are kept per user (`ARIALOG_MAX_USER_SESSIONS`, LRU) and never fall back
  to the service account, which is not needed (and not used) in this mode. A VRLI rejection
  blocks only that user for `login_cooldown_s`.
* **Lockout protection:** after `ARIALOG_LDAP_MAX_FAILED_BINDS` (5) wrong passwords for a
  username, further binds for it are refused for `ARIALOG_LDAP_FAILED_BIND_COOLDOWN_S` (300s)
  without contacting the directory; a user's cached valid login keeps working meanwhile.
* **Cache:** a successful bind is cached for `ARIALOG_LDAP_CACHE_TTL` (300s) under an HMAC of
  the credentials with a per-process key; failures are never cached. As in ariaops-mcp, an old
  password keeps working from cache for up to the TTL after a change.
* Passwords never appear in logs, errors, or serialised tokens; the audit line names the user.
* 401 responses carry `WWW-Authenticate: Basic realm="arialog-mcp"`; bearer tokens are refused.
* Probes are unauthenticated and never call VRLI:
  `GET /healthz` = liveness (process up), `GET /readyz` = readiness (503 while the circuit
  breaker is open, i.e. VRLI is failing).

```bash
podman run -d -p 8000:8000 --env-file .env -e ARIALOG_HTTP_AUTH_TOKEN="$(openssl rand -hex 32)" \
  localhost/arialog-mcp:0.1.0
```

## Resilience & safety
* Read-only by construction: the only non-GET call is the session login.
* Retries on 429/5xx/network errors with capped exponential backoff + jitter; `Retry-After` is
  honoured (up to `backoff_max_s`). A circuit breaker stops calling a failing appliance.
* `request_timeout_s` must exceed `query_timeout_ms`, so slow VRLI queries are not cut off and
  retried client-side.
* Tool errors: domain errors (bad window, VRLI unavailable, auth) reach the LLM as clear messages;
  any other exception is masked to a generic error and logged with its traceback.
* One structured JSON audit line per tool call on stderr (tool, arguments, duration, and in
  LDAP mode the user and mapped role; no secrets).

## Notes
* VRLI is contacted directly; `trust_env=false` by default so any `HTTP(S)_PROXY` in the environment is ignored.
  Set `ARIALOG_TRUST_ENV=true` if the appliance must be reached through a proxy.
* A rejected login is not retried for `login_cooldown_s` (protects AD accounts from lockout).
* Payload shapes follow the public API docs and are **not yet verified against a real 8.18 appliance**.

## Develop
Hermetic container run (ruff + mypy + pytest, `--network none`): `scripts/test-podman.sh`; full stack with the VRLI stub and an OpenLDAP container (LDAPS, LDAP-mode passthrough):
`scripts/e2e.sh`.
CI (`.github/workflows/ci.yml`) runs lint, format check, mypy and pytest on Python 3.11–3.13 and builds the image.

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && NO_PROXY=127.0.0.1,localhost uv run pytest
```

## Status
Alpha. Not verified against a real 8.18 appliance. The server does not terminate TLS itself:
put it behind a TLS reverse proxy outside a trusted network, and always so in LDAP mode, where
clients send their directory password with every request.
