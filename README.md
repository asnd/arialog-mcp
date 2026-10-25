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

Query parameters shared by the log tools:

| Parameter | VRLI mapping | Semantics |
|---|---|---|
| `last_minutes` / `start`+`end` | `timestamp LAST` / `>=` + `<` | always sent (VRLI otherwise covers 1 minute) |
| `text_all` | one `text HAS ...` | every word must occur, any order |
| `text_any` | repeated `text CONTAINS ...` | any of the phrases (VRLI ORs same field+operator) |
| `filters` | `field <op> value` | ANDed; filters sharing field **and** op are ORed (a note says so) |

Filter operators: `CONTAINS`, `NOT_CONTAINS`, `HAS`, `NOT_HAS`, `=`, `!=` (documented for numeric
fields; a note suggests `CONTAINS` for text), `=~`, `!=~` (regex; disabled on the appliance unless
`api-server.regex-query-enabled` is set, KB 2123058) and `EXISTS`.

## Configure & run
```bash
cp .env.example .env            # placeholders; use a read-only AD service account
uv sync && uv run arialog-mcp                       # stdio
ARIALOG_TRANSPORT=http uv run arialog-mcp           # streamable HTTP on :8000/mcp, GET /healthz
```
See `.env.example` and `src/arialog_mcp/config.py` for all settings (`ARIALOG_*`).

## Notes
* VRLI is contacted directly; `trust_env=false` by default so any `HTTP(S)_PROXY` in the environment is ignored.
  Set `ARIALOG_TRUST_ENV=true` if the appliance must be reached through a proxy.
* A rejected login is not retried for `login_cooldown_s` (protects AD accounts from lockout).
* An expired session (HTTP 401 or 440 "Login Timeout") triggers exactly one re-login.
* Query HTTP read timeout = `query_timeout_ms` + `query_timeout_margin_s`, so VRLI's partial
  answer (`complete=false`) arrives first. A read timeout beyond that is not retried (it would
  re-send the same heavy query); 429/5xx and connection errors are retried with backoff.
* `log_aggregate` requests `max_bins + 2` bins (VRLI defaults to 100), sorts them, zero-fills
  missing bins and marks bins crossing the window edge as `partial` (excluded from z-scores).
* Event fields found inside the message text (e.g. `hostname`, `appname`) arrive as
  `startPosition`/`length` and are resolved against the text (UTF-16 offsets, as in Java).
* The HTTP transport has no authentication yet: keep it on a private network (phase 5 hardening).
* Payload shapes follow the public Log Insight query API docs (vmw-loginsight.github.io); the 8.18
  v2 events/aggregated-events API is Tech Preview and documented only on the appliance
  (`https://<vrli>/rest-api/supported`). **Not yet verified against a real 8.18 appliance**; open
  points: `=` on text fields, `%2F` in path values, bin order/sparseness (handled defensively).

## Develop
Hermetic container run (ruff + mypy + pytest, `--network none`): `scripts/test-podman.sh`; full stack with stub: `scripts/e2e.sh`.

```bash
uv run ruff check . && uv run mypy && NO_PROXY=127.0.0.1,localhost uv run pytest
```

## Status
Alpha. Not verified against a real 8.18 appliance, and the HTTP transport is unauthenticated: do not expose it beyond a trusted network.
