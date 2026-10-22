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
ARIALOG_TRANSPORT=http uv run arialog-mcp           # streamable HTTP on :8000/mcp, GET /healthz
```
See `.env.example` and `src/arialog_mcp/config.py` for all settings (`ARIALOG_*`).

## Notes
* VRLI is contacted directly; `trust_env=false` by default so any `HTTP(S)_PROXY` in the environment is ignored.
  Set `ARIALOG_TRUST_ENV=true` if the appliance must be reached through a proxy.
* A rejected login is not retried for `login_cooldown_s` (protects AD accounts from lockout).
* The HTTP transport has no authentication yet: keep it on a private network (phase 5 hardening).
* Payload shapes follow the public API docs and are **not yet verified against a real 8.18 appliance**.

## Develop
Hermetic container run (ruff + mypy + pytest, `--network none`): `scripts/test-podman.sh`; full stack with stub: `scripts/e2e.sh`.

```bash
uv run ruff check . && uv run mypy && NO_PROXY=127.0.0.1,localhost uv run pytest
```

## Status
Alpha. Not verified against a real 8.18 appliance, and the HTTP transport is unauthenticated: do not expose it beyond a trusted network.
