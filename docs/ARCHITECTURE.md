# arialog-mcp-analysis — Architecture & Plan

Status: design notes (planning document; only the arialog-mcp server is implemented in this repo).

## 1. Goal
Analyse VMware Aria Operations for Logs (VRLI 8.18.x) logs on a remote appliance, driven by
user input (text or file) now, and by alarms (polling/webhook) later. Output a structured
root-cause report to a file and an MS Teams webhook.

## 2. Decisions (agreed)
| Topic | Decision |
|---|---|
| VRLI MCP | Build own `arialog-mcp` (read-only). Community servers (apollion69/vmware-aria-logs, zw008/VMware-Log-Insight) are reference only |
| Agent | Standalone Podman microservice `log-analyst`, modelled on `ai-enrichment-gw` (copy & adapt, no cross-repo coupling) |
| LLM | LiteLLM gateway, default model `gpt-oss-120b`, other models selectable via config |
| Agent style | Hybrid: deterministic YAML playbook first, then LLM may request <= 3 extra MCP tool calls |
| VRLI | 8.18.x, direct HTTPS :9543, `/api/v2`, AD auth (provider `ActiveDirectory`) |
| Intake (v1) | Free text or file; pluggable adapters for later alarm polling / webhook |
| Output (v1) | JSON/Markdown file (+ JSONL) and MS Teams incoming webhook |
| Fixtures | Deferred; start with synthetic stub data |

## 3. Components
```
 text/file ─▶ ┌────────────────────────── log-analyst (:8080) ─────────────────────────┐
 (later:      │ Intake → Incident → Playbook → Gather(MCP) → Reduce+Redact → LLM → Report │─▶ file, Teams
  poll/hook)  └───────────┬───────────────────────────────────────────────┬────────────┘
                          │ MCP streamable HTTP                           │ OpenAI-compatible
                          ▼                                               ▼
                 arialog-mcp (read-only)                          LiteLLM (gpt-oss-120b)
                          │ HTTPS :9543 /api/v2
                          ▼
                    VRLI 8.18.x            (optional later: ariaops-mcp for alert/metric context)
```

### 3.1 arialog-mcp (new, read-only)
Style per `ariaops-mcp` (async httpx client, pydantic-settings, typed tool schemas, circuit
breaker, domain exceptions, stdio + streamable HTTP). API client logic adapted from
`vmware-ai-ops-agent/collectors/vrli.py` (note: that one uses `/api/v1`; this uses `/api/v2`).

Tools:
- `log_aggregate` — `aggregated-events`, counts per time bin, optional group-by field, spike flag
- `log_signatures` — top message signatures (mask numbers/IDs/UUIDs/IPs, hash, count, first/last seen, 1-2 samples)
- `log_search` — `events`, hard caps on rows and bytes, returns `complete` flag
- `log_fields` — available fields for filtering
- `alert_list` / `alert_get` — alert definitions/history if exposed by 8.18 API
- `version`

Rules: every response carries the exact query + time window; timestamp constraint is always
set (VRLI defaults to last 1 minute); operator/value space encoded `%20`; session re-login on
401; retry/backoff on 503 (appliance startup); concurrency limit to protect the appliance;
all tools read-only (no write tools exist).

### 3.2 log-analyst (new microservice)
Modules adapted from `ai-enrichment-gw`: config (single YAML + `${ENV}`), http, llm client
(+cache, token metrics), sinks, obs, middleware (API key). New: `intake/`, `playbooks/`,
`gather` (MCP client), `reduce`, `analyse`, `report`, `teams` sink.

Flow:
1. **Intake** → `Incident{id, source, raw_text, entity?, window, keywords, severity?}`.
   Free text: the LLM extracts entity/time/keywords into a pydantic schema; if time is missing, use a configured default window (assumption flagged in the report) rather than guessing silently.
2. **Playbook select** — keyword/category rules in YAML (storage/APD, network, HA/vMotion, auth, generic).
3. **Gather** — run playbook steps via MCP: aggregate → signatures → samples → neighbours.
4. **Reduce + redact** — enforce token budget; mask IPs/usernames/secrets *before* prompt (defence in depth even if model is on-prem).
5. **Analyse** — LLM call with evidence; may request <= 3 extra tool calls from an allow-list (read-only MCP tools). If the model does not support/ignores tool calls, degrade to playbook-only.
6. **Report** — pydantic `RcaReport{summary, hypotheses[{text, confidence, evidence_refs}], affected_entities, queries_run, next_steps, assumptions, limitations}`; one repair retry on invalid JSON, then emit a degraded report with raw evidence.
7. **Sinks** — file (+JSONL) and Teams webhook (Adaptive Card / MessageCard, retries, size-trimmed, link to full file).

API: `POST /v1/analyse` (text or file upload), `GET /v1/reports/{id}`, `/healthz`, `/metrics`; CLI `la analyse --text/--file`, `la validate`.

## 4. Repo layout
```
arialog-mcp-analysis/
  ARCHITECTURE.md
  arialog-mcp/    src/arialog_mcp/{client,reduce,server,config}.py tools/ tests/ Containerfile
  log-analyst/    src/log_analyst/{intake,playbooks,gather,reduce,analyse,report,sinks,api,cli,config}.py tests/ Containerfile
  deploy/         compose.yaml  (arialog-mcp, log-analyst, vrli-stub, llm-stub)
  tests/stubs/    vrli_stub/ (FastAPI replaying JSON), llm_stub/ (OpenAI-compatible), fixtures/
```

## 5. Security
- Read-only AD service account for VRLI; secrets via env/`chmod 600` config, never logged.
- TLS verification on by default (configurable CA bundle).
- `log-analyst` API protected by API key; MCP server not exposed outside the compose network.
- Teams webhook URL is a secret. Reports may contain log excerpts: redaction applies to reports too.
- Audit log: every MCP call + LLM call (model, tokens, latency), no raw secrets.

## 6. Testing (Podman compose, hermetic)
Unit tests (respx) + compose e2e with `vrli-stub` and `llm-stub`. Failure paths: 503 on
startup, expired session (401), timeout/partial result (`complete=false`), empty results,
huge result (cap), malformed LLM JSON, LLM ignoring tool calls, gateway 429/5xx, Teams
webhook failure (report still written). Gates: `ruff check`, `mypy`, `pytest`, `py_compile`.

## 7. Phases
1. **arialog-mcp + vrli-stub** — ✅ DONE 2026-10-07: client, auth, 4 core tools (`version`, `log_aggregate`, `log_signatures`, `log_search`), 44 unit tests (90% coverage), Podman e2e (`scripts/e2e.sh`).
2. **log-analyst v1**: text/file intake, playbooks, gather, reduce/redact, single LLM call, file + Teams sinks, compose e2e.
3. **Hybrid tool loop**: allow-listed extra MCP calls, budget limits, fallback.
4. **Alarm intake**: VRLI alert polling and/or webhook endpoint; dedupe/debounce; optional ariaops-mcp enrichment.
5. **Hardening**: real-data fixtures (anonymised), tuning playbooks, evaluation set.

## 8. Resolved / open
Resolved (2026-10-07):
1. Models are hosted on-prem (vLLM provider behind a LiteLLM gateway); pin `gpt-oss-120b`, allow other on-prem models via config.
2. Tool calls and JSON output are supported on the gateway route.
3. Teams: Workflows webhook (Adaptive Card payload).
4. AD service account: placeholder credentials in config/compose for now.
5. Default time window for free-text incidents: configurable (`intake.default_window_minutes`, default 60).
6. Single VRLI instance for now (config still uses a named target).

7. MCP framework: **FastMCP, exact version pinned**, for both `arialog-mcp` (server) and `log-analyst` (client). `client.py`/`reduce.py` stay free of MCP imports so the framework can be swapped. A small spike (hello-tool, stdio + HTTP, in-memory test, under Podman) runs before phase 1 to confirm the pinned versions.

Open:
- Verify 8.18 API surface (`aggregated-events`, alert endpoints, any grouping endpoint) against a real appliance; signature grouping stays client-side until confirmed.
- Phase 1 limits: `log_fields`, `alert_list/get` and group-by aggregation are not built yet (need real-appliance response shapes). HTTP transport: `ARIALOG_HTTP_AUTH_MODE` = `token` (shared bearer) or `ldap` (HTTP Basic + LDAPS bind, ariaops-mcp-compatible group map, per-user VRLI passthrough); one of them is mandatory on non-loopback binds. OAuth remains open. Run `scripts/e2e.sh` for the hermetic Podman test; unit tests: `NO_PROXY=127.0.0.1,localhost uv run pytest`.
