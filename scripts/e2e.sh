#!/usr/bin/env bash
# Hermetic Podman end-to-end test: vrli-stub + arialog-mcp (+ a bad-credentials twin).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${TAG:-dev}"
NET="arialog-e2e-$$"
MCP_IMG="localhost/arialog-mcp:${TAG}"
STUB_IMG="localhost/vrli-stub:${TAG}"
PODRUN=(podman run --http-proxy=false --network "$NET")
TOTAL=7
STEP=0

exec 3>&2                                   # real terminal for progress
progress() {                                # [n/total] phase — only on a TTY
  STEP=$((STEP + 1))
  if [ -t 3 ]; then printf '[%d/%d] %s\n' "$STEP" "$TOTAL" "$1" >&3; fi
}

cleanup() {
  set +e
  podman rm -f vrli-stub arialog-mcp arialog-mcp-bad >/dev/null 2>&1
  podman network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

wait_healthy() {                            # name, tries
  local n=0
  until [ "$(podman inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" = "healthy" ]; do
    n=$((n + 1)); [ "$n" -gt "$2" ] && { podman logs "$1" >&2; echo "$1 not healthy" >&2; exit 1; }
    sleep 1
  done
}

progress "build images"
podman build --http-proxy=false --format docker -q -t "$MCP_IMG" "$ROOT" >/dev/null
podman build --http-proxy=false --format docker -q -t "$STUB_IMG" "$ROOT/tests/stubs" >/dev/null

progress "network + vrli-stub"
podman network create "$NET" >/dev/null
"${PODRUN[@]}" -d --name vrli-stub -e STUB_USER=svc-test -e STUB_PASS=placeholder "$STUB_IMG" >/dev/null
wait_healthy vrli-stub 30

COMMON=(-e ARIALOG_HOST=vrli-stub -e ARIALOG_USE_TLS=false -e ARIALOG_USERNAME=svc-test
        -e ARIALOG_RETRIES=3 -e ARIALOG_BACKOFF_BASE_S=0.1 -e ARIALOG_LOGIN_COOLDOWN_S=300)

progress "arialog-mcp (good credentials)"
"${PODRUN[@]}" -d --name arialog-mcp "${COMMON[@]}" -e ARIALOG_PASSWORD=placeholder "$MCP_IMG" >/dev/null
wait_healthy arialog-mcp 40

progress "arialog-mcp (wrong credentials)"
"${PODRUN[@]}" -d --name arialog-mcp-bad "${COMMON[@]}" -e ARIALOG_PASSWORD=wrong "$MCP_IMG" >/dev/null
wait_healthy arialog-mcp-bad 40

progress "functional + failure-path checks"
"${PODRUN[@]}" --rm -v "$ROOT/tests/e2e:/e2e:ro,Z" --entrypoint python "$MCP_IMG" \
  /e2e/e2e_client.py http://arialog-mcp:8000/mcp http://vrli-stub:9543 http://arialog-mcp-bad:8000/mcp

progress "VRLI down: liveness stays green, tools fail cleanly"
podman stop -t 1 vrli-stub >/dev/null
DOWN_OUT="$("${PODRUN[@]}" -i --rm --entrypoint python "$MCP_IMG" - <<'PY'
import asyncio, urllib.request as u
from fastmcp import Client
from fastmcp.exceptions import ToolError
op = u.build_opener(u.ProxyHandler({}))
assert op.open("http://arialog-mcp:8000/healthz", timeout=3).read() == b"ok"
async def go():
    async with Client("http://arialog-mcp:8000/mcp") as c:
        try:
            await c.call_tool("log_search", {"last_minutes": 5})
        except ToolError as e:
            assert "unavailable" in str(e).lower(), e
            print("PASS vrli down -> tool error; /healthz ok")
            return
    raise SystemExit("expected ToolError")
asyncio.run(go())
PY
)"
echo "$DOWN_OUT"
grep -q "PASS vrli down" <<<"$DOWN_OUT" || { echo "vrli-down check did not run" >&2; exit 1; }

progress "audit log sanity (no secrets)"
if podman logs arialog-mcp 2>&1 | grep -qE 'placeholder|Bearer '; then
  echo "secret found in logs" >&2; exit 1
fi
podman logs arialog-mcp 2>&1 | grep -c '"logger": "arialog_mcp.audit"' | sed 's/^/audit lines: /'
echo "E2E COMPLETE"
