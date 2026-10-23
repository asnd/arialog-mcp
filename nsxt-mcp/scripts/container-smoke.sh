#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${NSXT_IMAGE:-localhost/nsxt-mcp:0.1.0}"
NETWORK="nsxt-smoke-$$"
DATA="$(mktemp -d "$ROOT/.e2e-XXXXXX")"
STUB="nsxt-stub-$$"
SHARED="nsxt-shared-$$"
PERUSER="nsxt-per-user-$$"
exec 3>&2
progress() { if [ -t 3 ]; then printf '[%s/7] %s\n' "$1" "$2" >&3; fi; }
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    podman logs "$STUB" >&2 2>/dev/null || true
    podman logs "$SHARED" >&2 2>/dev/null || true
    podman logs "$PERUSER" >&2 2>/dev/null || true
  fi
  podman rm -f "$STUB" "$SHARED" "$PERUSER" >/dev/null 2>&1 || true
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -rf -- "$DATA"
}
trap cleanup EXIT
progress 1 'Building production image'
podman build --format docker -t "$IMAGE" -f "$ROOT/Containerfile" "$ROOT"
progress 2 'Preparing ephemeral TLS certificates and NSX fixtures'
uv run --project "$ROOT" python "$ROOT/tests/container/prepare.py" "$DATA"
printf 'NSXT_SERVICE_USER=svc-test\nNSXT_SERVICE_PASSWORD=synthetic-password\nNSXT_USER=alice@test\nNSXT_PASSWORD=pw\n' > "$DATA/test.env"
chmod 600 "$DATA/test.env"
podman network create "$NETWORK" >/dev/null
RUN=(podman run --http-proxy=false --network "$NETWORK" -v "$DATA:/config:ro,z")
progress 3 'Starting real HTTPS NSX stub'
"${RUN[@]}" -d --name "$STUB" --network-alias nsx-stub --network-alias nsx-fail \
  -v "$ROOT/tests:/fixtures:ro,z" --entrypoint python "$IMAGE" /fixtures/container/nsx_https_stub.py >/dev/null
progress 4 'Starting shared and per-user remote servers'
start_mcp() {
  "${RUN[@]}" -d --name "$1" --network-alias "$2" --env-file "$DATA/test.env" \
    -e NSXT_HEALTH_URL=https://localhost:8443/healthz -e NSXT_HEALTH_CA=/config/ca.crt \
    --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m --cap-drop ALL \
    --security-opt no-new-privileges "$IMAGE" --config "/config/$3.json" --transport http \
    --host 0.0.0.0 --port 8443 --ssl-certfile /config/server.crt --ssl-keyfile /config/server.key >/dev/null
}
start_mcp "$SHARED" mcp-shared shared
start_mcp "$PERUSER" mcp-per-user per_user
wait_ready() {
  local attempt
  for attempt in {1..40}; do
    if podman healthcheck run "$1" >/dev/null 2>&1; then return; fi
    if [ -t 3 ]; then printf '  waiting for %s (%s/40)\n' "$1" "$attempt" >&3; fi
    sleep 1
  done
  return 1
}
wait_ready "$SHARED"
wait_ready "$PERUSER"
progress 5 'Checking TLS, authentication, operational reads and failure paths'
"${RUN[@]}" --rm -v "$ROOT/tests:/fixtures:ro,z" -v "$ROOT/examples:/examples:ro,z" \
  --entrypoint python "$IMAGE" /fixtures/container/check_remote.py
progress 6 'Checking packaged stdio and non-root execution'
uv run --project "$ROOT" python "$ROOT/tests/container/check_stdio.py" "$IMAGE" "$NETWORK" "$DATA" "$DATA/test.env"
test "$(podman exec "$SHARED" id -u)" = 1001
progress 7 'Checking audit output and compose syntax'
podman logs "$SHARED" > "$DATA/shared.log" 2>&1
podman logs "$PERUSER" > "$DATA/per-user.log" 2>&1
uv run --project "$ROOT" python "$ROOT/tests/container/check_artifacts.py" "$DATA" "$ROOT"
