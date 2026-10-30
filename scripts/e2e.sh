#!/usr/bin/env bash
# Hermetic Podman end-to-end test: vrli-stub + arialog-mcp (+ a bad-credentials twin),
# plus LDAP mode: OpenLDAP over LDAPS (verified against its generated CA) with per-user
# VRLI passthrough.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${TAG:-dev}"
NET="arialog-e2e-$$"
MCP_IMG="localhost/arialog-mcp:${TAG}"
STUB_IMG="localhost/vrli-stub:${TAG}"
LDAP_IMG="docker.io/osixia/openldap:1.5.0"
WORK="$(mktemp -d)"
PODRUN=(podman run --http-proxy=false --network "$NET")
TOTAL=11
STEP=0

exec 3>&2                                   # real terminal for progress
progress() {                                # [n/total] phase — only on a TTY
  STEP=$((STEP + 1))
  if [ -t 3 ]; then printf '[%d/%d] %s\n' "$STEP" "$TOTAL" "$1" >&3; fi
}

cleanup() {
  local rc=$?
  set +e
  if [ "$rc" -ne 0 ]; then                  # keep failures diagnosable: last server logs
    for c in arialog-mcp arialog-mcp-ldap openldap; do
      echo "--- logs: $c" >&2; podman logs --tail 40 "$c" >&2 2>&1
    done
  fi
  podman rm -f vrli-stub arialog-mcp arialog-mcp-bad openldap arialog-mcp-ldap >/dev/null 2>&1
  rm -rf "$WORK"
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
"${PODRUN[@]}" -d --name vrli-stub -e STUB_USER=svc-test -e STUB_PASS=placeholder \
  -e STUB_USERS='{"alice": "pw-alice"}' "$STUB_IMG" >/dev/null
wait_healthy vrli-stub 30

TOKEN="e2e-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"   # throwaway bearer token
COMMON=(-e ARIALOG_HOST=vrli-stub -e ARIALOG_HTTP_AUTH_TOKEN="$TOKEN" -e ARIALOG_HTTP_BEHIND_TLS_PROXY=true
        -e ARIALOG_USE_TLS=false -e ARIALOG_USERNAME=svc-test
        -e ARIALOG_RETRIES=3 -e ARIALOG_BACKOFF_BASE_S=0.1 -e ARIALOG_LOGIN_COOLDOWN_S=300)

progress "arialog-mcp (good credentials)"
"${PODRUN[@]}" -d --name arialog-mcp "${COMMON[@]}" -e ARIALOG_PASSWORD=placeholder "$MCP_IMG" >/dev/null
wait_healthy arialog-mcp 40

progress "arialog-mcp (wrong credentials)"
"${PODRUN[@]}" -d --name arialog-mcp-bad "${COMMON[@]}" -e ARIALOG_PASSWORD=wrong "$MCP_IMG" >/dev/null
wait_healthy arialog-mcp-bad 40

progress "functional + failure-path checks"
"${PODRUN[@]}" --rm -e ARIALOG_HTTP_AUTH_TOKEN="$TOKEN" -v "$ROOT/tests/e2e:/e2e:ro,Z" \
  --entrypoint python "$MCP_IMG" \
  /e2e/e2e_client.py http://arialog-mcp:8000/mcp http://vrli-stub:9543 http://arialog-mcp-bad:8000/mcp

progress "MCP endpoint rejects missing / wrong bearer token"
"${PODRUN[@]}" -i --rm --entrypoint python "$MCP_IMG" - <<'PY'
import urllib.error, urllib.request as u
op = u.build_opener(u.ProxyHandler({}))
for hdr in ({}, {"Authorization": "Bearer not-the-token-0123456789"}):
    req = u.Request("http://arialog-mcp:8000/mcp", data=b"{}", method="POST",
                    headers={"content-type": "application/json", **hdr})
    try:
        op.open(req, timeout=5)
        raise SystemExit("expected 401")
    except urllib.error.HTTPError as e:
        assert e.code == 401, e.code
print("PASS unauthenticated /mcp -> 401")
PY

progress "OpenLDAP (LDAPS, throwaway CA) seeded with test users"
# The image's bundled CA has expired (and verification rightly rejects it): issue a fresh one.
mkdir -p "$WORK/certs"
(
  cd "$WORK/certs"
  printf '[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.cnf
  printf 'subjectAltName=DNS:openldap\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > leaf.ext
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=arialog-e2e-ca" \
    -config ca.cnf -extensions ca -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=openldap" -keyout ldap.key -out ldap.csr 2>/dev/null
  openssl x509 -req -in ldap.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile leaf.ext -out ldap.crt 2>/dev/null
  chmod 644 ca.crt ldap.crt ldap.key   # throwaway test key, read by slapd's own user
)
"${PODRUN[@]}" -d --name openldap --hostname openldap \
  -e LDAP_DOMAIN=example.org -e LDAP_ADMIN_PASSWORD=admin-placeholder -e LDAP_TLS_VERIFY_CLIENT=never \
  -e LDAP_TLS_CRT_FILENAME=ldap.crt -e LDAP_TLS_KEY_FILENAME=ldap.key -e LDAP_TLS_CA_CRT_FILENAME=ca.crt \
  -v "$WORK/certs:/container/service/slapd/assets/certs:ro,Z" \
  -v "$ROOT/tests/e2e/ldap:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro,Z" \
  "$LDAP_IMG" --copy-service >/dev/null
n=0
# Wait for the final LDAPS listener (bootstrap first runs a temporary plain-LDAP slapd).
until podman exec -e LDAPTLS_CACERT=/container/run/service/slapd/assets/certs/ca.crt openldap \
    ldapwhoami -x -H ldaps://openldap -D uid=alice,ou=people,dc=example,dc=org -w pw-alice \
    >/dev/null 2>&1; do
  n=$((n + 1)); [ "$n" -gt 60 ] && { podman logs openldap >&2; echo "openldap not ready" >&2; exit 1; }
  sleep 1
done
cp "$WORK/certs/ca.crt" "$WORK/ldap-ca.crt"

progress "arialog-mcp (LDAP mode, no service account)"
"${PODRUN[@]}" -d --name arialog-mcp-ldap -v "$WORK/ldap-ca.crt:/certs/ldap-ca.crt:ro,Z" \
  -e ARIALOG_HOST=vrli-stub -e ARIALOG_USE_TLS=false -e ARIALOG_RETRIES=3 -e ARIALOG_BACKOFF_BASE_S=0.1 \
  -e ARIALOG_HTTP_AUTH_MODE=ldap \
  -e ARIALOG_LDAP_SERVER_URI=ldaps://openldap:636 \
  -e ARIALOG_LDAP_CA_CERT_FILE=/certs/ldap-ca.crt \
  -e ARIALOG_LDAP_USER_DN_TEMPLATE='uid={username},ou=people,dc=example,dc=org' \
  -e ARIALOG_LDAP_USER_SEARCH_BASE=dc=example,dc=org \
  -e ARIALOG_LDAP_GROUP_ROLE_MAP='{"arialog-ops": {"role": "ops"}, "vrops-se": {"role": "country", "country": "SE"}}' \
  "$MCP_IMG" >/dev/null
wait_healthy arialog-mcp-ldap 40

progress "LDAP: Basic challenge, group mapping, per-user VRLI passthrough"
"${PODRUN[@]}" --rm -v "$ROOT/tests/e2e:/e2e:ro,Z" --entrypoint python "$MCP_IMG" \
  /e2e/e2e_ldap.py http://arialog-mcp-ldap:8000/mcp http://vrli-stub:9543
LDAP_LOGS="$(podman logs arialog-mcp-ldap 2>&1)"
if grep -qE 'pw-alice|pw-bob|pw-carol|nope' <<<"$LDAP_LOGS"; then
  echo "password found in LDAP-mode logs" >&2; exit 1
fi
grep -q '"user": "alice"' <<<"$LDAP_LOGS" || { echo "audit log lacks the LDAP user" >&2; exit 1; }
# Each 401 must have its real cause (not an unreachable directory masquerading as one).
if grep -q '"ldap_unavailable"' <<<"$LDAP_LOGS"; then
  echo "LDAPS to the directory failed" >&2; exit 1
fi
grep -q '"event": "ldap_bind_failed"' <<<"$LDAP_LOGS" || { echo "no rejected bind logged" >&2; exit 1; }
grep -q '"event": "ldap_unmapped"' <<<"$LDAP_LOGS" || { echo "no unmapped user logged" >&2; exit 1; }
echo "PASS LDAP-mode audit names the user and never logs passwords"

progress "VRLI down: liveness stays green, tools fail cleanly"
podman stop -t 1 vrli-stub >/dev/null
DOWN_OUT="$("${PODRUN[@]}" -i --rm -e ARIALOG_HTTP_AUTH_TOKEN="$TOKEN" --entrypoint python "$MCP_IMG" - <<'PY'
import asyncio, os, urllib.request as u
from fastmcp import Client
from fastmcp.exceptions import ToolError
op = u.build_opener(u.ProxyHandler({}))
assert op.open("http://arialog-mcp:8000/healthz", timeout=3).read() == b"ok"
async def go():
    async with Client("http://arialog-mcp:8000/mcp", auth=os.environ["ARIALOG_HTTP_AUTH_TOKEN"]) as c:
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
if podman logs arialog-mcp 2>&1 | grep -qE "placeholder|Bearer |$TOKEN"; then
  echo "secret found in logs" >&2; exit 1
fi
podman logs arialog-mcp 2>&1 | grep -c '"logger": "arialog_mcp.audit"' | sed 's/^/audit lines: /'
echo "E2E COMPLETE"
