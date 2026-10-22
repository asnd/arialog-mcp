#!/usr/bin/env bash
# Run lint + mypy + unit tests for arialog-mcp inside Podman, with the network disabled.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMG="localhost/arialog-mcp-test:${TAG:-dev}"
TOTAL=2
STEP=0

exec 3>&2
progress() {
  STEP=$((STEP + 1))
  if [ -t 3 ]; then printf '[%d/%d] %s\n' "$STEP" "$TOTAL" "$1" >&3; fi
}

progress "build test image"
podman build --http-proxy=false --format docker -q -f "$ROOT/Containerfile.test" -t "$IMG" "$ROOT" >/dev/null

progress "run ruff + mypy + pytest (--network none)"
# --network none proves the suite is hermetic; --http-proxy=false keeps the host proxy out.
podman run --rm --network none --http-proxy=false --read-only --tmpfs /tmp "$IMG" "$@"
