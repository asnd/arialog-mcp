#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec 3>&2
progress() { if [ -t 3 ]; then printf '[%s/6] %s\n' "$1" "$2" >&3; fi; }
export NO_PROXY="127.0.0.1,localhost,${NO_PROXY:-}"
LOCK=false
FIX=false
CONTAINER=false
for option in "$@"; do
  case "$option" in
    --lock) LOCK=true ;;
    --fix) FIX=true ;;
    --container) CONTAINER=true ;;
    *) printf 'Unknown option: %s\n' "$option" >&2; exit 2 ;;
  esac
done
progress 1 'Syncing locked uv environment'
if "$LOCK"; then
  uv lock --project "$ROOT"
fi
uv sync --project "$ROOT" --locked
if "$FIX"; then
  uv run --project "$ROOT" ruff format "$ROOT"
  uv run --project "$ROOT" ruff check --fix "$ROOT"
fi
progress 2 'Ruff lint'
uv run --project "$ROOT" ruff check "$ROOT"
progress 3 'Ruff formatting'
uv run --project "$ROOT" ruff format --check "$ROOT"
progress 4 'Type checks'
uv run --project "$ROOT" mypy "$ROOT/src/nsxt_mcp" "$ROOT/examples/mcp_client.py"
progress 5 'Python compilation'
uv run --project "$ROOT" python -m compileall -q "$ROOT/src" "$ROOT/tests" "$ROOT/examples"
progress 6 'Stub-backed unit and MCP transport tests'
uv run --project "$ROOT" pytest "$ROOT/tests" -v
if "$CONTAINER"; then
  bash "$ROOT/scripts/container-smoke.sh"
fi
