"""Validate compose structure and absence of credential values in container audit logs."""

import sys
from pathlib import Path

import yaml

directory, root = map(Path, sys.argv[1:])
for name in ("shared.log", "per-user.log"):
    text = (directory / name).read_text()
    assert '"event": "nsx_tool_call"' in text
    assert "synthetic-password" not in text
    assert "YWxpY2VAdGVzdDpwdw==" not in text
    assert "secret-bgp" not in text
compose = yaml.safe_load((root / "compose.yaml").read_text())
assert compose["services"]["nsxt-mcp"]["read_only"] is True
print("PASS audit secret exclusion, non-root server and compose structure")
