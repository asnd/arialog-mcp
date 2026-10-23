import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from nsxt_mcp.config import Settings
from nsxt_mcp.server import AuditFormatter


@pytest.mark.parametrize(
    "name",
    [
        "shared.json",
        "per-user.json",
        "remote-shared.json",
        "remote-per-user.json",
    ],
)
def test_configuration_examples(name):
    path = Path(__file__).parents[1] / "examples" / name
    settings = Settings.model_validate_json(path.read_text())
    assert settings.targets
    if name.startswith("remote-"):
        assert settings.remote.require_https


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("shared.json", "HTTP transport requires remote configuration"),
        ("remote-shared.json", "HTTPS requires a certificate/key"),
    ],
)
def test_http_cli_rejects_incomplete_deployment(name, expected):
    config = Path(__file__).parents[1] / "examples" / name
    result = subprocess.run(
        [sys.executable, "-m", "nsxt_mcp", "--config", str(config), "--transport", "http"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert expected in result.stderr


def test_audit_output_contains_metadata_not_arbitrary_log_fields():
    record = logging.LogRecord("nsxt_mcp.audit", logging.INFO, "", 0, "tool call", (), None)
    record.caller = "realm/operator"
    record.execution_mode = "per_user"
    record.authorization = "must-not-be-output"
    output = AuditFormatter().format(record)
    assert json.loads(output)["caller"] == "realm/operator"
    assert "must-not-be-output" not in output
