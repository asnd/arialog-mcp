"""Generate ephemeral CA/leaf certificates and synthetic configurations for Podman smoke tests."""

import ipaddress
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def prepare(directory: Path) -> None:
    directory.chmod(0o755)  # Ephemeral synthetic fixtures must be readable by container UID 1001.
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NSX MCP synthetic test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nsx-stub")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    *[
                        x509.DNSName(name)
                        for name in (
                            "nsx-stub",
                            "nsx-fail",
                            "mcp-shared",
                            "mcp-per-user",
                            "localhost",
                        )
                    ],
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    targets = {
        alias: {
            "url": f"https://{host}:8443",
            "ca_bundle": "/config/ca.crt",
            "credential_profile": "service",
        }
        for alias, host in (("primary", "nsx-stub"), ("unavailable", "nsx-fail"))
    }
    common = {
        "targets": targets,
        "attempts": 1,
        "timeout": 10,
        "credential_profiles": {
            "service": {
                "username_env": "NSXT_SERVICE_USER",
                "password_env": "NSXT_SERVICE_PASSWORD",
            }
        },
    }
    remote = {
        "realm": "test",
        "authentication_target": "primary",
        "targets": ["primary", "unavailable"],
        "burst": 100,
        "grants": {
            "alice@test": {
                "targets": ["primary", "unavailable"],
                "tool_groups": ["metadata", "gateway_firewall", "routing", "fabric"],
            }
        },
    }
    for mode in ("shared", "per_user"):
        (directory / f"{mode}.json").write_text(
            json.dumps({**common, "mode": mode, "remote": remote})
        )
    (directory / "stdio.json").write_text(json.dumps({**common, "mode": "per_user"}))
    (directory / "client.password").write_text("pw\n")
    for path in directory.iterdir():
        path.chmod(0o644)  # Test-only generated keys/credentials, never production secrets.


if __name__ == "__main__":
    prepare(Path(sys.argv[1]))
