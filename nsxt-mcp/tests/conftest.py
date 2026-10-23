import pytest

from nsxt_mcp.config import CredentialProfile, Settings, Target
from nsxt_mcp.credentials import Caller


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("TEST_NSX_USER", "reader@example.test")
    monkeypatch.setenv("TEST_NSX_PASSWORD", "synthetic-password")
    return Settings(
        targets={
            "a": Target(url="https://a.example.test", credential_profile="service"),
            "b": Target(url="https://b.example.test", credential_profile="service"),
        },
        credential_profiles={
            "service": CredentialProfile(
                username_env="TEST_NSX_USER", password_env="TEST_NSX_PASSWORD"
            )
        },
    )


@pytest.fixture
def caller():
    return Caller("test-realm/operator", frozenset({"a", "b"}))
