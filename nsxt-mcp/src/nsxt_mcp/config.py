"""Validated settings. Secrets are references, never configuration literals."""

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ALL_TOOL_GROUPS: frozenset[Literal["metadata", "gateway_firewall", "routing", "fabric"]] = (
    frozenset({"metadata", "gateway_firewall", "routing", "fabric"})
)


class CredentialProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username_env: str
    password_env: str | None = None
    password_file: Path | None = None

    @model_validator(mode="after")
    def one_password_source(self) -> "CredentialProfile":
        if (self.password_env is None) == (self.password_file is None):
            raise ValueError("Specify exactly one password source")
        return self


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    ca_bundle: Path | None = None
    credential_profile: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def https_origin(self) -> "Target":
        url = urlsplit(self.url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.path not in ("", "/")
            or url.query
            or url.fragment
        ):
            raise ValueError("Target must be an HTTPS origin without credentials or path")
        self.url = self.url.rstrip("/")
        return self


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: set[str]
    tool_groups: set[Literal["metadata", "gateway_firewall", "routing", "fabric"]] = Field(
        default={"metadata", "gateway_firewall"}
    )


class RemoteSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    realm: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    authentication_target: str
    targets: set[str] = Field(min_length=1)
    grants: dict[str, Grant] = Field(default_factory=dict)
    authentication_timeout: float = Field(default=10, gt=0)
    caller_concurrency: int = Field(default=2, ge=1)
    requests_per_minute: int = Field(default=120, ge=1)
    burst: int = Field(default=20, ge=1)
    max_callers: int = Field(default=1000, ge=1)
    caller_idle_seconds: float = Field(default=600, gt=0)
    # TLS is served directly; TLS offload is supported via an HTTPS ASGI scope from a trusted proxy.
    require_https: bool = True
    allowed_origins: set[str] = Field(default_factory=set)
    max_request_bytes: int = Field(default=262144, ge=1)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NSXT_", extra="forbid")
    mode: Literal["shared", "per_user"] = "shared"
    targets: dict[str, Target]
    credential_profiles: dict[str, CredentialProfile] = Field(default_factory=dict)
    global_concurrency: int = Field(default=16, ge=1)
    target_concurrency: int = Field(default=4, ge=1)
    timeout: float = Field(default=30, gt=0)
    attempts: int = Field(default=3, ge=1, le=5)
    max_response_bytes: int = Field(default=1_000_000, ge=1)
    max_pages: int = Field(default=10, ge=1)
    max_items: int = Field(default=1000, ge=1)
    breaker_threshold: int = Field(default=3, ge=1)
    breaker_cooldown: float = Field(default=30, gt=0)
    remote: RemoteSettings | None = None
    fleet_concurrency: int = Field(default=4, ge=1, le=16)
    max_fleet_targets: int = Field(default=100, ge=1, le=1000)

    @model_validator(mode="after")
    def profiles_exist(self) -> "Settings":
        for target in self.targets.values():
            if self.mode == "shared" and target.credential_profile not in self.credential_profiles:
                raise ValueError(
                    "Every shared target must reference an existing credential profile"
                )
        if self.remote:
            remote = self.remote
            if remote.authentication_target not in self.targets:
                raise ValueError("Unknown NSX authentication target")
            if not remote.targets <= self.targets.keys():
                raise ValueError("Unknown remote target alias")
            if self.mode == "shared" and not remote.grants:
                raise ValueError("Remote shared mode requires explicit caller grants")
            for grant in remote.grants.values():
                if not grant.targets <= remote.targets:
                    raise ValueError("Caller grant exceeds remote target set")
        return self
