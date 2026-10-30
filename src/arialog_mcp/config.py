"""Settings (pydantic-settings, env prefix ARIALOG_)."""

from __future__ import annotations

import ipaddress
import json
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

AuthMode = Literal["none", "token", "ldap"]


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARIALOG_", env_file=".env", extra="ignore")

    # --- VRLI connection -------------------------------------------------
    host: str
    port: int = Field(9543, ge=1, le=65535)
    use_tls: bool = True
    # Service account. Required except in LDAP mode, where every VRLI call is made with the
    # caller's own credentials (per-user passthrough) and the service account is never used.
    username: str | None = None
    password: SecretStr | None = None
    provider: Literal["Local", "ActiveDirectory", "vIDM"] = "ActiveDirectory"
    verify_ssl: bool = True
    ca_bundle: str | None = None
    # Off by default: VRLI is reached directly, and a corporate proxy must not intercept it.
    trust_env: bool = False

    # --- resilience --------------------------------------------------------
    request_timeout_s: float = Field(45.0, gt=0)
    # VRLI's own query timeout: when it expires VRLI answers with a partial result
    # (complete=false). The HTTP read timeout for queries is this plus the margin, so the
    # partial answer arrives before httpx gives up.
    query_timeout_ms: int = Field(30_000, ge=1_000)
    query_timeout_margin_s: float = Field(15.0, ge=1.0)
    max_concurrency: int = Field(4, ge=1, le=64)
    retries: int = Field(3, ge=0, le=10)
    backoff_base_s: float = Field(0.5, ge=0)
    backoff_max_s: float = Field(10.0, ge=0)
    breaker_failures: int = Field(5, ge=1)
    breaker_cooldown_s: float = Field(30.0, ge=0)
    # After a rejected login, do not try again for this long (protects AD accounts from lockout).
    login_cooldown_s: float = Field(60.0, ge=0)
    # Per-user VRLI sessions kept in LDAP mode (least recently used are dropped first).
    max_user_sessions: int = Field(256, ge=1)

    # --- response limits (what the LLM may receive) ------------------------
    max_events: int = Field(200, ge=1)
    max_bytes: int = Field(60_000, ge=1_000)
    max_response_bytes: int = Field(1_000_000, ge=1_000)
    max_event_fields: int = Field(50, ge=1, le=500)
    max_event_field_chars: int = Field(500, ge=1, le=10_000)
    max_text_chars: int = Field(1_000, ge=50)
    signature_scan_limit: int = Field(2_000, ge=1)
    max_bins: int = Field(144, ge=8)
    max_window_hours: int = Field(72, ge=1)
    spike_zscore: float = 3.0

    # --- serving ------------------------------------------------------------
    transport: Literal["stdio", "http"] = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = Field(8000, ge=1, le=65535)
    # How /mcp is protected (health probes stay open):
    #   none  - no auth (loopback only, unless http_allow_unauthenticated)
    #   token - shared bearer token (http_auth_token)
    #   ldap  - HTTP Basic checked by an LDAPS bind; VRLI is queried as that user
    # Left at "none" with a token set, the token is enforced (pre-LDAP behaviour).
    http_auth_mode: AuthMode = "none"
    http_auth_token: SecretStr | None = None
    http_allow_unauthenticated: bool = False
    http_behind_tls_proxy: bool = False
    caller_requests_per_minute: int = Field(120, ge=1)
    caller_burst: int = Field(20, ge=1)
    max_callers: int = Field(1000, ge=1)
    caller_idle_seconds: float = Field(600.0, gt=0)
    log_level: str = "INFO"

    # --- LDAP (http_auth_mode=ldap) -----------------------------------------
    # Same meaning and format as ariaops-mcp's ARIAOPS_LDAP_* settings, so values can be
    # shared between the two servers.
    ldap_server_uri: str | None = None
    ldap_user_dn_template: str | None = None  # e.g. "{username}@corp.example" or "uid=..."
    ldap_user_search_base: str | None = None
    # {"<group CN or full DN>": {"role": "ops" | "country", ...}}. Any mapped group grants
    # access (one VRLI, so no per-instance scoping); a user in no mapped group is rejected.
    ldap_group_role_map: Annotated[dict[str, dict[str, str]], NoDecode] = Field(
        default_factory=dict
    )
    # Granted to every bound user when no group map is set; must then be set explicitly.
    default_role: str | None = None
    ldap_ca_cert_file: str | None = None
    ldap_verify_tls: bool = True
    ldap_cache_ttl: int = Field(300, ge=0)
    ldap_bind_timeout: int = Field(10, gt=0)
    # Consecutive failed binds per username before further attempts are refused for
    # ldap_failed_bind_cooldown_s, so the MCP cannot be used to lock out AD accounts.
    ldap_max_failed_binds: int = Field(5, ge=1)
    ldap_failed_bind_cooldown_s: float = Field(300.0, ge=0)
    ldap_bind_requests_per_minute: int = Field(120, ge=1)
    ldap_bind_burst: int = Field(20, ge=1)
    # VRLI login name for an LDAP user; "{username}" is the HTTP Basic user name.
    ldap_vrli_username_template: str = "{username}"

    @field_validator("host")
    @classmethod
    def _bare_host(cls, v: str) -> str:
        v = v.strip()
        if not v or "://" in v or "/" in v or ":" in v or " " in v:
            raise ValueError("host must be a bare hostname or IPv4 (no scheme, port or path)")
        return v

    @field_validator("log_level")
    @classmethod
    def _log_level(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        return v

    @field_validator("http_auth_token")
    @classmethod
    def _token_strength(cls, v: SecretStr | None) -> SecretStr | None:
        if v is not None and len(v.get_secret_value().strip()) < 16:
            raise ValueError("http_auth_token must be at least 16 characters")
        return v

    @field_validator("ldap_group_role_map", mode="before")
    @classmethod
    def _group_map(cls, v: Any) -> Any:
        if v is None or (isinstance(v, str) and not v.strip()):
            return {}
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError as exc:
                raise ValueError(f"ldap_group_role_map must be valid JSON: {exc.msg}") from None
        if not isinstance(v, dict) or not all(isinstance(d, dict) for d in v.values()):
            raise ValueError('ldap_group_role_map must be {"<group>": {"role": ...}, ...}')
        return v

    @field_validator("ldap_vrli_username_template")
    @classmethod
    def _vrli_template(cls, v: str) -> str:
        if "{username}" not in v:
            raise ValueError("ldap_vrli_username_template must contain {username}")
        return v

    @property
    def auth_mode(self) -> AuthMode:
        """Effective /mcp auth mode (a token alone still enables token auth)."""
        if self.http_auth_mode == "none" and self.http_auth_token is not None:
            return "token"
        return self.http_auth_mode

    @model_validator(mode="after")
    def _cross_checks(self) -> Settings:
        if self.request_timeout_s * 1000 <= self.query_timeout_ms:
            raise ValueError("request_timeout_s must be longer than query_timeout_ms")
        mode = self.auth_mode
        if mode == "token" and self.http_auth_token is None:
            raise ValueError("http_auth_mode=token requires http_auth_token")
        if mode == "ldap":
            self._check_ldap()
        elif self.username is None or self.password is None:
            raise ValueError("username and password (VRLI service account) are required")
        remote_http = self.transport == "http" and not _is_loopback(self.http_host)
        if remote_http and not self.http_behind_tls_proxy:
            raise ValueError(
                "non-loopback HTTP requires http_behind_tls_proxy=true "
                "(or a future direct-TLS transport)"
            )
        if remote_http and mode == "none" and not self.http_allow_unauthenticated:
            raise ValueError(
                "http_auth_mode token or ldap is required when http_host is not loopback "
                "(or set http_allow_unauthenticated=true behind an authenticating proxy)"
            )
        return self

    def _check_ldap(self) -> None:
        if self.transport != "http":
            raise ValueError("http_auth_mode=ldap needs transport=http (stdio has no caller)")
        missing = [
            name
            for name in ("ldap_server_uri", "ldap_user_dn_template", "ldap_user_search_base")
            if not getattr(self, name)
        ]
        if missing:
            raise ValueError(f"http_auth_mode=ldap requires {', '.join(missing)}")
        assert self.ldap_server_uri is not None and self.ldap_user_dn_template is not None
        if "{username}" not in self.ldap_user_dn_template:
            raise ValueError("ldap_user_dn_template must contain {username}")
        if self.ldap_verify_tls and not self.ldap_server_uri.lower().startswith("ldaps://"):
            raise ValueError(
                "ldap_server_uri must use ldaps:// while ldap_verify_tls=true "
                "(set ldap_verify_tls=false only for tests)"
            )
        # Fail closed: without a map every directory user who can bind would get access.
        if not self.ldap_group_role_map and not self.default_role:
            raise ValueError(
                "http_auth_mode=ldap without ldap_group_role_map requires default_role, "
                "which is then granted to every user who can bind; set it deliberately"
            )

    @property
    def query_read_timeout_s(self) -> float:
        return self.query_timeout_ms / 1000 + self.query_timeout_margin_s

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}"
