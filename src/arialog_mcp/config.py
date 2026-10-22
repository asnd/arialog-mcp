"""Settings (pydantic-settings, env prefix ARIALOG_)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARIALOG_", env_file=".env", extra="ignore")

    # --- VRLI connection -------------------------------------------------
    host: str
    port: int = 9543
    use_tls: bool = True
    username: str
    password: SecretStr
    provider: Literal["Local", "ActiveDirectory", "vIDM"] = "ActiveDirectory"
    verify_ssl: bool = True
    ca_bundle: str | None = None
    # Off by default: VRLI is reached directly, and an HTTP proxy must not intercept it.
    trust_env: bool = False

    # --- resilience --------------------------------------------------------
    request_timeout_s: float = 30.0
    query_timeout_ms: int = 30_000
    max_concurrency: int = Field(4, ge=1)
    retries: int = Field(3, ge=0)
    backoff_base_s: float = 0.5
    breaker_failures: int = Field(5, ge=1)
    breaker_cooldown_s: float = 30.0
    # After a rejected login, do not try again for this long (protects AD accounts from lockout).
    login_cooldown_s: float = 60.0

    # --- response limits (what the LLM may receive) ------------------------
    max_events: int = Field(200, ge=1)
    max_bytes: int = Field(60_000, ge=1_000)
    max_text_chars: int = Field(1_000, ge=50)
    signature_scan_limit: int = Field(2_000, ge=1)
    max_bins: int = Field(144, ge=8)
    max_window_hours: int = Field(72, ge=1)
    spike_zscore: float = 3.0

    # --- serving ------------------------------------------------------------
    transport: Literal["stdio", "http"] = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    log_level: str = "INFO"

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

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}"
