"""Explicit execution identities; remote callers must be authenticated by an adapter."""

import os
from contextvars import ContextVar
from dataclasses import dataclass, field

from pydantic import SecretStr

from .config import ALL_TOOL_GROUPS, Settings
from .errors import AccessDenied, AuthenticationFailed


@dataclass(frozen=True)
class Credentials:
    username: SecretStr = field(repr=False)
    password: SecretStr = field(repr=False)

    def __post_init__(self) -> None:
        username = self.username.get_secret_value()
        if not username or ":" in username or not self.password.get_secret_value():
            raise AuthenticationFailed("Invalid Basic credentials")


@dataclass(frozen=True)
class Caller:
    """Trusted adapter output, never constructed from tool arguments."""

    identity: str
    allowed_targets: frozenset[str]
    credentials: Credentials | None = field(default=None, repr=False)
    tool_groups: frozenset[str] = ALL_TOOL_GROUPS


current_caller: ContextVar[Caller | None] = ContextVar("nsxt_caller", default=None)


def request_caller() -> Caller:
    caller = current_caller.get()
    if caller is None:
        raise AuthenticationFailed("Authenticated caller context required")
    return caller


class CredentialProvider:
    def __init__(self, settings: Settings):
        self.settings = settings

    def resolve(self, target: str, caller: Caller) -> Credentials:
        if target not in caller.allowed_targets:
            raise AccessDenied("Caller cannot access target")
        if self.settings.mode == "per_user":
            if caller.credentials is None:
                raise AuthenticationFailed("Per-user credentials required")
            return caller.credentials
        profile = self.settings.credential_profiles[
            self.settings.targets[target].credential_profile or ""
        ]
        try:
            username = os.environ[profile.username_env]
            if profile.password_env:
                password = os.environ[profile.password_env]
            else:
                assert profile.password_file is not None
                password = profile.password_file.read_text().rstrip("\r\n")
        except (KeyError, OSError, UnicodeError):
            raise AuthenticationFailed("Credential secret unavailable") from None
        if not username or not password or ":" in username:
            raise AuthenticationFailed("Invalid Basic credential configuration")
        return Credentials(SecretStr(username), SecretStr(password))
