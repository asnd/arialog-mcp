"""Explicit execution identities; remote callers must be authenticated by an adapter."""

import os
import stat
from contextvars import ContextVar
from dataclasses import dataclass, field

from pydantic import SecretStr

from .config import ALL_TOOL_GROUPS, Settings
from .errors import AccessDenied, AuthenticationFailed

MAX_PASSWORD_FILE_BYTES = 4096


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
                metadata = profile.password_file.stat()
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise AuthenticationFailed("Password file must be a private regular file")
                with profile.password_file.open("rb") as secret_file:
                    raw = secret_file.read(MAX_PASSWORD_FILE_BYTES + 1)
                if len(raw) > MAX_PASSWORD_FILE_BYTES:
                    raise AuthenticationFailed("Password file exceeds the configured size limit")
                password = raw.decode("utf-8").rstrip("\r\n")
        except AuthenticationFailed:
            raise
        except (KeyError, OSError, UnicodeError):
            raise AuthenticationFailed("Credential secret unavailable") from None
        if not username or not password or ":" in username:
            raise AuthenticationFailed("Invalid Basic credential configuration")
        return Credentials(SecretStr(username), SecretStr(password))
