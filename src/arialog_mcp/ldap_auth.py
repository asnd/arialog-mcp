"""LDAP/AD authentication for the HTTP transport, compatible with ariaops-mcp's LDAP mode.

MCP clients send HTTP Basic credentials; the server binds to LDAPS *as that user* (no
service account) and reads ``memberOf``. Groups are mapped with the same
``ldap_group_role_map`` format and rules as ariaops-mcp, so one map can serve both servers.
There is a single VRLI, so any mapped group grants access; the mapped role is kept for the
audit log only.

The caller's password travels with the request (never logged, never serialised) because
VRLI is queried as that user: see ``VRLIClient`` per-user sessions.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import logging
import re
import secrets
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastmcp.server.auth import AccessToken, TokenVerifier
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from pydantic import PrivateAttr, SecretStr
from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Settings

log = logging.getLogger("arialog_mcp.ldap")

OPS_ROLE = "ops"
COUNTRY_ROLE = "country"
REALM = "arialog-mcp"
_MAX_TRACKED = 1000  # cache / failure-counter entries before expired ones are swept
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")


# ------------------------------------------------------------------ group mapping
def _extract_cn(dn: str) -> str:
    """CN value of a full DN, or the input unchanged when it is a bare name."""
    for part in dn.split(","):
        stripped = part.strip()
        if stripped.upper().startswith("CN="):
            return stripped[3:]
    return dn


def map_groups_to_claims(
    groups: list[str], group_role_map: dict[str, dict[str, str]]
) -> dict[str, str] | None:
    """Match ``memberOf`` DNs against the map; ``None`` when nothing matches.

    Same rules as ariaops-mcp: a bare-CN key matches that CN in any OU, a full-DN key only
    that exact DN (never also by CN, so it cannot be bypassed via a same-named group
    elsewhere); an ``ops`` mapping wins, then the first ``country`` mapping, then any
    other mapped descriptor.
    """
    cn_map = {k.lower(): d for k, d in group_role_map.items() if _extract_cn(k) == k}
    dn_map = {k.lower(): d for k, d in group_role_map.items() if _extract_cn(k) != k}
    matched: list[dict[str, str]] = []
    for group in groups:
        descriptor = dn_map.get(group.lower()) or cn_map.get(_extract_cn(group).lower())
        if descriptor is not None:
            matched.append(descriptor)
    if not matched:
        return None
    for descriptor in matched:
        if descriptor.get("role", "").lower() == OPS_ROLE:
            return {"role": OPS_ROLE}
    for descriptor in matched:
        if descriptor.get("role", "").lower() == COUNTRY_ROLE:
            claims = {"role": COUNTRY_ROLE}
            for key in ("country", "instance"):
                if descriptor.get(key):
                    claims[key] = descriptor[key]
            return claims
    return {"role": matched[0].get("role") or "mapped"}


# ------------------------------------------------------------------ directory access
class DirectoryUnavailableError(Exception):
    """The directory could not be reached (not the user's fault; never counted)."""


Connector = Callable[[str, str], Any]
"""(bind_dn, password) -> bound ldap3 Connection; raises LDAPBindError on bad credentials."""


@dataclass(frozen=True)
class _Failures:
    count: int
    blocked_until: float


class LDAPAuthenticator:
    """Direct-bind authenticator with a success cache and a per-username failure throttle.

    * Success is cached for ``cache_ttl`` seconds under HMAC(per-process key, user:password),
      so a memory dump does not allow an offline dictionary attack. Failures are never
      cached; after a password change the old one keeps working from cache for up to the
      TTL (as in ariaops-mcp).
    * After ``max_failed_binds`` consecutive bad passwords for a username, binds for that
      username are refused for ``failed_bind_cooldown_s`` without contacting the directory.
      A cached valid login still works meanwhile, so the throttle cannot lock a user out.
    """

    def __init__(
        self,
        *,
        server_uri: str,
        user_dn_template: str,
        user_search_base: str,
        group_role_map: dict[str, dict[str, str]],
        default_role: str | None = None,
        ca_cert_file: str | None = None,
        verify_tls: bool = True,
        bind_timeout: int = 10,
        cache_ttl: int = 300,
        max_failed_binds: int = 5,
        failed_bind_cooldown_s: float = 300.0,
        bind_requests_per_minute: int = 120,
        bind_burst: int = 20,
        connector: Connector | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._server_uri = server_uri
        self._dn_template = user_dn_template
        self._search_base = user_search_base
        self._map = group_role_map
        self._default_role = default_role
        self._ca_cert_file = ca_cert_file
        self._verify_tls = verify_tls
        self._bind_timeout = bind_timeout
        self.cache_ttl = cache_ttl
        self._max_failed = max_failed_binds
        self._fail_cooldown = failed_bind_cooldown_s
        self._bind_rate = bind_requests_per_minute / 60
        self._bind_burst = bind_burst
        self._connector = connector or self._ldap3_connect
        self._clock = clock
        self._cache: dict[str, tuple[dict[str, str], float]] = {}
        self._failures: dict[str, _Failures] = {}
        self._inflight: dict[str, int] = {}
        self._state_lock = asyncio.Lock()
        self._bind_tokens = float(bind_burst)
        self._bind_updated = clock()
        self._hmac_key = secrets.token_bytes(32)
        self._server: Any = None
        self._server_lock = threading.Lock()

    @classmethod
    def from_settings(cls, s: Settings, **kw: Any) -> LDAPAuthenticator:
        assert s.ldap_server_uri and s.ldap_user_dn_template and s.ldap_user_search_base
        return cls(
            server_uri=s.ldap_server_uri,
            user_dn_template=s.ldap_user_dn_template,
            user_search_base=s.ldap_user_search_base,
            group_role_map=s.ldap_group_role_map,
            default_role=s.default_role,
            ca_cert_file=s.ldap_ca_cert_file,
            verify_tls=s.ldap_verify_tls,
            bind_timeout=s.ldap_bind_timeout,
            cache_ttl=s.ldap_cache_ttl,
            max_failed_binds=s.ldap_max_failed_binds,
            failed_bind_cooldown_s=s.ldap_failed_bind_cooldown_s,
            bind_requests_per_minute=s.ldap_bind_requests_per_minute,
            bind_burst=s.ldap_bind_burst,
            **kw,
        )

    # -- ldap3 (blocking; run in a worker thread) --
    def _ldap3_connect(self, bind_dn: str, password: str) -> Any:
        from ldap3 import Connection, Server, Tls
        from ldap3.core.exceptions import LDAPCommunicationError

        with self._server_lock:
            if self._server is None:
                use_ssl = self._server_uri.lower().startswith("ldaps://")
                tls = (
                    Tls(
                        ca_certs_file=self._ca_cert_file,
                        validate=ssl.CERT_REQUIRED if self._verify_tls else ssl.CERT_NONE,
                    )
                    if use_ssl
                    else None
                )
                self._server = Server(
                    self._server_uri, use_ssl=use_ssl, tls=tls, connect_timeout=self._bind_timeout
                )
            server = self._server
        try:
            return Connection(
                server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                read_only=True,
                raise_exceptions=True,
                receive_timeout=self._bind_timeout,
                # The filter names AD and RFC 2307 attributes together; let the server
                # evaluate unknown ones as non-matching instead of ldap3 rejecting them
                # client-side against the schema (OpenLDAP has no sAMAccountName).
                check_names=False,
            )
        except LDAPCommunicationError:
            # ldap3's Server remembers failed addresses and then refuses them ("invalid
            # server address"), so one outage would outlive the directory's recovery.
            with self._server_lock:
                if self._server is server:
                    self._server = None
            raise

    def _bind_and_groups(self, username: str, password: str) -> list[str] | None:
        """None = bad credentials. Raises DirectoryUnavailableError if unreachable."""
        from ldap3.core.exceptions import (
            LDAPBindError,
            LDAPException,
            LDAPInvalidCredentialsResult,
        )
        from ldap3.utils.conv import escape_filter_chars

        bind_dn = self._dn_template.replace("{username}", username)
        try:
            conn = self._connector(bind_dn, password)
        except (LDAPBindError, LDAPInvalidCredentialsResult):
            return None
        except LDAPException as exc:  # unreachable, TLS or protocol problem: an operator issue
            # ldap3 messages name the host/TLS failure, never the password; server log only.
            raise DirectoryUnavailableError(f"{type(exc).__name__}: {str(exc)[:300]}") from exc
        try:
            # Escaped so a crafted username cannot widen the filter to another entry.
            dn = escape_filter_chars(bind_dn)
            if "=" in bind_dn:
                from ldap3 import BASE

                conn.search(
                    search_base=bind_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["memberOf"],
                )
            else:
                conn.search(
                    search_base=self._search_base,
                    search_filter=f"(userPrincipalName={dn})",
                    attributes=["memberOf"],
                )
            if len(conn.entries) > 1:
                raise DirectoryUnavailableError("bound identity matched multiple directory entries")
            if not conn.entries:
                return []
            entry = conn.entries[0]
            if "=" in bind_dn and entry.entry_dn.lower() != bind_dn.lower():
                raise DirectoryUnavailableError("directory returned a different bound identity")
            raw = entry.memberOf.values if "memberOf" in entry and entry.memberOf else []
            return [str(g) for g in raw]
        except LDAPException as exc:
            # Fail closed, but as an operator error: reporting "no groups" would disguise a
            # directory/config problem as an unmapped user.
            raise DirectoryUnavailableError(
                f"group search failed: {type(exc).__name__}: {str(exc)[:300]}"
            ) from exc
        finally:
            with contextlib.suppress(Exception):  # best effort
                conn.unbind()

    # -- cache / throttle --
    def _key(self, username: str, password: str) -> str:
        msg = f"{username}\x00{password}".encode()
        return hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()

    def _sweep(self, now: float) -> None:
        if len(self._cache) >= _MAX_TRACKED:
            self._cache = {k: v for k, v in self._cache.items() if v[1] > now}
            while len(self._cache) >= _MAX_TRACKED:
                del self._cache[min(self._cache, key=lambda k: self._cache[k][1])]
        if len(self._failures) >= _MAX_TRACKED:
            self._failures = {k: v for k, v in self._failures.items() if v.blocked_until > now}

    def _record_failure(self, who: str, now: float) -> None:
        prev = self._failures.get(who, _Failures(0, 0.0))
        count = prev.count + 1
        blocked = now + self._fail_cooldown if count >= self._max_failed else 0.0
        self._failures[who] = _Failures(0 if blocked else count, blocked)
        if blocked:
            log.warning(
                "ldap binds throttled",
                extra={"event": "ldap_throttled", "user": who, "cooldown_s": self._fail_cooldown},
            )

    def _claims(self, groups: list[str]) -> dict[str, str] | None:
        if not self._map:
            return {"role": self._default_role} if self._default_role else None
        return map_groups_to_claims(groups, self._map)

    async def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        """Mapped claims for a valid, authorised user; otherwise None."""
        if not username or not password:
            return None
        now = self._clock()
        key = self._key(username, password)
        hit = self._cache.get(key)
        if hit is not None:
            if hit[1] > now:
                return hit[0]
            del self._cache[key]
        who = username.lower()
        async with self._state_lock:
            elapsed = max(0.0, now - self._bind_updated)
            self._bind_tokens = min(self._bind_burst, self._bind_tokens + elapsed * self._bind_rate)
            self._bind_updated = now
            if self._bind_tokens < 1:
                log.info("ldap bind rate limited", extra={"event": "ldap_rate_limited"})
                return None
            self._bind_tokens -= 1
            if not _USERNAME_RE.fullmatch(username):
                return None
            state = self._failures.get(who)
            inflight = self._inflight.get(who, 0)
            failure_count = state.count if state is not None else 0
            if (state is not None and state.blocked_until > now) or (
                failure_count + inflight >= self._max_failed
            ):
                log.info(
                    "ldap bind refused (throttled)",
                    extra={"event": "ldap_throttled", "user": username},
                )
                return None
            self._inflight[who] = inflight + 1
        try:
            groups = await asyncio.to_thread(self._bind_and_groups, username, password)
        except DirectoryUnavailableError as exc:
            log.error(
                "ldap directory unavailable", extra={"event": "ldap_unavailable", "error": str(exc)}
            )
            raise
        finally:
            async with self._state_lock:
                count = self._inflight.get(who, 1) - 1
                if count:
                    self._inflight[who] = count
                else:
                    self._inflight.pop(who, None)
        async with self._state_lock:
            if groups is None:
                self._record_failure(who, now)
                log.info(
                    "ldap bind rejected", extra={"event": "ldap_bind_failed", "user": username}
                )
                return None
            self._failures.pop(who, None)
        claims = self._claims(groups)
        if claims is None:
            log.info(
                "ldap user in no mapped group", extra={"event": "ldap_unmapped", "user": username}
            )
            return None
        self._sweep(now)
        self._cache[key] = (claims, now + self.cache_ttl)
        log.info("ldap login ok", extra={"event": "ldap_ok", "user": username, **claims})
        return claims


# ------------------------------------------------------------------ Starlette / FastMCP glue
class UserAccessToken(AccessToken):
    """Access token for an LDAP user; carries the password for VRLI passthrough.

    The password is a private attribute: it is excluded from model dumps, repr and logs.
    """

    _password: SecretStr = PrivateAttr(default=SecretStr(""))

    @property
    def password(self) -> SecretStr:
        return self._password


def _parse_basic(header: str) -> tuple[str, str] | None:
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    username, sep, password = decoded.partition(":")
    username = username.strip()
    if not sep or not username or not password:
        return None
    return username, password


class BasicLDAPAuthBackend(AuthenticationBackend):
    """``Authorization: Basic`` -> LDAP bind -> AuthenticatedUser(UserAccessToken)."""

    def __init__(self, authenticator: LDAPAuthenticator) -> None:
        self._authn = authenticator

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, AuthenticatedUser] | None:
        state = conn.scope.get("state", {})
        raw_header = state.pop("ldap_basic_authorization", conn.headers.get("authorization", ""))
        creds = _parse_basic(raw_header)
        if creds is None:
            return None
        username, password = creds
        try:
            claims = await self._authn.authenticate(username, password)
        except DirectoryUnavailableError:
            conn.scope.setdefault("state", {})["ldap_directory_unavailable"] = True
            return None
        if claims is None:
            return None
        token = UserAccessToken(
            token="ldap",
            client_id=username,
            scopes=[],
            expires_at=int(time.time()) + max(self._authn.cache_ttl, 60),
            subject=username,
            claims=claims,
        )
        token._password = SecretStr(password)
        return AuthCredentials([]), AuthenticatedUser(token)


class BasicChallengeMiddleware:
    """Rewrite FastMCP's Bearer challenge on 401 to ``Basic`` so Basic clients can respond."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        scope = dict(scope)
        headers = list(scope.get("headers", []))
        basic_header = next(
            (value for key, value in headers if key.lower() == b"authorization"), None
        )
        if basic_header is not None and basic_header[:6].lower() == b"basic ":
            scope.setdefault("state", {})["ldap_basic_authorization"] = basic_header.decode(
                "latin-1"
            )
            scope["headers"] = [
                (key, b"Bearer ldap" if key.lower() == b"authorization" else value)
                for key, value in headers
            ]

        response_unavailable = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_unavailable
            if (
                scope.get("state", {}).get("ldap_directory_unavailable", False)
                and message["type"] == "http.response.start"
                and message["status"] == 401
            ):
                response_unavailable = True
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in (b"www-authenticate", b"content-length")
                ]
                headers.extend(
                    [
                        (b"content-type", b"application/json"),
                        (b"content-length", b"39"),
                    ]
                )
                message = {**message, "status": 503, "headers": headers}
            if message["type"] == "http.response.start" and message["status"] == 401:
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() != b"www-authenticate"
                ]
                headers.append((b"www-authenticate", f'Basic realm="{REALM}"'.encode()))
                message = {**message, "headers": headers}
            elif response_unavailable and message["type"] == "http.response.body":
                message = {
                    **message,
                    "body": b'{"detail":"LDAP directory unavailable"}',
                    "more_body": False,
                }
            await send(message)

        await self.app(scope, receive, send_wrapper)


class LDAPBasicAuth(TokenVerifier):
    """FastMCP auth provider: HTTP Basic + LDAP instead of bearer tokens."""

    def __init__(self, authenticator: LDAPAuthenticator) -> None:
        super().__init__()
        self.authenticator = authenticator

    async def verify_token(self, token: str) -> AccessToken | None:
        return None  # bearer tokens are not accepted in LDAP mode

    def get_middleware(self) -> list[Any]:
        return [
            Middleware(BasicChallengeMiddleware),
            Middleware(AuthenticationMiddleware, backend=BasicLDAPAuthBackend(self.authenticator)),
            Middleware(AuthContextMiddleware),
        ]
