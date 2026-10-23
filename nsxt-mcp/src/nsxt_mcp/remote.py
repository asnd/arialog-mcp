"""NSX-validated HTTP Basic boundary for stateless remote MCP.

No credentials or MCP session IDs are stored. Only caller budget counters persist.
"""

import asyncio
import base64
import binascii
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import SecretStr
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .client import TargetRegistry
from .config import ALL_TOOL_GROUPS, RemoteSettings
from .credentials import Caller, Credentials, current_caller
from .errors import AccessDenied, AuthenticationFailed, Unavailable
from .server import create_server

audit = logging.getLogger("nsxt_mcp.audit")


@dataclass
class Budget:
    tokens: float
    updated: float
    active: int = 0


class CallerLimits:
    """Single-event-loop token bucket + active requests, bounded in memory."""

    def __init__(self, settings: RemoteSettings, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.clock = clock
        self.states: dict[str, Budget] = {}

    def enter(self, identity: str) -> bool:
        now = self.clock()
        state = self.states.get(identity)
        if state is None:
            expired = [
                key
                for key, value in self.states.items()
                if not value.active and now - value.updated > self.settings.caller_idle_seconds
            ]
            for key in expired:
                del self.states[key]
            if len(self.states) >= self.settings.max_callers:
                return False
            state = self.states[identity] = Budget(float(self.settings.burst), now)
        state.tokens = min(
            self.settings.burst,
            state.tokens + max(0, now - state.updated) * self.settings.requests_per_minute / 60,
        )
        state.updated = now
        if state.active >= self.settings.caller_concurrency or state.tokens < 1:
            return False
        state.tokens -= 1
        state.active += 1
        return True

    def exit(self, identity: str) -> None:
        state = self.states[identity]
        state.active -= 1
        state.updated = self.clock()


def parse_basic(headers: list[tuple[bytes, bytes]]) -> Credentials:
    values = [value for key, value in headers if key.lower() == b"authorization"]
    if len(values) != 1 or len(values[0]) > 8192:
        raise AuthenticationFailed("One Basic authorization header required")
    try:
        scheme, value = values[0].split(b" ", 1)
        if scheme.lower() != b"basic":
            raise ValueError
        username, password = base64.b64decode(value, validate=True).decode("utf-8").split(":", 1)
        if any(ord(c) < 32 for c in username):
            raise ValueError
        return Credentials(SecretStr(username), SecretStr(password))
    except (ValueError, UnicodeError, binascii.Error):
        raise AuthenticationFailed("Invalid Basic authorization header") from None


class RemoteApp:
    def __init__(self, app: ASGIApp, registry: TargetRegistry):
        if registry.settings.remote is None:
            raise ValueError("Remote settings required")
        self.app = app
        self.registry = registry
        self.settings = registry.settings.remote
        self.limits = CallerLimits(self.settings)

    async def reject(
        self, scope: Scope, receive: Receive, send: Send, status: int, message: str
    ) -> None:
        headers = {"Cache-Control": "no-store"}
        if status == 401:
            headers["WWW-Authenticate"] = f'Basic realm="{self.settings.realm}", charset="UTF-8"'
        if status == 429:
            headers["Retry-After"] = "1"
        await JSONResponse({"error": message}, status_code=status, headers=headers)(
            scope, receive, send
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        if self.settings.require_https and scope.get("scheme") != "https":
            await self.reject(scope, receive, send, 400, "HTTPS required")
            return
        if scope.get("path") == "/healthz" and scope.get("method") == "GET":
            await JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})(
                scope, receive, send
            )
            return
        headers = scope.get("headers", [])
        origin = [v.decode("latin-1") for k, v in headers if k.lower() == b"origin"]
        if origin and (len(origin) != 1 or origin[0] not in self.settings.allowed_origins):
            await self.reject(scope, receive, send, 403, "Origin denied")
            return
        try:
            credentials = parse_basic(headers)
        except AuthenticationFailed:
            await self.reject(scope, receive, send, 401, "Basic credentials required")
            return
        username = credentials.username.get_secret_value()
        identity = f"{self.settings.realm}/{username}"
        if not self.limits.enter(identity):
            await self.reject(scope, receive, send, 429, "Caller request budget exceeded")
            return
        token = None
        started = False
        canonical_budget: str | None = None

        async def safe_send(message):  # type: ignore[no-untyped-def]
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message["headers"] = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in (b"mcp-session-id", b"cache-control")
                ] + [(b"cache-control", b"no-store")]
            await send(message)

        try:
            async with asyncio.timeout(self.registry.settings.timeout):
                probe = Caller(
                    identity, frozenset({self.settings.authentication_target}), credentials
                )
                try:
                    async with asyncio.timeout(self.settings.authentication_timeout):
                        canonical_username = await self.registry.authenticate(
                            self.settings.authentication_target, probe
                        )
                except TimeoutError:
                    raise Unavailable("Authentication deadline exceeded") from None
                canonical_identity = f"{self.settings.realm}/{canonical_username}"
                if canonical_identity != identity:
                    if not self.limits.enter(canonical_identity):
                        await self.reject(
                            scope, receive, send, 429, "Caller request budget exceeded"
                        )
                        return
                    canonical_budget = canonical_identity
                grant = self.settings.grants.get(canonical_username)
                if self.registry.settings.mode == "shared" or self.settings.grants:
                    if grant is None:
                        raise AccessDenied("Caller has no access grant")
                    targets = grant.targets
                    groups = grant.tool_groups
                else:
                    targets = self.settings.targets
                    groups = set(ALL_TOOL_GROUPS)
                caller = Caller(
                    canonical_identity,
                    frozenset(targets),
                    credentials if self.registry.settings.mode == "per_user" else None,
                    frozenset(groups),
                )
                if any(k.lower() == b"mcp-session-id" for k, _ in headers):
                    await self.reject(scope, receive, send, 400, "Persistent sessions are disabled")
                    return
                if scope.get("path") != "/mcp":
                    await self.reject(scope, receive, send, 404, "Not found")
                    return
                if scope.get("method") != "POST":
                    await self.reject(scope, receive, send, 405, "Only MCP POST requests supported")
                    return
                body = bytearray()
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > self.settings.max_request_bytes:
                        await self.reject(scope, receive, send, 413, "MCP request too large")
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
                delivered = False

                async def bounded_receive():  # type: ignore[no-untyped-def]
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()

                # Remove credentials from the ASGI scope exposed to framework dependencies.
                clean_scope = dict(scope)
                clean_scope["headers"] = [
                    (k, v) for k, v in headers if k.lower() != b"authorization"
                ]
                token = current_caller.set(caller)
                await self.app(clean_scope, bounded_receive, safe_send)
        except AuthenticationFailed:
            await self.reject(scope, receive, send, 401, "NSX rejected caller credentials")
        except AccessDenied:
            await self.reject(scope, receive, send, 403, "Caller access denied")
        except (Unavailable, TimeoutError):
            if not started:
                await self.reject(scope, receive, send, 503, "NSX service unavailable")
        finally:
            if token is not None:
                current_caller.reset(token)
            if canonical_budget is not None:
                self.limits.exit(canonical_budget)
            self.limits.exit(identity)


def create_remote_app(registry: TargetRegistry) -> RemoteApp:
    """Stateless JSON responses ensure tool tasks have this request's identity and lifetime."""
    server = create_server(registry)
    return RemoteApp(server.http_app(stateless_http=True, json_response=True), registry)
