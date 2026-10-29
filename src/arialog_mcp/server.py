"""FastMCP server: four read-only tools over the VRLI client."""

from __future__ import annotations

import functools
import hmac
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, ParamSpec, TypeVar

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as McpValidationError
from fastmcp.server.auth import AccessToken, AuthProvider, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from pydantic import Field, SecretStr, ValidationError
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from . import __version__
from .client import Credentials, VRLIClient
from .config import Settings
from .constraints import (
    MAX_FILTERS,
    MAX_TEXT_TERMS,
    Filter,
)
from .errors import ArialogError, AuthError
from .ldap_auth import LDAPAuthenticator, LDAPBasicAuth, UserAccessToken
from .models import AggregateResult, SearchResult, SignatureResult, VersionInfo
from .service import ArialogService

audit = logging.getLogger("arialog_mcp.audit")

INSTRUCTIONS = """\
Read-only access to VMware Aria Operations for Logs (VRLI) 8.18.x.
Recommended order: log_aggregate (is there a spike, and when?) -> log_signatures (what are the
dominant message types?) -> log_search (a few raw lines for evidence).
Always give a time window: last_minutes, or start (+ optional end) as ISO-8601 WITH timezone.
Results are capped; check `complete`, `truncated` and `notes` before trusting counts.
"""

LastMinutes = Annotated[
    int | None, Field(ge=1, description="Window = last N minutes (appliance clock)")
]
Start = Annotated[
    str | None, Field(description="Window start, ISO-8601 with timezone, e.g. 2026-10-07T12:00:00Z")
]
End = Annotated[str | None, Field(description="Window end (default: now); needs start")]
TextTerms = Annotated[
    list[str] | None,
    Field(
        max_length=MAX_TEXT_TERMS,
        description=f"Message must contain ALL of these terms (max {MAX_TEXT_TERMS})",
    ),
]
Filters = Annotated[
    list[Filter] | None,
    Field(
        max_length=MAX_FILTERS,
        description=f"Field constraints, e.g. hostname (max {MAX_FILTERS})",
    ),
]

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}

P = ParamSpec("P")
R = TypeVar("R")


def domain_errors(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
    """Surface domain errors (written to be LLM-safe) as tool errors.

    The server masks every other exception, so internals never reach the client.
    """

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return await fn(*args, **kwargs)
        except ArialogError as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


class SharedTokenVerifier(TokenVerifier):
    """Static bearer token for the HTTP transport, compared in constant time."""

    def __init__(self, token: SecretStr) -> None:
        super().__init__()
        self._token = token.get_secret_value().encode()

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token.encode(), self._token):
            return None
        return AccessToken(token=token, client_id="arialog-mcp-client", scopes=[])


def _caller() -> AccessToken | None:
    try:
        return get_access_token()
    except (RuntimeError, TypeError):  # no HTTP request (stdio / in-memory)
        return None


class AuditMiddleware(Middleware):
    """One audit line per tool call; domain errors become clean tool errors."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.callers: dict[str, _CallerBudget] = {}

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        name = context.message.name
        who = _caller()
        base: dict[str, Any] = {"tool": name}
        if who is not None:
            base["user"] = who.client_id
            if role := (who.claims or {}).get("role"):
                base["role"] = role
            if not self._enter(who.client_id):
                raise ToolError("Caller request budget exceeded")
        t0 = time.monotonic()
        try:
            result = await call_next(context)
        except ToolError as exc:
            # FastMCP wraps whatever the tool raised; classify by the original cause.
            cause = exc.__cause__
            extra = {**base, "error_type": type(cause).__name__, "ms": _ms(t0)}
            if isinstance(cause, ArialogError):
                audit.warning("tool failed", extra=extra)
            elif cause is None or isinstance(cause, ValidationError | McpValidationError):
                audit.warning("tool rejected", extra=extra)
            else:
                audit.error("tool crashed", extra=extra, exc_info=exc)
            raise
        except (McpValidationError, ValidationError) as exc:  # bad arguments (caller mistake)
            audit.warning(
                "tool rejected",
                extra={**base, "error_type": type(exc).__name__, "ms": _ms(t0)},
            )
            raise
        except Exception:
            audit.exception("tool crashed", extra={**base, "ms": _ms(t0)})
            raise
        finally:
            if who is not None:
                self._exit(who.client_id)
        audit.info("tool ok", extra={**base, "ms": _ms(t0)})
        return result

    def _enter(self, identity: str) -> bool:
        now = time.monotonic()
        state = self.callers.get(identity)
        if state is None:
            expired = [
                key
                for key, value in self.callers.items()
                if not value.active and now - value.updated > self.settings.caller_idle_seconds
            ]
            for key in expired:
                del self.callers[key]
            if len(self.callers) >= self.settings.max_callers:
                return False
            state = self.callers[identity] = _CallerBudget(
                tokens=float(self.settings.caller_burst), updated=now
            )
        state.tokens = min(
            self.settings.caller_burst,
            state.tokens
            + max(0.0, now - state.updated) * self.settings.caller_requests_per_minute / 60,
        )
        state.updated = now
        if state.tokens < 1:
            return False
        state.tokens -= 1
        state.active += 1
        return True

    def _exit(self, identity: str) -> None:
        state = self.callers.get(identity)
        if state is not None:
            state.active = max(0, state.active - 1)
            state.updated = time.monotonic()


@dataclass
class _CallerBudget:
    tokens: float
    updated: float
    active: int = 0


def _auth_provider(
    settings: Settings, authenticator: LDAPAuthenticator | None
) -> AuthProvider | None:
    mode = settings.auth_mode
    if mode == "token":
        assert settings.http_auth_token is not None
        return SharedTokenVerifier(settings.http_auth_token)
    if mode == "ldap":
        return LDAPBasicAuth(authenticator or LDAPAuthenticator.from_settings(settings))
    return None


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def create_server(
    settings: Settings,
    client: VRLIClient | None = None,
    *,
    authenticator: LDAPAuthenticator | None = None,
) -> FastMCP:
    owned = client is None
    vrli = client or VRLIClient(settings)
    ldap_mode = settings.auth_mode == "ldap"

    def creds() -> Credentials | None:
        """VRLI identity for this call: the LDAP caller, or None for the service account."""
        if not ldap_mode:
            return None
        who = _caller()
        if not isinstance(who, UserAccessToken):
            raise AuthError("this server requires an LDAP-authenticated caller")  # fail closed
        username = settings.ldap_vrli_username_template.replace("{username}", who.client_id)
        return Credentials(username, who.password)

    service = ArialogService(settings, vrli, creds)

    @asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owned:
                await vrli.aclose()

    mcp = FastMCP(
        "arialog-mcp",
        version=__version__,
        instructions=INSTRUCTIONS,
        middleware=[AuditMiddleware(settings)],
        lifespan=lifespan,
        mask_error_details=True,
        auth=_auth_provider(settings, authenticator),
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> PlainTextResponse:  # liveness only; never calls VRLI
        return PlainTextResponse("ok")

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_: Request) -> PlainTextResponse:  # from breaker state; never calls VRLI
        if vrli.breaker_open:
            return PlainTextResponse("vrli unavailable (circuit open)", status_code=503)
        return PlainTextResponse("ready")

    @mcp.tool(annotations=READ_ONLY)
    @domain_errors
    async def version() -> VersionInfo:
        """Appliance version (also a cheap reachability probe)."""
        return await service.version()

    @mcp.tool(annotations=READ_ONLY)
    @domain_errors
    async def log_aggregate(
        last_minutes: LastMinutes = None,
        start: Start = None,
        end: End = None,
        text_contains: TextTerms = None,
        filters: Filters = None,
        bin_seconds: Annotated[
            int | None, Field(ge=1, description="Bin width; default picks ~60 bins")
        ] = None,
    ) -> AggregateResult:
        """Event counts over time bins with spike detection (z-score). Use this FIRST."""
        return await service.aggregate(
            last_minutes=last_minutes,
            start=start,
            end=end,
            text_contains=text_contains,
            filters=filters,
            bin_seconds=bin_seconds,
        )

    @mcp.tool(annotations=READ_ONLY)
    @domain_errors
    async def log_signatures(
        last_minutes: LastMinutes = None,
        start: Start = None,
        end: End = None,
        text_contains: TextTerms = None,
        filters: Filters = None,
        top_n: Annotated[int, Field(ge=1, le=50)] = 15,
        samples_per_signature: Annotated[int, Field(ge=0, le=3)] = 2,
    ) -> SignatureResult:
        """Group events into message templates (ids/IPs/numbers masked), most frequent first."""
        return await service.signatures(
            last_minutes=last_minutes,
            start=start,
            end=end,
            text_contains=text_contains,
            filters=filters,
            top_n=top_n,
            samples_per_signature=samples_per_signature,
        )

    @mcp.tool(annotations=READ_ONLY)
    @domain_errors
    async def log_search(
        last_minutes: LastMinutes = None,
        start: Start = None,
        end: End = None,
        text_contains: TextTerms = None,
        filters: Filters = None,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Max events (server cap applies)")
        ] = 50,
    ) -> SearchResult:
        """Raw events, newest first. Capped by count and bytes; use for a few evidence lines."""
        return await service.search(
            last_minutes=last_minutes,
            start=start,
            end=end,
            text_contains=text_contains,
            filters=filters,
            limit=limit,
        )

    return mcp
