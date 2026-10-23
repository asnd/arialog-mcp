"""FastMCP server: four read-only tools over the VRLI client."""

from __future__ import annotations

import functools
import hmac
import json
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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
    Window,
    build_constraints,
    resolve_window,
)
from .errors import ArialogError, AuthError
from .ldap_auth import LDAPAuthenticator, LDAPBasicAuth, UserAccessToken
from .models import (
    AggregateResult,
    Bin,
    Event,
    QueryInfo,
    SearchResult,
    Signature,
    SignatureResult,
    VersionInfo,
)
from .reduce import cap_events, group_signatures, zscores

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

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        name = context.message.name
        args = json.dumps(context.message.arguments or {}, default=str)[:500]
        who = _caller()
        base: dict[str, Any] = {"tool": name, "tool_args": args}
        if who is not None:
            base["user"] = who.client_id
            if role := (who.claims or {}).get("role"):
                base["role"] = role
        t0 = time.monotonic()
        try:
            result = await call_next(context)
        except ToolError as exc:
            # FastMCP wraps whatever the tool raised; classify by the original cause.
            cause = exc.__cause__
            extra = {**base, "error": str(exc), "ms": _ms(t0)}
            if isinstance(cause, ArialogError):
                audit.warning("tool failed", extra=extra)
            elif cause is None or isinstance(cause, ValidationError | McpValidationError):
                audit.warning("tool rejected", extra=extra)  # bad arguments
            else:
                audit.error("tool crashed", extra=extra, exc_info=exc)
            raise
        except (McpValidationError, ValidationError) as exc:  # bad arguments (caller mistake)
            audit.warning("tool rejected", extra={**base, "error": str(exc)[:300], "ms": _ms(t0)})
            raise
        except Exception:
            audit.exception("tool crashed", extra={**base, "ms": _ms(t0)})
            raise
        audit.info("tool ok", extra={**base, "ms": _ms(t0)})
        return result


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


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat(timespec="seconds")


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
        middleware=[AuditMiddleware()],
        lifespan=lifespan,
        mask_error_details=True,
        auth=_auth_provider(settings, authenticator),
    )

    def prepare(
        last_minutes: int | None,
        start: str | None,
        end: str | None,
        text_contains: list[str] | None,
        filters: list[Filter] | None,
    ) -> tuple[Window, str, list[str]]:
        window = resolve_window(
            last_minutes, start, end, now=datetime.now(UTC), max_hours=settings.max_window_hours
        )
        path, human = build_constraints(window, text_contains, filters)
        return window, path, human

    def info(endpoint: str, window: Window, human: list[str]) -> QueryInfo:
        return QueryInfo(
            endpoint=endpoint,
            constraints=human,
            window_start=window.start.isoformat(timespec="seconds"),
            window_end=window.end.isoformat(timespec="seconds"),
            relative_window=window.last_ms is not None,
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
        raw = await vrli.version()
        return VersionInfo(
            version=str(raw["version"]) if "version" in raw else None,
            release=str(raw["releaseName"]) if "releaseName" in raw else None,
            raw={k: v for k, v in raw.items() if isinstance(v, str | int | float | bool)},
        )

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
        window, path, human = prepare(last_minutes, start, end, text_contains, filters)
        min_bin = max(1, -(-window.seconds // settings.max_bins))  # ceil: never exceed max_bins
        width = max(bin_seconds or max(10, round(window.seconds / 60 / 10) * 10), min_bin)
        raw = await vrli.aggregated(path, bin_width_ms=width * 1000, creds=creds())
        bins_raw = raw.bins[: settings.max_bins]
        values = [b.value for b in bins_raw]
        zs = zscores(values)
        bins = [
            Bin(
                start=_iso(b.start_ms),
                count=int(b.value),
                zscore=z,
                spike=z is not None and z >= settings.spike_zscore,
            )
            for b, z in zip(bins_raw, zs, strict=True)
        ]
        notes: list[str] = []
        if bin_seconds and bin_seconds < min_bin:
            notes.append(f"bin_seconds raised to {width} to keep at most {settings.max_bins} bins")
        if len(raw.bins) > settings.max_bins:
            notes.append(f"{len(raw.bins) - settings.max_bins} bins dropped (cap)")
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout); counts may be low")
        if all(z is None for z in zs):
            notes.append("spike detection skipped: too few bins or no variance")
        spikes = [b for b in bins if b.spike]
        return AggregateResult(
            query=info("/api/v2/aggregated-events", window, human),
            bin_seconds=width,
            total=sum(b.count for b in bins),
            peak=max(bins, key=lambda b: b.count, default=None),
            spikes=spikes,
            bins=bins,
            complete=raw.complete,
            notes=notes,
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
        window, path, human = prepare(last_minutes, start, end, text_contains, filters)
        scan = settings.signature_scan_limit
        raw = await vrli.events(path, limit=scan, creds=creds())
        groups, distinct = group_signatures(
            raw.events,
            top_n=top_n,
            samples=samples_per_signature,
            max_text_chars=settings.max_text_chars,
        )
        truncated = len(raw.events) >= scan
        notes: list[str] = []
        if truncated:
            notes.append(
                f"scan stopped at {scan} events (newest first): counts are lower bounds and the "
                "older part of the window is not covered; narrow the window or add filters"
            )
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout)")
        return SignatureResult(
            query=info("/api/v2/events", window, human),
            scanned=len(raw.events),
            distinct_signatures=distinct,
            scan_truncated=truncated,
            covered_from=_iso(min(e.ts_ms for e in raw.events)) if raw.events else None,
            complete=raw.complete,
            signatures=[
                Signature(
                    signature_id=g.sig_id,
                    template=g.template,
                    count=g.count,
                    first_seen=_iso(g.first_ms),
                    last_seen=_iso(g.last_ms),
                    top_hosts=dict(g.hosts),
                    samples=g.samples,
                )
                for g in groups
            ],
            notes=notes,
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
        window, path, human = prepare(last_minutes, start, end, text_contains, filters)
        applied = min(limit, settings.max_events)
        raw = await vrli.events(path, limit=applied, creds=creds())
        kept, reason = cap_events(
            raw.events,
            limit=applied,
            max_bytes=settings.max_bytes,
            max_text_chars=settings.max_text_chars,
        )
        notes: list[str] = []
        if limit > applied:
            notes.append(f"limit lowered to the server cap of {applied}")
        if len(raw.events) >= applied and reason is None:
            reason = f"limited to {applied} events; more may match"
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout)")
        return SearchResult(
            query=info("/api/v2/events", window, human),
            returned=len(kept),
            complete=raw.complete,
            truncated=reason is not None,
            truncated_reason=reason,
            events=[
                Event(time=_iso(e.ts_ms), host=e.host, text=e.text, fields=e.fields) for e in kept
            ],
            notes=notes,
        )

    return mcp
