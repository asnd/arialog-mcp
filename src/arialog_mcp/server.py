"""FastMCP server: four read-only tools over the VRLI client."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as McpValidationError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from pydantic import Field, ValidationError
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from . import __version__
from .client import VRLIClient
from .config import Settings
from .constraints import Filter, Window, build_constraints, resolve_window
from .errors import ArialogError
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
    list[str] | None, Field(description="Message must contain ALL of these terms (max 10)")
]
Filters = Annotated[list[Filter] | None, Field(description="Field constraints, e.g. hostname")]

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


class AuditMiddleware(Middleware):
    """One audit line per tool call; domain errors become clean tool errors."""

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        name = context.message.name
        args = json.dumps(context.message.arguments or {}, default=str)[:500]
        t0 = time.monotonic()
        try:
            result = await call_next(context)
        except ToolError as exc:
            # FastMCP wraps whatever the tool raised; classify by the original cause.
            cause = exc.__cause__
            extra = {"tool": name, "tool_args": args, "error": str(exc), "ms": _ms(t0)}
            if isinstance(cause, ArialogError):
                audit.warning("tool failed", extra=extra)
            elif cause is None or isinstance(cause, ValidationError | McpValidationError):
                audit.warning("tool rejected", extra=extra)  # bad arguments
            else:
                audit.error("tool crashed", extra=extra, exc_info=exc)
            raise
        except (McpValidationError, ValidationError) as exc:  # bad arguments (caller mistake)
            audit.warning(
                "tool rejected",
                extra={"tool": name, "tool_args": args, "error": str(exc)[:300], "ms": _ms(t0)},
            )
            raise
        except Exception:
            audit.exception("tool crashed", extra={"tool": name, "tool_args": args, "ms": _ms(t0)})
            raise
        audit.info("tool ok", extra={"tool": name, "tool_args": args, "ms": _ms(t0)})
        return result


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat(timespec="seconds")


def create_server(settings: Settings, client: VRLIClient | None = None) -> FastMCP:
    owned = client is None
    vrli = client or VRLIClient(settings)

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

    @mcp.tool(annotations=READ_ONLY)
    async def version() -> VersionInfo:
        """Appliance version (also a cheap reachability probe)."""
        raw = await vrli.version()
        return VersionInfo(
            version=str(raw["version"]) if "version" in raw else None,
            release=str(raw["releaseName"]) if "releaseName" in raw else None,
            raw={k: v for k, v in raw.items() if isinstance(v, str | int | float | bool)},
        )

    @mcp.tool(annotations=READ_ONLY)
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
        raw = await vrli.aggregated(path, bin_width_ms=width * 1000)
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
        raw = await vrli.events(path, limit=scan)
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
        raw = await vrli.events(path, limit=applied)
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
