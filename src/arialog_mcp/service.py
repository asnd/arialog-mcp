"""VRLI query orchestration and bounded result reduction, independent of MCP."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from .client import Credentials, VRLIClient
from .config import Settings
from .constraints import Constraints, Filter, Window, build_constraints, resolve_window
from .errors import QueryError
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
from .reduce import cap_events, group_signatures, sanitize_event, time_bins, zscores


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat(timespec="seconds")


class ArialogService:
    """Translate validated query inputs into VRLI calls and bounded domain results."""

    def __init__(
        self, settings: Settings, client: VRLIClient, credentials: Callable[[], Credentials | None]
    ) -> None:
        self.settings = settings
        self.client = client
        self.credentials = credentials

    def _prepare(
        self,
        last_minutes: int | None,
        start: str | None,
        end: str | None,
        text_all: list[str] | None,
        text_any: list[str] | None,
        filters: list[Filter] | None,
    ) -> tuple[Window, Constraints]:
        window = resolve_window(
            last_minutes,
            start,
            end,
            now=datetime.now(UTC),
            max_hours=self.settings.max_window_hours,
        )
        constraints = build_constraints(window, text_all, text_any, filters)
        return window, constraints

    @staticmethod
    async def _run(constraints: Constraints, query: Awaitable[Any]) -> Any:
        try:
            return await query
        except QueryError as exc:
            if constraints.error_hint is None:
                raise
            raise QueryError(f"{exc}; {constraints.error_hint}") from exc

    @staticmethod
    def _info(endpoint: str, window: Window, human: list[str]) -> QueryInfo:
        return QueryInfo(
            endpoint=endpoint,
            constraints=human,
            window_start=window.start.isoformat(timespec="seconds"),
            window_end=window.end.isoformat(timespec="seconds"),
            relative_window=window.last_ms is not None,
        )

    async def version(self) -> VersionInfo:
        raw = await self.client.version(creds=self.credentials())
        return VersionInfo(
            version=str(raw["version"]) if "version" in raw else None,
            release=str(raw["releaseName"]) if "releaseName" in raw else None,
            raw={k: v for k, v in raw.items() if isinstance(v, str | int | float | bool)},
        )

    async def aggregate(
        self,
        *,
        last_minutes: int | None,
        start: str | None,
        end: str | None,
        text_all: list[str] | None,
        text_any: list[str] | None,
        filters: list[Filter] | None,
        bin_seconds: int | None,
    ) -> AggregateResult:
        window, constraints = self._prepare(last_minutes, start, end, text_all, text_any, filters)
        start_ms = int(window.start.timestamp() * 1000)
        end_ms = int(window.end.timestamp() * 1000)
        min_bin = max(
            1,
            -(-(end_ms - start_ms) // ((self.settings.max_bins - 1) * 1000)),
        )
        width = max(
            bin_seconds or max(10, round(window.seconds / 60 / 10) * 10),
            min_bin,
        )
        raw = await self._run(
            constraints,
            self.client.aggregated(
                constraints.path,
                bin_width_ms=width * 1000,
                limit=self.settings.max_bins + 2,
                creds=self.credentials(),
            ),
        )
        grid = time_bins(
            [(bin_.start_ms, bin_.value) for bin_ in raw.bins],
            start_ms=start_ms,
            end_ms=end_ms,
            width_ms=width * 1000,
        )
        dropped = max(0, len(grid) - self.settings.max_bins)
        if dropped:
            grid = grid[-self.settings.max_bins :]
        full = [i for i, bin_ in enumerate(grid) if not bin_.partial]
        z_of = dict(zip(full, zscores([grid[i].count for i in full]), strict=True))
        bins = [
            Bin(
                start=_iso(bin_.start_ms),
                count=int(bin_.count),
                zscore=z_of.get(i),
                spike=(z := z_of.get(i)) is not None and z >= self.settings.spike_zscore,
                partial=bin_.partial,
            )
            for i, bin_ in enumerate(grid)
        ]
        notes = list(constraints.notes)
        if dropped:
            notes.append(f"{dropped} oldest bins dropped (cap)")
        if bin_seconds and bin_seconds < min_bin:
            notes.append(
                f"bin_seconds raised to {width} to keep at most {self.settings.max_bins} bins"
            )
        if raw.limit_reached:
            notes.append("VRLI bin limit reached; later bins may be missing")
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout); counts may be low")
        if all(bin_.zscore is None for bin_ in bins):
            notes.append("spike detection skipped: too few bins or no variance")
        bins_with_spikes = [bin_ for bin_ in bins if bin_.spike]
        return AggregateResult(
            query=self._info("/api/v2/aggregated-events", window, constraints.human),
            bin_seconds=width,
            total=sum(bin_.count for bin_ in bins),
            peak=max(bins, key=lambda bin_: bin_.count, default=None),
            spikes=bins_with_spikes,
            bins=bins,
            complete=raw.complete and not raw.limit_reached,
            notes=notes,
        )

    async def signatures(
        self,
        *,
        last_minutes: int | None,
        start: str | None,
        end: str | None,
        text_all: list[str] | None,
        text_any: list[str] | None,
        filters: list[Filter] | None,
        top_n: int,
        samples_per_signature: int,
    ) -> SignatureResult:
        window, constraints = self._prepare(last_minutes, start, end, text_all, text_any, filters)
        scan = self.settings.signature_scan_limit
        raw = await self._run(
            constraints,
            self.client.events(constraints.path, limit=scan, creds=self.credentials()),
        )
        safe_events = [
            sanitize_event(event, max_text_chars=self.settings.max_text_chars)
            for event in raw.events
        ]
        groups, distinct = group_signatures(
            safe_events,
            top_n=top_n,
            samples=samples_per_signature,
            max_text_chars=self.settings.max_text_chars,
        )
        truncated = len(raw.events) >= scan
        notes = [
            *constraints.notes,
            "Sensitive-looking credential values in event content are redacted.",
        ]
        if truncated:
            notes.append(
                f"scan stopped at {scan} events (newest first): counts are lower bounds and the "
                "older part of the window is not covered; narrow the window or add filters"
            )
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout)")
        return SignatureResult(
            query=self._info("/api/v2/events", window, constraints.human),
            scanned=len(raw.events),
            distinct_signatures=distinct,
            scan_truncated=truncated,
            covered_from=_iso(min(event.ts_ms for event in raw.events)) if raw.events else None,
            complete=raw.complete,
            signatures=[
                Signature(
                    signature_id=group.sig_id,
                    template=group.template,
                    count=group.count,
                    first_seen=_iso(group.first_ms),
                    last_seen=_iso(group.last_ms),
                    top_hosts=dict(group.hosts),
                    samples=group.samples,
                )
                for group in groups
            ],
            notes=notes,
        )

    async def search(
        self,
        *,
        last_minutes: int | None,
        start: str | None,
        end: str | None,
        text_all: list[str] | None,
        text_any: list[str] | None,
        filters: list[Filter] | None,
        limit: int,
    ) -> SearchResult:
        window, constraints = self._prepare(last_minutes, start, end, text_all, text_any, filters)
        applied = min(limit, self.settings.max_events)
        raw = await self._run(
            constraints,
            self.client.events(constraints.path, limit=applied, creds=self.credentials()),
        )
        kept, reason = cap_events(
            raw.events,
            limit=applied,
            max_bytes=self.settings.max_bytes,
            max_text_chars=self.settings.max_text_chars,
        )
        notes = [
            *constraints.notes,
            "Sensitive-looking credential values in event content are redacted.",
        ]
        if limit > applied:
            notes.append(f"limit lowered to the server cap of {applied}")
        if len(raw.events) >= applied and reason is None:
            reason = f"limited to {applied} events; more may match"
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout)")
        return SearchResult(
            query=self._info("/api/v2/events", window, constraints.human),
            returned=len(kept),
            complete=raw.complete,
            truncated=reason is not None,
            truncated_reason=reason,
            events=[
                Event(time=_iso(event.ts_ms), host=event.host, text=event.text, fields=event.fields)
                for event in kept
            ],
            notes=notes,
        )
