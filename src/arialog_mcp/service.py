"""VRLI query orchestration and bounded result reduction, independent of MCP."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from .client import Credentials, VRLIClient
from .config import Settings
from .constraints import Filter, Window, build_constraints, resolve_window
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
from .reduce import cap_events, group_signatures, sanitize_event, zscores


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
        text_contains: list[str] | None,
        filters: list[Filter] | None,
    ) -> tuple[Window, str, list[str]]:
        window = resolve_window(
            last_minutes,
            start,
            end,
            now=datetime.now(UTC),
            max_hours=self.settings.max_window_hours,
        )
        path, human = build_constraints(window, text_contains, filters)
        return window, path, human

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
        raw = await self.client.version()
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
        text_contains: list[str] | None,
        filters: list[Filter] | None,
        bin_seconds: int | None,
    ) -> AggregateResult:
        window, path, human = self._prepare(last_minutes, start, end, text_contains, filters)
        min_bin = max(1, -(-window.seconds // self.settings.max_bins))
        width = max(
            bin_seconds or max(10, round(window.seconds / 60 / 10) * 10),
            min_bin,
        )
        raw = await self.client.aggregated(
            path, bin_width_ms=width * 1000, creds=self.credentials()
        )
        bins_raw = raw.bins[: self.settings.max_bins]
        zs = zscores([bin_.value for bin_ in bins_raw])
        bins = [
            Bin(
                start=_iso(bin_.start_ms),
                count=int(bin_.value),
                zscore=zscore,
                spike=zscore is not None and zscore >= self.settings.spike_zscore,
            )
            for bin_, zscore in zip(bins_raw, zs, strict=True)
        ]
        notes: list[str] = []
        if bin_seconds and bin_seconds < min_bin:
            notes.append(
                f"bin_seconds raised to {width} to keep at most {self.settings.max_bins} bins"
            )
        if len(raw.bins) > self.settings.max_bins:
            notes.append(f"{len(raw.bins) - self.settings.max_bins} bins dropped (cap)")
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout); counts may be low")
        if all(zscore is None for zscore in zs):
            notes.append("spike detection skipped: too few bins or no variance")
        bins_with_spikes = [bin_ for bin_ in bins if bin_.spike]
        return AggregateResult(
            query=self._info("/api/v2/aggregated-events", window, human),
            bin_seconds=width,
            total=sum(bin_.count for bin_ in bins),
            peak=max(bins, key=lambda bin_: bin_.count, default=None),
            spikes=bins_with_spikes,
            bins=bins,
            complete=raw.complete,
            notes=notes,
        )

    async def signatures(
        self,
        *,
        last_minutes: int | None,
        start: str | None,
        end: str | None,
        text_contains: list[str] | None,
        filters: list[Filter] | None,
        top_n: int,
        samples_per_signature: int,
    ) -> SignatureResult:
        window, path, human = self._prepare(last_minutes, start, end, text_contains, filters)
        scan = self.settings.signature_scan_limit
        raw = await self.client.events(path, limit=scan, creds=self.credentials())
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
        notes = ["Sensitive-looking credential values in event content are redacted."]
        if truncated:
            notes.append(
                f"scan stopped at {scan} events (newest first): counts are lower bounds and the "
                "older part of the window is not covered; narrow the window or add filters"
            )
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout)")
        return SignatureResult(
            query=self._info("/api/v2/events", window, human),
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
        text_contains: list[str] | None,
        filters: list[Filter] | None,
        limit: int,
    ) -> SearchResult:
        window, path, human = self._prepare(last_minutes, start, end, text_contains, filters)
        applied = min(limit, self.settings.max_events)
        raw = await self.client.events(path, limit=applied, creds=self.credentials())
        kept, reason = cap_events(
            raw.events,
            limit=applied,
            max_bytes=self.settings.max_bytes,
            max_text_chars=self.settings.max_text_chars,
        )
        notes = ["Sensitive-looking credential values in event content are redacted."]
        if limit > applied:
            notes.append(f"limit lowered to the server cap of {applied}")
        if len(raw.events) >= applied and reason is None:
            reason = f"limited to {applied} events; more may match"
        if not raw.complete:
            notes.append("VRLI returned a partial result (query timeout)")
        return SearchResult(
            query=self._info("/api/v2/events", window, human),
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
