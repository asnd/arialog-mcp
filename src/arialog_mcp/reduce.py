"""Server-side log reduction: signature grouping, spike detection and hard caps.

The point of this module is that the LLM never receives thousands of raw lines.
No MCP imports here.
"""

from __future__ import annotations

import hashlib
import json
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

# Order matters: most specific first, bare numbers last.
_MASKS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
        "<TS>",
    ),
    # RFC 4122 (8-4-4-4-12) and VMFS (8-8-4-12) identifiers
    (re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4,12}){2,4}\b"), "<UUID>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{8,}\b"), "<HEX>"),
    (re.compile(r"\d+"), "<N>"),
]
_WS = re.compile(r"\s+")
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)(["']?)(password|passwd|token|secret|api[_-]?key|private[_-]?key)\1"""
    r"""(\s*[:=]\s*)(["']?)[^\s,;}"']+"""
)
_AUTH_HEADER = re.compile(r"(?i)\b(Bearer|Basic)(\s+)[A-Za-z0-9._~+/-]+=*")
_URL_CREDENTIALS = re.compile(r"(?i)(://)[^/@\s:]+:[^/@\s]+@")
MAX_TEMPLATE_CHARS = 300


def mask(text: str) -> str:
    """Collapse variable parts (ids, addresses, numbers) so similar lines share a template."""
    for pattern, repl in _MASKS:
        text = pattern.sub(repl, text)
    return _WS.sub(" ", text).strip()[:MAX_TEMPLATE_CHARS]


def redact_sensitive_text(text: str) -> str:
    """Redact common credential assignments and authorization material in log content."""
    text = _SECRET_ASSIGNMENT.sub(r"\1\2\1\3[redacted]", text)
    text = _AUTH_HEADER.sub(r"\1\2[redacted]", text)
    return _URL_CREDENTIALS.sub(r"\1[redacted]@", text)


def signature_id(template: str) -> str:
    return hashlib.sha1(template.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]


@dataclass(frozen=True)
class RawEvent:
    ts_ms: int
    text: str
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str | None:
        return self.fields.get("hostname") or self.fields.get("source")


@dataclass
class SignatureGroup:
    sig_id: str
    template: str
    count: int
    first_ms: int
    last_ms: int
    hosts: list[tuple[str, int]]
    samples: list[str]


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def sanitize_event(ev: RawEvent, *, max_text_chars: int = 1000) -> RawEvent:
    fields = {
        name[:128]: (
            "[redacted]"
            if any(
                secret in name.lower()
                for secret in ("password", "passwd", "secret", "token", "key")
            )
            else truncate(redact_sensitive_text(value), max_text_chars)
        )
        for name, value in list(ev.fields.items())[:50]
    }
    return RawEvent(
        ts_ms=ev.ts_ms,
        text=truncate(redact_sensitive_text(ev.text), max_text_chars),
        fields=fields,
    )


def group_signatures(
    events: list[RawEvent], *, top_n: int, samples: int, max_text_chars: int
) -> tuple[list[SignatureGroup], int]:
    """Return (top_n groups, number of distinct signatures)."""
    counts: Counter[str] = Counter()
    first: dict[str, int] = {}
    last: dict[str, int] = {}
    hosts: dict[str, Counter[str]] = {}
    sample_map: dict[str, list[str]] = {}
    for ev in events:
        tpl = mask(ev.text)
        counts[tpl] += 1
        first[tpl] = min(first.get(tpl, ev.ts_ms), ev.ts_ms)
        last[tpl] = max(last.get(tpl, ev.ts_ms), ev.ts_ms)
        if ev.host:
            hosts.setdefault(tpl, Counter())[ev.host] += 1
        bucket = sample_map.setdefault(tpl, [])
        if len(bucket) < samples:
            bucket.append(truncate(ev.text, max_text_chars))
    top = [
        SignatureGroup(
            sig_id=signature_id(tpl),
            template=tpl,
            count=n,
            first_ms=first[tpl],
            last_ms=last[tpl],
            hosts=hosts.get(tpl, Counter()).most_common(3),
            samples=sample_map[tpl],
        )
        for tpl, n in counts.most_common(top_n)
    ]
    return top, len(counts)


MIN_BINS_FOR_SPIKES = 8


def zscores(values: list[float]) -> list[float | None]:
    """Population z-score per bin; all None when there is too little data or no variance."""
    if len(values) < MIN_BINS_FOR_SPIKES:
        return [None] * len(values)
    sd = statistics.pstdev(values)
    if sd == 0:
        return [None] * len(values)
    mean = statistics.fmean(values)
    return [round((v - mean) / sd, 2) for v in values]


def cap_events(
    events: list[RawEvent], *, limit: int, max_bytes: int, max_text_chars: int
) -> tuple[list[RawEvent], str | None]:
    """Apply count, byte and per-line caps. Returns (kept, reason-if-truncated)."""
    kept: list[RawEvent] = []
    used = 0
    reason: str | None = None
    for ev in events:
        if len(kept) >= limit:
            reason = f"limited to {limit} events"
            break
        safe = sanitize_event(ev, max_text_chars=max_text_chars)
        event_time = datetime.fromtimestamp(safe.ts_ms / 1000, tz=UTC).isoformat(timespec="seconds")
        size = len(
            json.dumps(
                {
                    "time": event_time,
                    "host": safe.host,
                    "text": safe.text,
                    "fields": safe.fields,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        if used + size > max_bytes:
            reason = f"byte budget of {max_bytes} reached"
            break
        used += size
        kept.append(safe)
    return kept, reason
