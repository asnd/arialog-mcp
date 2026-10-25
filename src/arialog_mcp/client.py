"""Async VRLI API v2 client: session handling, retries, circuit breaker, concurrency cap.

Read-only by construction: the only non-GET call is the session login.
No MCP imports here.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings
from .errors import (
    ArialogError,
    AuthError,
    BreakerOpenError,
    QueryError,
    UnavailableError,
)
from .reduce import RawEvent

log = logging.getLogger("arialog_mcp.client")

RETRY_STATUS = {429, 502, 503, 504}
SESSION_EXPIRED = {401, 440}  # 440 "Login Timeout": the session ID has expired
SESSION_REFRESH_FRACTION = 0.9
DEFAULT_SESSION_TTL_S = 1800
MAX_RETRY_AFTER_S = 30.0


@dataclass
class RawEvents:
    events: list[RawEvent]
    complete: bool


@dataclass
class RawBin:
    start_ms: int
    end_ms: int
    value: float


@dataclass
class RawBins:
    bins: list[RawBin]  # sorted by start_ms
    complete: bool
    limit_reached: bool  # VRLI returned as many bins as requested; more may exist


class CircuitBreaker:
    """Opens after N consecutive infrastructure failures; after a cooldown one probe passes."""

    def __init__(self, threshold: int, cooldown_s: float, clock: Callable[[], float]) -> None:
        self._threshold = threshold
        self._cooldown = cooldown_s
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probing = False

    def before(self) -> bool:
        """Raise while open; return True when this call is the single half-open probe."""
        if self._opened_at is None:
            return False
        remaining = self._cooldown - (self._clock() - self._opened_at)
        if remaining > 0 or self._probing:
            wait = max(remaining, 1.0)
            raise BreakerOpenError(
                f"VRLI marked unavailable after repeated failures; retry in {wait:.0f}s"
            )
        self._probing = True
        self._failures = self._threshold - 1  # one more failure re-opens
        return True

    def end_probe(self) -> None:
        self._probing = False

    def success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._probing = False

    def failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = self._clock()


class VRLIClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._s = settings
        self._sleep = sleep
        self._clock = clock
        verify: bool | str = settings.ca_bundle or settings.verify_ssl
        self._http = httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=settings.request_timeout_s,
            verify=verify,
            trust_env=settings.trust_env,
            transport=transport,
        )
        self._query_timeout = httpx.Timeout(
            settings.request_timeout_s, read=settings.query_read_timeout_s
        )
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._breaker = CircuitBreaker(
            settings.breaker_failures, settings.breaker_cooldown_s, clock
        )
        self._login_lock = asyncio.Lock()
        self._token: str | None = None
        self._token_expires: float = 0.0
        self._login_blocked_until: float = 0.0

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ session
    async def _login(self) -> None:
        now = self._clock()
        if now < self._login_blocked_until:
            raise AuthError(
                "VRLI login was rejected earlier; not retrying yet to avoid locking the account"
            )
        body = {
            "username": self._s.username,
            "password": self._s.password.get_secret_value(),
            "provider": self._s.provider,
        }
        try:
            resp = await self._http.post("/api/v2/sessions", json=body)
        except httpx.HTTPError as exc:
            raise UnavailableError(
                f"VRLI unavailable: login failed ({type(exc).__name__})"
            ) from exc
        if resp.status_code in (401, 403):
            self._login_blocked_until = now + self._s.login_cooldown_s
            raise AuthError(
                f"VRLI rejected the credentials for provider {self._s.provider} "
                f"(HTTP {resp.status_code})"
            )
        if resp.status_code in RETRY_STATUS or resp.status_code >= 500:
            raise UnavailableError(f"VRLI login unavailable (HTTP {resp.status_code})")
        if resp.status_code >= 400:
            raise AuthError(f"VRLI login refused (HTTP {resp.status_code})")
        try:
            data = resp.json()
            token = str(data["sessionId"])
            ttl = float(data.get("ttl", DEFAULT_SESSION_TTL_S))
        except (ValueError, KeyError, TypeError) as exc:
            raise UnavailableError("VRLI login returned an unexpected payload") from exc
        self._token = token
        self._token_expires = now + ttl * SESSION_REFRESH_FRACTION
        log.info("vrli session established", extra={"event": "login_ok", "ttl_s": ttl})

    async def _bearer(self) -> str:
        async with self._login_lock:
            if self._token is None or self._clock() >= self._token_expires:
                await self._login()
            assert self._token is not None
            return self._token

    def _invalidate(self, stale: str) -> None:
        if self._token == stale:
            self._token = None

    # ------------------------------------------------------------------ requests
    async def _get(
        self, path: str, params: dict[str, Any] | None = None, *, query: bool = False
    ) -> Any:
        probe = self._breaker.before()
        try:
            return await self._get_with_retries(path, params, query=query)
        finally:
            if probe:
                self._breaker.end_probe()

    async def _get_with_retries(
        self, path: str, params: dict[str, Any] | None, *, query: bool
    ) -> Any:
        timeout = self._query_timeout if query else httpx.USE_CLIENT_DEFAULT
        attempt = 0
        relogged = False
        last: ArialogError = UnavailableError("VRLI request failed")
        while True:
            retry_after = 0.0
            try:
                token = await self._bearer()
                async with self._sem:
                    resp = await self._http.get(
                        path,
                        params=params,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=timeout,
                    )
                code = resp.status_code
                if code in SESSION_EXPIRED and not relogged:
                    self._invalidate(token)
                    relogged = True
                    continue
                if code in SESSION_EXPIRED or code == 403:
                    raise AuthError(f"VRLI refused the session (HTTP {code})")
                if code in RETRY_STATUS or code >= 500:
                    retry_after = _retry_after(resp)
                    raise UnavailableError(f"VRLI unavailable (HTTP {code})")
                if code >= 400:
                    self._breaker.success()  # the appliance is healthy; the query was bad
                    raise QueryError(f"VRLI rejected the query (HTTP {code}): {_detail(resp)}")
                try:
                    payload = resp.json()
                except ValueError as exc:
                    raise UnavailableError("VRLI returned a non-JSON response") from exc
                self._breaker.success()
                return payload
            except UnavailableError as exc:  # includes a 503 during login (appliance starting)
                last = exc
            except httpx.ReadTimeout as exc:
                # VRLI answers partial results at its own query timeout; silence beyond that
                # means it is overloaded. Re-sending the same heavy query would make it worse.
                self._breaker.failure()
                raise UnavailableError(
                    "VRLI did not answer in time (ReadTimeout); narrow the window or add filters"
                ) from exc
            except httpx.HTTPError as exc:
                last = UnavailableError(f"VRLI unavailable: request failed ({type(exc).__name__})")
            attempt += 1
            if attempt > self._s.retries:
                self._breaker.failure()
                raise last
            delay = max(self._s.backoff_base_s * (2 ** (attempt - 1)), retry_after)
            log.warning(
                "vrli request retry",
                extra={"event": "retry", "attempt": attempt, "delay_s": delay, "reason": str(last)},
            )
            await self._sleep(delay)

    # ------------------------------------------------------------------ API
    async def version(self) -> dict[str, Any]:
        data = await self._get("/api/v2/version")  # requires a session (API docs)
        return data if isinstance(data, dict) else {"raw": data}

    async def events(self, constraints: str, *, limit: int) -> RawEvents:
        data = await self._get(
            f"/api/v2/events/{constraints}",
            {
                "limit": limit,
                "timeout": self._s.query_timeout_ms,
                "order-by-direction": "DESC",
            },
            query=True,
        )
        try:
            events = [_parse_event(e) for e in data.get("events", [])]
            return RawEvents(events=events, complete=bool(data.get("complete", True)))
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise UnavailableError("VRLI events response had an unexpected shape") from exc

    async def aggregated(self, constraints: str, *, bin_width_ms: int, limit: int) -> RawBins:
        # VRLI returns 100 bins unless `limit` is given (max 2000); bin order and whether
        # empty bins are included are not documented, so the result is sorted here and
        # gaps are filled by the caller.
        data = await self._get(
            f"/api/v2/aggregated-events/{constraints}",
            {
                "bin-width": bin_width_ms,
                "aggregation-function": "COUNT",
                "limit": limit,
                "timeout": self._s.query_timeout_ms,
            },
            query=True,
        )
        try:
            raw = data.get("bins", [])
            bins = [
                RawBin(int(b["minTimestamp"]), int(b["maxTimestamp"]), float(b.get("value", 0)))
                for b in raw
            ]
            bins.sort(key=lambda b: b.start_ms)
            return RawBins(
                bins=bins,
                complete=bool(data.get("complete", True)),
                limit_reached=len(raw) >= limit,
            )
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise UnavailableError(
                "VRLI aggregated-events response had an unexpected shape"
            ) from exc


def _parse_event(raw: dict[str, Any]) -> RawEvent:
    text = str(raw.get("text", ""))
    fields: dict[str, str] = {}
    for f in raw.get("fields", []) or []:
        if not isinstance(f, dict):
            continue
        name = f.get("name")
        if not name or str(name) in fields:
            continue
        value = _field_value(f, text)
        if value is not None:
            fields[str(name)] = value
    return RawEvent(ts_ms=int(raw["timestamp"]), text=text, fields=fields)


def _field_value(f: dict[str, Any], text: str) -> str | None:
    """A field carries either ``content`` or a ``startPosition``/``length`` slice of the text."""
    if "content" in f:
        return str(f["content"])
    start, length = f.get("startPosition"), f.get("length")
    if type(start) is not int or type(length) is not int or start < 0 or length < 0:
        return None
    # Offsets index the event text as a Java string, i.e. in UTF-16 code units.
    units = text.encode("utf-16-le")[2 * start : 2 * (start + length)]
    if len(units) != 2 * length:
        return None
    return units.decode("utf-16-le", errors="replace")


def _retry_after(resp: httpx.Response) -> float:
    value = resp.headers.get("retry-after", "")
    return min(float(value), MAX_RETRY_AFTER_S) if value.isdigit() else 0.0


def _detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        msg = body.get("errorMessage") or body.get("message") or ""
    except (ValueError, AttributeError):
        msg = resp.text
    return str(msg)[:200]
