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
SESSION_REFRESH_FRACTION = 0.9
DEFAULT_SESSION_TTL_S = 1800


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
    bins: list[RawBin]
    complete: bool


class CircuitBreaker:
    """Opens after N consecutive infrastructure failures; half-opens after a cooldown."""

    def __init__(self, threshold: int, cooldown_s: float, clock: Callable[[], float]) -> None:
        self._threshold = threshold
        self._cooldown = cooldown_s
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None

    def before(self) -> None:
        if self._opened_at is None:
            return
        remaining = self._cooldown - (self._clock() - self._opened_at)
        if remaining > 0:
            raise BreakerOpenError(
                f"VRLI marked unavailable after repeated failures; retry in {remaining:.0f}s"
            )
        self._opened_at = None  # half-open: let one request through
        self._failures = self._threshold - 1

    def success(self) -> None:
        self._failures = 0
        self._opened_at = None

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
        self, path: str, params: dict[str, Any] | None = None, *, auth: bool = True
    ) -> Any:
        self._breaker.before()
        attempt = 0
        relogged = False
        last: ArialogError = UnavailableError("VRLI request failed")
        while True:
            try:
                token = await self._bearer() if auth else None
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                async with self._sem:
                    resp = await self._http.get(path, params=params, headers=headers)
                code = resp.status_code
                if code == 401 and token and not relogged:
                    self._invalidate(token)
                    relogged = True
                    continue
                if code in (401, 403):
                    raise AuthError(f"VRLI refused the session (HTTP {code})")
                if code in RETRY_STATUS or code >= 500:
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
            except httpx.HTTPError as exc:
                last = UnavailableError(f"VRLI unavailable: request failed ({type(exc).__name__})")
            attempt += 1
            if attempt > self._s.retries:
                self._breaker.failure()
                raise last
            delay = self._s.backoff_base_s * (2 ** (attempt - 1))
            log.warning(
                "vrli request retry",
                extra={"event": "retry", "attempt": attempt, "delay_s": delay, "reason": str(last)},
            )
            await self._sleep(delay)

    # ------------------------------------------------------------------ API
    async def version(self) -> dict[str, Any]:
        data = await self._get("/api/v1/version", auth=False)
        return data if isinstance(data, dict) else {"raw": data}

    async def events(self, constraints: str, *, limit: int) -> RawEvents:
        data = await self._get(
            f"/api/v2/events/{constraints}",
            {
                "limit": limit,
                "timeout": self._s.query_timeout_ms,
                "order-by-direction": "DESC",
            },
        )
        try:
            events = [_parse_event(e) for e in data.get("events", [])]
            return RawEvents(events=events, complete=bool(data.get("complete", True)))
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise UnavailableError("VRLI events response had an unexpected shape") from exc

    async def aggregated(self, constraints: str, *, bin_width_ms: int) -> RawBins:
        data = await self._get(
            f"/api/v2/aggregated-events/{constraints}",
            {
                "bin-width": bin_width_ms,
                "aggregation-function": "COUNT",
                "timeout": self._s.query_timeout_ms,
            },
        )
        try:
            bins = [
                RawBin(int(b["minTimestamp"]), int(b["maxTimestamp"]), float(b.get("value", 0)))
                for b in data.get("bins", [])
            ]
            return RawBins(bins=bins, complete=bool(data.get("complete", True)))
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise UnavailableError(
                "VRLI aggregated-events response had an unexpected shape"
            ) from exc


def _parse_event(raw: dict[str, Any]) -> RawEvent:
    fields: dict[str, str] = {}
    for f in raw.get("fields", []) or []:
        name = f.get("name")
        if name and name not in fields:
            fields[str(name)] = str(f.get("content", ""))
    return RawEvent(ts_ms=int(raw["timestamp"]), text=str(raw.get("text", "")), fields=fields)


def _detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        msg = body.get("errorMessage") or body.get("message") or ""
    except (ValueError, AttributeError):
        msg = resp.text
    return str(msg)[:200]
