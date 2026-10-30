"""Async VRLI API v2 client: session handling, retries, circuit breaker, concurrency cap.

Read-only by construction: the only non-GET call is the session login.
No MCP imports here.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import secrets
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import SecretStr

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
SESSION_EXPIRED = {401, 440}
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
    bins: list[RawBin]
    complete: bool
    limit_reached: bool = False


@dataclass(frozen=True)
class Credentials:
    """VRLI login of one caller (LDAP passthrough). The password is never logged."""

    username: str
    password: SecretStr = field(repr=False)


@dataclass
class _Session:
    """One VRLI login: its bearer token and its own lockout guard."""

    username: str
    password: SecretStr = field(repr=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    token: str | None = None
    expires: float = 0.0
    blocked_until: float = 0.0


class CircuitBreaker:
    """Opens after N consecutive infrastructure failures; half-opens after a cooldown."""

    def __init__(self, threshold: int, cooldown_s: float, clock: Callable[[], float]) -> None:
        self._threshold = threshold
        self._cooldown = cooldown_s
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = asyncio.Lock()

    async def before(self) -> None:
        async with self._lock:
            if self._opened_at is None:
                return
            remaining = self._cooldown - (self._clock() - self._opened_at)
            if remaining > 0:
                raise BreakerOpenError(
                    f"VRLI marked unavailable after repeated failures; retry in {remaining:.0f}s"
                )
            if self._probe_in_flight:
                raise BreakerOpenError("VRLI recovery probe is already in progress")
            self._probe_in_flight = True
            self._failures = self._threshold - 1

    @property
    def is_open(self) -> bool:
        return self._opened_at is not None and self._clock() - self._opened_at < self._cooldown

    def success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._probe_in_flight = False

    def failure(self) -> None:
        self._probe_in_flight = False
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = self._clock()

    def abandon_probe(self) -> None:
        self._probe_in_flight = False


class VRLIClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self._s = settings
        self._sleep = sleep
        self._clock = clock
        self._jitter = jitter
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
        self._service: _Session | None = (
            _Session(settings.username, settings.password)
            if settings.username and settings.password
            else None
        )
        # Per-user sessions, keyed by HMAC(user, password) so a changed or wrong password
        # never reuses another login's session; least recently used are dropped first.
        self._users: OrderedDict[str, _Session] = OrderedDict()
        # VRLI rejections per username outlive session eviction (AD lockout guard).
        self._user_blocked: dict[str, float] = {}
        self._hmac_key = secrets.token_bytes(32)

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def breaker_open(self) -> bool:
        """True while VRLI calls are short-circuited (used by the readiness probe)."""
        return self._breaker.is_open

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        # Exponential with "equal jitter" so concurrent callers do not retry in lockstep;
        # a server-supplied Retry-After wins, but nothing waits longer than backoff_max_s.
        base = self._s.backoff_base_s * (2 ** (attempt - 1))
        delay = base / 2 + self._jitter() * base / 2
        if retry_after is not None:
            delay = max(delay, retry_after)
        return min(delay, self._s.backoff_max_s)

    # ------------------------------------------------------------------ session
    def _session(self, creds: Credentials | None) -> _Session:
        if creds is None:
            if self._service is None:
                # LDAP mode has no service account: never fall back to a shared identity.
                raise AuthError("no VRLI credentials for this request")
            return self._service
        msg = f"{creds.username}\x00{creds.password.get_secret_value()}".encode()
        key = hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()
        sess = self._users.get(key)
        if sess is None:
            sess = _Session(creds.username, creds.password)
            self._users[key] = sess
            while len(self._users) > self._s.max_user_sessions:
                self._users.popitem(last=False)
        self._users.move_to_end(key)
        return sess

    def _blocked_until(self, sess: _Session) -> float:
        if sess is self._service:
            return sess.blocked_until
        return self._user_blocked.get(sess.username.lower(), 0.0)

    def _block(self, sess: _Session, until: float) -> None:
        if sess is self._service:
            sess.blocked_until = until
            return
        now = self._clock()
        if len(self._user_blocked) >= 4 * self._s.max_user_sessions:
            self._user_blocked = {u: t for u, t in self._user_blocked.items() if t > now}
        self._user_blocked[sess.username.lower()] = until

    async def _login(self, sess: _Session) -> None:
        now = self._clock()
        if now < self._blocked_until(sess):
            raise AuthError(
                "VRLI login was rejected earlier; not retrying yet to avoid locking the account"
            )
        body = {
            "username": sess.username,
            "password": sess.password.get_secret_value(),
            "provider": self._s.provider,
        }
        try:
            code, headers, content = await self._request("POST", "/api/v2/sessions", json=body)
        except httpx.HTTPError as exc:
            raise UnavailableError(
                f"VRLI unavailable: login failed ({type(exc).__name__})"
            ) from exc
        if code in (401, 403):
            self._block(sess, now + self._s.login_cooldown_s)
            raise AuthError(
                f"VRLI rejected the credentials for provider {self._s.provider} (HTTP {code})"
            )
        if code in RETRY_STATUS or code >= 500:
            raise UnavailableError(f"VRLI login unavailable (HTTP {code})")
        if code >= 400:
            raise AuthError(f"VRLI login refused (HTTP {code})")
        try:
            data = json.loads(content)
            token = str(data["sessionId"])
            ttl = float(data.get("ttl", DEFAULT_SESSION_TTL_S))
        except (ValueError, KeyError, TypeError) as exc:
            raise UnavailableError("VRLI login returned an unexpected payload") from exc
        sess.token = token
        sess.expires = now + ttl * SESSION_REFRESH_FRACTION
        log.info(
            "vrli session established",
            extra={
                "event": "login_ok",
                "ttl_s": ttl,
                "vrli_user": "service" if sess is self._service else sess.username,
            },
        )

    async def _bearer(self, sess: _Session) -> str:
        async with sess.lock:
            if sess.token is None or self._clock() >= sess.expires:
                await self._login(sess)
            assert sess.token is not None
            return sess.token

    @staticmethod
    def _invalidate(sess: _Session, stale: str) -> None:
        if sess.token == stale:
            sess.token = None

    # ------------------------------------------------------------------ requests
    async def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        auth: bool = True,
        creds: Credentials | None = None,
        query: bool = False,
    ) -> Any:
        sess = self._session(creds) if auth else None  # fail closed before any I/O
        await self._breaker.before()
        attempt = 0
        relogged = False
        last: ArialogError = UnavailableError("VRLI request failed")
        while True:
            retry_after: float | None = None
            try:
                token = await self._bearer(sess) if sess else None
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                async with self._sem:
                    code, response_headers, content = await self._request(
                        "GET",
                        path,
                        params=params,
                        headers=headers,
                        timeout=(self._query_timeout if query else httpx.USE_CLIENT_DEFAULT),
                    )
                if code in SESSION_EXPIRED and sess and token and not relogged:
                    self._invalidate(sess, token)
                    relogged = True
                    continue
                if code in SESSION_EXPIRED or code == 403:
                    raise AuthError(f"VRLI refused the session (HTTP {code})")
                if code in RETRY_STATUS or code >= 500:
                    retry_after = _retry_after(response_headers)
                    raise UnavailableError(f"VRLI unavailable (HTTP {code})")
                if code >= 400:
                    self._breaker.success()  # the appliance is healthy; the query was bad
                    raise QueryError(f"VRLI rejected the query (HTTP {code}): {_detail(content)}")
                try:
                    payload = json.loads(content)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise UnavailableError("VRLI returned a non-JSON response") from exc
                self._breaker.success()
                return payload
            except AuthError:
                self._breaker.success()
                raise
            except UnavailableError as exc:  # includes a 503 during login (appliance starting)
                last = exc
            except httpx.ReadTimeout as exc:
                # The appliance returns a partial result at its own query timeout; do not resend
                # the same expensive query if it fails to respond even after the margin.
                self._breaker.failure()
                raise UnavailableError(
                    "VRLI did not answer in time (ReadTimeout); narrow the window or add filters"
                ) from exc
            except httpx.HTTPError as exc:
                last = UnavailableError(f"VRLI unavailable: request failed ({type(exc).__name__})")
            except BaseException:
                self._breaker.abandon_probe()
                raise
            attempt += 1
            if attempt > self._s.retries:
                self._breaker.failure()
                raise last
            delay = self._backoff(attempt, retry_after)
            log.warning(
                "vrli request retry",
                extra={"event": "retry", "attempt": attempt, "delay_s": delay, "reason": str(last)},
            )
            await self._sleep(delay)

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> tuple[int, httpx.Headers, bytes]:
        async with self._http.stream(method, path, **kwargs) as response:
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > self._s.max_response_bytes:
                    raise UnavailableError("VRLI response exceeded the configured byte limit")
                content.extend(chunk)
            return response.status_code, response.headers, bytes(content)

    # ------------------------------------------------------------------ API
    async def version(self, *, creds: Credentials | None = None) -> dict[str, Any]:
        data = await self._get("/api/v2/version", creds=creds)
        return data if isinstance(data, dict) else {"raw": data}

    async def events(
        self, constraints: str, *, limit: int, creds: Credentials | None = None
    ) -> RawEvents:
        data = await self._get(
            f"/api/v2/events/{constraints}",
            {
                "limit": limit,
                "timeout": self._s.query_timeout_ms,
                "order-by-direction": "DESC",
            },
            creds=creds,
            query=True,
        )
        try:
            events = [
                _parse_event(
                    e,
                    max_fields=self._s.max_event_fields,
                    max_field_chars=self._s.max_event_field_chars,
                )
                for e in data.get("events", [])
            ]
            return RawEvents(events=events, complete=bool(data.get("complete", True)))
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise UnavailableError("VRLI events response had an unexpected shape") from exc

    async def aggregated(
        self,
        constraints: str,
        *,
        bin_width_ms: int,
        limit: int = 100,
        creds: Credentials | None = None,
    ) -> RawBins:
        data = await self._get(
            f"/api/v2/aggregated-events/{constraints}",
            {
                "bin-width": bin_width_ms,
                "aggregation-function": "COUNT",
                "limit": limit,
                "timeout": self._s.query_timeout_ms,
            },
            creds=creds,
            query=True,
        )
        try:
            raw = data.get("bins", [])
            bins = [
                RawBin(int(b["minTimestamp"]), int(b["maxTimestamp"]), float(b.get("value", 0)))
                for b in raw
            ]
            bins.sort(key=lambda bin_: bin_.start_ms)
            return RawBins(
                bins=bins,
                complete=bool(data.get("complete", True)),
                limit_reached=len(raw) >= limit,
            )
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise UnavailableError(
                "VRLI aggregated-events response had an unexpected shape"
            ) from exc


def _parse_event(
    raw: dict[str, Any], *, max_fields: int = 50, max_field_chars: int = 500
) -> RawEvent:
    text = str(raw.get("text", ""))
    fields: dict[str, str] = {}
    for f in (raw.get("fields", []) or [])[:max_fields]:
        if not isinstance(f, dict):
            continue
        name = f.get("name")
        if name and name not in fields:
            value = f.get("content")
            if value is None:
                start, length = f.get("startPosition"), f.get("length")
                if type(start) is int and type(length) is int and start >= 0 and length >= 0:
                    units = text.encode("utf-16-le")[2 * start : 2 * (start + length)]
                    if len(units) == 2 * length:
                        value = units.decode("utf-16-le", errors="replace")
            if value is not None:
                fields[str(name)[:128]] = str(value)[:max_field_chars]
    return RawEvent(ts_ms=int(raw["timestamp"]), text=text, fields=fields)


def _retry_after(headers: httpx.Headers) -> float | None:
    """Retry-After in seconds (delta form only; HTTP-date is ignored)."""
    raw = headers.get("retry-after", "").strip()
    try:
        return min(MAX_RETRY_AFTER_S, max(0.0, float(raw))) if raw else None
    except ValueError:
        return None


def _detail(content: bytes) -> str:
    try:
        body = json.loads(content)
        msg = body.get("errorMessage") or body.get("message") or ""
    except (ValueError, AttributeError, UnicodeDecodeError):
        msg = content.decode("utf-8", errors="replace")
    return str(msg)[:200]
