"""Bounded GET-only NSX client with isolated credentials and target failure controls."""

import asyncio
import json
import math
import random
import re
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .config import Settings
from .credentials import Caller, CredentialProvider, Credentials
from .endpoints import endpoint_for, validate_edge_scope, validate_policy_path
from .errors import (
    AccessDenied,
    AuthenticationFailed,
    ContractError,
    LimitExceeded,
    ResourceNotFound,
    Unavailable,
)


class PageResult(BaseModel):
    target: str
    endpoint: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    items: list[dict[str, Any] | str]
    next_cursor: str | None
    complete: bool
    pages: int


def decode_json(body: bytes | bytearray) -> Any:
    """JSON observations must not turn NaN/Infinity/overflow into silent null outputs."""

    def reject_constant(value: str) -> Any:
        raise ValueError("Non-finite JSON constant")

    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("JSON floating-point overflow")
        return result

    return json.loads(body, parse_constant=reject_constant, parse_float=finite_float)


def validate_cursor(cursor: Any, *, optional: bool = False) -> None:
    if optional and cursor is None:
        return
    if not isinstance(cursor, str) or not cursor or len(cursor) > 8192:
        raise ContractError("Invalid NSX continuation cursor")


@dataclass
class Breaker:
    failures: int = 0
    opened_at: float | None = None


class TargetRegistry:
    """One registry per process/event loop; credentials never live in target state."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.settings = settings
        self.credentials = CredentialProvider(settings)
        self.transport = transport
        self.sleep = sleep
        self.clock = clock
        self.global_limit = asyncio.Semaphore(settings.global_concurrency)
        self.target_limits: dict[str, asyncio.Semaphore] = {}
        self.breakers: dict[str, Breaker] = {}
        self.shared_clients: dict[str, httpx.AsyncClient] = {}
        self.versions: dict[str, str] = {}

    def list_targets(self, caller: Caller) -> list[str]:
        return sorted(set(self.settings.targets) & caller.allowed_targets)

    def _check_target(self, target: str, caller: Caller) -> None:
        if target not in caller.allowed_targets:
            raise AccessDenied("Caller cannot access target")
        if target not in self.settings.targets:
            raise ContractError("Unknown target alias")

    def _new_client(self, target: str) -> httpx.AsyncClient:
        config = self.settings.targets[target]
        tls = ssl.create_default_context(cafile=str(config.ca_bundle) if config.ca_bundle else None)
        return httpx.AsyncClient(
            base_url=config.url,
            verify=tls,
            follow_redirects=False,
            trust_env=False,
            timeout=self.settings.timeout,
            transport=self.transport,
        )

    @asynccontextmanager
    async def _client(self, target: str) -> AsyncIterator[httpx.AsyncClient]:
        if self.settings.mode == "shared":
            if target not in self.shared_clients:
                self.shared_clients[target] = self._new_client(target)
            yield self.shared_clients[target]
        else:
            async with self._new_client(target) as client:
                yield client

    async def aclose(self) -> None:
        for client in self.shared_clients.values():
            await client.aclose()
        self.shared_clients.clear()

    async def get(
        self,
        target: str,
        endpoint: str,
        caller: Caller,
        *,
        parameters: dict[str, str] | None = None,
        query: Mapping[str, str | int] | None = None,
    ) -> dict[str, Any]:
        """No method/URL input: all network requests are allowlisted GETs."""
        self._check_target(target, caller)
        contract, path = endpoint_for(endpoint, parameters or {})
        query = dict(query or {})
        if set(query) - contract.query:
            raise ContractError("Query parameter is not allowlisted")
        if "sort_by" in query and query["sort_by"] != "sequence_number":
            raise ContractError("Only sequence_number ordering is supported")
        if "sort_ascending" in query and query["sort_ascending"] != "true":
            raise ContractError("Only ascending ordering is supported")
        for key in ("intent_path", "enforcement_point_path"):
            if key in query:
                if not isinstance(query[key], str):
                    raise ContractError("Expected a policy path")
                validate_policy_path(str(query[key]), enforcement=key == "enforcement_point_path")
        if endpoint == "realization_status" and "intent_path" not in query:
            raise ContractError("intent_path required")
        if "include_enforced_status" in query and query["include_enforced_status"] != "true":
            raise ContractError("Only detailed realization status is supported")
        if "edge_path" in query:
            validate_edge_scope(
                str(query.get("enforcement_point_path", "")), str(query["edge_path"])
            )
        if "route_source" in query and query["route_source"] not in (
            "BGP",
            "STATIC",
            "CONNECTED",
            "OSPF",
        ):
            raise ContractError("Invalid route source")
        if "network_prefix" in query:
            from ipaddress import ip_network

            try:
                ip_network(str(query["network_prefix"]), strict=False)
            except ValueError:
                raise ContractError("Invalid network prefix") from None
        if "status" in query:
            allowed = (
                {"UP", "DOWN"}
                if endpoint == "transport_node_tunnels"
                else {"OPEN", "ACKNOWLEDGED", "SUPPRESSED", "RESOLVED"}
            )
            if query["status"] not in allowed:
                raise ContractError("Invalid status filter")
        if "severity" in query and query["severity"] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raise ContractError("Invalid alarm severity")
        if "page_size" in query:
            size = query["page_size"]
            if type(size) is not int or not 1 <= size <= 1000:
                raise ContractError("page_size must be between 1 and 1000")
        if "cursor" in query:
            validate_cursor(query["cursor"])
        credentials = self.credentials.resolve(target, caller)
        breaker = self.breakers.setdefault(target, Breaker())
        if (
            breaker.opened_at is not None
            and self.clock() - breaker.opened_at < self.settings.breaker_cooldown
        ):
            raise Unavailable("Target circuit breaker is open")
        try:
            async with asyncio.timeout(self.settings.timeout):
                result = await self._get(target, path, credentials, query)
        except TimeoutError:
            self._failed(breaker)
            raise Unavailable("NSX request deadline exceeded") from None
        except Unavailable:
            self._failed(breaker)
            raise
        else:
            breaker.failures = 0
            breaker.opened_at = None
            return result

    def _failed(self, breaker: Breaker) -> None:
        breaker.failures += 1
        if breaker.failures >= self.settings.breaker_threshold:
            breaker.opened_at = self.clock()

    async def _get(
        self, target: str, path: str, credentials: Credentials, query: dict[str, str | int]
    ) -> dict[str, Any]:
        limit = self.target_limits.setdefault(
            target, asyncio.Semaphore(self.settings.target_concurrency)
        )
        auth = httpx.BasicAuth(
            credentials.username.get_secret_value(), credentials.password.get_secret_value()
        )
        async with self._client(target) as client:
            for attempt in range(self.settings.attempts):
                retry_after: str | None = None
                try:
                    async with (
                        limit,
                        self.global_limit,
                        client.stream(
                            "GET", path, params=query, auth=auth, headers={"Cookie": ""}
                        ) as response,
                    ):
                        status = response.status_code
                        if status == 401:
                            raise AuthenticationFailed("NSX rejected credentials")
                        if status == 403:
                            raise AccessDenied("NSX denied read permission")
                        if status == 404:
                            raise ResourceNotFound("NSX resource not found")
                        if status in (429, 502, 503, 504):
                            retry_after = response.headers.get("retry-after")
                        elif status != 200:
                            raise ContractError("Unexpected NSX HTTP status")
                        else:
                            body = bytearray()
                            async for chunk in response.aiter_bytes():
                                if len(body) + len(chunk) > self.settings.max_response_bytes:
                                    raise LimitExceeded("NSX response exceeds byte limit")
                                body.extend(chunk)
                            try:
                                payload = decode_json(body)
                            except (ValueError, UnicodeError, RecursionError):
                                raise ContractError("Invalid NSX JSON response") from None
                            if not isinstance(payload, dict):
                                raise ContractError("NSX response must be an object")
                            # Never retain server cookies on shared pooled clients.
                            client.cookies.clear()
                            return payload
                except httpx.TransportError:
                    pass
                finally:
                    client.cookies.clear()
                if attempt + 1 < self.settings.attempts:
                    await self.sleep(self._delay(attempt, retry_after))
        raise Unavailable("NSX unavailable after bounded retries")

    @staticmethod
    def _delay(attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                try:
                    delay = (parsedate_to_datetime(retry_after) - datetime.now(UTC)).total_seconds()
                except (ValueError, TypeError, OverflowError):
                    delay = 0
            return max(0, delay)
        return min(2**attempt, 8) + random.uniform(0, 0.25)

    async def authenticate(self, target: str, caller: Caller) -> str:
        """Validate *caller's* Basic credentials, even in shared execution mode.

        Return NSX's current-user identity; version reads cannot establish authentication.
        No LDAP group membership or execution permissions are inferred from NSX role data.
        """
        self._check_target(target, caller)
        if caller.credentials is None:
            raise AuthenticationFailed("Caller credentials required")
        _, probe_path = endpoint_for("current_user", {})
        try:
            async with asyncio.timeout(self.settings.timeout):
                # Always a fresh client: caller auth cannot borrow service-account state.
                async with self._new_client(target) as client:
                    auth = httpx.BasicAuth(
                        caller.credentials.username.get_secret_value(),
                        caller.credentials.password.get_secret_value(),
                    )
                    limit = self.target_limits.setdefault(
                        target, asyncio.Semaphore(self.settings.target_concurrency)
                    )
                    async with (
                        limit,
                        self.global_limit,
                        client.stream("GET", probe_path, auth=auth) as res,
                    ):
                        if res.status_code == 401:
                            raise AuthenticationFailed("NSX rejected caller credentials")
                        if res.status_code == 403:
                            raise AccessDenied("NSX denied caller identity read")
                        if res.status_code != 200:
                            raise Unavailable("NSX authentication probe unavailable")
                        body = bytearray()
                        async for chunk in res.aiter_bytes():
                            if len(body) + len(chunk) > min(
                                self.settings.max_response_bytes, 65536
                            ):
                                raise Unavailable("Invalid NSX identity response")
                            body.extend(chunk)
                        try:
                            data = decode_json(body)
                        except (ValueError, UnicodeError, RecursionError):
                            raise Unavailable("Invalid NSX identity response") from None
                        username = data.get("user_name") if isinstance(data, dict) else None
                        if (
                            not isinstance(username, str)
                            or not username
                            or len(username) > 1024
                            or any(ord(c) < 32 for c in username)
                        ):
                            raise Unavailable("Invalid NSX identity response")
                        return username
        except (TimeoutError, httpx.TransportError):
            raise Unavailable("NSX authentication probe unavailable") from None

    async def discover_version(self, target: str, caller: Caller) -> str:
        # Always authenticate/authorize this request; a cached version cannot bypass access checks.
        payload = await self.get(target, "node_version", caller)
        version = payload.get("product_version")
        if not isinstance(version, str) or not re.fullmatch(r"4\.\d+(?:\.\d+){0,3}", version):
            raise ContractError("Expected an NSX 4.x product_version")
        self.versions[target] = version
        return version

    async def list_pages(
        self,
        target: str,
        endpoint: str,
        caller: Caller,
        *,
        parameters: dict[str, str] | None = None,
        cursor: str | None = None,
        page_size: int = 100,
        query: Mapping[str, str | int] | None = None,
        progress: Callable[[int, int], Awaitable[None]] | None = None,
    ) -> PageResult:
        """Bound the whole traversal, including all requests, retries and semaphore waits."""
        try:
            async with asyncio.timeout(self.settings.timeout):
                return await self._list_pages(
                    target,
                    endpoint,
                    caller,
                    parameters=parameters,
                    cursor=cursor,
                    page_size=page_size,
                    query=query,
                    progress=progress,
                )
        except TimeoutError:
            raise Unavailable("NSX pagination deadline exceeded") from None

    async def _list_pages(
        self,
        target: str,
        endpoint: str,
        caller: Caller,
        *,
        parameters: dict[str, str] | None = None,
        cursor: str | None = None,
        page_size: int = 100,
        query: Mapping[str, str | int] | None = None,
        progress: Callable[[int, int], Awaitable[None]] | None = None,
    ) -> PageResult:
        """Page-boundary continuation; oversized pages fail instead of silently dropping items."""
        contract, _ = endpoint_for(endpoint, parameters or {})
        validate_cursor(cursor, optional=True)
        if query and set(query) & {"cursor", "page_size"}:
            raise ContractError("Pagination parameters must be passed separately")
        base_query = query or {}
        items: list[dict[str, Any] | str] = []
        seen: set[str] = {cursor} if cursor else set()
        total_bytes = 0
        pages = 0
        async with asyncio.timeout(self.settings.timeout):
            for _ in range(self.settings.max_pages):
                pages += 1
                page_query: dict[str, str | int] = {**base_query, "page_size": page_size}
                if cursor:
                    page_query["cursor"] = cursor
                payload = await self.get(
                    target, endpoint, caller, parameters=parameters, query=page_query
                )
                rows = payload.get(contract.list_key)
                item_type = str if contract.string_items else dict
                if not isinstance(rows, list) or any(
                    not isinstance(row, item_type) for row in rows
                ):
                    raise ContractError("Invalid NSX list results")
                total_bytes += len(json.dumps(payload).encode())
                if (
                    len(items) + len(rows) > self.settings.max_items
                    or total_bytes > self.settings.max_response_bytes
                ):
                    raise LimitExceeded("Pagination budget exceeded; request smaller pages")
                items.extend(rows)
                cursor = payload.get("cursor")
                validate_cursor(cursor, optional=True)
                if cursor in seen:
                    raise ContractError("Repeated NSX continuation cursor")
                if cursor:
                    seen.add(cursor)
                if progress:
                    await progress(pages, self.settings.max_pages)
                if not cursor or len(items) >= self.settings.max_items:
                    break
        return PageResult(
            target=target,
            endpoint=endpoint,
            items=items,
            next_cursor=cursor,
            complete=cursor is None,
            pages=pages,
        )
