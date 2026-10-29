"""Routing and fabric observations, with explicit scopes and bounded fleet reads."""

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from .client import TargetRegistry
from .credentials import Caller
from .endpoints import endpoint_for
from .errors import AccessDenied, ContractError, LimitExceeded, NSXError
from .models import Collection, Observation

Progress = Callable[[int, int], Awaitable[None]]


def redact_secrets(value: Any) -> Any:
    """Remove secret values sometimes included on BGP/transport-node configuration reads."""
    if isinstance(value, dict):
        return {
            key: "[redacted]"
            if key.lower().replace("-", "_")
            in {
                "password",
                "passwd",
                "passphrase",
                "secret",
                "private_key",
                "shared_secret",
                "client_secret",
                "api_key",
                "access_key",
                "token",
                "access_token",
                "authorization",
                "credential",
                "credentials",
            }
            else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


class FleetTarget(BaseModel):
    target: str
    readable: bool
    data: dict[str, Any] | None = None
    error_type: str | None = None
    error: str | None = None


class FleetHealth(BaseModel):
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = "/api/v1/cluster/status"
    targets: list[FleetTarget]
    complete: bool
    notes: list[str] = [
        "readable means the management status read succeeded, not that all services are healthy."
    ]


class OperationsService:
    def __init__(self, registry: TargetRegistry):
        self.registry = registry

    async def listing(
        self,
        target: str,
        caller: Caller,
        endpoint: str,
        *,
        parameters: dict[str, str] | None = None,
        query: Mapping[str, str | int] | None = None,
        cursor: str | None = None,
        page_size: int = 100,
        runtime: bool = False,
        progress: Progress | None = None,
        notes: list[str] | None = None,
    ) -> Collection[dict[str, Any]]:
        parameters = parameters or {}
        page = await self.registry.list_pages(
            target,
            endpoint,
            caller,
            parameters=parameters,
            query=query,
            cursor=cursor,
            page_size=page_size,
            progress=progress,
        )
        _, path = endpoint_for(endpoint, parameters)
        return Collection[dict[str, Any]](
            target=target,
            source=path,
            selection={**parameters, **(query or {})},
            collected_at=page.collected_at,
            items=redact_secrets(page.items),
            complete=page.complete,
            next_cursor=page.next_cursor,
            pages=page.pages,
            notes=[self._note(runtime), *(notes or [])],
        )

    async def read(
        self,
        target: str,
        caller: Caller,
        endpoint: str,
        *,
        parameters: dict[str, str] | None = None,
        query: Mapping[str, str | int] | None = None,
        runtime: bool = False,
    ) -> Observation:
        parameters = parameters or {}
        data = await self.registry.get(target, endpoint, caller, parameters=parameters, query=query)
        if not data:
            raise ContractError("Empty NSX object response")
        _, path = endpoint_for(endpoint, parameters)
        return Observation(
            target=target,
            source=path,
            selection={**parameters, **(query or {})},
            data=redact_secrets(data),
            complete=not bool(data.get("cursor")),
            notes=[self._note(runtime)],
        )

    @staticmethod
    def _note(runtime: bool) -> str:
        return (
            "Observed state may be cached by NSX; native timestamps and Edge/enforcement scope "
            "are preserved. This is not a traffic simulation."
            if runtime
            else "Configured intent is not proof of realized state or connectivity."
        )

    async def fleet_health(
        self, targets: list[str], caller: Caller, progress: Progress | None = None
    ) -> FleetHealth:
        if not targets or len(targets) > self.registry.settings.max_fleet_targets:
            raise ContractError("Select between 1 and max_fleet_targets explicit targets")
        if len(set(targets)) != len(targets):
            raise ContractError("Duplicate fleet targets")
        if not set(targets) <= set(self.registry.list_targets(caller)):
            raise AccessDenied("Fleet selection includes unknown or unauthorized targets")
        results: dict[str, FleetTarget] = {}
        queue = iter(targets)

        async def worker() -> None:
            for target in queue:
                try:
                    data = await self.registry.get(target, "cluster_status", caller)
                    if not data:
                        raise ContractError("Empty NSX cluster status")
                    if len(json.dumps(data).encode()) > 16384:
                        raise LimitExceeded("Cluster status exceeds fleet per-target budget")
                    result = FleetTarget(target=target, readable=True, data=redact_secrets(data))
                except NSXError as exc:
                    result = FleetTarget(
                        target=target, readable=False, error_type=type(exc).__name__, error=str(exc)
                    )
                results[target] = result
                if progress:
                    await progress(len(results), len(targets))

        tasks = [
            asyncio.create_task(worker())
            for _ in range(min(self.registry.settings.fleet_concurrency, len(targets)))
        ]
        try:
            async with asyncio.timeout(self.registry.settings.timeout):
                await asyncio.gather(*tasks)
        except TimeoutError:
            for target in targets:
                results.setdefault(
                    target,
                    FleetTarget(
                        target=target,
                        readable=False,
                        error_type="Unavailable",
                        error="Fleet deadline exceeded before status collection completed",
                    ),
                )
            if progress:
                await progress(len(targets), len(targets))
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        response = FleetHealth(
            targets=[results[t] for t in targets],
            complete=all(result.readable for result in results.values()),
        )
        if len(response.model_dump_json().encode()) > self.registry.settings.max_response_bytes:
            raise LimitExceeded("Fleet output budget exceeded; select fewer targets")
        return response
