"""Gateway Firewall domain reads, independent of the MCP framework."""

import re
from collections.abc import Awaitable, Callable
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ValidationError

from .client import TargetRegistry
from .credentials import Caller
from .endpoints import endpoint_for, validate_policy_path
from .errors import ContractError
from .models import Collection, Detail, FirewallRule, GatewayPolicy, Observation, PolicyObject

T = TypeVar("T", bound=BaseModel)
Progress = Callable[[int, int], Awaitable[None]]
CONFIG_NOTE = (
    "Configuration and realization do not prove that a particular traffic flow is allowed."
)


class GatewayService:
    def __init__(self, registry: TargetRegistry):
        self.registry = registry

    async def list_objects(
        self,
        target: str,
        caller: Caller,
        endpoint: str,
        model: type[T],
        parameters: dict[str, str],
        *,
        cursor: str | None = None,
        page_size: int = 100,
        progress: Progress | None = None,
    ) -> Collection[T]:
        ordered = endpoint in ("gateway_policies", "gateway_rules")
        query = {"sort_by": "sequence_number", "sort_ascending": "true"} if ordered else {}
        page = await self.registry.list_pages(
            target,
            endpoint,
            caller,
            parameters=parameters,
            cursor=cursor,
            page_size=page_size,
            query=query,
            progress=progress,
        )
        try:
            items = [model.model_validate(item) for item in page.items]
        except ValidationError:
            raise ContractError("Invalid NSX policy object response") from None
        _, path = endpoint_for(endpoint, parameters)
        notes = [CONFIG_NOTE]
        if ordered:
            notes.append(
                "Requested sequence_number ascending; response order and category are preserved. "
                "Policy categories and rule scope must be evaluated together; partial pages "
                "are not a complete effective ruleset. Equal sequence numbers have "
                "nondeterministic order in NSX."
            )
        return Collection[model](  # type: ignore[valid-type]
            target=target,
            source=path,
            selection={**parameters, **query},
            items=items,
            complete=page.complete,
            next_cursor=page.next_cursor,
            pages=page.pages,
            collected_at=page.collected_at,
            notes=notes,
        )

    async def detail(
        self,
        target: str,
        caller: Caller,
        endpoint: str,
        model: type[T],
        parameters: dict[str, str],
    ) -> Detail[T]:
        payload = await self.registry.get(target, endpoint, caller, parameters=parameters)
        try:
            data = model.model_validate(payload)
        except ValidationError:
            raise ContractError("Invalid NSX policy object response") from None
        _, path = endpoint_for(endpoint, parameters)
        return Detail[model](  # type: ignore[valid-type]
            target=target, source=path, selection={**parameters}, data=data, notes=[CONFIG_NOTE]
        )

    async def policies(
        self, target: str, caller: Caller, domain_id: str, **kwargs: Any
    ) -> Collection[GatewayPolicy]:
        return await self.list_objects(
            target, caller, "gateway_policies", GatewayPolicy, {"domain_id": domain_id}, **kwargs
        )

    async def policy(
        self, target: str, caller: Caller, domain_id: str, policy_id: str
    ) -> Detail[GatewayPolicy]:
        return await self.detail(
            target,
            caller,
            "gateway_policy",
            GatewayPolicy,
            {"domain_id": domain_id, "policy_id": policy_id},
        )

    async def rules(
        self, target: str, caller: Caller, domain_id: str, policy_id: str, **kwargs: Any
    ) -> Collection[FirewallRule]:
        return await self.list_objects(
            target,
            caller,
            "gateway_rules",
            FirewallRule,
            {"domain_id": domain_id, "policy_id": policy_id},
            **kwargs,
        )

    async def group_members(
        self,
        target: str,
        caller: Caller,
        domain_id: str,
        group_id: str,
        member_type: Literal["ip-addresses", "virtual-machines"],
        *,
        enforcement_point_path: str | None = None,
        cursor: str | None = None,
        page_size: int = 100,
        progress: Progress | None = None,
    ) -> Collection[str | dict[str, Any]]:
        endpoint = "group_ip_members" if member_type == "ip-addresses" else "group_vm_members"
        parameters = {"domain_id": domain_id, "group_id": group_id}
        query = {"enforcement_point_path": enforcement_point_path} if enforcement_point_path else {}
        page = await self.registry.list_pages(
            target,
            endpoint,
            caller,
            parameters=parameters,
            cursor=cursor,
            page_size=page_size,
            query=query,
            progress=progress,
        )
        _, path = endpoint_for(endpoint, parameters)
        return Collection(
            target=target,
            source=path,
            selection={**parameters, **query},
            items=page.items,
            complete=page.complete,
            next_cursor=page.next_cursor,
            pages=page.pages,
            notes=["Membership is limited to the requested member type and enforcement scope."],
        )

    async def statistics(
        self,
        target: str,
        caller: Caller,
        domain_id: str,
        policy_id: str,
        rule_id: str,
        enforcement_point_path: str,
    ) -> Observation:
        validate_policy_path(enforcement_point_path, enforcement=True)
        parameters = {"domain_id": domain_id, "policy_id": policy_id, "rule_id": rule_id}
        query = {"enforcement_point_path": enforcement_point_path}
        data = await self.registry.get(
            target, "gateway_rule_statistics", caller, parameters=parameters, query=query
        )
        results = data.get("results")
        if not isinstance(results, list) or any(not isinstance(row, dict) for row in results):
            raise ContractError("Invalid NSX statistics results")
        _, path = endpoint_for("gateway_rule_statistics", parameters)
        return Observation(
            target=target,
            source=path,
            selection={**parameters, **query},
            data=data,
            complete=not bool(data.get("cursor")),
            notes=[
                "Counters are observations, not proof of connectivity. "
                "A statistics cursor is preserved but this API has no documented cursor input."
            ],
        )

    async def realization(self, target: str, caller: Caller, intent_path: str) -> Observation:
        validate_policy_path(intent_path)
        query = {"intent_path": intent_path, "include_enforced_status": "true"}
        data = await self.registry.get(target, "realization_status", caller, query=query)
        if data.get("intent_path") != intent_path or not (
            isinstance(data.get("publish_status"), str)
            or isinstance(data.get("consolidated_status"), dict)
        ):
            raise ContractError("Invalid NSX realization status response")
        _, path = endpoint_for("realization_status", {})
        return Observation(
            target=target, source=path, selection={**query}, data=data, notes=[CONFIG_NOTE]
        )

    async def reference(self, target: str, caller: Caller, path: str) -> Detail[PolicyObject]:
        """Resolve one group/service reference explicitly; never follow server-supplied URLs."""
        validate_policy_path(path)
        if match := re.fullmatch(r"/infra/domains/([^/]+)/groups/([^/]+)", path):
            return await self.detail(
                target,
                caller,
                "group",
                PolicyObject,
                {"domain_id": match[1], "group_id": match[2]},
            )
        if match := re.fullmatch(r"/infra/services/([^/]+)", path):
            return await self.detail(
                target, caller, "service", PolicyObject, {"service_id": match[1]}
            )
        raise ContractError("Only local domain-group and service references can be resolved")
