"""Read-only MCP tools with per-invocation identity and authorization."""

import json
import logging
import sys
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from pydantic import BaseModel, Field

from .client import TargetRegistry
from .credentials import Caller, request_caller
from .errors import AccessDenied, NSXError
from .gateway import GatewayService
from .models import Collection, Detail, FirewallRule, GatewayPolicy, Observation, PolicyObject
from .operation_tools import register_operation_tools

READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


class VersionResult(BaseModel):
    target: str
    version: str
    compatibility: str = "NSX 4.x candidate; appliance validation pending"


audit = logging.getLogger("nsxt_mcp.audit")
PageSize = Annotated[int, Field(ge=1, le=1000)]


class AuditFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        keys = (
            "caller",
            "tool",
            "target",
            "execution_mode",
            "credential_profile",
            "outcome",
            "duration_ms",
        )
        return json.dumps(
            {
                "event": "nsx_tool_call",
                "timestamp": record.created,
                **{key: getattr(record, key, None) for key in keys},
            }
        )


def configure_audit_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(AuditFormatter())
    audit.handlers = [handler]
    audit.setLevel(logging.INFO)
    audit.propagate = False


def create_server(registry: TargetRegistry, caller: Caller | None = None) -> FastMCP:
    """Fixed caller for stdio; HTTP resolves identity from the current ASGI request."""

    def identity() -> Caller:
        return caller if caller is not None else request_caller()

    groups: dict[str, str] = {}

    def register_tool(
        group: str, *, timeout: float | None = None
    ) -> Callable[[Callable[..., Any]], Any]:
        def register(function: Callable[..., Any]) -> Any:
            groups[function.__name__] = group
            options: dict[str, Any] = {"annotations": READ_ONLY}
            if timeout is not None:
                options["timeout"] = timeout
            return server.tool(**options)(function)

        return register

    class Guard(Middleware):
        async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
            who = identity()
            name = context.message.name
            group = groups.get(name)
            started = time.monotonic()
            target = (context.message.arguments or {}).get("target")
            outcome = "error"
            try:
                if group not in who.tool_groups:
                    raise AccessDenied("Caller cannot access tool group")
                result = await call_next(context)
                outcome = "ok"
                return result
            except NSXError as exc:
                raise ToolError(str(exc)) from None
            except ToolError as exc:
                if isinstance(exc.__cause__, NSXError):
                    raise ToolError(str(exc.__cause__)) from None
                raise
            finally:
                profile = None
                if isinstance(target, str) and target in registry.settings.targets:
                    profile = registry.settings.targets[target].credential_profile
                audit.info(
                    "NSX tool call",
                    extra={
                        "caller": who.identity,
                        "tool": name,
                        "target": target if isinstance(target, str) else None,
                        "execution_mode": registry.settings.mode,
                        "credential_profile": profile
                        if registry.settings.mode == "shared"
                        else None,
                        "outcome": outcome,
                        "duration_ms": int((time.monotonic() - started) * 1000),
                    },
                )

    @asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await registry.aclose()

    server = FastMCP("nsxt-mcp", lifespan=lifespan, mask_error_details=True, middleware=[Guard()])
    gateway = GatewayService(registry)

    @register_tool("metadata")
    async def nsx_list_targets() -> list[str]:
        """List configured target aliases accessible to this caller; no network requests."""
        return registry.list_targets(identity())

    @register_tool("metadata")
    async def nsx_get_version(target: str) -> VersionResult:
        """Read the selected NSX Manager version. Requires an explicit target alias."""
        try:
            version = await registry.discover_version(target, identity())
        except NSXError as exc:
            raise ToolError(str(exc)) from None
        return VersionResult(target=target, version=version)

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_list_gateway_firewall_policies(
        target: str,
        ctx: Context,
        domain_id: str = "default",
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[GatewayPolicy]:
        """List domain-scoped Gateway Firewall policies, retaining category and applied scope.

        All policies in the domain are returned, not a gateway-filtered effective ruleset.
        """
        return await gateway.policies(
            target,
            identity(),
            domain_id,
            cursor=cursor,
            page_size=page_size,
            progress=lambda done, total: ctx.report_progress(done, total),
        )

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_get_gateway_firewall_policy(
        target: str,
        policy_id: str,
        domain_id: str = "default",
    ) -> Detail[GatewayPolicy]:
        """Read one Gateway Firewall policy including category, sequence and scope."""
        return await gateway.policy(target, identity(), domain_id, policy_id)

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_list_gateway_firewall_rules(
        target: str,
        policy_id: str,
        ctx: Context,
        domain_id: str = "default",
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[FirewallRule]:
        """List rules in sequence order, retaining disabled/logging flags, scope and references.

        Follow next_cursor when complete=false. No traffic-permission conclusion is inferred.
        """
        return await gateway.rules(
            target,
            identity(),
            domain_id,
            policy_id,
            cursor=cursor,
            page_size=page_size,
            progress=lambda done, total: ctx.report_progress(done, total),
        )

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_get_gateway_firewall_rule_statistics(
        target: str,
        policy_id: str,
        rule_id: str,
        enforcement_point_path: str,
        domain_id: str = "default",
    ) -> Observation:
        """Read rule counters for an explicit enforcement-point policy path; never reset them."""
        return await gateway.statistics(
            target, identity(), domain_id, policy_id, rule_id, enforcement_point_path
        )

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_get_group(
        target: str,
        group_id: str,
        domain_id: str = "default",
    ) -> Detail[PolicyObject]:
        """Read group expressions and tags; configuration is not realized membership."""
        return await gateway.detail(
            target,
            identity(),
            "group",
            PolicyObject,
            {"domain_id": domain_id, "group_id": group_id},
        )

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_get_group_members(
        target: str,
        group_id: str,
        member_type: Literal["ip-addresses", "virtual-machines"],
        ctx: Context,
        domain_id: str = "default",
        enforcement_point_path: str | None = None,
        cursor: str | None = None,
        page_size: PageSize = 100,
    ) -> Collection[str | dict[str, Any]]:
        """Read realized members of the selected type, optionally at one enforcement point.

        IP membership may be empty for groups containing other member types.
        """
        return await gateway.group_members(
            target,
            identity(),
            domain_id,
            group_id,
            member_type,
            enforcement_point_path=enforcement_point_path,
            cursor=cursor,
            page_size=page_size,
            progress=lambda done, total: ctx.report_progress(done, total),
        )

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_get_service(target: str, service_id: str) -> Detail[PolicyObject]:
        """Read a service and its protocol/port entries by ID."""
        return await gateway.detail(
            target, identity(), "service", PolicyObject, {"service_id": service_id}
        )

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_resolve_firewall_reference(target: str, path: str) -> Detail[PolicyObject]:
        """Resolve a local domain-group or service policy path from a rule. ANY is a literal,
        not a resource; gateway-local legacy group paths and external URLs are not followed.
        """
        return await gateway.reference(target, identity(), path)

    @register_tool("gateway_firewall", timeout=registry.settings.timeout)
    async def nsx_get_realization_status(target: str, intent_path: str) -> Observation:
        """Read consolidated realization and enforcement-point status for a local intent path."""
        return await gateway.realization(target, identity(), intent_path)

    groups.update(register_operation_tools(server, registry, identity))
    return server
