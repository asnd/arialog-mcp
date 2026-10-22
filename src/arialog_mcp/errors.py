"""Domain exceptions. Nothing here imports MCP/FastMCP."""


class ArialogError(Exception):
    """Base class; messages are safe to show to an LLM/user (never contain secrets)."""


class InvalidInputError(ArialogError):
    """The caller supplied an invalid window/filter."""


class AuthError(ArialogError):
    """VRLI rejected the credentials or the session."""


class QueryError(ArialogError):
    """VRLI rejected the query (HTTP 4xx other than auth)."""


class UnavailableError(ArialogError):
    """VRLI is unreachable or failing (timeouts, 5xx, bad payloads)."""


class BreakerOpenError(UnavailableError):
    """Circuit breaker is open; the appliance is not being called."""
