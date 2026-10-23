"""Sanitized domain errors; upstream bodies and credentials are never included."""


class NSXError(Exception):
    """Base operational error."""


class AccessDenied(NSXError):
    """Caller or execution identity is not authorized."""


class AuthenticationFailed(NSXError):
    """NSX rejected credentials."""


class ResourceNotFound(NSXError):
    """Resource missing; does not imply endpoint incompatibility."""


class Unavailable(NSXError):
    """Transient transport or target failure."""


class ContractError(NSXError):
    """Unexpected payload, version, or rejected request."""


class LimitExceeded(NSXError):
    """Bounded response cannot be returned safely."""
