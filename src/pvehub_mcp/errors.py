"""Typed errors used across the server."""

from __future__ import annotations

from typing import Any


class PVEHubError(Exception):
    """Base class for all expected errors."""

    code = "internal_error"
    http_status: int | None = None

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class ConfigError(PVEHubError):
    code = "config_error"


class PolicyError(PVEHubError):
    code = "policy_denied"


class ConfirmRequired(PolicyError):
    code = "confirm_required"


class PermissionDenied(PVEHubError):
    code = "permission_denied"


class AuthenticationError(PVEHubError):
    code = "authentication_failed"


class NotFound(PVEHubError):
    code = "not_found"


class UpstreamError(PVEHubError):
    code = "upstream_error"


class TaskFailed(UpstreamError):
    code = "task_failed"


class TaskTimeout(UpstreamError):
    code = "task_timeout"


class SSHUnavailable(PVEHubError):
    code = "ssh_unavailable"


class InvalidArgument(PVEHubError):
    code = "invalid_argument"


class AuditError(PVEHubError):
    code = "audit_error"


def error_payload(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, PVEHubError):
        return exc.as_dict()
    return {"code": "internal_error", "message": str(exc) or exc.__class__.__name__}
