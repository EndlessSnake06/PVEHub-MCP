"""Validation for user-supplied values that are embedded in Proxmox API paths.

Proxmox API paths are assembled from tool arguments (node, storage, UPID, snapshot
name, ...).  ``httpx`` normalises literal ``..`` segments before sending a request,
so an unchecked argument such as ``../../access/users`` silently escapes the
``/api2/json`` prefix and turns a narrowly scoped tool into an arbitrary API call.
These helpers reject anything that cannot be a single, literal path segment.
"""

from __future__ import annotations

import re
from typing import Any

from .errors import InvalidArgument

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Characters that either change the meaning of a URL path or are never valid in
# Proxmox object names.  ``%`` is rejected as well so a decoded sequence can never
# be introduced after validation.
_FORBIDDEN_PATH_CHARS = frozenset("/\\%?#")


def _require_text(value: Any, field: str, *, max_length: int) -> str:
    if not isinstance(value, str):
        raise InvalidArgument(f"{field} must be a string")
    if not value or value != value.strip():
        raise InvalidArgument(f"{field} must be non-empty without surrounding whitespace")
    if len(value) > max_length:
        raise InvalidArgument(f"{field} must be at most {max_length} characters")
    if _CONTROL_RE.search(value):
        raise InvalidArgument(f"{field} must not contain control characters")
    return value


def api_segment(value: Any, field: str, *, max_length: int = 128) -> str:
    """Return ``value`` if it is safe as one literal API path segment."""

    text = _require_text(value, field, max_length=max_length)
    if text in {".", ".."}:
        raise InvalidArgument(f"{field} must not be '.' or '..'")
    forbidden = sorted({char for char in text if char in _FORBIDDEN_PATH_CHARS})
    if forbidden:
        rendered = ", ".join(repr(char) for char in forbidden)
        raise InvalidArgument(f"{field} contains characters that are not allowed in a path: {rendered}")
    return text


def task_upid(value: Any) -> str:
    """Validate a PVE/PBS UPID used as an API path segment.

    Formats differ slightly between PVE and PBS, but both are colon separated and
    never contain slashes or whitespace.
    """

    text = _require_text(value, "upid", max_length=512)
    if not text.startswith("UPID:"):
        raise InvalidArgument("upid must start with 'UPID:'")
    if any(char in text for char in _FORBIDDEN_PATH_CHARS) or any(char.isspace() for char in text):
        raise InvalidArgument("upid contains characters that are not allowed in a path")
    parts = text.split(":")
    if len(parts) < 7 or not parts[1]:
        raise InvalidArgument("upid is not a well-formed task id")
    return text
