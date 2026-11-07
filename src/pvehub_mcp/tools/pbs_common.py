"""Shared validation helpers for the curated PBS tool modules."""

from __future__ import annotations

import re
from typing import Any

from ..errors import InvalidArgument

_STORE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_NAMESPACE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_NODE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")

BACKUP_TYPES = ("vm", "ct", "host")
JOB_TYPES = ("prune", "verify", "sync")


def max_bytes(hub: Any) -> int:
    return int(hub.settings.max_output_bytes)


def store_name(value: str) -> str:
    name = value.strip() if isinstance(value, str) else ""
    if not name or not 3 <= len(name) <= 32 or not _STORE_RE.match(name):
        raise InvalidArgument(
            "store must match [A-Za-z0-9_][A-Za-z0-9._-]* and be 3-32 characters"
        )
    return name


def namespace_name(value: str | None, *, field: str = "ns") -> str | None:
    if value is None:
        return None
    name = value.strip()
    segments = name.split("/")
    if (
        not name
        or len(segments) > 8
        or any(not _NAMESPACE_SEGMENT_RE.match(segment) for segment in segments)
    ):
        raise InvalidArgument(
            f"{field} must be a namespace path of at most 8 segments "
            "matching [A-Za-z0-9_][A-Za-z0-9._-]*"
        )
    return name


def backup_type(value: str) -> str:
    kind = value.strip() if isinstance(value, str) else ""
    if kind not in BACKUP_TYPES:
        raise InvalidArgument("backup_type must be one of: vm, ct, host")
    return kind


def backup_id(value: str) -> str:
    identifier = value.strip() if isinstance(value, str) else ""
    if not identifier or len(identifier) > 128:
        raise InvalidArgument("backup_id must be a non-empty backup ID")
    return identifier


def job_id(value: str) -> str:
    identifier = value.strip() if isinstance(value, str) else ""
    if not identifier or len(identifier) > 32 or not _JOB_ID_RE.match(identifier):
        raise InvalidArgument(
            "id must match [A-Za-z0-9_][A-Za-z0-9._-]* and be at most 32 characters"
        )
    return identifier


def backup_time(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise InvalidArgument("backup_time must be a positive Unix epoch integer")
    return value


def node_name(value: str) -> str:
    node = value.strip() if isinstance(value, str) else ""
    if not node or (node != "localhost" and not _NODE_RE.match(node)):
        raise InvalidArgument("node must be 'localhost' or a valid PBS node name")
    return node


def upid_value(value: str) -> str:
    upid = value.strip() if isinstance(value, str) else ""
    if not upid.startswith("UPID:") or len(upid) < 36:
        raise InvalidArgument("upid must be a PBS UPID string")
    return upid
