"""Small helpers shared by tools."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

DEFAULT_LIMIT = 65536


def dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)


def ok(data: Any, *, max_bytes: int = DEFAULT_LIMIT) -> str:
    text = dumps({"ok": True, "data": data})
    if len(text.encode("utf-8")) <= max_bytes:
        return text
    preview = dumps(data)[: max(512, max_bytes // 2)]
    return dumps(
        {
            "ok": True,
            "truncated": True,
            "data_preview": preview,
            "hint": "response exceeded max_output_bytes; narrow the request",
        }
    )


def fail(code: str, message: str, **extra: Any) -> str:
    payload: dict[str, Any] = {"ok": False, "error": {"code": code, "message": message}}
    if extra:
        payload["error"]["details"] = extra
    return dumps(payload)


def pick(data: Any, keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    return {key: data[key] for key in keys if key in data}


def guest_summary(resource: dict[str, Any]) -> dict[str, Any]:
    return pick(
        resource,
        (
            "vmid",
            "name",
            "node",
            "type",
            "status",
            "template",
            "pool",
            "tags",
            "maxcpu",
            "maxmem",
            "maxdisk",
            "uptime",
            "disk",
            "diskread",
            "diskwrite",
            "netin",
            "netout",
            "cpu",
            "mem",
            "lock",
            "hastate",
        ),
    )


def node_summary(node: dict[str, Any]) -> dict[str, Any]:
    return pick(
        node,
        (
            "node",
            "status",
            "type",
            "id",
            "level",
            "local",
            "online",
            "cpu",
            "maxcpu",
            "mem",
            "maxmem",
            "disk",
            "maxdisk",
            "uptime",
            "ssl_fingerprint",
            "pveversion",
        ),
    )


def storage_summary(storage: dict[str, Any]) -> dict[str, Any]:
    return pick(
        storage,
        (
            "storage",
            "node",
            "type",
            "content",
            "active",
            "enabled",
            "shared",
            "total",
            "used",
            "avail",
            "used_fraction",
            "path",
            "server",
            "export",
            "pool",
        ),
    )


def task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return pick(
        task,
        (
            "upid",
            "node",
            "type",
            "id",
            "user",
            "status",
            "exitstatus",
            "starttime",
            "endtime",
            "pid",
            "pstart",
        ),
    )


def snapshot_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    return pick(
        snapshot,
        (
            "name",
            "description",
            "snaptime",
            "parent",
            "vmstate",
            "running",
            "template",
        ),
    )


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_upid_node(upid: str) -> str | None:
    parts = upid.split(":")
    if len(parts) >= 3 and parts[0] == "UPID":
        return parts[1] or None
    return None
