"""Curated PBS task tools."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from .common import ok, pick
from .pbs_common import max_bytes, node_name, upid_value

_TASK_FIELDS = (
    "upid",
    "node",
    "worker_type",
    "worker_id",
    "user",
    "status",
    "starttime",
    "endtime",
)


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return pick(task, _TASK_FIELDS)


def register(hub: Any) -> None:
    @hub.tool(
        name="pbs_tasks_list",
        category="read",
        pbs=[("Sys.Audit", "/")],
        service="pbs",
    )
    async def pbs_tasks_list(
        node: str = "localhost",
        errors: bool = False,
        running: bool = False,
        limit: int = 50,
        start: int = 0,
        typefilter: str | None = None,
        userfilter: str | None = None,
        since: int | None = None,
        until: int | None = None,
        store: str | None = None,
        instance: str | None = None,
    ) -> str:
        """List PBS tasks, optionally only failed or running ones."""
        target = node_name(node)
        if not 0 <= limit <= 1000:
            raise InvalidArgument("limit must be between 0 and 1000")
        if start < 0:
            raise InvalidArgument("start must be >= 0")
        params: dict[str, Any] = {
            "errors": errors,
            "running": running,
            "limit": limit,
            "start": start,
            "typefilter": typefilter,
            "userfilter": userfilter,
            "since": since,
            "until": until,
            "store": store,
        }
        client = hub.pbs(instance)
        data = await client.get(f"/nodes/{target}/tasks", params=params)
        tasks = (
            [_task_summary(item) for item in data if isinstance(item, dict)]
            if isinstance(data, list)
            else []
        )
        return ok(
            {"node": target, "tasks": tasks, "count": len(tasks)},
            max_bytes=max_bytes(hub),
        )

    @hub.tool(
        name="pbs_task_status",
        category="read",
        pbs=[("Sys.Audit", "/")],
        service="pbs",
    )
    async def pbs_task_status(
        upid: str,
        node: str = "localhost",
        instance: str | None = None,
    ) -> str:
        """Read the status of a PBS task."""
        task = upid_value(upid)
        target = node_name(node)
        client = hub.pbs(instance)
        data = await client.task_status(target, task)
        return ok({"node": target, "status": data}, max_bytes=max_bytes(hub))

    @hub.tool(
        name="pbs_task_log",
        category="read",
        pbs=[("Sys.Audit", "/")],
        service="pbs",
    )
    async def pbs_task_log(
        upid: str,
        node: str = "localhost",
        start: int = 0,
        limit: int = 50,
        instance: str | None = None,
    ) -> str:
        """Read a PBS task log (start offset plus line limit)."""
        task = upid_value(upid)
        target = node_name(node)
        if start < 0:
            raise InvalidArgument("start must be >= 0")
        if not 1 <= limit <= 1000:
            raise InvalidArgument("limit must be between 1 and 1000")
        client = hub.pbs(instance)
        log = await client.task_log(target, task, start=start, limit=limit)
        return ok(
            {"node": target, "upid": task, "log": log},
            max_bytes=max_bytes(hub),
        )
