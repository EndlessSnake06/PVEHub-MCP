"""Task tools: recent task lists, status, log and cancelling a running task."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from ..validation import api_segment, task_upid
from .common import ok, task_summary


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_tasks_list",
        category="read",
        pve=[("Sys.Audit", "/nodes")],
        service="pve",
    )
    async def pve_tasks_list(
        node: str | None = None,
        vmid: int | None = None,
        limit: int = 50,
        type: str | None = None,
        status: str | None = None,
        errors: bool = False,
        since: int | None = None,
        until: int | None = None,
        instance: str | None = None,
    ) -> str:
        """List recent tasks, newest first.

        Without node, tasks of all cluster nodes are merged. vmid, type and status filter
        the result; errors=true only returns tasks that failed; since/until are epoch
        seconds.
        """
        if limit < 1 or limit > 500:
            raise InvalidArgument("limit must be between 1 and 500")
        client = hub.pve(instance)
        base: dict[str, Any] = {"limit": limit}
        if vmid is not None:
            base["vmid"] = vmid
        if type is not None:
            base["typefilter"] = type
        if status is not None:
            base["statusfilter"] = status
        if errors:
            base["errors"] = True
        if since is not None:
            base["since"] = since
        if until is not None:
            base["until"] = until
        nodes: list[str]
        if node is not None:
            nodes = [api_segment(node, "node")]
        else:
            node_data = await client.get("/nodes")
            nodes = [item["node"] for item in _as_items(node_data) if item.get("node")]
        tasks: list[dict[str, Any]] = []
        for current in nodes:
            data = await client.get(f"/nodes/{current}/tasks", params=base)
            tasks.extend(task_summary(item) for item in _as_items(data))
        tasks.sort(key=lambda task: task.get("starttime", 0), reverse=True)
        tasks = tasks[:limit]
        return ok(
            {"nodes": nodes, "count": len(tasks), "tasks": tasks},
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(
        name="pve_task_status",
        category="read",
        pve=[("Sys.Audit", "/nodes/{node}")],
        service="pve",
    )
    async def pve_task_status(node: str, upid: str, instance: str | None = None) -> str:
        """Show a task's status and exit status by UPID."""
        node = api_segment(node, "node")
        upid = task_upid(upid)
        client = hub.pve(instance)
        data = await client.get(f"/nodes/{node}/tasks/{upid}/status")
        status = task_summary(data)
        status["running"] = data.get("status") == "running" if isinstance(data, dict) else None
        payload = {"node": node, "upid": upid, "status": status}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_task_log",
        category="read",
        pve=[("Sys.Audit", "/nodes/{node}")],
        service="pve",
    )
    async def pve_task_log(
        node: str,
        upid: str,
        start: int = 0,
        limit: int = 50,
        instance: str | None = None,
    ) -> str:
        """Read a task log tail (start line offset, limit up to 1000 lines)."""
        node = api_segment(node, "node")
        upid = task_upid(upid)
        if start < 0:
            raise InvalidArgument("start must be zero or positive")
        if limit < 1 or limit > 1000:
            raise InvalidArgument("limit must be between 1 and 1000")
        client = hub.pve(instance)
        text = await client.task_log(node, upid, start=start, limit=limit)
        payload = {"node": node, "upid": upid, "start": start, "limit": limit, "log": text}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_task_stop",
        category="destructive",
        pve=[("Sys.Modify", "/nodes/{node}")],
        service="pve",
    )
    async def pve_task_stop(
        node: str,
        upid: str,
        confirm: bool = False,
        dry_run: bool = False,
        instance: str | None = None,
    ) -> str:
        """Stop a running task (requires confirm=true)."""
        node = api_segment(node, "node")
        upid = task_upid(upid)
        if dry_run:
            return ok(
                {
                    "dry_run": True,
                    "action": "task_stop",
                    "would_call": f"DELETE /nodes/{node}/tasks/{upid}",
                    "node": node,
                    "upid": upid,
                    "note": "no API call performed",
                },
                max_bytes=hub.settings.max_output_bytes,
            )
        client = hub.pve(instance)
        await client.delete(f"/nodes/{node}/tasks/{upid}")
        payload = {"node": node, "upid": upid, "stopped": True}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
