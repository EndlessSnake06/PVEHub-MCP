"""Curated PBS datastore, namespace and health tools."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument, PVEHubError
from .common import ok, pick
from .pbs_common import max_bytes, namespace_name, store_name


def _task_brief(task: dict[str, Any]) -> dict[str, Any]:
    return pick(
        task,
        (
            "upid",
            "node",
            "worker_type",
            "worker_id",
            "user",
            "status",
            "starttime",
            "endtime",
        ),
    )


def register(hub: Any) -> None:
    @hub.tool(
        name="pbs_datastores_list",
        category="read",
        pbs=[("Datastore.Audit", "/datastore")],
        service="pbs",
    )
    async def pbs_datastores_list(instance: str | None = None) -> str:
        """List accessible PBS datastores."""
        client = hub.pbs(instance)
        data = await client.get("/admin/datastore")
        stores = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
        return ok({"datastores": stores, "count": len(stores)}, max_bytes=max_bytes(hub))

    @hub.tool(
        name="pbs_datastore_status",
        category="read",
        pbs=[("Datastore.Audit", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_datastore_status(
        store: str,
        verbose: bool = True,
        instance: str | None = None,
    ) -> str:
        """Read datastore usage, snapshot counts and GC information."""
        name = store_name(store)
        client = hub.pbs(instance)
        data = await client.get(
            f"/admin/datastore/{name}/status",
            params={"verbose": verbose},
        )
        return ok({"store": name, "status": data}, max_bytes=max_bytes(hub))

    @hub.tool(
        name="pbs_namespaces_list",
        category="read",
        pbs=[("Datastore.Audit", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_namespaces_list(
        store: str,
        parent: str | None = None,
        max_depth: int = 7,
        instance: str | None = None,
    ) -> str:
        """List the backup namespaces of a datastore."""
        name = store_name(store)
        parent_ns = namespace_name(parent, field="parent")
        if not 0 <= max_depth <= 7:
            raise InvalidArgument("max_depth must be between 0 and 7")
        client = hub.pbs(instance)
        data = await client.get(
            f"/admin/datastore/{name}/namespace",
            params={"parent": parent_ns, "max-depth": max_depth},
        )
        namespaces = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
        return ok(
            {"store": name, "namespaces": namespaces, "count": len(namespaces)},
            max_bytes=max_bytes(hub),
        )

    @hub.tool(
        name="pbs_namespace_create",
        category="write",
        pbs=[("Datastore.Modify", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_namespace_create(
        store: str,
        name: str,
        parent: str | None = None,
        instance: str | None = None,
    ) -> str:
        """Create a namespace below an optional parent namespace."""
        datastore = store_name(store)
        namespace = namespace_name(name, field="name")
        if namespace is None:  # pragma: no cover - name is required
            raise InvalidArgument("name must not be empty")
        if "/" in namespace:
            raise InvalidArgument("name must be a single namespace segment; use parent for nesting")
        parent_ns = namespace_name(parent, field="parent")
        client = hub.pbs(instance)
        result = await client.post(
            f"/admin/datastore/{datastore}/namespace",
            data={"name": namespace, "parent": parent_ns},
        )
        return ok(
            {"store": datastore, "parent": parent_ns, "namespace": result, "created": True},
            max_bytes=max_bytes(hub),
        )

    @hub.tool(
        name="pbs_namespace_delete",
        category="destructive",
        pbs=[("Datastore.Modify", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_namespace_delete(
        store: str,
        ns: str,
        delete_groups: bool = False,
        error_on_protected: bool = True,
        confirm: bool = False,
        dry_run: bool = False,
        instance: str | None = None,
    ) -> str:
        """Delete a namespace, optionally together with every group below it."""
        datastore = store_name(store)
        target = namespace_name(ns)
        if target is None:  # pragma: no cover - ns is required
            raise InvalidArgument("ns must not be empty")
        payload: dict[str, Any] = {
            "store": datastore,
            "ns": target,
            "delete_groups": delete_groups,
            "error_on_protected": error_on_protected,
        }
        if dry_run:
            return ok(
                {
                    "dry_run": True,
                    "action": "delete_namespace",
                    **payload,
                    "would_call": f"DELETE /admin/datastore/{datastore}/namespace",
                },
                max_bytes=max_bytes(hub),
            )
        client = hub.pbs(instance)
        result = await client._request(
            "DELETE",
            f"/admin/datastore/{datastore}/namespace",
            params={
                "ns": target,
                "delete-groups": delete_groups,
                "error-on-protected": error_on_protected,
            },
        )
        return ok({**payload, "deleted": True, "result": result}, max_bytes=max_bytes(hub))

    @hub.tool(
        name="pbs_health",
        category="read",
        pbs=[("Datastore.Audit", "/datastore")],
        service="pbs",
    )
    async def pbs_health(
        max_stores: int = 30,
        failed_tasks: int = 5,
        instance: str | None = None,
    ) -> str:
        """Bounded PBS overview: datastore usage/GC plus recent failed tasks."""
        if not 1 <= max_stores <= 100:
            raise InvalidArgument("max_stores must be between 1 and 100")
        if not 0 <= failed_tasks <= 50:
            raise InvalidArgument("failed_tasks must be between 0 and 50")
        client = hub.pbs(instance)
        raw_stores = await client.get("/admin/datastore")
        stores = [item for item in raw_stores if isinstance(item, dict)] if isinstance(raw_stores, list) else []

        usage_error: str | None = None
        try:
            raw_usage = await client.get("/status/datastore-usage")
        except PVEHubError as exc:
            raw_usage = []
            usage_error = exc.message
        usage = {
            str(item.get("store")): item
            for item in raw_usage
            if isinstance(item, dict) and item.get("store")
        } if isinstance(raw_usage, list) else {}

        tasks_error: str | None = None
        failed: list[dict[str, Any]] = []
        if failed_tasks:
            try:
                raw_tasks = await client.get(
                    "/nodes/localhost/tasks",
                    params={"errors": True, "limit": failed_tasks},
                )
            except PVEHubError as exc:
                raw_tasks = []
                tasks_error = exc.message
            if isinstance(raw_tasks, list):
                failed = [_task_brief(item) for item in raw_tasks if isinstance(item, dict)]

        rows: list[dict[str, Any]] = []
        for item in stores[:max_stores]:
            name = str(item.get("store"))
            entry: dict[str, Any] = pick(item, ("store", "comment", "maintenance", "mount-status"))
            current = usage.get(name, {})
            entry.update(pick(current, ("total", "used", "avail", "estimated-full-date", "error")))
            gc = current.get("gc-status")
            if isinstance(gc, dict) and gc:
                entry["gc"] = pick(
                    gc,
                    (
                        "last-run-state",
                        "last-run-endtime",
                        "next-run",
                        "duration",
                        "disk-bytes",
                        "pending-bytes",
                    ),
                )
            rows.append(entry)

        payload: dict[str, Any] = {
            "stores": rows,
            "store_count": len(rows),
            "failed_tasks": failed,
        }
        if len(stores) > max_stores:
            payload["truncated"] = True
            payload["total_stores"] = len(stores)
        if usage_error:
            payload["usage_error"] = usage_error
        if tasks_error:
            payload["tasks_error"] = tasks_error
        return ok(payload, max_bytes=max_bytes(hub))
