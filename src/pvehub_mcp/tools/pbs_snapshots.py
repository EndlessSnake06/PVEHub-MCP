"""Curated PBS snapshot, protect, prune, GC and verify tools."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from . import pbs_common
from .common import ok, parse_vmid_from_upid, pick

_SNAPSHOT_FIELDS = (
    "backup-type",
    "backup-id",
    "backup-time",
    "ns",
    "size",
    "protected",
    "owner",
    "comment",
    "verification",
)


def _snapshot_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    return pick(snapshot, _SNAPSHOT_FIELDS)


def _snapshot_ref(
    store: str,
    backup_type: str,
    backup_id: str,
    backup_time: int,
    ns: str | None,
) -> dict[str, Any]:
    return {
        "store": store,
        "backup_type": pbs_common.backup_type(backup_type),
        "backup_id": pbs_common.backup_id(backup_id),
        "backup_time": pbs_common.backup_time(backup_time),
        "ns": pbs_common.namespace_name(ns),
    }


async def _wait_for_upid(
    hub: Any,
    client: Any,
    upid: Any,
    *,
    wait: bool,
    timeout: int | None,
) -> dict[str, Any] | None:
    if not wait or not isinstance(upid, str) or not upid.startswith("UPID:"):
        return None
    node = parse_vmid_from_upid(upid) or "localhost"
    result: dict[str, Any] = await client.wait_task(
        node,
        upid,
        timeout=float(timeout or hub.settings.task_timeout_seconds),
    )
    return result


def register(hub: Any) -> None:
    @hub.tool(
        name="pbs_snapshots_list",
        category="read",
        pbs=[("Datastore.Audit", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_snapshots_list(
        store: str,
        backup_type: str | None = None,
        backup_id: str | None = None,
        ns: str | None = None,
        limit: int = 200,
        instance: str | None = None,
    ) -> str:
        """List backup snapshots, optionally filtered by type, ID and namespace."""
        name = pbs_common.store_name(store)
        if not 1 <= limit <= 1000:
            raise InvalidArgument("limit must be between 1 and 1000")
        params: dict[str, Any] = {
            "backup-type": pbs_common.backup_type(backup_type) if backup_type else None,
            "backup-id": pbs_common.backup_id(backup_id) if backup_id else None,
            "ns": pbs_common.namespace_name(ns),
        }
        client = hub.pbs(instance)
        data = await client.get(f"/admin/datastore/{name}/snapshots", params=params)
        items = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
        snapshots = [_snapshot_summary(item) for item in items[:limit]]
        payload: dict[str, Any] = {
            "store": name,
            "snapshots": snapshots,
            "count": len(snapshots),
            "total": len(items),
        }
        if len(items) > limit:
            payload["truncated"] = True
        return ok(payload, max_bytes=pbs_common.max_bytes(hub))

    @hub.tool(
        name="pbs_snapshot_forget",
        category="destructive",
        pbs=[
            ("Datastore.Modify", "/datastore/{store}"),
            ("Datastore.Prune", "/datastore/{store}"),
        ],
        service="pbs",
    )
    async def pbs_snapshot_forget(
        store: str,
        backup_type: str,
        backup_id: str,
        backup_time: int,
        ns: str | None = None,
        confirm: bool = False,
        dry_run: bool = False,
        instance: str | None = None,
    ) -> str:
        """Delete one backup snapshot (requires confirm unless dry_run)."""
        name = pbs_common.store_name(store)
        reference = _snapshot_ref(name, backup_type, backup_id, backup_time, ns)
        if dry_run:
            return ok(
                {
                    "dry_run": True,
                    "action": "forget_snapshot",
                    **reference,
                    "would_call": f"DELETE /admin/datastore/{name}/snapshots",
                },
                max_bytes=pbs_common.max_bytes(hub),
            )
        client = hub.pbs(instance)
        result = await client._request(
            "DELETE",
            f"/admin/datastore/{name}/snapshots",
            params={
                "backup-type": reference["backup_type"],
                "backup-id": reference["backup_id"],
                "backup-time": reference["backup_time"],
                "ns": reference["ns"],
            },
        )
        return ok({**reference, "forgotten": True, "result": result}, max_bytes=pbs_common.max_bytes(hub))

    @hub.tool(
        name="pbs_snapshot_protect",
        category="write",
        pbs=[("Datastore.Modify", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_snapshot_protect(
        store: str,
        backup_type: str,
        backup_id: str,
        backup_time: int,
        protected: bool = True,
        ns: str | None = None,
        instance: str | None = None,
    ) -> str:
        """Enable or disable prune protection for one backup snapshot."""
        name = pbs_common.store_name(store)
        reference = _snapshot_ref(name, backup_type, backup_id, backup_time, ns)
        client = hub.pbs(instance)
        result = await client.put(
            f"/admin/datastore/{name}/protected",
            data={
                "backup-type": reference["backup_type"],
                "backup-id": reference["backup_id"],
                "backup-time": reference["backup_time"],
                "ns": reference["ns"],
                "protected": protected,
            },
        )
        return ok(
            {**reference, "protected": protected, "updated": True, "result": result},
            max_bytes=pbs_common.max_bytes(hub),
        )

    @hub.tool(
        name="pbs_prune",
        category="destructive",
        pbs=[
            ("Datastore.Prune", "/datastore/{store}"),
            ("Datastore.Modify", "/datastore/{store}"),
        ],
        service="pbs",
    )
    async def pbs_prune(
        store: str,
        backup_type: str,
        backup_id: str,
        keep_last: int | None = None,
        keep_hourly: int | None = None,
        keep_daily: int | None = None,
        keep_weekly: int | None = None,
        keep_monthly: int | None = None,
        keep_yearly: int | None = None,
        ns: str | None = None,
        dry_run: bool = True,
        confirm: bool = False,
        instance: str | None = None,
    ) -> str:
        """Prune one backup group; defaults to a dry-run plan."""
        name = pbs_common.store_name(store)
        kind = pbs_common.backup_type(backup_type)
        identifier = pbs_common.backup_id(backup_id)
        namespace = pbs_common.namespace_name(ns)
        keeps = {
            "keep-last": keep_last,
            "keep-hourly": keep_hourly,
            "keep-daily": keep_daily,
            "keep-weekly": keep_weekly,
            "keep-monthly": keep_monthly,
            "keep-yearly": keep_yearly,
        }
        payload: dict[str, Any] = {}
        for key, value in keeps.items():
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise InvalidArgument(f"{key.replace('-', '_')} must be a positive integer")
            payload[key] = value
        if not payload:
            raise InvalidArgument("at least one keep-* retention value is required")
        data: dict[str, Any] = {
            "backup-type": kind,
            "backup-id": identifier,
            "ns": namespace,
            "dry-run": dry_run,
            **payload,
        }
        client = hub.pbs(instance)
        result = await client.post(f"/admin/datastore/{name}/prune", data=data)
        return ok(
            {
                "store": name,
                "backup_type": kind,
                "backup_id": identifier,
                "ns": namespace,
                "dry_run": dry_run,
                "results": result,
            },
            max_bytes=pbs_common.max_bytes(hub),
        )

    @hub.tool(
        name="pbs_gc",
        category="destructive",
        pbs=[("Datastore.Modify", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_gc(
        store: str,
        dry_run: bool = False,
        confirm: bool = False,
        wait: bool = True,
        timeout: int | None = None,
        instance: str | None = None,
    ) -> str:
        """Show GC status (dry_run) or start garbage collection on a datastore."""
        name = pbs_common.store_name(store)
        client = hub.pbs(instance)
        if dry_run:
            status = await client.get(f"/admin/datastore/{name}/gc")
            return ok(
                {"dry_run": True, "store": name, "status": status},
                max_bytes=pbs_common.max_bytes(hub),
            )
        upid = await client.post(f"/admin/datastore/{name}/gc")
        task = await _wait_for_upid(hub, client, upid, wait=wait, timeout=timeout)
        return ok(
            {"store": name, "upid": upid, "task": task},
            max_bytes=pbs_common.max_bytes(hub),
        )

    @hub.tool(
        name="pbs_verify",
        category="write",
        pbs=[("Datastore.Verify", "/datastore/{store}")],
        service="pbs",
    )
    async def pbs_verify(
        store: str,
        backup_type: str | None = None,
        backup_id: str | None = None,
        backup_time: int | None = None,
        ns: str | None = None,
        ignore_verified: bool = True,
        verify_threads: int = 4,
        read_threads: int = 1,
        outdated_after: int | None = None,
        max_depth: int = 7,
        wait: bool = True,
        timeout: int | None = None,
        instance: str | None = None,
    ) -> str:
        """Verify one snapshot, one backup group, or a whole datastore."""
        name = pbs_common.store_name(store)
        partial = [backup_type, backup_id, backup_time]
        if any(value is not None for value in partial) and not all(
            value is not None for value in partial
        ):
            raise InvalidArgument(
                "backup_type, backup_id and backup_time must be given together for a single snapshot"
            )
        if not 1 <= verify_threads <= 32 or not 1 <= read_threads <= 32:
            raise InvalidArgument("verify_threads and read_threads must be between 1 and 32")
        if not 0 <= max_depth <= 7:
            raise InvalidArgument("max_depth must be between 0 and 7")
        if outdated_after is not None and outdated_after < 0:
            raise InvalidArgument("outdated_after must be >= 0")
        params: dict[str, Any] = {
            "backup-type": pbs_common.backup_type(backup_type) if backup_type else None,
            "backup-id": pbs_common.backup_id(backup_id) if backup_id else None,
            "backup-time": pbs_common.backup_time(backup_time) if backup_time is not None else None,
            "ns": pbs_common.namespace_name(ns),
            "ignore-verified": ignore_verified,
            "verify-threads": verify_threads,
            "read-threads": read_threads,
            "outdated-after": outdated_after,
            "max-depth": max_depth,
        }
        client = hub.pbs(instance)
        upid = await client.post(f"/admin/datastore/{name}/verify", data=params)
        task = await _wait_for_upid(hub, client, upid, wait=wait, timeout=timeout)
        return ok(
            {
                "store": name,
                "backup_type": params["backup-type"],
                "backup_id": params["backup-id"],
                "backup_time": params["backup-time"],
                "ns": params["ns"],
                "upid": upid,
                "task": task,
            },
            max_bytes=pbs_common.max_bytes(hub),
        )
