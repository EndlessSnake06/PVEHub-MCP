"""Backup tools: vzdump backups, backup listing and guest restore."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from .common import ok, pick

_BACKUP_KEYS = (
    "volid",
    "content",
    "format",
    "size",
    "ctime",
    "vmid",
    "notes",
    "protected",
    "verification",
    "encrypted",
)
_MODES = {"snapshot", "suspend", "stop"}
_COMPRESSION = {"0", "1", "gzip", "lzo", "zstd"}
_GUEST_TYPES = {"qemu", "lxc"}


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_backup_start",
        category="write",
        pve=[
            ("VM.Backup", "/vms/{vmid}"),
            ("Datastore.AllocateSpace", "/storage/{storage}"),
        ],
        service="pve",
    )
    async def pve_backup_start(
        node: str,
        vmid: int,
        storage: str,
        mode: str = "snapshot",
        compress: str | None = None,
        notes_template: str | None = None,
        remove: bool = False,
        protected: bool = False,
        bwlimit: int | None = None,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Start a vzdump backup of one guest.

        mode is snapshot, suspend or stop; compress is 0, 1, gzip, lzo or zstd;
        remove deletes old backups according to the storage prune settings.
        """
        if mode not in _MODES:
            raise InvalidArgument(f"unknown mode {mode!r}; expected one of {sorted(_MODES)}")
        if compress is not None and compress not in _COMPRESSION:
            raise InvalidArgument(
                f"unknown compress value {compress!r}; expected one of {sorted(_COMPRESSION)}"
            )
        if bwlimit is not None and bwlimit < 0:
            raise InvalidArgument("bwlimit must be zero or positive (KiB/s)")
        client = hub.pve(instance)
        data: dict[str, Any] = {"vmid": vmid, "storage": storage, "mode": mode}
        if compress is not None:
            data["compress"] = compress
        if notes_template is not None:
            data["notes-template"] = notes_template
        if remove:
            data["remove"] = True
        if protected:
            data["protected"] = True
        if bwlimit is not None:
            data["bwlimit"] = bwlimit
        upid = await client.post(f"/nodes/{node}/vzdump", data=data)
        payload: dict[str, Any] = {"vmid": vmid, "node": node, "storage": storage, "upid": upid}
        should_wait = hub.settings.wait_default if wait is None else wait
        if should_wait and isinstance(upid, str) and upid.startswith("UPID:"):
            payload["task"] = await client.wait_task(
                node, upid, timeout=float(hub.settings.task_timeout_seconds)
            )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_backup_list",
        category="read",
        pve=[("Datastore.Audit", "/storage/{storage}")],
        service="pve",
    )
    async def pve_backup_list(
        node: str,
        storage: str,
        vmid: int | None = None,
        instance: str | None = None,
    ) -> str:
        """List backup volumes on a storage, optionally only for one VMID."""
        client = hub.pve(instance)
        params: dict[str, Any] = {"content": "backup"}
        if vmid is not None:
            params["vmid"] = vmid
        data = await client.get(f"/nodes/{node}/storage/{storage}/content", params=params)
        backups = [pick(item, _BACKUP_KEYS) for item in _as_items(data)]
        payload = {
            "node": node,
            "storage": storage,
            "vmid": vmid,
            "count": len(backups),
            "backups": backups,
        }
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_backup_restore",
        category="destructive",
        pve=[
            ("VM.Allocate", "/vms"),
            ("Datastore.AllocateSpace", "/storage/{storage}"),
        ],
        service="pve",
    )
    async def pve_backup_restore(
        node: str,
        vmid: int,
        storage: str,
        archive: str,
        type: str = "qemu",
        name: str | None = None,
        force: bool = False,
        unique: bool = False,
        start: bool = False,
        confirm: bool = False,
        dry_run: bool = False,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Restore a guest from a backup volume (requires confirm=true).

        archive is a backup volume ID such as local:backup/vzdump-qemu-100-....vma.zst;
        type selects qemu or lxc; force overwrites an existing VMID; start starts the
        guest after restore.
        """
        if type not in _GUEST_TYPES:
            raise InvalidArgument("type must be 'qemu' or 'lxc'")
        if dry_run:
            endpoint = f"/nodes/{node}/{type}"
            return ok(
                {
                    "dry_run": True,
                    "action": "backup_restore",
                    "would_call": f"POST {endpoint}",
                    "node": node,
                    "vmid": vmid,
                    "type": type,
                    "storage": storage,
                    "archive": archive,
                    "force": force,
                    "start": start,
                    "note": "no API call performed",
                },
                max_bytes=hub.settings.max_output_bytes,
            )
        if unique and type != "qemu":
            raise InvalidArgument("unique is only supported for QEMU restores")
        client = hub.pve(instance)
        data: dict[str, Any] = {"vmid": vmid, "storage": storage, "start": start}
        if type == "qemu":
            data["archive"] = archive
            if name is not None:
                data["name"] = name
            if force:
                data["force"] = True
            if unique:
                data["unique"] = True
        else:
            data["ostemplate"] = archive
            data["restore"] = True
            if name is not None:
                data["hostname"] = name
            if force:
                data["force"] = True
        upid = await client.post(f"/nodes/{node}/{type}", data=data)
        payload: dict[str, Any] = {
            "vmid": vmid,
            "node": node,
            "type": type,
            "storage": storage,
            "upid": upid,
        }
        should_wait = hub.settings.wait_default if wait is None else wait
        if should_wait and isinstance(upid, str) and upid.startswith("UPID:"):
            payload["task"] = await client.wait_task(
                node, upid, timeout=float(hub.settings.task_timeout_seconds)
            )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
