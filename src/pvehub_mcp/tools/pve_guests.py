"""Guest (QEMU VM and LXC) inspection, lifecycle, config and snapshot tools."""

from __future__ import annotations

from typing import Any

from ..audit import redact_value
from ..errors import InvalidArgument, PolicyError
from ..validation import api_segment
from .common import guest_summary, ok, snapshot_summary

_POWER_ACTIONS = ("start", "stop", "shutdown", "reboot", "suspend", "resume")
_GUEST_TYPES = {"qemu", "lxc"}


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


async def _target(
    hub: Any, vmid: int, instance: str | None, node: str | None = None
) -> tuple[str, str]:
    """Resolve the node and guest type (qemu/lxc) for a VMID."""
    resource = await hub.resolve_guest(vmid, instance)
    resolved = resource.get("node")
    kind = resource.get("type")
    if not isinstance(resolved, str) or kind not in _GUEST_TYPES:
        raise InvalidArgument(f"guest {vmid} has no usable node/type in cluster resources")
    if node is not None and node != resolved:
        raise InvalidArgument(f"guest {vmid} is on node {resolved!r}, not {node!r}")
    return resolved, kind


def _guest_path(node: str, kind: str, vmid: int) -> str:
    return f"/nodes/{node}/{kind}/{vmid}"


async def _task(
    client: Any,
    node: str,
    upid: Any,
    *,
    wait: bool | None,
    timeout: int | None,
    default_wait: bool,
    default_timeout: float,
) -> dict[str, Any]:
    """Build a UPID result and optionally poll until the task finishes."""
    payload: dict[str, Any] = {"node": node, "upid": upid if isinstance(upid, str) else None}
    should_wait = default_wait if wait is None else wait
    if should_wait and isinstance(upid, str) and upid.startswith("UPID:"):
        payload["task"] = await client.wait_task(
            node, upid, timeout=float(timeout or default_timeout)
        )
    return payload


def _dry_run(action: str, would_call: str, **fields: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "dry_run": True,
        "action": action,
        "would_call": would_call,
        "note": "no API call performed; values are resolved from /cluster/resources at execution time",
    }
    payload.update(fields)
    return payload


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_guests_list",
        category="read",
        pve=[("VM.Audit", "/vms")],
        service="pve",
    )
    async def pve_guests_list(
        node: str | None = None,
        status: str | None = None,
        type: str | None = None,
        instance: str | None = None,
    ) -> str:
        """List QEMU VMs and LXC containers with status, resource usage and node.

        node and status filter the result; type is qemu or lxc.
        """
        if type is not None and type not in _GUEST_TYPES:
            raise InvalidArgument("type must be 'qemu' or 'lxc'")
        client = hub.pve(instance)
        data = await client.get("/cluster/resources", params={"type": "vm"})
        guests = [guest_summary(item) for item in _as_items(data)]
        if type is not None:
            guests = [guest for guest in guests if guest.get("type") == type]
        if node is not None:
            guests = [guest for guest in guests if guest.get("node") == node]
        if status is not None:
            guests = [guest for guest in guests if guest.get("status") == status]
        guests.sort(key=lambda guest: guest.get("vmid", 0))
        return ok(
            {"count": len(guests), "guests": guests},
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(
        name="pve_guest_status",
        category="read",
        pve=[("VM.Audit", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_status(
        vmid: int, node: str | None = None, instance: str | None = None
    ) -> str:
        """Show a guest's runtime status (state, uptime, CPU, memory, disks, network)."""
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        data = await client.get(f"{_guest_path(resolved, kind, vmid)}/status/current")
        payload = {"vmid": vmid, "node": resolved, "type": kind, "status": guest_summary(data)}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_config",
        category="read",
        pve=[("VM.Audit", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_config(
        vmid: int,
        node: str | None = None,
        snapshot: str | None = None,
        instance: str | None = None,
    ) -> str:
        """Read a guest configuration; secret-like values are redacted.

        snapshot reads the config as stored in a snapshot instead of the current one.
        """
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        params = {"snapshot": snapshot} if snapshot else None
        data = await client.get(f"{_guest_path(resolved, kind, vmid)}/config", params=params)
        payload = {
            "vmid": vmid,
            "node": resolved,
            "type": kind,
            "snapshot": snapshot,
            "config": redact_value(data),
        }
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_power",
        category="lifecycle",
        pve=[("VM.PowerMgmt", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_power(
        vmid: int,
        action: str,
        node: str | None = None,
        timeout: int | None = None,
        force_stop: bool = False,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Start, stop, shutdown, reboot, suspend or resume a guest.

        action is start/stop/shutdown/reboot/suspend/resume. timeout applies to
        shutdown and reboot; force_stop escalates a shutdown to a hard stop.
        """
        if action not in _POWER_ACTIONS:
            raise InvalidArgument(f"unknown action {action!r}; expected one of {list(_POWER_ACTIONS)}")
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        data: dict[str, Any] = {}
        if timeout is not None and action in {"shutdown", "reboot"}:
            data["timeout"] = timeout
        if force_stop and action == "shutdown":
            data["forceStop"] = True
        upid = await client.post(f"{_guest_path(resolved, kind, vmid)}/status/{action}", data=data or None)
        payload = {"vmid": vmid, "action": action, "type": kind}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_snapshots",
        category="read",
        pve=[("VM.Audit", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_snapshots(
        vmid: int, node: str | None = None, instance: str | None = None
    ) -> str:
        """List snapshots of a guest, including the current state entry."""
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        data = await client.get(f"{_guest_path(resolved, kind, vmid)}/snapshot")
        snapshots = [snapshot_summary(item) for item in _as_items(data)]
        payload = {
            "vmid": vmid,
            "node": resolved,
            "type": kind,
            "count": len(snapshots),
            "snapshots": snapshots,
        }
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_snapshot_create",
        category="write",
        pve=[("VM.Snapshot", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_snapshot_create(
        vmid: int,
        snapname: str,
        node: str | None = None,
        description: str | None = None,
        vmstate: bool = False,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Create a guest snapshot.

        vmstate includes RAM state and is only supported for QEMU VMs.
        """
        snapname = api_segment(snapname, "snapname")
        resolved, kind = await _target(hub, vmid, instance, node)
        if vmstate and kind != "qemu":
            raise InvalidArgument("vmstate snapshots are only supported for QEMU VMs")
        client = hub.pve(instance)
        data: dict[str, Any] = {"snapname": snapname}
        if description is not None:
            data["description"] = description
        if vmstate:
            data["vmstate"] = True
        upid = await client.post(f"{_guest_path(resolved, kind, vmid)}/snapshot", data=data)
        payload = {"vmid": vmid, "snapname": snapname, "type": kind}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_snapshot_delete",
        category="destructive",
        pve=[("VM.Snapshot", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_snapshot_delete(
        vmid: int,
        snapname: str,
        node: str | None = None,
        force: bool = False,
        confirm: bool = False,
        dry_run: bool = False,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Delete a guest snapshot permanently (requires confirm=true)."""
        snapname = api_segment(snapname, "snapname")
        if dry_run:
            return ok(
                _dry_run(
                    "snapshot_delete",
                    f"DELETE /nodes/{{node}}/{{type}}/{vmid}/snapshot/{snapname}",
                    vmid=vmid,
                    snapname=snapname,
                    node=node,
                    force=force,
                ),
                max_bytes=hub.settings.max_output_bytes,
            )
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        params = {"force": True} if force else None
        # DELETE parameters must go through the query string; client.delete() drops them.
        upid = await client._request(
            "DELETE", f"{_guest_path(resolved, kind, vmid)}/snapshot/{snapname}", params=params
        )
        payload = {"vmid": vmid, "snapname": snapname, "type": kind, "deleted": True}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_snapshot_rollback",
        category="destructive",
        pve=[("VM.Snapshot.Rollback", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_snapshot_rollback(
        vmid: int,
        snapname: str,
        node: str | None = None,
        start: bool = False,
        confirm: bool = False,
        dry_run: bool = False,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Roll a guest back to a snapshot, discarding newer state (requires confirm=true)."""
        snapname = api_segment(snapname, "snapname")
        if dry_run:
            return ok(
                _dry_run(
                    "snapshot_rollback",
                    f"POST /nodes/{{node}}/{{type}}/{vmid}/snapshot/{snapname}/rollback",
                    vmid=vmid,
                    snapname=snapname,
                    node=node,
                    start=start,
                ),
                max_bytes=hub.settings.max_output_bytes,
            )
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        data: dict[str, Any] = {}
        if start:
            data["start"] = True
        upid = await client.post(
            f"{_guest_path(resolved, kind, vmid)}/snapshot/{snapname}/rollback", data=data or None
        )
        payload = {"vmid": vmid, "snapname": snapname, "type": kind, "rolled_back": True}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_clone",
        category="write",
        pve=[
            ("VM.Clone", "/vms/{vmid}"),
            ("VM.Allocate", "/vms/{newid}"),
            ("Datastore.AllocateSpace", "/storage"),
        ],
        service="pve",
    )
    async def pve_guest_clone(
        vmid: int,
        newid: int,
        node: str | None = None,
        name: str | None = None,
        storage: str | None = None,
        full: bool = True,
        target: str | None = None,
        pool: str | None = None,
        description: str | None = None,
        snapshot: str | None = None,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Clone a guest to a new VMID; full=false creates a linked clone.

        name sets the VM name (QEMU) or hostname (LXC); target places the clone on
        another node; storage selects the target storage.
        """
        if not hub.policy.file.exec.vmid_allowed(newid):
            raise PolicyError(
                f"newid {newid} is outside exec.allowed_vmids",
                details={"newid": newid},
            )
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        data: dict[str, Any] = {"newid": newid, "full": full}
        if name is not None:
            data["name" if kind == "qemu" else "hostname"] = name
        if storage is not None:
            data["storage"] = storage
        if target is not None:
            data["target"] = target
        if pool is not None:
            data["pool"] = pool
        if description is not None:
            data["description"] = description
        if snapshot is not None:
            data["snapname"] = snapshot
        upid = await client.post(f"{_guest_path(resolved, kind, vmid)}/clone", data=data)
        payload = {"vmid": vmid, "newid": newid, "type": kind}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_migrate",
        category="lifecycle",
        pve=[("VM.Migrate", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_migrate(
        vmid: int,
        target: str,
        node: str | None = None,
        online: bool = True,
        with_local_disks: bool = False,
        target_storage: str | None = None,
        bwlimit: int | None = None,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Migrate a guest to another cluster node.

        online keeps a running guest running during migration; with_local_disks moves
        local disks; target_storage selects the destination storage.
        """
        resolved, kind = await _target(hub, vmid, instance, node)
        if target == resolved:
            raise InvalidArgument(f"guest {vmid} is already on node {target!r}")
        client = hub.pve(instance)
        data: dict[str, Any] = {"target": target, "online": online}
        if bwlimit is not None:
            data["bwlimit"] = bwlimit
        if target_storage is not None:
            data["targetstorage" if kind == "qemu" else "target-storage"] = target_storage
        if with_local_disks:
            if kind != "qemu":
                raise InvalidArgument("with_local_disks is only supported for QEMU VMs")
            data["with-local-disks"] = True
        upid = await client.post(f"{_guest_path(resolved, kind, vmid)}/migrate", data=data)
        payload = {"vmid": vmid, "type": kind, "source": resolved, "target": target}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_create_lxc",
        category="write",
        pve=[
            ("VM.Allocate", "/vms/{vmid}"),
            ("Datastore.AllocateSpace", "/storage/{storage}"),
        ],
        service="pve",
    )
    async def pve_guest_create_lxc(
        node: str,
        vmid: int,
        ostemplate: str,
        storage: str,
        hostname: str | None = None,
        cores: int | None = None,
        memory: int | None = None,
        swap: int | None = None,
        unprivileged: bool = True,
        start: bool = False,
        pool: str | None = None,
        tags: str | None = None,
        description: str | None = None,
        nameserver: str | None = None,
        searchdomain: str | None = None,
        rootfs: str | None = None,
        ssh_public_keys: str | None = None,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Create an LXC container from a template.

        ostemplate is a volume ID such as local:vztmpl/debian-12-standard_amd64.tar.zst;
        rootfs overrides the container root filesystem (default storage:<size>).
        """
        node = api_segment(node, "node")
        client = hub.pve(instance)
        data: dict[str, Any] = {
            "vmid": vmid,
            "ostemplate": ostemplate,
            "storage": storage,
            "unprivileged": unprivileged,
            "start": start,
        }
        optional = {
            "hostname": hostname,
            "cores": cores,
            "memory": memory,
            "swap": swap,
            "pool": pool,
            "tags": tags,
            "description": description,
            "nameserver": nameserver,
            "searchdomain": searchdomain,
            "rootfs": rootfs,
            "ssh-public-keys": ssh_public_keys,
        }
        data.update({key: value for key, value in optional.items() if value is not None})
        upid = await client.post(f"/nodes/{node}/lxc", data=data)
        payload = {"vmid": vmid, "type": "lxc", "node": node}
        payload.update(
            await _task(
                client,
                node,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_create_vm",
        category="write",
        pve=[
            ("VM.Allocate", "/vms/{vmid}"),
            ("Datastore.AllocateSpace", "/storage/{storage}"),
        ],
        service="pve",
    )
    async def pve_guest_create_vm(
        node: str,
        vmid: int,
        storage: str,
        name: str | None = None,
        memory: int | None = None,
        cores: int | None = None,
        sockets: int | None = None,
        ostype: str | None = None,
        net0: str | None = None,
        scsi0: str | None = None,
        start: bool = False,
        pool: str | None = None,
        tags: str | None = None,
        description: str | None = None,
        agent: bool | None = None,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Create an empty QEMU VM; disks and NICs are optional but usually required to boot.

        memory is MiB; net0/scsi0 take PVE config strings such as
        'virtio,bridge=vmbr0' and 'storage:32'.
        """
        node = api_segment(node, "node")
        client = hub.pve(instance)
        data: dict[str, Any] = {"vmid": vmid, "storage": storage, "start": start}
        optional = {
            "name": name,
            "memory": memory,
            "cores": cores,
            "sockets": sockets,
            "ostype": ostype,
            "net0": net0,
            "scsi0": scsi0,
            "pool": pool,
            "tags": tags,
            "description": description,
            "agent": agent,
        }
        data.update({key: value for key, value in optional.items() if value is not None})
        upid = await client.post(f"/nodes/{node}/qemu", data=data)
        payload = {"vmid": vmid, "type": "qemu", "node": node}
        payload.update(
            await _task(
                client,
                node,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_delete",
        category="destructive",
        pve=[("VM.Allocate", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_delete(
        vmid: int,
        node: str | None = None,
        purge: bool = True,
        force: bool = False,
        confirm: bool = False,
        dry_run: bool = False,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Destroy a guest and its disks permanently (requires confirm=true).

        purge also removes the guest from backup jobs, HA, replication and firewall.
        """
        if dry_run:
            return ok(
                _dry_run(
                    "guest_delete",
                    f"DELETE /nodes/{{node}}/{{type}}/{vmid}",
                    vmid=vmid,
                    node=node,
                    purge=purge,
                    force=force,
                ),
                max_bytes=hub.settings.max_output_bytes,
            )
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        data: dict[str, Any] = {"purge": purge}
        if force and kind == "lxc":
            data["force"] = True
        # DELETE parameters must go through the query string; client.delete() drops them.
        upid = await client._request("DELETE", _guest_path(resolved, kind, vmid), params=data)
        payload = {"vmid": vmid, "type": kind, "deleted": True}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_resize",
        category="write",
        pve=[("VM.Config.Disk", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_resize(
        vmid: int,
        disk: str,
        size: str,
        node: str | None = None,
        wait: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """Grow a guest disk; size is absolute ('32G') or relative ('+8G').

        disk is a config key such as scsi0, virtio0, sata0 or rootfs.
        """
        resolved, kind = await _target(hub, vmid, instance, node)
        client = hub.pve(instance)
        upid = await client.put(
            f"{_guest_path(resolved, kind, vmid)}/resize", data={"disk": disk, "size": size}
        )
        payload = {"vmid": vmid, "type": kind, "disk": disk, "size": size}
        payload.update(
            await _task(
                client,
                resolved,
                upid,
                wait=wait,
                timeout=None,
                default_wait=hub.settings.wait_default,
                default_timeout=hub.settings.task_timeout_seconds,
            )
        )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_guest_agent_ping",
        category="read",
        pve=[("VM.GuestAgent.Audit", "/vms/{vmid}")],
        service="pve",
    )
    async def pve_guest_agent_ping(
        vmid: int, node: str | None = None, instance: str | None = None
    ) -> str:
        """Ping the QEMU guest agent to check whether it is installed and running."""
        resolved, kind = await _target(hub, vmid, instance, node)
        if kind != "qemu":
            raise InvalidArgument("guest agent ping is only available for QEMU VMs")
        client = hub.pve(instance)
        data = await client.post(f"{_guest_path(resolved, kind, vmid)}/agent/ping")
        payload = {"vmid": vmid, "node": resolved, "type": kind, "result": data}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
