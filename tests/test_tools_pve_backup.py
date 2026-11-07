"""Tests for backup start, backup listing and restore."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl

from httpx import Response

BACKUP_UPID = "UPID:pve1:00000020:00000021:65000000:vzdump:100:root@pam:"
QEMU_RESTORE_UPID = "UPID:pve1:00000026:00000027:65000000:qmrestore:100:root@pam:"
LXC_RESTORE_UPID = "UPID:pve1:00000028:00000029:65000000:vzrestore:101:root@pam:"
UNUSED_RESTORE_UPID = "UPID:pve1:00000022:00000023:65000000:qmrestore:100:root@pam:"
OTHER_RESTORE_UPID = "UPID:pve1:00000024:00000025:65000000:qmrestore:100:root@pam:"


def form(request: Any) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


async def test_backup_start_creates_vzdump_task(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.post("/api2/json/nodes/pve1/vzdump").mock(
        return_value=Response(200, json={"data": BACKUP_UPID})
    )

    payload = await call(
        hub,
        "pve_backup_start",
        node="pve1",
        vmid=100,
        storage="pbs",
        mode="snapshot",
        compress="zstd",
        wait=False,
    )

    assert payload["ok"] is True
    assert payload["data"]["upid"] == BACKUP_UPID
    data = form(route.calls[0].request)
    assert data["vmid"] == "100"
    assert data["storage"] == "pbs"
    assert data["mode"] == "snapshot"
    assert data["compress"] == "zstd"


async def test_backup_start_validates_mode(pve: Any, call: Any) -> None:
    hub, _router = pve

    payload = await call(hub, "pve_backup_start", node="pve1", vmid=100, storage="pbs", mode="fast")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_backup_list_filters_content_backup(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/nodes/pve1/storage/pbs/content").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "volid": "pbs:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst",
                        "format": "vma.zst",
                        "size": 2048,
                        "vmid": 100,
                        "ctime": 1700000000,
                        "protected": 0,
                    }
                ]
            },
        )
    )

    payload = await call(hub, "pve_backup_list", node="pve1", storage="pbs", vmid=100)

    assert payload["data"]["count"] == 1
    assert payload["data"]["backups"][0]["vmid"] == 100
    params = route.calls[0].request.url.params
    assert params["content"] == "backup"
    assert params["vmid"] == "100"


async def test_backup_restore_requires_confirm(pve: Any, call: Any) -> None:
    hub, router = pve
    create = router.post("/api2/json/nodes/pve1/qemu").mock(
        return_value=Response(200, json={"data": UNUSED_RESTORE_UPID})
    )

    payload = await call(
        hub,
        "pve_backup_restore",
        node="pve1",
        vmid=100,
        storage="local-lvm",
        archive="pbs:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst",
    )

    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert not create.called


async def test_backup_restore_dry_run_makes_no_write(pve: Any, call: Any) -> None:
    hub, router = pve
    create = router.post("/api2/json/nodes/pve1/qemu").mock(
        return_value=Response(200, json={"data": OTHER_RESTORE_UPID})
    )

    payload = await call(
        hub,
        "pve_backup_restore",
        node="pve1",
        vmid=100,
        storage="local-lvm",
        archive="pbs:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst",
        dry_run=True,
    )

    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert not create.called
    assert not [item for item in router.calls if item.request.method == "POST"]


async def test_backup_restore_creates_qemu_from_archive(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.post("/api2/json/nodes/pve1/qemu").mock(
        return_value=Response(200, json={"data": QEMU_RESTORE_UPID})
    )

    payload = await call(
        hub,
        "pve_backup_restore",
        node="pve1",
        vmid=100,
        storage="local-lvm",
        archive="pbs:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst",
        confirm=True,
        wait=False,
    )

    assert payload["ok"] is True
    assert payload["data"]["type"] == "qemu"
    data = form(route.calls[0].request)
    assert data["archive"].startswith("pbs:backup/")
    assert data["storage"] == "local-lvm"
    assert data["vmid"] == "100"
    assert "restore" not in data


async def test_backup_restore_lxc_uses_ostemplate_and_restore_flag(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.post("/api2/json/nodes/pve1/lxc").mock(
        return_value=Response(200, json={"data": LXC_RESTORE_UPID})
    )

    await call(
        hub,
        "pve_backup_restore",
        node="pve1",
        vmid=101,
        storage="local-lvm",
        archive="pbs:backup/vzdump-lxc-101-2026_01_01-00_00_00.tar.zst",
        type="lxc",
        name="db",
        confirm=True,
        wait=False,
    )

    data = form(route.calls[0].request)
    assert data["ostemplate"].startswith("pbs:backup/")
    assert data["restore"] == "1"
    assert data["hostname"] == "db"
