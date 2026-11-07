"""Tests for the storage tools."""

from __future__ import annotations

from typing import Any

from httpx import Response

STORAGE_TOOLS = {"pve_storage_list", "pve_storage_status", "pve_storage_content"}


async def test_storage_tools_registered_as_read(pve: Any) -> None:
    hub, _router = pve
    names = {tool.name for tool in await hub.mcp.list_tools()}

    assert names >= STORAGE_TOOLS
    for name in STORAGE_TOOLS:
        assert hub.registered[name].category == "read"
        assert all(privilege.priv.startswith("Datastore.") for privilege in hub.registered[name].pve_privileges)


async def test_storage_list_cluster_wide(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/storage").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {"storage": "local", "type": "dir", "content": "iso,vztmpl", "shared": 0},
                    {"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1},
                ]
            },
        )
    )

    payload = await call(hub, "pve_storage_list", type="dir")

    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["storages"][0]["storage"] == "local"
    assert route.calls[0].request.url.params["type"] == "dir"


async def test_storage_list_per_node_includes_usage(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/nodes/pve1/storage").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "storage": "local-lvm",
                        "type": "lvmthin",
                        "content": "images,rootdir",
                        "active": 1,
                        "enabled": 1,
                        "total": 100,
                        "used": 40,
                        "avail": 60,
                        "used_fraction": 0.4,
                    }
                ]
            },
        )
    )

    payload = await call(hub, "pve_storage_list", node="pve1")

    storage = payload["data"]["storages"][0]
    assert payload["data"]["node"] == "pve1"
    assert storage["used"] == 40
    assert storage["avail"] == 60


async def test_storage_status(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/nodes/pve1/storage/local/status").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "active": 1,
                    "enabled": 1,
                    "total": 500,
                    "used": 100,
                    "avail": 400,
                    "content": "iso,vztmpl,backup",
                }
            },
        )
    )

    payload = await call(hub, "pve_storage_status", node="pve1", storage="local")

    assert payload["data"]["storage"] == "local"
    assert payload["data"]["status"]["avail"] == 400


async def test_storage_content_filters(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/nodes/pve1/storage/pbs/content").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "volid": "pbs:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst",
                        "format": "vma.zst",
                        "size": 1024,
                        "vmid": 100,
                        "ctime": 1700000000,
                    }
                ]
            },
        )
    )

    payload = await call(hub, "pve_storage_content", node="pve1", storage="pbs", content="backup", vmid=100)

    assert payload["data"]["count"] == 1
    assert payload["data"]["volumes"][0]["vmid"] == 100
    params = route.calls[0].request.url.params
    assert params["content"] == "backup"
    assert params["vmid"] == "100"


async def test_storage_content_rejects_unknown_content_type(pve: Any, call: Any) -> None:
    hub, _router = pve

    payload = await call(hub, "pve_storage_content", node="pve1", storage="local", content="movies")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
