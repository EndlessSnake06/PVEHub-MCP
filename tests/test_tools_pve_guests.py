"""Tests for curated guest tools: listing, status, power, snapshots, create and delete."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl

from httpx import Response

UPID = "UPID:pve1:0000000A:0000000B:65000000:qmstart:100:root@pam:"
DELETE_UPID = "UPID:pve1:0000000E:0000000F:65000000:qmdestroy:100:root@pam:"
SNAPSHOT_UPID = "UPID:pve1:0000000C:0000000D:65000000:qmsnapshot:100:root@pam:"
CLONE_UPID = "UPID:pve1:00000010:00000011:65000000:qmclone:100:root@pam:"
CREATE_UPID = "UPID:pve1:00000012:00000013:65000000:vzcreate:102:root@pam:"
RESIZE_UPID = "UPID:pve1:00000014:00000015:65000000:resize:100:root@pam:"

GUESTS = [
    {"vmid": 100, "name": "web", "node": "pve1", "type": "qemu", "status": "running", "maxcpu": 2},
    {"vmid": 101, "name": "db", "node": "pve2", "type": "lxc", "status": "stopped", "maxcpu": 1},
]


def form(request: Any) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


def mock_guests(router: Any) -> None:
    router.get("/api2/json/cluster/resources").mock(
        return_value=Response(200, json={"data": GUESTS})
    )


async def test_guest_list_filters(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)

    payload = await call(hub, "pve_guests_list", status="running")

    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["guests"][0]["vmid"] == 100
    assert payload["data"]["guests"][0]["type"] == "qemu"


async def test_guest_status_resolves_node_and_type(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    router.get("/api2/json/nodes/pve2/lxc/101/status/current").mock(
        return_value=Response(
            200,
            json={"data": {"vmid": 101, "name": "db", "status": "stopped", "type": "lxc"}},
        )
    )

    payload = await call(hub, "pve_guest_status", vmid=101)

    assert payload["data"]["node"] == "pve2"
    assert payload["data"]["type"] == "lxc"
    assert payload["data"]["status"]["status"] == "stopped"


async def test_guest_status_rejects_wrong_node_hint(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)

    payload = await call(hub, "pve_guest_status", vmid=100, node="pve9")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_guest_config_is_redacted(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    router.get("/api2/json/nodes/pve1/qemu/100/config").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "name": "web",
                    "cores": 2,
                    "cipassword": "cloud-init-secret",
                    "description": "public",
                }
            },
        )
    )

    payload = await call(hub, "pve_guest_config", vmid=100)

    config = payload["data"]["config"]
    assert config["name"] == "web"
    assert config["cipassword"] == "***"
    assert config["description"] == "public"


async def test_guest_power_posts_and_waits_for_task(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    start = router.post("/api2/json/nodes/pve1/qemu/100/status/start").mock(
        return_value=Response(200, json={"data": UPID})
    )
    router.get(f"/api2/json/nodes/pve1/tasks/{UPID}/status").mock(
        return_value=Response(200, json={"data": {"status": "stopped", "exitstatus": "OK"}})
    )
    router.get(f"/api2/json/nodes/pve1/tasks/{UPID}/log").mock(
        return_value=Response(200, json={"data": [{"n": 1, "t": "started"}]})
    )

    payload = await call(hub, "pve_guest_power", vmid=100, action="start")

    assert payload["ok"] is True
    assert payload["data"]["upid"] == UPID
    assert payload["data"]["task"]["success"] is True
    assert payload["data"]["task"]["exitstatus"] == "OK"
    assert start.calls[0].request.method == "POST"


async def test_guest_power_rejects_unknown_action(pve: Any, call: Any) -> None:
    hub, _router = pve

    payload = await call(hub, "pve_guest_power", vmid=100, action="explode")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_snapshot_create_uses_snapname(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    route = router.post("/api2/json/nodes/pve1/qemu/100/snapshot").mock(
        return_value=Response(
            200,
            json={"data": SNAPSHOT_UPID},
        )
    )

    payload = await call(
        hub, "pve_guest_snapshot_create", vmid=100, snapname="pre-upgrade", wait=False
    )

    assert payload["ok"] is True
    data = form(route.calls[0].request)
    assert data["snapname"] == "pre-upgrade"


async def test_snapshot_list_returns_summaries(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    router.get("/api2/json/nodes/pve1/qemu/100/snapshot").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {"name": "current", "running": 1},
                    {"name": "pre-upgrade", "snaptime": 1700000000, "description": "before"},
                ]
            },
        )
    )

    payload = await call(hub, "pve_guest_snapshots", vmid=100)

    assert [item["name"] for item in payload["data"]["snapshots"]] == ["current", "pre-upgrade"]


async def test_guest_delete_requires_confirm(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    delete = router.delete("/api2/json/nodes/pve1/qemu/100").mock(
        return_value=Response(200, json={"data": UPID})
    )

    payload = await call(hub, "pve_guest_delete", vmid=100)

    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert not delete.called


async def test_guest_delete_dry_run_makes_no_write(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    delete = router.delete("/api2/json/nodes/pve1/qemu/100").mock(
        return_value=Response(200, json={"data": UPID})
    )

    payload = await call(hub, "pve_guest_delete", vmid=100, dry_run=True)

    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["action"] == "guest_delete"
    assert not delete.called
    assert not [item for item in router.calls if item.request.method == "DELETE"]


async def test_guest_delete_with_confirm_purges(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    delete = router.delete("/api2/json/nodes/pve1/qemu/100").mock(
        return_value=Response(200, json={"data": DELETE_UPID})
    )

    payload = await call(hub, "pve_guest_delete", vmid=100, confirm=True, wait=False)

    assert payload["ok"] is True
    assert payload["data"]["deleted"] is True
    request = delete.calls[0].request
    assert request.url.params["purge"] == "1"


async def test_guest_clone_enforces_vmid_range_and_maps_name(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    clone = router.post("/api2/json/nodes/pve1/qemu/100/clone").mock(
        return_value=Response(200, json={"data": CLONE_UPID})
    )

    blocked = await call(hub, "pve_guest_clone", vmid=100, newid=300)
    payload = await call(hub, "pve_guest_clone", vmid=100, newid=150, name="web-clone", wait=False)

    assert blocked["ok"] is False
    assert blocked["error"]["code"] == "policy_denied"
    assert payload["ok"] is True
    data = form(clone.calls[0].request)
    assert data["newid"] == "150"
    assert data["name"] == "web-clone"
    assert data["full"] == "1"


async def test_guest_create_lxc_posts_template_and_storage(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.post("/api2/json/nodes/pve1/lxc").mock(
        return_value=Response(200, json={"data": CREATE_UPID})
    )

    payload = await call(
        hub,
        "pve_guest_create_lxc",
        node="pve1",
        vmid=102,
        ostemplate="local:vztmpl/debian-12-standard_amd64.tar.zst",
        storage="local-lvm",
        hostname="cache",
        wait=False,
    )

    assert payload["ok"] is True
    data = form(route.calls[0].request)
    assert data["vmid"] == "102"
    assert data["ostemplate"].startswith("local:vztmpl/")
    assert data["storage"] == "local-lvm"
    assert data["hostname"] == "cache"
    assert data["unprivileged"] == "1"


async def test_guest_resize_puts_disk_and_size(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    route = router.put("/api2/json/nodes/pve1/qemu/100/resize").mock(
        return_value=Response(200, json={"data": RESIZE_UPID})
    )

    payload = await call(hub, "pve_guest_resize", vmid=100, disk="scsi0", size="+5G", wait=False)

    assert payload["ok"] is True
    data = form(route.calls[0].request)
    assert data["disk"] == "scsi0"
    assert data["size"] == "+5G"


async def test_guest_agent_ping(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)
    ping = router.post("/api2/json/nodes/pve1/qemu/100/agent/ping").mock(
        return_value=Response(200, json={"data": {"result": {}}})
    )

    payload = await call(hub, "pve_guest_agent_ping", vmid=100)

    assert payload["ok"] is True
    assert ping.called


async def test_guest_agent_ping_rejects_lxc(pve: Any, call: Any) -> None:
    hub, router = pve
    mock_guests(router)

    payload = await call(hub, "pve_guest_agent_ping", vmid=101)

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_read_only_policy_hides_write_tools(pve_read_only: Any) -> None:
    hub, _router = pve_read_only
    names = {tool.name for tool in await hub.mcp.list_tools()}

    assert "pve_guest_status" in names
    assert "pve_guests_list" in names
    assert "pve_guest_power" not in names
    assert "pve_guest_delete" not in names
    blocked = {item.name: item.reason for item in hub.blocked}
    assert "read_only" in blocked["pve_guest_power"]
    assert "read_only" in blocked["pve_guest_delete"]


async def test_missing_privilege_hides_tool(pve_audit_only: Any) -> None:
    hub, _router = pve_audit_only
    names = {tool.name for tool in await hub.mcp.list_tools()}

    assert "pve_guest_status" in names
    assert "pve_guest_power" not in names
    blocked = {item.name: item.reason for item in hub.blocked}
    assert "VM.PowerMgmt" in blocked["pve_guest_power"]
