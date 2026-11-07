"""Tests for the curated cluster/node/HA read tools."""

from __future__ import annotations

from typing import Any

from httpx import Response

CLUSTER_TOOLS = {
    "pve_cluster_status",
    "pve_cluster_resources",
    "pve_nodes_list",
    "pve_node_status",
    "pve_node_rrddata",
    "pve_ha_status",
    "pve_ha_resources",
    "pve_ha_groups",
    "pve_cluster_log",
}


async def test_cluster_tools_registered_as_read(pve: Any) -> None:
    hub, _router = pve
    names = {tool.name for tool in await hub.mcp.list_tools()}
    assert names >= CLUSTER_TOOLS
    for name in CLUSTER_TOOLS:
        registered = hub.registered[name]
        assert registered.category == "read"
        assert registered.pve_privileges
        assert all(privilege.priv == "Sys.Audit" for privilege in registered.pve_privileges)


async def test_cluster_status_returns_compact_entries(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/cluster/status").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "id": "cluster",
                        "type": "cluster",
                        "name": "home",
                        "nodes": 3,
                        "quorate": 1,
                        "version": 7,
                    },
                    {
                        "id": "node/pve1",
                        "type": "node",
                        "name": "pve1",
                        "online": 1,
                        "local": 1,
                        "ip": "10.0.0.11",
                    },
                ]
            },
        )
    )

    payload = await call(hub, "pve_cluster_status")

    assert payload["ok"] is True
    entries = payload["data"]["entries"]
    assert entries[0]["quorate"] == 1
    assert entries[1]["ip"] == "10.0.0.11"


async def test_cluster_resources_filters_by_node(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/cluster/resources").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "id": "qemu/100",
                        "vmid": 100,
                        "name": "web",
                        "node": "pve1",
                        "type": "qemu",
                        "status": "running",
                        "maxmem": 1024,
                    },
                    {
                        "id": "lxc/101",
                        "vmid": 101,
                        "name": "db",
                        "node": "pve2",
                        "type": "lxc",
                        "status": "stopped",
                    },
                    {
                        "id": "storage/pve1/local",
                        "storage": "local",
                        "node": "pve1",
                        "type": "storage",
                        "content": "iso,vztmpl",
                    },
                ]
            },
        )
    )

    payload = await call(hub, "pve_cluster_resources", type="vm", node="pve1")

    assert payload["ok"] is True
    resources = payload["data"]["resources"]
    assert [item["vmid"] for item in resources if "vmid" in item] == [100]
    assert route.calls[0].request.url.params["type"] == "vm"


async def test_cluster_resources_rejects_unknown_type(pve: Any, call: Any) -> None:
    hub, _router = pve

    payload = await call(hub, "pve_cluster_resources", type="nonsense")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_nodes_and_node_status(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/nodes").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "node": "pve1",
                        "status": "online",
                        "cpu": 0.05,
                        "maxcpu": 8,
                        "mem": 1024,
                        "maxmem": 4096,
                        "uptime": 100,
                    }
                ]
            },
        )
    )
    router.get("/api2/json/nodes/pve1/status").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "pveversion": "pve-manager/9.0.3/abcdef",
                    "cpu": 0.01,
                    "memory": {"used": 1, "total": 2},
                    "rootfs": {"used": 3, "total": 4},
                    "loadavg": ["0.1", "0.2", "0.3"],
                    "cpuinfo": {"cores": 4, "cpus": 8, "model": "Test CPU", "sockets": 1},
                }
            },
        )
    )

    nodes = await call(hub, "pve_nodes_list")
    status = await call(hub, "pve_node_status", node="pve1")

    assert nodes["data"]["count"] == 1
    assert nodes["data"]["nodes"][0]["node"] == "pve1"
    assert status["data"]["status"]["pveversion"].startswith("pve-manager/")
    assert status["data"]["status"]["memory"]["total"] == 2


async def test_node_rrddata_limits_points_and_validates_timeframe(pve: Any, call: Any) -> None:
    hub, router = pve
    points = [{"time": index, "cpu": 0.5} for index in range(300)]
    route = router.get("/api2/json/nodes/pve1/rrddata").mock(
        return_value=Response(200, json={"data": points})
    )

    payload = await call(hub, "pve_node_rrddata", node="pve1", timeframe="hour", limit=100)
    invalid = await call(hub, "pve_node_rrddata", node="pve1", timeframe="fortnight")

    assert payload["data"]["points"][0]["time"] == 200
    assert len(payload["data"]["points"]) == 100
    assert route.calls[0].request.url.params["timeframe"] == "hour"
    assert invalid["ok"] is False
    assert invalid["error"]["code"] == "invalid_argument"


async def test_ha_status_resources_and_groups(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/cluster/ha/status/current").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {"id": "quorum", "type": "quorum", "status": "OK", "quorate": 1},
                    {"id": "service:vm:100", "type": "service", "sid": "vm:100", "state": "started"},
                ]
            },
        )
    )
    router.get("/api2/json/cluster/ha/resources").mock(
        return_value=Response(200, json={"data": [{"sid": "vm:100", "state": "started", "group": "g1"}]})
    )
    router.get("/api2/json/cluster/ha/groups").mock(
        return_value=Response(200, json={"data": [{"group": "g1", "nodes": "pve1,pve2"}]})
    )

    status = await call(hub, "pve_ha_status")
    resources = await call(hub, "pve_ha_resources")
    groups = await call(hub, "pve_ha_groups")

    assert status["data"]["entries"][0]["quorate"] == 1
    assert resources["data"]["resources"] == [{"sid": "vm:100", "state": "started", "group": "g1"}]
    assert groups["data"]["groups"][0]["nodes"] == "pve1,pve2"


async def test_cluster_log_caps_entries(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/cluster/log").mock(
        return_value=Response(
            200,
            json={"data": [{"time": 1, "node": "pve1", "user": "root@pam", "msg": "started", "tag": "pve"}]},
        )
    )

    payload = await call(hub, "pve_cluster_log", max=10)
    invalid = await call(hub, "pve_cluster_log", max=1000)

    assert payload["data"]["lines"][0]["msg"] == "started"
    assert route.calls[0].request.url.params["max"] == "10"
    assert invalid["error"]["code"] == "invalid_argument"
