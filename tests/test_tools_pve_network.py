"""Tests for the node network read tools."""

from __future__ import annotations

from typing import Any

from httpx import Response

INTERFACE = {
    "iface": "vmbr0",
    "type": "bridge",
    "active": 1,
    "exists": 1,
    "method": "static",
    "address": "10.0.0.11",
    "netmask": "255.255.255.0",
    "gateway": "10.0.0.1",
    "bridge_ports": "eno1",
    "bridge_vlan_aware": 1,
    "autostart": 1,
    "families": ["inet"],
    "comments": "management",
}


async def test_network_tools_registered_as_read(pve: Any) -> None:
    hub, _router = pve
    names = {tool.name for tool in await hub.mcp.list_tools()}

    assert {"pve_network_list", "pve_network_interface"} <= names
    for name in ("pve_network_list", "pve_network_interface"):
        assert hub.registered[name].category == "read"
        assert hub.registered[name].pve_privileges[0].path == "/nodes/{node}"


async def test_network_list_filters_type(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/nodes/pve1/network").mock(
        return_value=Response(
            200,
            json={"data": [INTERFACE, {"iface": "eno1", "type": "eth", "active": 1}]},
        )
    )

    payload = await call(hub, "pve_network_list", node="pve1", type="bridge")

    assert payload["ok"] is True
    assert payload["data"]["count"] == 2
    assert payload["data"]["interfaces"][0]["iface"] == "vmbr0"
    assert route.calls[0].request.url.params["type"] == "bridge"


async def test_network_interface_single(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/nodes/pve1/network/vmbr0").mock(
        return_value=Response(200, json={"data": INTERFACE})
    )

    payload = await call(hub, "pve_network_interface", node="pve1", iface="vmbr0")

    assert payload["data"]["interface"]["address"] == "10.0.0.11"
    assert payload["data"]["interface"]["bridge_ports"] == "eno1"


async def test_network_list_rejects_unknown_type(pve: Any, call: Any) -> None:
    hub, _router = pve

    payload = await call(hub, "pve_network_list", node="pve1", type="wifi")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
