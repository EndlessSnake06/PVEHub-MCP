"""Node network interface tools (read-only)."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from .common import ok, pick

_NETWORK_KEYS = (
    "iface",
    "type",
    "active",
    "exists",
    "method",
    "method6",
    "address",
    "netmask",
    "cidr",
    "gateway",
    "address6",
    "netmask6",
    "cidr6",
    "gateway6",
    "autostart",
    "priority",
    "mtu",
    "families",
    "bridge_ports",
    "bridge_vlan_aware",
    "bridge-access",
    "bridge_vids",
    "bond_mode",
    "bond-primary",
    "bond_xmit_hash_policy",
    "slaves",
    "vlan-id",
    "vlan-raw-device",
    "ovs_bridge",
    "ovs_bonds",
    "ovs_ports",
    "ovs_options",
    "ovs_tag",
    "comments",
    "comments6",
)
_INTERFACE_TYPES = {
    "bridge",
    "bond",
    "eth",
    "alias",
    "vlan",
    "fabric",
    "OVSBridge",
    "OVSBond",
    "OVSPort",
    "OVSIntPort",
    "vnet",
    "unknown",
}


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_network_list",
        category="read",
        pve=[("Sys.Audit", "/nodes/{node}")],
        service="pve",
    )
    async def pve_network_list(
        node: str,
        type: str | None = None,
        instance: str | None = None,
    ) -> str:
        """List a node's network interfaces (bridges, bonds, VLANs, physical NICs).

        type filters by interface type, for example bridge or bond.
        """
        if type is not None and type not in _INTERFACE_TYPES:
            raise InvalidArgument(
                f"unknown interface type {type!r}; expected one of {sorted(_INTERFACE_TYPES)}"
            )
        client = hub.pve(instance)
        params = {"type": type} if type else None
        data = await client.get(f"/nodes/{node}/network", params=params)
        interfaces = [pick(item, _NETWORK_KEYS) for item in _as_items(data)]
        payload = {"node": node, "count": len(interfaces), "interfaces": interfaces}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_network_interface",
        category="read",
        pve=[("Sys.Audit", "/nodes/{node}")],
        service="pve",
    )
    async def pve_network_interface(
        node: str,
        iface: str,
        instance: str | None = None,
    ) -> str:
        """Show one network interface's configuration and state on a node."""
        client = hub.pve(instance)
        data = await client.get(f"/nodes/{node}/network/{iface}")
        payload = {"node": node, "interface": pick(data, _NETWORK_KEYS)}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
