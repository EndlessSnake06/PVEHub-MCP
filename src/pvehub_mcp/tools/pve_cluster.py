"""Cluster, node and HA read tools."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from ..validation import api_segment
from .common import guest_summary, node_summary, ok, pick, storage_summary

_CLUSTER_KEYS = (
    "id",
    "type",
    "name",
    "nodeid",
    "nodes",
    "online",
    "quorate",
    "version",
    "ip",
    "level",
    "local",
)
_HA_KEYS = (
    "id",
    "type",
    "node",
    "status",
    "state",
    "sid",
    "quorate",
    "crm_state",
    "request_state",
    "armed-state",
    "timestamp",
    "max_relocate",
    "max_restart",
    "failback",
    "auto-rebalance",
    "resource_mode",
)
_HA_RESOURCE_KEYS = (
    "sid",
    "type",
    "state",
    "group",
    "comment",
    "max_relocate",
    "max_restart",
    "failback",
    "auto-rebalance",
)
_HA_GROUP_KEYS = ("group", "nodes", "comment", "restricted", "nofailback", "digest")
_RESOURCE_KEYS = (
    "id",
    "type",
    "status",
    "name",
    "node",
    "pool",
    "sdn",
    "network",
    "network-type",
    "zone-type",
    "protocol",
    "plugintype",
    "shared",
)
_LOG_KEYS = ("time", "node", "user", "msg", "tag", "type", "sev")
_NODE_STATUS_KEYS = (
    "pveversion",
    "cpu",
    "cpuinfo",
    "memory",
    "rootfs",
    "loadavg",
    "boot-info",
    "current-kernel",
    "uptime",
)
_RESOURCE_TYPES = {
    "node",
    "storage",
    "pool",
    "qemu",
    "lxc",
    "openvz",
    "sdn",
    "network",
    "vm",
}
_RRD_TIMEFRAMES = {"hour", "day", "week", "month", "year", "decade"}
_RRD_CONSOLIDATION = {"AVERAGE", "MAX"}


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _resource_summary(item: dict[str, Any]) -> dict[str, Any]:
    kind = item.get("type")
    if kind == "node":
        return node_summary(item)
    if kind == "storage":
        return storage_summary(item)
    if kind in {"qemu", "lxc"}:
        return guest_summary(item)
    return pick(item, _RESOURCE_KEYS)


def _log_line(item: dict[str, Any]) -> dict[str, Any]:
    selected = pick(item, _LOG_KEYS)
    return selected or item


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_cluster_status",
        category="read",
        pve=[("Sys.Audit", "/")],
        service="pve",
    )
    async def pve_cluster_status(instance: str | None = None) -> str:
        """Show cluster quorum and membership from /cluster/status.

        Returns one entry per cluster and node (id, online, quorate, node count, IP).
        """
        client = hub.pve(instance)
        data = await client.get("/cluster/status")
        entries = [pick(item, _CLUSTER_KEYS) for item in _as_items(data)]
        return ok({"entries": entries}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_cluster_resources",
        category="read",
        pve=[("Sys.Audit", "/")],
        service="pve",
    )
    async def pve_cluster_resources(
        type: str | None = None,
        node: str | None = None,
        instance: str | None = None,
    ) -> str:
        """List cluster resources (nodes, guests, storage, pools) with a compact summary.

        type filters the API result (node, storage, pool, qemu, lxc, sdn, network, vm);
        node filters guests and storage by cluster node.
        """
        if type is not None and type not in _RESOURCE_TYPES:
            raise InvalidArgument(f"unknown resource type {type!r}; expected one of {sorted(_RESOURCE_TYPES)}")
        client = hub.pve(instance)
        params = {"type": type} if type else None
        data = await client.get("/cluster/resources", params=params)
        items = [_resource_summary(item) for item in _as_items(data)]
        if node is not None:
            items = [item for item in items if item.get("node") == node]
        return ok(
            {"type": type, "node": node, "count": len(items), "resources": items},
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(
        name="pve_nodes_list",
        category="read",
        pve=[("Sys.Audit", "/nodes")],
        service="pve",
    )
    async def pve_nodes_list(instance: str | None = None) -> str:
        """List cluster nodes with status, CPU, memory and uptime."""
        client = hub.pve(instance)
        data = await client.get("/nodes")
        nodes = [node_summary(item) for item in _as_items(data)]
        return ok({"count": len(nodes), "nodes": nodes}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_node_status",
        category="read",
        pve=[("Sys.Audit", "/nodes/{node}")],
        service="pve",
    )
    async def pve_node_status(node: str, instance: str | None = None) -> str:
        """Show a node's PVE version, CPU, memory, root filesystem and load average."""
        node = api_segment(node, "node")
        client = hub.pve(instance)
        data = await client.get(f"/nodes/{node}/status")
        payload = {"node": node, "status": pick(data, _NODE_STATUS_KEYS)}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_node_rrddata",
        category="read",
        pve=[("Sys.Audit", "/nodes/{node}")],
        service="pve",
    )
    async def pve_node_rrddata(
        node: str,
        timeframe: str,
        cf: str | None = None,
        limit: int = 120,
        instance: str | None = None,
    ) -> str:
        """Read node RRD metrics (cpu, memory, network, disk) for a timeframe.

        timeframe is hour, day, week, month, year or decade; cf is AVERAGE (default) or MAX.
        limit caps the number of returned points (most recent kept).
        """
        if timeframe not in _RRD_TIMEFRAMES:
            raise InvalidArgument(f"unknown timeframe {timeframe!r}; expected one of {sorted(_RRD_TIMEFRAMES)}")
        if cf is not None and cf not in _RRD_CONSOLIDATION:
            raise InvalidArgument(f"unknown cf {cf!r}; expected one of {sorted(_RRD_CONSOLIDATION)}")
        if limit < 1 or limit > 1000:
            raise InvalidArgument("limit must be between 1 and 1000")
        node = api_segment(node, "node")
        client = hub.pve(instance)
        params: dict[str, Any] = {"timeframe": timeframe}
        if cf is not None:
            params["cf"] = cf
        data = await client.get(f"/nodes/{node}/rrddata", params=params)
        points = _as_items(data)[-limit:]
        return ok(
            {"node": node, "timeframe": timeframe, "cf": cf, "points": points},
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(
        name="pve_ha_status",
        category="read",
        pve=[("Sys.Audit", "/")],
        service="pve",
    )
    async def pve_ha_status(instance: str | None = None) -> str:
        """Show current HA manager status (quorum, master, LRM and service states)."""
        client = hub.pve(instance)
        data = await client.get("/cluster/ha/status/current")
        entries = [pick(item, _HA_KEYS) for item in _as_items(data)]
        return ok({"entries": entries}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_ha_resources",
        category="read",
        pve=[("Sys.Audit", "/")],
        service="pve",
    )
    async def pve_ha_resources(type: str | None = None, instance: str | None = None) -> str:
        """List HA-managed resources; type filters ct or vm."""
        if type is not None and type not in {"ct", "vm"}:
            raise InvalidArgument("type must be 'ct' or 'vm'")
        client = hub.pve(instance)
        params = {"type": type} if type else None
        data = await client.get("/cluster/ha/resources", params=params)
        resources = [pick(item, _HA_RESOURCE_KEYS) for item in _as_items(data)]
        return ok(
            {"count": len(resources), "resources": resources},
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(
        name="pve_ha_groups",
        category="read",
        pve=[("Sys.Audit", "/")],
        service="pve",
    )
    async def pve_ha_groups(instance: str | None = None) -> str:
        """List HA node affinity groups with member nodes and flags."""
        client = hub.pve(instance)
        data = await client.get("/cluster/ha/groups")
        groups = [pick(item, _HA_GROUP_KEYS) for item in _as_items(data)]
        return ok({"count": len(groups), "groups": groups}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_cluster_log",
        category="read",
        pve=[("Sys.Syslog", "/")],
        service="pve",
    )
    async def pve_cluster_log(max: int = 50, instance: str | None = None) -> str:
        """Read the recent cluster log (max entries capped at 500)."""
        if max < 1 or max > 500:
            raise InvalidArgument("max must be between 1 and 500")
        client = hub.pve(instance)
        data = await client.get("/cluster/log", params={"max": max})
        lines = [_log_line(item) for item in _as_items(data)]
        return ok({"count": len(lines), "lines": lines}, max_bytes=hub.settings.max_output_bytes)
