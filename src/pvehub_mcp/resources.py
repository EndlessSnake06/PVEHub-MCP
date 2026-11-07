"""Read-only MCP resources for PVE and PBS.

Resources expose the same data as read-only tools, so they are subject to the
same policy decision (``read`` category, ``tools.allow``/``tools.deny``).  A
policy that hides every read tool must not leave the guest/node/storage lists
reachable through ``resources/list``.
"""

from __future__ import annotations

import json
from typing import Any

from .tools.common import guest_summary, node_summary, storage_summary


def _visible(hub: Any, name: str) -> bool:
    return bool(hub.policy.tool_decision(name, "read").allowed)


def register(hub: Any) -> None:
    mcp = hub.mcp

    if _visible(hub, "pvehub_resource_nodes"):

        @mcp.resource("proxmox://nodes", name="PVE nodes", mime_type="application/json")
        async def nodes_resource() -> str:
            """All configured PVE nodes with status and load."""
            output: dict[str, Any] = {}
            for name, client in hub.pve_clients.items():
                try:
                    data = await client.get("/nodes")
                    output[name] = [
                        node_summary(item) for item in data if isinstance(item, dict)
                    ] if isinstance(data, list) else []
                except Exception as exc:  # resource reads must not crash the server
                    output[name] = {"error": str(exc)}
            return json.dumps(output, ensure_ascii=False, separators=(",", ":"))

    if _visible(hub, "pvehub_resource_guests"):

        @mcp.resource("proxmox://guests", name="PVE guests", mime_type="application/json")
        async def guests_resource() -> str:
            """All VMs and LXC containers across configured PVE instances."""
            output: dict[str, Any] = {}
            for name, client in hub.pve_clients.items():
                try:
                    data = await client.get("/cluster/resources", params={"type": "vm"})
                    output[name] = [
                        guest_summary(item) for item in data if isinstance(item, dict)
                    ] if isinstance(data, list) else []
                except Exception as exc:
                    output[name] = {"error": str(exc)}
            return json.dumps(output, ensure_ascii=False, separators=(",", ":"))

    if _visible(hub, "pvehub_resource_storage"):

        @mcp.resource("proxmox://storage", name="PVE storage", mime_type="application/json")
        async def storage_resource() -> str:
            """All PVE storage entries across configured PVE instances."""
            output: dict[str, Any] = {}
            for name, client in hub.pve_clients.items():
                try:
                    data = await client.get("/storage")
                    output[name] = [
                        storage_summary(item) for item in data if isinstance(item, dict)
                    ] if isinstance(data, list) else []
                except Exception as exc:
                    output[name] = {"error": str(exc)}
            return json.dumps(output, ensure_ascii=False, separators=(",", ":"))

    if _visible(hub, "pvehub_resource_pbs_datastores"):

        @mcp.resource("pbs://datastores", name="PBS datastores", mime_type="application/json")
        async def pbs_datastores_resource() -> str:
            """All PBS datastores across configured PBS instances."""
            output: dict[str, Any] = {}
            for name, client in hub.pbs_clients.items():
                try:
                    output[name] = await client.get("/admin/datastore")
                except Exception as exc:
                    output[name] = {"error": str(exc)}
            return json.dumps(output, ensure_ascii=False, separators=(",", ":"))
