"""Storage tools: definitions, usage and content listings."""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from .common import ok, pick, storage_summary

_CONTENT_KEYS = (
    "volid",
    "content",
    "format",
    "size",
    "used",
    "vmid",
    "ctime",
    "notes",
    "protected",
    "verification",
    "encrypted",
    "parent",
)
_CONTENT_TYPES = {
    "backup",
    "images",
    "iso",
    "rootdir",
    "vztmpl",
    "snippets",
    "dump",
}


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_storage_list",
        category="read",
        pve=[("Datastore.Audit", "/storage")],
        service="pve",
    )
    async def pve_storage_list(
        node: str | None = None,
        type: str | None = None,
        instance: str | None = None,
    ) -> str:
        """List storages with type, content types, usage and shared flag.

        Without node the cluster-wide storage configuration is returned; with node the
        node's view including capacity is returned. type filters by storage plugin.
        """
        client = hub.pve(instance)
        if node is not None:
            data = await client.get(f"/nodes/{node}/storage")
        else:
            params = {"type": type} if type else None
            data = await client.get("/storage", params=params)
        storages = [storage_summary(item) for item in _as_items(data)]
        if type is not None:
            storages = [storage for storage in storages if storage.get("type") == type]
        payload = {"node": node, "count": len(storages), "storages": storages}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_storage_status",
        category="read",
        pve=[("Datastore.Audit", "/storage/{storage}")],
        service="pve",
    )
    async def pve_storage_status(
        node: str,
        storage: str,
        instance: str | None = None,
    ) -> str:
        """Show one storage's status on a node (active, total, used, available)."""
        client = hub.pve(instance)
        data = await client.get(f"/nodes/{node}/storage/{storage}/status")
        payload = {"node": node, "storage": storage, "status": storage_summary(data)}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_storage_content",
        category="read",
        pve=[("Datastore.Audit", "/storage/{storage}")],
        service="pve",
    )
    async def pve_storage_content(
        node: str,
        storage: str,
        content: str | None = None,
        vmid: int | None = None,
        instance: str | None = None,
    ) -> str:
        """List volumes on a storage; content and vmid narrow the result.

        content is backup, images, iso, rootdir, vztmpl, snippets or dump.
        """
        if content is not None and content not in _CONTENT_TYPES:
            raise InvalidArgument(
                f"unknown content type {content!r}; expected one of {sorted(_CONTENT_TYPES)}"
            )
        client = hub.pve(instance)
        params: dict[str, Any] = {}
        if content is not None:
            params["content"] = content
        if vmid is not None:
            params["vmid"] = vmid
        data = await client.get(
            f"/nodes/{node}/storage/{storage}/content", params=params or None
        )
        volumes = [pick(item, _CONTENT_KEYS) for item in _as_items(data)]
        payload = {
            "node": node,
            "storage": storage,
            "content": content,
            "vmid": vmid,
            "count": len(volumes),
            "volumes": volumes,
        }
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
