"""Generic PVE API bridge: schema lookup plus arbitrary API calls."""

from __future__ import annotations

from typing import Any

from ..tools.common import ok, parse_vmid_from_upid


def register(hub: Any) -> None:
    @hub.tool(name="pve_api_schema", category="read", service="pve")
    async def pve_api_schema(
        path: str = "/",
        search: str | None = None,
        instance: str | None = None,
    ) -> str:
        """Describe a PVE API path (methods, parameters, return type) or search paths.

        Use this before pve_api_call when no curated tool exists. The schema comes from the
        server's own apidoc.js and is cached on disk.
        """
        client = hub.pve(instance)
        schema = await client.schema()
        if search:
            return ok({"search": search, "paths": schema.search(search, limit=50)})
        data = schema.describe(path)
        return ok(data, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(name="pve_api_call", category="generic", service="pve")
    async def pve_api_call(
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        instance: str | None = None,
        wait: bool = False,
        timeout: int | None = None,
    ) -> str:
        """Call an arbitrary PVE API endpoint through the token's permissions.

        method is GET/POST/PUT/DELETE; path must start with '/'. Parameters are sent as
        query (GET/DELETE) or form data (POST/PUT); lists become repeated keys, objects
        JSON strings. With wait=true a returned UPID is polled until completion.
        """
        hub.policy.check_generic(method, path, params)
        client = hub.pve(instance)
        result = await client._request(method.upper(), path, params=params, data=params)
        payload: dict[str, Any] = {"method": method.upper(), "path": path, "result": result}
        if wait and isinstance(result, str) and result.startswith("UPID:"):
            node = parse_vmid_from_upid(result)
            if node:
                task = await client.wait_task(
                    node,
                    result,
                    timeout=float(timeout or hub.settings.task_timeout_seconds),
                )
                payload["task"] = task
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
