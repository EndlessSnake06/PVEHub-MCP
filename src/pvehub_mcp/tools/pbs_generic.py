"""Generic PBS API bridge: schema lookup plus arbitrary API calls."""

from __future__ import annotations

from typing import Any

from ..errors import ConfirmRequired
from .common import ok, parse_upid_node


def register(hub: Any) -> None:
    @hub.tool(name="pbs_api_schema", category="read", service="pbs")
    async def pbs_api_schema(
        path: str = "/",
        search: str | None = None,
        instance: str | None = None,
    ) -> str:
        """Describe a PBS API path (methods, parameters, return type) or search paths."""
        client = hub.pbs(instance)
        schema = await client.schema()
        if search:
            return ok({"search": search, "paths": schema.search(search, limit=50)})
        return ok(
            schema.describe(path),
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(name="pbs_api_call", category="generic", service="pbs")
    async def pbs_api_call(
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        instance: str | None = None,
        wait: bool = False,
        timeout: int | None = None,
        confirm: bool = False,
    ) -> str:
        """Call an arbitrary PBS API endpoint through the token's permissions.

        Non-GET methods require confirm=true.
        """
        hub.policy.check_generic(method, path, params)
        if method.upper() != "GET" and not confirm:
            raise ConfirmRequired(
                f"{method.upper()} via the generic API requires confirm=true",
                details={"method": method.upper(), "path": path},
            )
        client = hub.pbs(instance)
        result = await client._request(method.upper(), path, params=params, data=params)
        payload: dict[str, Any] = {"method": method.upper(), "path": path, "result": result}
        if wait and isinstance(result, str) and result.startswith("UPID:"):
            node = parse_upid_node(result) or "localhost"
            payload["task"] = await client.wait_task(
                node,
                result,
                timeout=float(timeout or hub.settings.task_timeout_seconds),
            )
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
