"""Proxmox Backup Server REST client."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..errors import UpstreamError
from .base import BaseProxmoxClient, SchemaIndex
from .pve import _async_sleep, _format_task_log, _read_cache, _write_cache, parse_apidoc_js

logger = logging.getLogger(__name__)

_SCHEMA_URL = "/docs/api-viewer/apidoc.js"


class PBSClient(BaseProxmoxClient):
    kind = "pbs"

    def __init__(
        self,
        *,
        name: str,
        url: str,
        api_path: str,
        token_id: str,
        token_secret: str,
        verify: bool | str = True,
        ca_file: str | None = None,
        fingerprint: str | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        state_dir: str = "/data",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            name=name,
            url=url,
            api_path=api_path,
            auth_header=f"PBSAPIToken={token_id}:{token_secret}",
            verify=verify,
            ca_file=ca_file,
            fingerprint=fingerprint,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            transport=transport,
        )
        self.token_id = token_id
        self._state_dir = state_dir
        self._schema: SchemaIndex | None = None

    async def schema(self, *, refresh: bool = False) -> SchemaIndex:
        if self._schema is not None and not refresh:
            return self._schema
        from pathlib import Path

        cache = Path(self._state_dir) / f"apidoc-pbs-{self.name}.json"
        cached = _read_cache(cache)
        if cached is not None and not refresh:
            self._schema = SchemaIndex(cached["tree"], kind="pbs")
            return self._schema
        try:
            response = await self._client.get(_SCHEMA_URL)
            response.raise_for_status()
            tree = parse_apidoc_js(response.text)
            # PBS apidoc.js may contain several top-level schema variables; the management
            # API is the one whose first node is "/". Keep the largest root array.
            tree = _management_tree(tree)
        except (httpx.HTTPError, ValueError) as exc:
            if cached is not None:
                logger.warning("PBS schema refresh failed, using cached copy: %s", exc)
                self._schema = SchemaIndex(cached["tree"], kind="pbs")
                return self._schema
            raise UpstreamError(f"pbs {self.name}: cannot load API schema: {exc}") from exc
        self._schema = SchemaIndex(tree, kind="pbs")
        _write_cache(cache, tree)
        return self._schema

    async def api_schema(self, path: str) -> dict[str, Any]:
        schema = await self.schema()
        return schema.describe(path)

    async def permissions(self, path: str | None = None) -> dict[str, dict[str, Any]]:
        params = {"path": path} if path else None
        data = await self.get("/access/permissions", params=params)
        return data if isinstance(data, dict) else {}

    async def task_status(self, node: str, upid: str) -> dict[str, Any]:
        data = await self.get(f"/nodes/{node}/tasks/{upid}/status")
        return data if isinstance(data, dict) else {"raw": data}

    async def task_log(self, node: str, upid: str, *, start: int = 0, limit: int = 50) -> str:
        data = await self.get(
            f"/nodes/{node}/tasks/{upid}/log", params={"start": start, "limit": limit}
        )
        return _format_task_log(data)

    async def wait_task(
        self,
        node: str,
        upid: str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        interval = max(0.25, poll_interval)
        while True:
            status = await self.task_status(node, upid)
            state = str(status.get("status", ""))
            if state != "running":
                exitstatus = status.get("exitstatus")
                result: dict[str, Any] = {
                    "upid": upid,
                    "node": node,
                    "completed": True,
                    "status": state,
                    "exitstatus": exitstatus,
                    "success": exitstatus in {"OK", None},
                }
                try:
                    result["log_tail"] = await self.task_log(node, upid, limit=15)
                except Exception as exc:
                    result["log_tail_error"] = str(exc)
                return result
            if time.monotonic() >= deadline:
                return {
                    "upid": upid,
                    "node": node,
                    "completed": False,
                    "timed_out": True,
                    "status": state,
                }
            await _async_sleep(interval)
            interval = min(3.0, interval * 1.5)


def _management_tree(tree: list[dict[str, Any]]) -> list[dict[str, Any]]:
    roots = [node for node in tree if isinstance(node, dict) and node.get("path") == "/"]
    if roots:
        return roots
    return tree
