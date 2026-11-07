"""Proxmox VE REST client."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from ..errors import UpstreamError
from .base import BaseProxmoxClient, SchemaIndex

logger = logging.getLogger(__name__)

_SCHEMA_URL = "/pve-docs/api-viewer/apidoc.js"
_SCHEMA_TTL = 24 * 3600


def parse_apidoc_js(text: str) -> list[dict[str, Any]]:
    """Extract the ``apiSchema`` array from Proxmox' ``apidoc.js``."""

    index = text.find("[")
    if index < 0:
        raise ValueError("no JSON array found in apidoc.js")
    try:
        parsed, _ = json.JSONDecoder().raw_decode(text[index:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"cannot parse apidoc.js: {exc}") from exc
    if not isinstance(parsed, list):
        raise ValueError("apidoc.js does not contain an array")
    return parsed


class PVEClient(BaseProxmoxClient):
    kind = "pve"

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
            auth_header=f"PVEAPIToken={token_id}={token_secret}",
            verify=verify,
            ca_file=ca_file,
            fingerprint=fingerprint,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            transport=transport,
        )
        self.token_id = token_id
        self._state_dir = Path(state_dir)
        self._schema: SchemaIndex | None = None

    # -- schema ------------------------------------------------------------
    async def schema(self, *, refresh: bool = False) -> SchemaIndex:
        if self._schema is not None and not refresh:
            return self._schema
        cache = self._state_dir / f"apidoc-{self.name}.json"
        cached = _read_cache(cache)
        if cached is not None and not refresh:
            self._schema = SchemaIndex(cached["tree"], kind="pve")
            return self._schema
        try:
            response = await self._client.get(_SCHEMA_URL)
            response.raise_for_status()
            tree = parse_apidoc_js(response.text)
        except (httpx.HTTPError, ValueError) as exc:
            if cached is not None:
                logger.warning("PVE schema refresh failed, using cached copy: %s", exc)
                self._schema = SchemaIndex(cached["tree"], kind="pve")
                return self._schema
            raise UpstreamError(f"pve {self.name}: cannot load API schema: {exc}") from exc
        self._schema = SchemaIndex(tree, kind="pve")
        _write_cache(cache, tree)
        return self._schema

    async def api_schema(self, path: str) -> dict[str, Any]:
        schema = await self.schema()
        return schema.describe(path)

    # -- permissions -------------------------------------------------------
    async def permissions(self, path: str | None = None) -> dict[str, dict[str, Any]]:
        params = {"path": path} if path else None
        data = await self.get("/access/permissions", params=params)
        return data if isinstance(data, dict) else {}

    # -- tasks -------------------------------------------------------------
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
                    "success": exitstatus in {"OK", None} if state == "stopped" else False,
                }
                try:
                    result["log_tail"] = await self.task_log(node, upid, limit=15)
                except Exception as exc:  # log tail is best-effort
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


def _format_task_log(data: Any, *, max_lines: int = 200) -> str:
    if isinstance(data, list):
        lines = []
        for item in data[-max_lines:]:
            if isinstance(item, dict):
                lines.append(str(item.get("t", "")))
            else:
                lines.append(str(item))
        return "\n".join(line for line in lines if line)
    return str(data)[:8000]


def _read_cache(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    fetched = payload.get("fetched_at", 0)
    tree = payload.get("tree")
    if not isinstance(fetched, (int, float)) or not isinstance(tree, list):
        return None
    if time.time() - fetched > _SCHEMA_TTL:
        return None
    return payload


def _write_cache(path: Path, tree: list[dict[str, Any]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"fetched_at": int(time.time()), "tree": tree}, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError as exc:
        logger.warning("cannot write API schema cache %s: %s", path, exc)


async def _async_sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
