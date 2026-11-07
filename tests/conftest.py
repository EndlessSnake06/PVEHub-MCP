"""Shared fixtures for the curated PVE tool tests.

A real :class:`PVEHub` is built against a mocked PVE API: ``/access/permissions`` returns a
full permission set so every curated tool registers, and individual tests add routes for
the endpoints they exercise.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
import respx
from httpx import Response

from pvehub_mcp.config import Settings
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import PVEHub

BASE = "https://pve.test:8006"

FULL_PERMISSIONS: dict[str, dict[str, int]] = {
    "/": {
        "Sys.Audit": 1,
        "VM.Audit": 1,
        "VM.PowerMgmt": 1,
        "VM.Snapshot": 1,
        "VM.Snapshot.Rollback": 1,
        "VM.Clone": 1,
        "VM.Allocate": 1,
        "VM.Migrate": 1,
        "VM.Config.Disk": 1,
        "VM.Backup": 1,
        "VM.Monitor": 1,
        "Datastore.Audit": 1,
        "Datastore.AllocateSpace": 1,
        "propagate": 1,
    }
}

AUDIT_ONLY_PERMISSIONS: dict[str, dict[str, int]] = {
    "/": {"Sys.Audit": 1, "VM.Audit": 1, "propagate": 1}
}


def make_settings(tmp_path: Any) -> Settings:
    return Settings.model_validate(
        {
            "transport": "stdio",
            "pve": [
                {
                    "name": "test",
                    "url": BASE,
                    "token_id": "root@pam!pvehub",
                    "token_secret": "test-secret",
                }
            ],
            "policy_file": str(tmp_path / "policy.yaml"),
            "audit_log": None,
            "state_dir": str(tmp_path),
            "capabilities_refresh_seconds": 0,
            "capabilities_fail_open": True,
            "task_timeout_seconds": 5,
        }
    )


async def _build(
    tmp_path: Any,
    router: respx.MockRouter,
    *,
    permissions: dict[str, dict[str, int]] | None = None,
    policy: Policy | None = None,
) -> PVEHub:
    router.get("/api2/json/access/permissions").mock(
        return_value=Response(200, json={"data": permissions or FULL_PERMISSIONS})
    )
    hub = PVEHub(make_settings(tmp_path), policy)
    hub.build()
    await hub.initialize()
    return hub


@pytest.fixture
async def pve(tmp_path: Any) -> AsyncIterator[tuple[PVEHub, respx.MockRouter]]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        hub = await _build(tmp_path, router)
        try:
            yield hub, router
        finally:
            await hub.close()


@pytest.fixture
async def pve_read_only(tmp_path: Any) -> AsyncIterator[tuple[PVEHub, respx.MockRouter]]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        hub = await _build(tmp_path, router, policy=Policy(file=PolicyFile(read_only=True)))
        try:
            yield hub, router
        finally:
            await hub.close()


@pytest.fixture
async def pve_audit_only(tmp_path: Any) -> AsyncIterator[tuple[PVEHub, respx.MockRouter]]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        hub = await _build(tmp_path, router, permissions=AUDIT_ONLY_PERMISSIONS)
        try:
            yield hub, router
        finally:
            await hub.close()


CallTool = Callable[..., Awaitable[dict[str, Any]]]


@pytest.fixture
def call() -> CallTool:
    async def _call(hub: PVEHub, tool: str, **arguments: Any) -> dict[str, Any]:
        result = await hub.mcp.call_tool(tool, arguments)
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert isinstance(payload, dict)
        return payload

    return _call
