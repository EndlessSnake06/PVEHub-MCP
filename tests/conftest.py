"""Shared fixtures for the curated tool tests.

The PVE fixtures build a real :class:`PVEHub` against a mocked PVE API; the PBS fixtures do
the same for PBS. The exec tests use their own recorder-based environment further below.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from httpx import Response

from pvehub_mcp.config import PBSInstance, Settings
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import PVEHub

# -- PVE -------------------------------------------------------------------
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


def _pve_settings(tmp_path: Any) -> Settings:
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
    hub = PVEHub(_pve_settings(tmp_path), policy)
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


# -- PBS -------------------------------------------------------------------
BASE_URL = "https://pbs.test"
TOKEN_ID = "root@pam!pvehub"
ALL_PRIVILEGES = (
    "Datastore.Audit",
    "Datastore.Modify",
    "Datastore.Prune",
    "Datastore.Verify",
    "Remote.Audit",
    "Remote.Modify",
    "Remote.Read",
    "Sys.Audit",
)


def build_hub(*, read_only: bool = False) -> PVEHub:
    settings = Settings(
        transport="stdio",
        pbs=[
            PBSInstance(
                name="pbs1",
                url=BASE_URL,
                token_id=TOKEN_ID,
                token_secret="test-secret",
            )
        ],
        audit_log=None,
        capabilities_fail_open=True,
        capabilities_refresh_seconds=0,
    )
    hub = PVEHub(settings, Policy(file=PolicyFile(read_only=read_only)))
    hub.build()
    return hub


def grant_permissions(router: respx.Router, privileges: tuple[str, ...] = ALL_PRIVILEGES) -> None:
    permissions = {"/": {**{privilege: True for privilege in privileges}, "propagate": True}}
    router.get("/api2/extjs/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": permissions})
    )


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock_router:
        yield mock_router


@pytest.fixture
async def hub_factory(router: respx.Router) -> Any:
    hubs: list[PVEHub] = []

    async def factory(
        *,
        read_only: bool = False,
        privileges: tuple[str, ...] = ALL_PRIVILEGES,
    ) -> PVEHub:
        hub = build_hub(read_only=read_only)
        grant_permissions(router, privileges)
        await hub.initialize()
        hubs.append(hub)
        return hub

    yield factory
    for hub in hubs:
        await hub.close()


@pytest.fixture
async def hub(hub_factory: Callable[..., Awaitable[PVEHub]]) -> PVEHub:
    return await hub_factory()


# -- common ----------------------------------------------------------------
CallTool = Callable[..., Awaitable[dict[str, Any]]]


@pytest.fixture
def call() -> CallTool:
    async def _call(hub: PVEHub, tool: str, **arguments: Any) -> dict[str, Any]:
        result = await hub.mcp.call_tool(tool, arguments)
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert isinstance(payload, dict)
        return payload

    return _call


@pytest.fixture
def form() -> Callable[[httpx.Request], dict[str, list[str]]]:
    def _form(request: httpx.Request) -> dict[str, list[str]]:
        return parse_qs(request.content.decode())

    return _form
