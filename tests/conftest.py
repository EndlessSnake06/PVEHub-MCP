"""Shared fixtures for the curated PBS tool tests."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
import respx

from pvehub_mcp.config import PBSInstance, Settings
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import PVEHub

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


@pytest.fixture
def call() -> Callable[..., Awaitable[dict[str, Any]]]:
    async def _call(hub: PVEHub, tool: str, **arguments: Any) -> dict[str, Any]:
        result = await hub.mcp.call_tool(tool, arguments)
        text = result.content[0].text
        payload: dict[str, Any] = json.loads(text)
        return payload

    return _call


@pytest.fixture
def form() -> Callable[[httpx.Request], dict[str, list[str]]]:
    from urllib.parse import parse_qs

    def _form(request: httpx.Request) -> dict[str, list[str]]:
        return parse_qs(request.content.decode())

    return _form
