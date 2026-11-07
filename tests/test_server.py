"""Server registration, wrapper and HTTP transport tests."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.client import Client
from pydantic import ValidationError

from pvehub_mcp.config import PVEInstance, Settings
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import PVEHub, build_http_app

PERMISSIONS = {
    "/": {"Sys.Audit": 1},
    "/vms": {"VM.Audit": 1},
    "/vms/100": {"VM.PowerMgmt": 1},
    "/storage": {"Datastore.Audit": 1},
}


def _settings(**overrides: object) -> Settings:
    data = {
        "transport": "stdio",
        "pve": [
            PVEInstance(
                name="test",
                url="https://pve.test:8006",
                token_id="pvehub@pve!mcp",
                token_secret="secret",
                verify=False,
                max_retries=0,
            )
        ],
        "audit_log": None,
        "state_dir": "/tmp/pvehub-server-tests",
        "capabilities_fail_open": True,
    }
    data.update(overrides)
    return Settings.model_validate(data)


async def _hub(policy: Policy | None = None) -> PVEHub:
    hub = PVEHub(_settings(), policy or Policy(file=PolicyFile()))
    hub.build()
    await hub.initialize()
    return hub


@respx.mock
async def test_tools_list_and_generic_call() -> None:
    respx.get("https://pve.test:8006/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    respx.get("https://pve.test:8006/api2/json/version").mock(
        return_value=httpx.Response(200, json={"data": {"version": "8.2.4", "release": "8.2"}})
    )
    hub = await _hub()
    try:
        async with Client(hub.mcp) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"pvehub_capabilities", "pvehub_health", "pve_api_schema", "pve_api_call"} <= names
            result = await client.call_tool("pve_api_call", {"method": "GET", "path": "/version"})
            assert not result.is_error
            payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
            assert payload["data"]["result"]["version"] == "8.2.4"
    finally:
        await hub.close()


@respx.mock
async def test_generic_policy_denial() -> None:
    respx.get("https://pve.test:8006/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    hub = await _hub()
    try:
        async with Client(hub.mcp) as client:
            result = await client.call_tool(
                "pve_api_call", {"method": "POST", "path": "/access/ticket"}
            )
            assert not result.is_error
            payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
            assert payload["ok"] is False
            assert payload["error"]["code"] == "policy_denied"
    finally:
        await hub.close()


@respx.mock
async def test_destructive_confirm_and_dry_run() -> None:
    respx.get("https://pve.test:8006/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    hub = await _hub()

    @hub.tool(name="test_delete", category="destructive", service="pve")
    async def test_delete(vmid: int, confirm: bool = False, dry_run: bool = False) -> str:
        """Test-only destructive tool."""
        if dry_run:
            return json.dumps({"ok": True, "data": {"dry_run": True}})
        return json.dumps({"ok": True, "data": {"deleted": vmid}})

    try:
        async with Client(hub.mcp) as client:
            result = await client.call_tool("test_delete", {"vmid": 100})
            payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
            assert payload["error"]["code"] == "confirm_required"

            result = await client.call_tool("test_delete", {"vmid": 100, "dry_run": True})
            payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
            assert payload["data"]["dry_run"] is True

            result = await client.call_tool("test_delete", {"vmid": 100, "confirm": True})
            payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
            assert payload["data"]["deleted"] == 100

            result = await client.call_tool("test_delete", {"vmid": 999, "confirm": True})
            payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
            assert payload["error"]["code"] == "policy_denied"
    finally:
        await hub.close()


@respx.mock
async def test_read_only_hides_mutating_tools() -> None:
    respx.get("https://pve.test:8006/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    hub = await _hub(Policy(file=PolicyFile.model_validate({"read_only": True})))

    @hub.tool(name="test_delete", category="destructive", service="pve")
    async def test_delete(vmid: int, confirm: bool = False) -> str:
        """Test-only destructive tool."""
        return json.dumps({"ok": True, "data": {"deleted": vmid}})

    try:
        async with Client(hub.mcp) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert "test_delete" not in names
            assert "pvehub_capabilities" in names
            assert any(item.name == "test_delete" for item in hub.blocked)
    finally:
        await hub.close()


@respx.mock
async def test_http_health_and_bearer_auth() -> None:
    respx.get("https://pve.test:8006/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    settings = _settings(
        transport="http",
        host="127.0.0.1",
        mcp_auth_token="test-token-0123456789",
    )
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            unauthorized = await client.post("/mcp", json={})
            assert unauthorized.status_code == 401

            wrong = await client.post(
                "/mcp", json={}, headers={"Authorization": "Bearer wrong"}
            )
            assert wrong.status_code == 401

            ok = await client.post(
                "/mcp", json={}, headers={"Authorization": "Bearer test-token-0123456789"}
            )
            assert ok.status_code != 401


def test_non_loopback_requires_token_at_settings_level() -> None:
    with pytest.raises(ValidationError):
        _settings(transport="http", host="0.0.0.0", mcp_auth_token=None)
