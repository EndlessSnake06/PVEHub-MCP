"""Tests for the read-only access-control tools."""

from __future__ import annotations

from typing import Any

from httpx import Response

ACCESS_TOOLS = {
    "pve_access_users",
    "pve_access_roles",
    "pve_access_acl",
    "pve_access_groups",
}


async def test_access_tools_are_read_only(pve: Any) -> None:
    hub, _router = pve
    names = {tool.name for tool in await hub.mcp.list_tools()}

    assert names >= ACCESS_TOOLS
    for name in ACCESS_TOOLS:
        assert hub.registered[name].category == "read"
        assert hub.registered[name].pve_privileges[0].priv == "Sys.Audit"
        assert hub.registered[name].pve_privileges[0].path == "/access"


async def test_no_credential_mutating_tools_registered(pve: Any) -> None:
    hub, _router = pve
    names = {tool.name for tool in await hub.mcp.list_tools()}

    forbidden = {name for name in names if "token" in name or "password" in name}
    assert forbidden == set()
    assert all(hub.registered[name].category == "read" for name in ACCESS_TOOLS)


async def test_access_users_returns_summary(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get("/api2/json/access/users").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "userid": "root@pam",
                        "enable": 1,
                        "expire": 0,
                        "firstname": "Root",
                        "groups": ["ops"],
                    },
                    {"userid": "pvehub@pve", "enable": 1, "comment": "automation"},
                ]
            },
        )
    )

    payload = await call(hub, "pve_access_users", full=True)

    assert payload["data"]["count"] == 2
    assert payload["data"]["users"][0]["userid"] == "root@pam"
    assert route.calls[0].request.url.params["full"] == "1"


async def test_access_roles_and_acl(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/access/roles").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {"roleid": "PVEAuditor", "privs": "Datastore.Audit,VM.Audit", "special": 0},
                    {"roleid": "PVEAdmin", "privs": "Sys.Modify", "special": 0},
                ]
            },
        )
    )
    router.get("/api2/json/access/acl").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {
                        "path": "/vms/100",
                        "type": "user",
                        "ugid": "pvehub@pve",
                        "roleid": "PVEAdmin",
                        "propagate": 1,
                    }
                ]
            },
        )
    )

    roles = await call(hub, "pve_access_roles")
    acl = await call(hub, "pve_access_acl")

    assert roles["data"]["roles"][0]["roleid"] == "PVEAuditor"
    assert acl["data"]["entries"][0]["path"] == "/vms/100"
    assert acl["data"]["entries"][0]["propagate"] == 1


async def test_access_groups(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/access/groups").mock(
        return_value=Response(
            200,
            json={"data": [{"groupid": "ops", "comment": "operators", "users": "root@pam"}]},
        )
    )

    payload = await call(hub, "pve_access_groups")

    assert payload["data"]["groups"][0]["groupid"] == "ops"
    assert payload["data"]["groups"][0]["users"] == "root@pam"
