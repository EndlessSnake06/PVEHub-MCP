"""Access-control read tools: users, groups, roles and ACLs.

Deliberately read-only: token creation, password changes and ACL modification are not
exposed here.
"""

from __future__ import annotations

from typing import Any

from .common import ok, pick

_USER_KEYS = (
    "userid",
    "comment",
    "email",
    "enable",
    "expire",
    "firstname",
    "lastname",
    "groups",
    "keys",
    "realm",
)
_ROLE_KEYS = ("roleid", "privs", "special")
_ACL_KEYS = ("path", "type", "ugid", "roleid", "propagate")
_GROUP_KEYS = ("groupid", "comment", "users")


def _as_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def register(hub: Any) -> None:
    @hub.tool(
        name="pve_access_users",
        category="read",
        pve=[("Sys.Audit", "/access")],
        service="pve",
    )
    async def pve_access_users(
        full: bool = False,
        enabled: bool | None = None,
        instance: str | None = None,
    ) -> str:
        """List PVE users with realm, groups and enabled state.

        full includes the users' effective permissions; enabled filters by account state.
        """
        client = hub.pve(instance)
        params: dict[str, Any] = {"full": full}
        if enabled is not None:
            params["enabled"] = enabled
        data = await client.get("/access/users", params=params)
        users = [pick(item, _USER_KEYS) for item in _as_items(data)]
        return ok({"count": len(users), "users": users}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_access_roles",
        category="read",
        pve=[("Sys.Audit", "/access")],
        service="pve",
    )
    async def pve_access_roles(instance: str | None = None) -> str:
        """List PVE roles and their privileges."""
        client = hub.pve(instance)
        data = await client.get("/access/roles")
        roles = [pick(item, _ROLE_KEYS) for item in _as_items(data)]
        return ok({"count": len(roles), "roles": roles}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_access_acl",
        category="read",
        pve=[("Sys.Audit", "/access")],
        service="pve",
    )
    async def pve_access_acl(instance: str | None = None) -> str:
        """List ACL entries (path, user/group, role, propagate) effective for this token."""
        client = hub.pve(instance)
        data = await client.get("/access/acl")
        entries = [pick(item, _ACL_KEYS) for item in _as_items(data)]
        return ok({"count": len(entries), "entries": entries}, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(
        name="pve_access_groups",
        category="read",
        pve=[("Sys.Audit", "/access")],
        service="pve",
    )
    async def pve_access_groups(instance: str | None = None) -> str:
        """List PVE groups with their member users."""
        client = hub.pve(instance)
        data = await client.get("/access/groups")
        groups = [pick(item, _GROUP_KEYS) for item in _as_items(data)]
        return ok({"count": len(groups), "groups": groups}, max_bytes=hub.settings.max_output_bytes)
