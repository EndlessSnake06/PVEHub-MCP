"""Structural contract tests across all curated PVE tools."""

from __future__ import annotations

import re
from typing import Any

CURATED_CATEGORIES = {"read", "lifecycle", "write", "destructive"}


def _curated(hub: Any) -> dict[str, Any]:
    return {
        name: registered
        for name, registered in hub.registered.items()
        if name.startswith("pve_")
        and name not in {"pve_api_schema", "pve_api_call"}
        and registered.category in CURATED_CATEGORIES
    }


async def test_every_tool_has_instance_parameter(pve: Any) -> None:
    hub, _router = pve
    schemas = {tool.name: tool.input_schema for tool in await hub.mcp.list_tools()}

    for name in _curated(hub):
        properties = schemas[name].get("properties", {})
        assert "instance" in properties, f"{name} is missing the instance parameter"


async def test_privilege_placeholders_exist_in_signature(pve: Any) -> None:
    hub, _router = pve
    schemas = {tool.name: tool.input_schema for tool in await hub.mcp.list_tools()}

    for name, registered in _curated(hub).items():
        properties = set(schemas[name].get("properties", {}))
        for privilege in registered.pve_privileges:
            placeholders = set(re.findall(r"{(\w+)}", privilege.path))
            missing = placeholders - properties
            assert not missing, f"{name}: {privilege.path} needs {sorted(missing)} in the signature"


async def test_destructive_tools_expose_confirm_and_dry_run(pve: Any) -> None:
    hub, _router = pve
    schemas = {tool.name: tool.input_schema for tool in await hub.mcp.list_tools()}
    destructive = {
        name for name, registered in _curated(hub).items() if registered.category == "destructive"
    }

    assert destructive
    for name in destructive:
        properties = schemas[name].get("properties", {})
        assert "confirm" in properties, f"{name} must accept confirm"
        assert "dry_run" in properties, f"{name} must accept dry_run"
        assert properties["confirm"].get("default") is False
        assert properties["dry_run"].get("default") is False


async def test_read_tools_have_no_confirm_parameter(pve: Any) -> None:
    hub, _router = pve
    schemas = {tool.name: tool.input_schema for tool in await hub.mcp.list_tools()}

    for name, registered in _curated(hub).items():
        if registered.category != "read":
            continue
        assert "confirm" not in schemas[name].get("properties", {}), f"{name} must not ask confirm"


async def test_catalog_covers_expected_tool_names(pve: Any) -> None:
    hub, _router = pve
    names = set(_curated(hub))

    expected = {
        "pve_cluster_status",
        "pve_cluster_resources",
        "pve_nodes_list",
        "pve_node_status",
        "pve_node_rrddata",
        "pve_ha_status",
        "pve_ha_resources",
        "pve_ha_groups",
        "pve_cluster_log",
        "pve_guests_list",
        "pve_guest_status",
        "pve_guest_config",
        "pve_guest_power",
        "pve_guest_snapshots",
        "pve_guest_snapshot_create",
        "pve_guest_snapshot_delete",
        "pve_guest_snapshot_rollback",
        "pve_guest_clone",
        "pve_guest_migrate",
        "pve_guest_create_lxc",
        "pve_guest_create_vm",
        "pve_guest_delete",
        "pve_guest_resize",
        "pve_guest_agent_ping",
        "pve_storage_list",
        "pve_storage_status",
        "pve_storage_content",
        "pve_backup_start",
        "pve_backup_list",
        "pve_backup_restore",
        "pve_network_list",
        "pve_network_interface",
        "pve_access_users",
        "pve_access_roles",
        "pve_access_acl",
        "pve_access_groups",
        "pve_tasks_list",
        "pve_task_status",
        "pve_task_log",
        "pve_task_stop",
    }
    assert names == expected
