"""Registration contract: all exec/file tools exist with the documented schema."""

from __future__ import annotations

from typing import Any

EXPECTED = {
    "exec_vm",
    "exec_lxc",
    "exec_host",
    "exec_pbs",
    "file_read_guest",
    "file_write_guest",
    "file_pull_host",
    "file_push_host",
}

CONFIRM_TOOLS = {
    "exec_vm",
    "exec_lxc",
    "exec_host",
    "exec_pbs",
    "file_write_guest",
    "file_push_host",
}


async def test_all_exec_and_file_tools_are_registered(registered_tools: dict[str, Any]) -> None:
    assert set(registered_tools) >= EXPECTED


async def test_confirm_parameter_is_exposed(registered_tools: dict[str, Any]) -> None:
    for name in CONFIRM_TOOLS:
        schema = registered_tools[name].input_schema
        assert schema["properties"]["confirm"]["type"] == "boolean", name
        assert schema["properties"]["confirm"]["default"] is False, name


async def test_exec_vm_schema(registered_tools: dict[str, Any]) -> None:
    schema = registered_tools["exec_vm"].input_schema
    assert set(schema["required"]) == {"vmid", "command"}
    assert schema["properties"]["vmid"]["type"] == "integer"
    assert schema["properties"]["command"]["type"] == "string"
    assert schema["properties"]["timeout"]["anyOf"][0]["type"] == "integer"


async def test_file_tools_expose_limits(registered_tools: dict[str, Any]) -> None:
    read_schema = registered_tools["file_read_guest"].input_schema
    assert read_schema["properties"]["max_bytes"]["default"] == 1048576
    pull_schema = registered_tools["file_pull_host"].input_schema
    assert pull_schema["properties"]["max_bytes"]["default"] == 1048576
    write_schema = registered_tools["file_write_guest"].input_schema
    assert set(write_schema["required"]) == {"vmid", "path", "content_base64"}


async def test_exec_tools_are_annotated_non_readonly(registered_tools: dict[str, Any]) -> None:
    for name in ("exec_vm", "exec_lxc", "exec_host", "exec_pbs", "file_write_guest"):
        annotations = registered_tools[name].annotations
        assert annotations is not None, name
        assert annotations.read_only_hint is False, name
