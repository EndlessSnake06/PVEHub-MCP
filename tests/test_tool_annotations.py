"""tools/list level: readable titles, confirm note in descriptions, _meta."""

from __future__ import annotations

from typing import Any

from mcp.client import Client

from pvehub_mcp.server import CONFIRM_DRY_RUN_NOTE, CONFIRM_NOTE, PVEHub

CONFIRM_MARKER = "confirm=true"


async def _tools(hub: PVEHub) -> dict[str, Any]:
    async with Client(hub.mcp) as client:
        return {tool.name: tool for tool in (await client.list_tools()).tools}


async def test_every_tool_has_readable_title(pve) -> None:
    hub, _router = pve
    tools = await _tools(hub)
    assert len(tools) >= 40
    for tool in tools.values():
        assert tool.title, tool.name
        assert "_" not in tool.title, tool.name
        assert tool.title != tool.name, tool.name
        assert tool.annotations is not None
        assert tool.annotations.title == tool.title, tool.name
        # The meta channel carries the grouping/reachability data.
        assert tool.meta is not None, tool.name
        assert tool.meta["confirm_required"] in (True, False), tool.name


async def test_read_tool_title_and_meta(pve) -> None:
    hub, _router = pve
    tools = await _tools(hub)
    health = tools["pvehub_health"]
    assert health.title == "PVEHub Health"
    assert health.annotations.title == "PVEHub Health"
    assert health.meta == {"category": "read", "confirm_required": False}
    assert CONFIRM_MARKER not in health.description


async def test_destructive_tool_confirm_note_and_meta(pve) -> None:
    # pve_guest_delete is registered under the pve fixture (full PVE
    # permissions, default policy: require_confirm_for = destructive + exec).
    hub, _router = pve
    tools = await _tools(hub)
    guest = tools["pve_guest_delete"]
    assert guest.title == "PVE Guest Delete"
    assert guest.annotations.title == "PVE Guest Delete"
    assert guest.annotations.destructive_hint is True
    # The confirm requirement is visible from tools/list alone.
    assert CONFIRM_NOTE in guest.description
    assert CONFIRM_MARKER in guest.description
    assert CONFIRM_DRY_RUN_NOTE in guest.description
    assert guest.meta == {"category": "destructive", "confirm_required": True}


async def test_read_tools_never_carry_the_confirm_note(pve) -> None:
    hub, _router = pve
    tools = await _tools(hub)
    for name in ("pvehub_capabilities", "pvehub_health", "pve_guest_status", "pve_nodes_list"):
        assert CONFIRM_NOTE not in tools[name].description, name
