"""Meta tools: capabilities report and health."""

from __future__ import annotations

from typing import Any

from .common import ok


def register(hub: Any) -> None:
    @hub.tool(name="pvehub_capabilities", category="read")
    async def pvehub_capabilities(detail: bool = False) -> str:
        """Show registered tools, policy blocks, token privileges and shell prerequisites."""
        report = hub.capabilities_report()
        if not detail and report.get("capabilities"):
            for kind in ("pve", "pbs"):
                for snapshot in report["capabilities"].get(kind, []):
                    snapshot.pop("privileges", None)
        return ok(report, max_bytes=hub.settings.max_output_bytes)

    @hub.tool(name="pvehub_health", category="read")
    async def pvehub_health() -> str:
        """Liveness and capability discovery status of this MCP server."""
        return ok(hub.health())
