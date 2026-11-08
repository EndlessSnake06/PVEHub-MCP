"""Meta tools: capabilities report, health, and the redacted audit tail."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from ..audit import read_audit_tail
from ..clientid import valid_client_name
from ..errors import AuditDisabled, InvalidArgument, NotFound
from .common import ok

#: Maximum number of entries pvehub_audit_tail returns per call.
MAX_TAIL_LIMIT = 500

#: How many recent log lines to scan when a filter is active, so that
#: "the last N *matching* entries" is correct; the 8 MiB byte window in
#: read_audit_tail is the real memory cap.
SCAN_LINES = 10_000


def _parse_since(since: str | None) -> datetime | None:
    if since is None:
        return None
    try:
        parsed = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidArgument("since must be ISO-8601, e.g. 2026-11-08T00:00:00Z") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _entry_ts(entry: dict[str, Any]) -> datetime | None:
    raw_ts = entry.get("ts")
    if not isinstance(raw_ts, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


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
        body = hub.health()
        # D020 (issue #20): the MCP tool additionally reports the audit state;
        # the unauthenticated /health and the authenticated /ready endpoints
        # are deliberately unchanged.
        body["audit"] = {
            "enabled": hub.audit.enabled,
            "path": str(hub.audit.path) if hub.audit.path else None,
        }
        return ok(body)

    @hub.tool(name="pvehub_audit_tail", category="read")
    async def pvehub_audit_tail(
        limit: int = 50,
        tool: str | None = None,
        category: str | None = None,
        status: str | None = None,
        client: str | None = None,
        since: str | None = None,
    ) -> str:
        """Tail the redacted audit log (last N entries, oldest first).

        Optional filters: tool, category, status, client (the name a bearer
        token maps to, D019), and since (ISO-8601 UTC).  Entries are
        re-redacted on the way out; nothing leaves the server unredacted.
        """
        if limit < 1 or limit > MAX_TAIL_LIMIT:
            raise InvalidArgument(f"limit must be between 1 and {MAX_TAIL_LIMIT}")
        if client is not None and not valid_client_name(client):
            raise InvalidArgument(
                "client must be 1-32 characters of [a-z0-9_-] starting with "
                "a letter or digit"
            )
        since_dt = _parse_since(since)
        path = hub.audit.path
        if not hub.audit.enabled or path is None:
            raise AuditDisabled("the audit log is disabled (PVEHUB_AUDIT_LOG unset)")
        if not path.exists():
            raise NotFound("audit log file does not exist")
        entries = await asyncio.to_thread(read_audit_tail, path, SCAN_LINES)
        if tool is not None:
            entries = [entry for entry in entries if entry.get("tool") == tool]
        if category is not None:
            entries = [entry for entry in entries if entry.get("category") == category]
        if status is not None:
            entries = [entry for entry in entries if entry.get("status") == status]
        if client is not None:
            entries = [entry for entry in entries if entry.get("client") == client]
        if since_dt is not None:
            entries = [
                entry
                for entry in entries
                if (ts := _entry_ts(entry)) is not None and ts >= since_dt
            ]
        entries = entries[-limit:]
        return ok(
            {"count": len(entries), "entries": entries},
            max_bytes=hub.settings.max_output_bytes,
        )
