"""tools: memory_recall / memory_remember / memory_forget (issue #34)."""

from __future__ import annotations

from typing import Any


async def test_remember_then_recall_roundtrip(pve: Any, call: Any) -> None:
    hub, _router = pve

    stored = await call(
        hub,
        "memory_remember",
        entity_type="guest",
        entity_key="100",
        title="Backup window",
        body="PBS verify job runs Monday night",
        tags=["backup", "pbs"],
        expires_in_days=30,
    )
    assert stored["ok"] is True
    note_id = stored["data"]["id"]
    assert stored["data"]["source"] == "unknown"
    assert stored["data"]["expires"] is not None

    result = await call(hub, "memory_recall", query="verify")
    assert result["data"]["count"] == 1
    note = result["data"]["notes"][0]
    assert note["id"] == note_id
    assert note["entity_type"] == "guest"
    assert note["entity_key"] == "100"
    assert note["title"] == "Backup window"
    assert note["tags"] == ["backup", "pbs"]
    assert note["age_days"] == 0
    assert note["source"] == "unknown"


async def test_recall_filters_by_entity(pve: Any, call: Any) -> None:
    hub, _router = pve
    await call(hub, "memory_remember", entity_type="guest", entity_key="100", body="alpha")
    await call(hub, "memory_remember", entity_type="guest", entity_key="101", body="beta")

    result = await call(hub, "memory_recall", entity_type="guest", entity_key="101")
    assert [note["body"] for note in result["data"]["notes"]] == ["beta"]
    assert result["data"]["events"] == []


async def test_recall_without_hits_returns_empty_payload(pve: Any, call: Any) -> None:
    hub, _router = pve
    result = await call(hub, "memory_recall", query="nothing-matches")
    assert result["ok"] is True
    assert result["data"] == {"count": 0, "notes": [], "events": [], "fts": True}


async def test_recall_includes_events_for_the_entity(pve: Any, call: Any) -> None:
    hub, _router = pve

    @hub.tool(name="demo_write", category="write")
    async def demo_write(vmid: int) -> str:
        """Write."""
        return '{"ok":true,"data":{}}'

    await call(hub, "demo_write", vmid=100)
    result = await call(hub, "memory_recall", entity_type="guest", entity_key="100")
    assert len(result["data"]["events"]) == 1
    assert result["data"]["events"][0]["tool"] == "demo_write"

    without = await call(
        hub, "memory_recall", entity_type="guest", entity_key="100", include_events=False
    )
    assert without["data"]["events"] == []


async def test_forget_requires_confirm(pve: Any, call: Any) -> None:
    hub, _router = pve
    stored = await call(hub, "memory_remember", entity_type="guest", entity_key="100", body="x")
    note_id = stored["data"]["id"]

    denied = await call(hub, "memory_forget", note_id=note_id)
    assert denied["ok"] is False
    assert denied["error"]["code"] == "confirm_required"

    still_there = await call(hub, "memory_recall", entity_type="guest", entity_key="100")
    assert still_there["data"]["count"] == 1

    deleted = await call(hub, "memory_forget", note_id=note_id, confirm=True)
    assert deleted["data"]["deleted"] is True

    gone = await call(hub, "memory_recall", entity_type="guest", entity_key="100")
    assert gone["data"]["count"] == 0

    again = await call(hub, "memory_forget", note_id=note_id, confirm=True)
    assert again["data"]["deleted"] is False
    assert again["data"]["hint"]


async def test_invalid_entity_type_is_rejected(pve: Any, call: Any) -> None:
    hub, _router = pve
    payload = await call(hub, "memory_remember", entity_type="vm", entity_key="100", body="x")
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert "entity_type must be one of" in payload["error"]["message"]


async def test_oversize_body_is_rejected(pve: Any, call: Any) -> None:
    hub, _router = pve
    payload = await call(
        hub,
        "memory_remember",
        entity_type="guest",
        entity_key="100",
        body="x" * (hub.settings.memory_note_max_bytes + 1),
    )
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_secrets_are_redacted_before_persisting(pve: Any, call: Any) -> None:
    hub, _router = pve
    await call(
        hub,
        "memory_remember",
        entity_type="guest",
        entity_key="100",
        body="api_token=abcdef1234567890",
    )
    result = await call(hub, "memory_recall", entity_type="guest", entity_key="100")
    body = result["data"]["notes"][0]["body"]
    assert "abcdef1234567890" not in body
    assert "***" in body
    data = hub.memory.path.read_bytes() if hub.memory.path else b""
    assert b"abcdef1234567890" not in data


async def test_expired_notes_are_hidden(pve: Any, call: Any, monkeypatch: Any) -> None:
    hub, _router = pve
    stored = await call(
        hub,
        "memory_remember",
        entity_type="guest",
        entity_key="100",
        body="temporary note",
        expires_in_days=1,
    )
    assert stored["data"]["expires"] is not None

    from datetime import UTC, datetime, timedelta

    future = datetime.now(UTC) + timedelta(days=2)
    monkeypatch.setattr(hub.memory, "_now", lambda: future)

    result = await call(hub, "memory_recall", entity_type="guest", entity_key="100")
    assert result["data"]["count"] == 0
