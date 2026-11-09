"""Enrichment middleware: the ``_memory`` field (issue #35)."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from httpx import Response

GUESTS = [
    {"vmid": 100, "name": "web", "node": "pve1", "type": "qemu", "status": "running"},
]


def mock_guests(router: Any) -> None:
    router.get("/api2/json/cluster/resources").mock(
        return_value=Response(200, json={"data": GUESTS})
    )


async def _remember(hub: Any, body: str, *, entity_key: str = "100") -> int:
    stored = await hub.mcp.call_tool(
        "memory_remember",
        {"entity_type": "guest", "entity_key": entity_key, "body": body},
    )
    import json

    payload = json.loads(stored.content[0].text)  # type: ignore[union-attr]
    return int(payload["data"]["id"])


def _mock_guest_status(router: Any) -> None:
    mock_guests(router)
    router.get("/api2/json/nodes/pve1/qemu/100/status/current").mock(
        return_value=Response(200, json={"data": {"vmid": 100, "status": "running"}})
    )


async def test_note_is_attached_to_matching_subject(pve: Any, call: Any) -> None:
    hub, router = pve
    _mock_guest_status(router)
    note_id = await _remember(hub, "Do not reboot during backup window")

    payload = await call(hub, "pve_guest_status", vmid=100)

    assert payload["ok"] is True
    assert payload["data"]["status"]["status"] == "running"
    memory = payload["_memory"]
    assert memory["trust"] == "untrusted-data"
    assert "not instructions" in memory["hint"]
    assert [note["id"] for note in memory["notes"]] == [note_id]
    assert memory["notes"][0]["age_days"] == 0
    assert memory["notes"][0]["source"] == "unknown"


async def test_no_note_means_no_memory_field(pve: Any, call: Any) -> None:
    hub, router = pve
    _mock_guest_status(router)
    payload = await call(hub, "pve_guest_status", vmid=100)
    assert "_memory" not in payload


async def test_note_for_other_subject_is_not_attached(pve: Any, call: Any) -> None:
    hub, router = pve
    _mock_guest_status(router)
    await _remember(hub, "note for another guest", entity_key="101")
    payload = await call(hub, "pve_guest_status", vmid=100)
    assert "_memory" not in payload


async def test_error_responses_are_never_enriched(pve: Any, call: Any) -> None:
    hub, router = pve
    _mock_guest_status(router)
    await _remember(hub, "note")
    payload = await call(hub, "pve_guest_status", vmid=999)
    assert payload["ok"] is False
    assert "_memory" not in payload


async def test_tools_without_subject_are_not_enriched(pve: Any, call: Any) -> None:
    hub, _router = pve
    await _remember(hub, "irrelevant for meta tools")
    payload = await call(hub, "pvehub_health")
    assert "_memory" not in payload


async def test_last_action_is_attached(pve: Any, call: Any) -> None:
    hub, router = pve
    _mock_guest_status(router)

    @hub.tool(name="demo_write", category="write")
    async def demo_write(vmid: int) -> str:
        """Write."""
        return '{"ok":true,"data":{}}'

    await call(hub, "demo_write", vmid=100)
    payload = await call(hub, "pve_guest_status", vmid=100)
    action = payload["_memory"]["last_action"]
    assert action["tool"] == "demo_write"
    assert action["status"] == "ok"


async def test_budget_overflow_drops_the_block_and_keeps_data(
    pve: Any, call: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    hub, router = pve
    _mock_guest_status(router)
    await _remember(hub, "x" * 300)

    monkeypatch.setattr(hub.memory, "max_output_bytes", 1200)  # budget = 300 bytes
    payload = await call(hub, "pve_guest_status", vmid=100)
    assert payload["ok"] is True
    assert payload["data"]["status"]["status"] == "running"
    assert "_memory" not in payload


async def test_enrichment_failure_is_fail_open(
    pve: Any, call: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    hub, router = pve
    _mock_guest_status(router)
    await _remember(hub, "note")

    async def boom(action: Any) -> Any:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(hub.memory, "_run", boom)
    payload = await call(hub, "pve_guest_status", vmid=100)
    assert payload["ok"] is True
    assert payload["data"]["status"]["status"] == "running"
    assert "_memory" not in payload


async def test_enrichment_can_be_disabled(pve: Any, call: Any) -> None:
    hub, router = pve
    _mock_guest_status(router)
    await _remember(hub, "note")
    hub.memory.enrich_enabled = False
    payload = await call(hub, "pve_guest_status", vmid=100)
    assert "_memory" not in payload


async def test_memory_tools_are_not_enriched(pve: Any, call: Any) -> None:
    hub, _router = pve
    await _remember(hub, "note")
    payload = await call(hub, "memory_recall", query="note")
    assert payload["ok"] is True
    assert "_memory" not in payload
