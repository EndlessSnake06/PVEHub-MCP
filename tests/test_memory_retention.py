"""TTL, retention and the cleanup job (issue #36)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pvehub_mcp.memory import MemoryStore


def make_store(tmp_path: Path, **kwargs: Any) -> MemoryStore:
    return MemoryStore(str(tmp_path / "memory.db"), **kwargs)


def clock(start: datetime) -> Any:
    """A mutable clock so TTL/retention can be tested without sleeping."""

    state = {"now": start}

    def _now() -> datetime:
        return state["now"]

    _now.advance = lambda days=0, seconds=0: state.update(  # type: ignore[attr-defined]
        {"now": state["now"] + timedelta(days=days, seconds=seconds)}
    )
    return _now


async def test_expired_note_is_deleted_by_cleanup(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    now = clock(datetime(2026, 1, 1, tzinfo=UTC))
    store._now = now  # type: ignore[method-assign]
    await store.remember(
        entity_type="guest", entity_key="100", body="short lived", source="t", expires_in_days=1
    )
    await store.remember(entity_type="guest", entity_key="100", body="keep me", source="t")

    now.advance(days=2)
    result = await store.cleanup()

    assert result["deleted_notes"] == 1
    remaining = await store.recall(entity_type="guest", entity_key="100")
    assert [note["body"] for note in remaining["notes"]] == ["keep me"]
    await store.close()


async def test_retention_window_removes_old_notes(tmp_path: Path) -> None:
    store = make_store(tmp_path, retention_days=30)
    now = clock(datetime(2026, 1, 1, tzinfo=UTC))
    store._now = now  # type: ignore[method-assign]
    await store.remember(entity_type="guest", entity_key="100", body="old", source="t")

    now.advance(days=31)
    result = await store.cleanup()

    assert result["deleted_notes"] == 1
    assert (await store.recent_notes()) == []
    await store.close()


async def test_retention_zero_keeps_notes(tmp_path: Path) -> None:
    store = make_store(tmp_path, retention_days=0)
    now = clock(datetime(2026, 1, 1, tzinfo=UTC))
    store._now = now  # type: ignore[method-assign]
    await store.remember(entity_type="guest", entity_key="100", body="old", source="t")

    now.advance(days=3650)
    result = await store.cleanup()
    assert result["deleted_notes"] == 0
    await store.close()


async def test_tombstones_are_purged(tmp_path: Path) -> None:
    store = make_store(tmp_path, tombstone_days=30)
    now = clock(datetime(2026, 1, 1, tzinfo=UTC))
    store._now = now  # type: ignore[method-assign]
    note = await store.remember(entity_type="guest", entity_key="100", body="x", source="t")
    assert await store.forget(note["id"]) is True

    now.advance(days=10)
    early = await store.cleanup()
    assert early["deleted_notes"] == 0

    now.advance(days=21)
    late = await store.cleanup()
    assert late["deleted_notes"] == 1
    import sqlite3

    with sqlite3.connect(tmp_path / "memory.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0
    await store.close()


async def test_event_retention(tmp_path: Path) -> None:
    store = make_store(tmp_path, event_retention_days=90)
    now = clock(datetime(2026, 1, 1, tzinfo=UTC))
    store._now = now  # type: ignore[method-assign]
    await store.record_event(
        tool="pve_guest_status",
        category="write",
        status="ok",
        client="unknown",
        subjects=[("guest", "100")],
        summary="pve_guest_status vmid=100 -> ok",
    )
    assert len(await store._events_for([("guest", "100")], limit=5)) == 1

    now.advance(days=91)
    result = await store.cleanup()
    assert result["deleted_events"] == 1
    assert await store._events_for([("guest", "100")], limit=5) == []
    await store.close()


async def test_max_notes_caps_the_table(tmp_path: Path) -> None:
    store = make_store(tmp_path, max_notes=2)
    for index in range(3):
        await store.remember(
            entity_type="guest", entity_key=str(100 + index), body=f"note {index}", source="t"
        )
    result = await store.cleanup()
    assert result["deleted_notes"] == 1
    remaining = await store.recent_notes()
    assert len(remaining) == 2
    await store.close()


async def test_cleanup_reports_last_run(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.cleanup()
    report = store.report()
    assert report["cleanup"] is not None
    assert report["cleanup"]["error"] is None
    assert "ts" in report["cleanup"]
    await store.close()


async def test_cleanup_errors_are_recorded_not_raised(
    tmp_path: Path, monkeypatch: Any
) -> None:
    store = make_store(tmp_path)

    async def boom(action: Any) -> Any:
        raise RuntimeError("backup holds the lock")

    monkeypatch.setattr(store, "_run", boom)
    result = await store.cleanup()
    assert "backup holds the lock" in (result["error"] or "")
    assert store.report()["cleanup"]["error"]
    await store.close()


async def test_cleanup_task_lifecycle(tmp_path: Path) -> None:
    store = make_store(tmp_path, cleanup_interval_seconds=3600)
    await store.start_cleanup_task()
    await store.start_cleanup_task()  # idempotent
    assert store._task is not None
    await store.close()
    assert store._task is None


async def test_cleanup_task_disabled_with_zero_interval(tmp_path: Path) -> None:
    store = make_store(tmp_path, cleanup_interval_seconds=0)
    await store.start_cleanup_task()
    assert store._task is None
    await store.close()


async def test_cleanup_on_disabled_store_is_skipped(tmp_path: Path) -> None:
    store = MemoryStore(str(tmp_path / "memory.db"), enabled=False)
    result = await store.cleanup()
    assert result["skipped"] is True
    await store.close()


async def test_background_task_survives_a_failing_run(tmp_path: Path, monkeypatch: Any) -> None:
    store = make_store(tmp_path, cleanup_interval_seconds=1)
    calls: list[int] = []

    async def failing() -> dict[str, Any]:
        calls.append(1)
        raise RuntimeError("boom")

    monkeypatch.setattr(store, "cleanup", failing)
    await store.start_cleanup_task()
    await asyncio.sleep(1.1)
    await store.close()
    assert calls
