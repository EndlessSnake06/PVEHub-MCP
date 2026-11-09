"""Store-level tests for the SQLite memory layer (issues #32, #38)."""

from __future__ import annotations

import asyncio
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from pvehub_mcp.config import Settings
from pvehub_mcp.errors import InvalidArgument, MemoryUnavailable
from pvehub_mcp.memory import SCHEMA_VERSION, MemoryStore, _fts_query


def make_store(tmp_path: Path, **kwargs: Any) -> tuple[MemoryStore, Path]:
    path = tmp_path / "memory.db"
    return MemoryStore(str(path), **kwargs), path


def _tables(path: Path) -> set[str]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')"
        ).fetchall()
    return {str(row[0]) for row in rows}


async def test_schema_is_created_with_version(tmp_path: Path) -> None:
    store, path = make_store(tmp_path)
    assert store.enabled is True
    assert store.error is None
    assert store.schema_version == SCHEMA_VERSION
    table_names = _tables(path)
    assert {"notes", "events", "notes_fts", "notes_ai", "notes_au", "notes_ad"} <= table_names
    with sqlite3.connect(path) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert version == SCHEMA_VERSION
    assert str(journal).lower() == "wal"
    await store.close()


async def test_migration_is_idempotent_and_data_survives_reopen(tmp_path: Path) -> None:
    store, path = make_store(tmp_path)
    note = await store.remember(
        entity_type="guest", entity_key="100", body="Backup window Tuesday", source="test"
    )
    await store.close()

    reopened = MemoryStore(str(path))
    assert reopened.schema_version == SCHEMA_VERSION
    result = await reopened.recall(query="Tuesday")
    assert [item["id"] for item in result["notes"]] == [note["id"]]
    await reopened.close()


async def test_database_file_is_owner_only(tmp_path: Path) -> None:
    store, path = make_store(tmp_path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
    await store.close()


async def test_fts5_search_and_special_characters(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    assert store.fts is True
    await store.remember(
        entity_type="runbook",
        entity_key="backup",
        title="PBS verify",
        body="verify job runs Monday and Thursday",
        source="test",
    )
    hits = await store.recall(query="Monday")
    assert hits["count"] == 1
    assert hits["fts"] is True

    # FTS5 syntax characters must not raise; they are quoted per token.
    for query in ('"', "AND", "body(", "*", "a:b", "-minus"):
        result = await store.recall(query=query)
        assert "notes" in result
    await store.close()


async def test_like_fallback_when_fts_is_unavailable(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    await store.remember(
        entity_type="guest", entity_key="100", body="special maintenance note", source="test"
    )
    store.fts = False  # simulate a SQLite build without FTS5
    result = await store.recall(query="maintenance")
    assert result["count"] == 1
    assert result["fts"] is False
    await store.close()


async def test_concurrent_access_is_thread_safe(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    notes = await asyncio.gather(
        *(
            store.remember(
                entity_type="guest", entity_key="100", body=f"note {index}", source="load"
            )
            for index in range(30)
        )
    )
    assert len({note["id"] for note in notes}) == 30
    result = await store.recall(entity_type="guest", entity_key="100", limit=50)
    assert result["count"] == 30
    await store.close()


async def test_unwritable_path_disables_the_store(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    store = MemoryStore(str(blocker / "memory.db"))
    assert store.enabled is False
    assert store.error is not None and "disabled" in store.error
    report = store.report()
    assert report["enabled"] is False
    with pytest.raises(MemoryUnavailable):
        await store.remember(entity_type="guest", entity_key="100", body="x", source="t")


async def test_memory_enabled_false_disables_with_reason(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, enabled=False)
    assert store.enabled is False
    assert store.error == "disabled by configuration"
    with pytest.raises(MemoryUnavailable):
        await store.recall(query="x")


def test_settings_derive_default_path_from_state_dir(tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {
            "transport": "stdio",
            "state_dir": str(tmp_path),
            "pve": [
                {
                    "name": "test",
                    "url": "https://pve.test:8006",
                    "token_id": "root@pam!pvehub",
                    "token_secret": "s3cret",
                }
            ],
        }
    )
    assert settings.memory_db_path == str(tmp_path / "memory.db")
    assert settings.memory_enrich is True


def test_settings_reject_invalid_memory_values() -> None:
    base = {
        "transport": "stdio",
        "pve": [
            {
                "name": "test",
                "url": "https://pve.test:8006",
                "token_id": "root@pam!pvehub",
                "token_secret": "s3cret",
            }
        ],
    }
    with pytest.raises(ValidationError):
        Settings.model_validate({**base, "memory_note_max_bytes": 10})
    with pytest.raises(ValidationError):
        Settings.model_validate({**base, "memory_retention_days": -1})
    with pytest.raises(ValidationError):
        Settings.model_validate({**base, "memory_unknown_key": 1})


def test_env_overrides_memory_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from pvehub_mcp.config import load_settings

    config = tmp_path / "config.yaml"
    config.write_text(
        "transport: stdio\n"
        "pve:\n"
        "  - name: test\n"
        "    url: https://pve.test:8006\n"
        "    token_id: root@pam!pvehub\n"
        "    token_secret: s3cret\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PVEHUB_CONFIG_FILE", str(config))
    monkeypatch.setenv("PVEHUB_MEMORY_DB", "/data/custom-memory.db")
    monkeypatch.setenv("PVEHUB_MEMORY_ENRICH", "false")
    monkeypatch.setenv("PVEHUB_MEMORY_ENRICH_MAX_NOTES", "2")
    settings = load_settings()
    assert settings.memory_db_path == "/data/custom-memory.db"
    assert settings.memory_enrich is False
    assert settings.memory_enrich_max_notes == 2


def test_fts_query_quotes_every_token() -> None:
    assert _fts_query('foo "bar" baz') == '"foo" OR """bar""" OR "baz"'
    assert _fts_query("   ") == ""


async def test_capabilities_report_includes_memory_state(pve: Any, call: Any) -> None:
    hub, _router = pve
    payload = await call(hub, "pvehub_capabilities")
    memory = payload["data"]["memory"]
    assert memory["enabled"] is True
    assert memory["schema_version"] == SCHEMA_VERSION
    assert memory["path"].endswith("memory.db")
    assert memory["error"] is None
    assert memory["fts"] is True


async def test_invalid_arguments_are_rejected(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path, note_max_bytes=256)
    with pytest.raises(InvalidArgument):
        await store.remember(entity_type="vm", entity_key="100", body="x", source="t")
    with pytest.raises(InvalidArgument):
        await store.remember(entity_type="guest", entity_key=" ", body="x", source="t")
    with pytest.raises(InvalidArgument):
        await store.remember(entity_type="guest", entity_key="100", body="", source="t")
    with pytest.raises(InvalidArgument):
        await store.remember(
            entity_type="guest", entity_key="100", body="x" * 300, source="t"
        )
    with pytest.raises(InvalidArgument):
        await store.remember(
            entity_type="guest", entity_key="100", body="x", source="t", expires_in_days=0
        )
    with pytest.raises(InvalidArgument):
        await store.recall(limit=0)
    with pytest.raises(InvalidArgument):
        await store.forget(0)
    await store.close()
