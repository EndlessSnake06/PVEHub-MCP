"""MCP resource memory://notes and the memory_briefing prompt (issue #37)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from httpx import Response
from mcp.client import Client

from pvehub_mcp.config import Settings
from pvehub_mcp.server import PVEHub


async def _resource_text(hub: PVEHub, uri: str = "memory://notes") -> dict[str, Any]:
    async with Client(hub.mcp) as client:
        result = await client.read_resource(uri)
    payload = json.loads(result.contents[0].text)  # type: ignore[union-attr]
    assert isinstance(payload, dict)
    return payload


async def test_resource_lists_notes(pve: Any, call: Any) -> None:
    hub, _router = pve
    await call(hub, "memory_remember", entity_type="guest", entity_key="100", body="resource note")

    payload = await _resource_text(hub)
    assert payload["trust"] == "untrusted-data"
    assert [note["body"] for note in payload["notes"]] == ["resource note"]


async def test_resource_is_valid_when_empty(pve: Any) -> None:
    hub, _router = pve
    payload = await _resource_text(hub)
    assert payload["notes"] == []


async def test_resource_hidden_when_memory_category_denied(tmp_path: Path, router: Any) -> None:
    hub = await _hub(tmp_path, router, policy_text="categories:\n  deny: [memory]\n")
    try:
        async with Client(hub.mcp) as client:
            uris = {str(resource.uri) for resource in (await client.list_resources()).resources}
        assert "memory://notes" not in uris
    finally:
        await hub.close()


async def test_prompt_is_registered_by_default(pve: Any) -> None:
    hub, _router = pve
    async with Client(hub.mcp) as client:
        prompts = {prompt.name for prompt in (await client.list_prompts()).prompts}
    assert "memory_briefing" in prompts


async def test_prompt_content_has_no_note_data(pve: Any, call: Any) -> None:
    hub, _router = pve
    await call(hub, "memory_remember", entity_type="guest", entity_key="100", body="secret note")
    async with Client(hub.mcp) as client:
        result = await client.get_prompt("memory_briefing", {})
    text = " ".join(
        message.content.text  # type: ignore[union-attr]
        for message in result.messages
    )
    assert "secret note" not in text
    assert "memory://notes" in text
    assert "untrusted" in text


async def test_prompt_and_resource_disappear_when_store_disabled(
    tmp_path: Path, router: Any
) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("x", encoding="utf-8")
    hub = await _hub(
        tmp_path, router, policy_text="", memory_db=str(blocker / "memory.db")
    )
    try:
        async with Client(hub.mcp) as client:
            prompts = {prompt.name for prompt in (await client.list_prompts()).prompts}
            uris = {str(resource.uri) for resource in (await client.list_resources()).resources}
        assert "memory_briefing" not in prompts
        assert "memory://notes" not in uris
    finally:
        await hub.close()


def _settings(tmp_path: Path) -> Settings:
    return Settings.model_validate(
        {
            "transport": "stdio",
            "pve": [
                {
                    "name": "test",
                    "url": "https://pve.test:8006",
                    "token_id": "root@pam!pvehub",
                    "token_secret": "s3cret",
                }
            ],
            "policy_file": str(tmp_path / "policy.yaml"),
            "audit_log": None,
            "state_dir": str(tmp_path),
            "memory_db": str(tmp_path / "memory.db"),
            "capabilities_refresh_seconds": 0,
            "capabilities_fail_open": True,
        }
    )


async def _hub(
    tmp_path: Path,
    router: Any,
    *,
    policy_text: str = "",
    memory_db: str | None = None,
) -> PVEHub:
    (tmp_path / "policy.yaml").write_text(policy_text, encoding="utf-8")
    router.get("/api2/json/access/permissions").mock(
        return_value=Response(200, json={"data": {}})
    )
    settings = _settings(tmp_path)
    if memory_db is not None:
        settings.memory_db = memory_db
    hub = PVEHub(settings)
    hub.build()
    await hub.initialize()
    return hub
