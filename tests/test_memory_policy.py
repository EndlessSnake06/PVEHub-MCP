"""Policy matrix for the memory tools (issues #34, #38)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from httpx import Response
from pydantic import ValidationError

from pvehub_mcp.config import Settings
from pvehub_mcp.errors import PolicyError
from pvehub_mcp.policy import CATEGORIES, Policy, PolicyFile, ToolDecision
from pvehub_mcp.server import PVEHub

MEMORY_TOOLS = {"memory_recall", "memory_remember", "memory_forget"}
WRITE_TOOLS = {"memory_remember", "memory_forget"}


def settings_for(tmp_path: Path) -> Settings:
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


async def make_hub(tmp_path: Path, router: Any, policy_text: str = "") -> PVEHub:
    (tmp_path / "policy.yaml").write_text(policy_text, encoding="utf-8")
    router.get("/api2/json/access/permissions").mock(
        return_value=Response(200, json={"data": {}})
    )
    hub = PVEHub(settings_for(tmp_path))
    hub.build()
    await hub.initialize()
    return hub


async def tool_names(hub: PVEHub) -> set[str]:
    return {tool.name for tool in await hub.mcp.list_tools()}


def blocked_reason(hub: PVEHub, name: str) -> str | None:
    for item in hub.blocked:
        if item.name == name:
            return item.reason
    return None


def test_memory_categories_are_valid() -> None:
    assert "memory" in CATEGORIES
    assert "memory_write" in CATEGORIES
    # Validation accepts them in the deny list; a bogus category still fails.
    PolicyFile.model_validate({"categories": {"deny": ["memory", "memory_write"]}})
    with pytest.raises(ValidationError):
        PolicyFile.model_validate({"categories": {"deny": ["memory_typo"]}})


async def test_operator_profile_allows_every_memory_tool(tmp_path: Path, router: Any) -> None:
    hub = await make_hub(tmp_path, router)
    try:
        names = await tool_names(hub)
        assert names >= MEMORY_TOOLS
        for name in MEMORY_TOOLS:
            assert blocked_reason(hub, name) is None
    finally:
        await hub.close()


async def test_readonly_profile_keeps_recall_only(tmp_path: Path, router: Any) -> None:
    hub = await make_hub(tmp_path, router, "read_only: true\n")
    try:
        names = await tool_names(hub)
        assert "memory_recall" in names
        assert not (WRITE_TOOLS & names)
        assert blocked_reason(hub, "memory_remember") == "policy: read_only"
        assert blocked_reason(hub, "memory_forget") == "policy: read_only"
        with pytest.raises(PolicyError):
            hub.policy.check_call(
                "memory_remember",
                "memory_write",
                {"entity_type": "guest", "entity_key": "100", "body": "x"},
            )
    finally:
        await hub.close()


async def test_denied_memory_category_hides_recall(tmp_path: Path, router: Any) -> None:
    hub = await make_hub(tmp_path, router, "categories:\n  deny: [memory]\n")
    try:
        names = await tool_names(hub)
        assert "memory_recall" not in names
        assert blocked_reason(hub, "memory_recall") == "policy: category 'memory' denied"
        # The split lets writes stay available when only reads are denied.
        assert names >= WRITE_TOOLS
    finally:
        await hub.close()


async def test_denied_memory_write_category_keeps_recall(tmp_path: Path, router: Any) -> None:
    hub = await make_hub(tmp_path, router, "categories:\n  deny: [memory_write]\n")
    try:
        names = await tool_names(hub)
        assert "memory_recall" in names
        assert not (WRITE_TOOLS & names)
        assert blocked_reason(hub, "memory_forget") == "policy: category 'memory_write' denied"
    finally:
        await hub.close()


async def test_tools_deny_wins_over_category(tmp_path: Path, router: Any) -> None:
    hub = await make_hub(tmp_path, router, "tools:\n  deny: [memory_recall]\n")
    try:
        names = await tool_names(hub)
        assert "memory_recall" not in names
        assert blocked_reason(hub, "memory_recall") == "policy: in tools.deny"
        assert names >= WRITE_TOOLS
    finally:
        await hub.close()


async def test_disabled_store_blocks_all_memory_tools(tmp_path: Path, router: Any) -> None:
    (tmp_path / "policy.yaml").write_text("", encoding="utf-8")
    blocker = tmp_path / "blocked"
    blocker.write_text("x", encoding="utf-8")
    settings = settings_for(tmp_path)
    settings.memory_db = str(blocker / "memory.db")
    router.get("/api2/json/access/permissions").mock(
        return_value=Response(200, json={"data": {}})
    )
    hub = PVEHub(settings)
    hub.build()
    await hub.initialize()
    try:
        names = await tool_names(hub)
        assert names.isdisjoint(MEMORY_TOOLS)
        for name in MEMORY_TOOLS:
            reason = blocked_reason(hub, name)
            assert reason is not None and reason.startswith("memory:"), name
        report = hub.capabilities_report()
        assert report["memory"]["enabled"] is False
        assert report["memory"]["error"]
    finally:
        await hub.close()


async def test_unrestricted_policy_without_memory_section_still_starts(
    tmp_path: Path, router: Any
) -> None:
    """Backwards compatibility: an old policy file (no memory category) loads."""

    hub = await make_hub(
        tmp_path,
        router,
        "tools:\n  deny: [pve_guest_delete]\nread_only: false\n",
    )
    try:
        assert await tool_names(hub) >= WRITE_TOOLS
        policy = Policy(file=PolicyFile.model_validate({}))
        assert isinstance(policy.tool_decision("memory_recall", "memory"), ToolDecision)
    finally:
        await hub.close()
