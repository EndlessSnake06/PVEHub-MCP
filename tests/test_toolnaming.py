"""Unit tests for the title derivation (``pvehub_mcp.toolnaming``)."""

from __future__ import annotations

import ast
import pathlib

import pytest

from pvehub_mcp.toolnaming import derive_title

TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1] / "src" / "pvehub_mcp" / "tools"


def _all_tool_names() -> list[str]:
    """Extract every tool name declared via ``@hub.tool(name=...)`` (AST scan)."""
    names: list[str] = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "tool"
                and isinstance(func.value, ast.Name)
                and func.value.id == "hub"
            ):
                continue
            for keyword in node.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    names.append(str(keyword.value.value))
    return names


ALL_NAMES = _all_tool_names()

# Pinned examples: the exact, current output of derive_title for representative
# names. If the derivation changes, these assertions fail on purpose.
PINNED = {
    "pvehub_capabilities": "PVEHub Capabilities",
    "pvehub_health": "PVEHub Health",
    "pve_guest_delete": "PVE Guest Delete",
    "pve_guest_info": "PVE Guest Info",
    "pve_guest_status": "PVE Guest Status",
    "pve_task_log": "PVE Task Log",
    "pbs_datastore_status": "PBS Datastore Status",
    "pbs_snapshot_forget": "PBS Snapshot Forget",
    "exec_lxc": "Exec LXC",
    "exec_pbs": "Exec PBS",
    "exec_vm": "Exec VM",
    "file_pull_host": "File Pull Host",
    "pve_api_schema": "PVE API Schema",
    "pbs_api_call": "PBS API Call",
}


@pytest.mark.parametrize(
    ("name", "expected"),
    sorted(PINNED.items()),
    ids=list(PINNED),
)
def test_derive_title_pinned_examples(name: str, expected: str) -> None:
    assert derive_title(name) == expected


def test_brand_prefix_is_a_single_word() -> None:
    assert derive_title("pvehub_capabilities") == "PVEHub Capabilities"
    # The brand prefix must not split into PVE + Hub.
    assert "PVE Hub" not in derive_title("pvehub_capabilities")


def test_all_tool_names_derive_readable_titles() -> None:
    # Guard against tool-set drift: the catalog must stay complete.
    assert len(ALL_NAMES) == 78
    for name in ALL_NAMES:
        title = derive_title(name)
        assert title, name
        assert "_" not in title, name
        assert title != name, name
        # Deterministic.
        assert derive_title(name) == title


def test_deterministic_and_pure() -> None:
    for _ in range(3):
        assert derive_title("pve_guest_delete") == "PVE Guest Delete"
