"""Contract for scripts/generate_tool_docs.py (static AST scan).

Runs the real generator against the real source tree and verifies that the
rendered catalog stays complete, carries the derived titles, and honors a
literal ``title=`` override.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

from pvehub_mcp.toolnaming import derive_title

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TOOLS_DIR = ROOT / "src" / "pvehub_mcp" / "tools"

ROW_RE = re.compile(r"^\| `(?P<name>[^`]+)` \| (?P<title>[^|]+?) \|")


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "generate_tool_docs", SCRIPTS / "generate_tool_docs.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_tool_docs"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


generate_tool_docs: ModuleType = _load_generator()


def _all_tool_names() -> list[str]:
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
    return sorted(set(names))


ALL_NAMES = _all_tool_names()


def _run_script() -> str:
    result = subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script
        [sys.executable, str(SCRIPTS / "generate_tool_docs.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _table_rows(content: str) -> dict[str, str]:
    """name -> title, parsed from the main catalog table only."""
    rows: dict[str, str] = {}
    in_main = False
    for line in content.splitlines():
        if line.startswith("| Tool | Title |"):
            in_main = True
            continue
        if in_main and line.startswith(("## ", "| Tool | Service")):
            break
        if not in_main or not line.startswith("| `"):
            continue
        match = ROW_RE.match(line)
        if match:
            rows[match.group("name")] = match.group("title").strip()
    return rows


def test_script_stays_pure() -> None:
    source = (SCRIPTS / "generate_tool_docs.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.lstrip().startswith(("import ", "from ")):
            assert "pvehub_mcp.server" not in line
            assert "pvehub_mcp.policy" not in line


def _line(content: str, prefix: str) -> str:
    for line in content.splitlines():
        if line.startswith(prefix):
            return line
    raise AssertionError(f"line not found: {prefix!r}")


def test_generated_catalog_is_complete_and_titled() -> None:
    content = _run_script()
    rows = _table_rows(content)
    assert len(ALL_NAMES) == 74
    assert set(rows) == set(ALL_NAMES)
    assert "**74 tools**" in content
    for name in ALL_NAMES:
        assert rows[name] == derive_title(name), name
        assert "_" not in rows[name]


def test_generated_catalog_matches_committed_docs() -> None:
    committed = (ROOT / "docs" / "TOOLS.md").read_text(encoding="utf-8")
    assert _run_script() == committed


def test_confirm_note_rendered_for_default_categories() -> None:
    content = _run_script()
    for name in ("pve_guest_delete", "exec_lxc", "exec_vm"):
        line = _line(content, f"| `{name}` |")
        assert "confirm=true" in line, name
    # write is NOT in the default require_confirm set: no note.
    line = _line(content, "| `pve_guest_resize` |")
    assert "confirm=true" not in line
    assert "This tool is protected" not in line


def test_literal_title_override_is_honored(tmp_path: Path) -> None:
    module = tmp_path / "sample.py"
    module.write_text(
        '''
from __future__ import annotations


def register(hub) -> None:
    @hub.tool(name="fake_widget_delete", category="destructive", title="Delete the widget")
    async def fake_widget_delete(confirm: bool = False, dry_run: bool = False) -> str:
        """Delete the widget."""
        return ""

    @hub.tool(name="fake_widget_list", category="read")
    async def fake_widget_list() -> str:
        """List widgets."""
        return ""
''',
        encoding="utf-8",
    )
    output, warnings = generate_tool_docs.generate(tmp_path)
    assert warnings == []
    assert "Delete the widget" in output
    # The overridden tool must NOT show the derived title.
    assert "Fake Widget Delete" not in output
    # The un-overridden tool shows its derived title.
    assert "Fake Widget List" in output
    # destructive still carries the confirm note (dry_run detected statically).
    line = _line(output, "| `fake_widget_delete` |")
    assert "confirm=true" in line
    assert "dry_run=true" in line
