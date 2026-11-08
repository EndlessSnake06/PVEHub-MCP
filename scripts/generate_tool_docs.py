#!/usr/bin/env python3
"""Generate the tool catalog from ``@hub.tool(...)`` declarations.

The scan is purely static (Python ``ast``): it never imports the server (only
the side-effect-free ``toolnaming`` helper, which is stdlib-only), never
contacts PVE or PBS and therefore works while tool modules are still stubs.
Only literal decorator arguments are read; computed values are reported as
``?`` with a warning on stderr.

Usage::

    uv run python scripts/generate_tool_docs.py > docs/TOOLS.md

Exit codes: 0 = success, 2 = source directory missing.
"""

from __future__ import annotations

import argparse
import ast
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pvehub_mcp.toolnaming import derive_title

CATEGORY_ORDER = ("read", "lifecycle", "write", "destructive", "exec", "generic")
EMPTY = "—"

# Static mirrors of the runtime values in ``pvehub_mcp.server`` /
# ``pvehub_mcp.policy``. The generator must stay a pure static scan, so it
# cannot import the policy engine; keep these in sync with
# ``_default_confirm_categories()`` and the CONFIRM_* notes in ``server.py``.
DEFAULT_REQUIRE_CONFIRM: tuple[str, ...] = ("destructive", "exec")
CONFIRM_NOTE = "This tool is protected: the call is rejected unless confirm=true is passed."
CONFIRM_DRY_RUN_NOTE = " Use dry_run=true to preview the effect without executing."


@dataclass
class Tool:
    module: str
    name: str
    category: str
    title: str
    pve: list[tuple[str, str]] = field(default_factory=list)
    pbs: list[tuple[str, str]] = field(default_factory=list)
    shell: str | None = None
    service: str | None = None
    description: str = ""
    lineno: int = 0
    dry_run: bool = False


def _literal(node: ast.AST, where: str, warnings: list[str]) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        warnings.append(f"{where}: non-literal value {ast.unparse(node)!r} rendered as '?'")
        return None


def _pairs(value: Any, where: str, warnings: list[str]) -> list[tuple[str, str]]:
    if not isinstance(value, (list, tuple)):
        if value is not None:
            warnings.append(f"{where}: privilege list is not a list/tuple, ignored")
        return []
    result: list[tuple[str, str]] = []
    for item in value:
        if (
            isinstance(item, (list, tuple))
            and len(item) == 2
            and all(isinstance(part, str) for part in item)
        ):
            result.append((item[0], item[1]))
        else:
            warnings.append(f"{where}: privilege entry {item!r} is not a (privilege, path) pair")
    return result


def _docstring_summary(node: ast.AST) -> str:
    doc = ast.get_docstring(node)  # type: ignore[arg-type]
    if not doc:
        return ""
    text = inspect.cleandoc(doc)
    for line in text.splitlines():
        line = line.strip()
        if line:
            return " ".join(line.split())
    return ""


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = node.args
    return {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}


def _tool_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call | None:
    for decorator in node.decorator_list:
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "tool"
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "hub"
        ):
            return decorator
    return None


def _collect(path: Path, warnings: list[str]) -> tuple[list[Tool], bool]:
    """Return tools declared in ``path`` and whether it defines ``register``."""

    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    has_register = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "register"
        for node in tree.body
    )
    tools: list[Tool] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        call = _tool_decorator(node)
        if call is None:
            continue
        where = f"{path.name}:{getattr(call, 'lineno', node.lineno)}"
        kwargs: dict[str, Any] = {}
        for keyword in call.keywords:
            if keyword.arg is None:
                warnings.append(f"{where}: **kwargs in @hub.tool() is not supported")
                continue
            kwargs[keyword.arg] = _literal(keyword.value, f"{where} ({keyword.arg})", warnings)

        name = kwargs.get("name")
        if not isinstance(name, str) or not name:
            warnings.append(f"{where}: missing literal tool name, skipped")
            continue
        category = kwargs.get("category")
        if not isinstance(category, str):
            warnings.append(f"{where}: tool {name!r} has no literal category, using '?'")
            category = "?"
        shell = kwargs.get("shell")
        service = kwargs.get("service")

        raw_title = kwargs.get("title")
        if raw_title is not None and not isinstance(raw_title, str):
            warnings.append(f"{where}: non-literal title for {name!r}, deriving from name")
            raw_title = None
        title = raw_title if isinstance(raw_title, str) else derive_title(name)

        params = _param_names(node)

        tools.append(
            Tool(
                module=path.stem,
                name=name,
                category=category,
                title=title,
                pve=_pairs(kwargs.get("pve"), f"{where} ({name}.pve)", warnings),
                pbs=_pairs(kwargs.get("pbs"), f"{where} ({name}.pbs)", warnings),
                shell=shell if isinstance(shell, str) else None,
                service=service if isinstance(service, str) else None,
                description=_docstring_summary(node),
                lineno=node.lineno,
                dry_run="dry_run" in params,
            )
        )
    return tools, has_register


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _priv_cell(entries: list[tuple[str, str]]) -> str:
    if not entries:
        return EMPTY
    return "<br>".join(f"`{_cell(priv)}` on `{_cell(path)}`" for priv, path in entries)


def _confirm_note(tool: Tool) -> str:
    """The confirm note the server appends at runtime for default-confirmed
    categories (``DEFAULT_REQUIRE_CONFIRM``); empty for all other tools."""
    if tool.category not in DEFAULT_REQUIRE_CONFIRM:
        return ""
    note = CONFIRM_NOTE
    if tool.dry_run:
        note += CONFIRM_DRY_RUN_NOTE
    return note


def generate(src_dir: Path) -> tuple[str, list[str]]:
    warnings: list[str] = []
    tools: list[Tool] = []
    modules: list[tuple[str, bool, int]] = []

    for path in sorted(src_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        found, has_register = _collect(path, warnings)
        if not found and not has_register:
            continue
        modules.append((path.stem, has_register, len(found)))
        tools.extend(found)

    seen: dict[str, str] = {}
    for tool in tools:
        if tool.name in seen:
            warnings.append(
                f"duplicate tool name {tool.name!r} in {tool.module}.py "
                f"(first defined in {seen[tool.name]}.py)"
            )
        else:
            seen[tool.name] = tool.module

    order = {category: index for index, category in enumerate(CATEGORY_ORDER)}
    tools.sort(key=lambda item: (order.get(item.category, len(order)), item.name))

    with_tools = [module for module, _, count in modules if count]
    without = [(module, count) for module, has_register, count in modules if has_register and not count]

    lines: list[str] = [
        "<!-- Generated by scripts/generate_tool_docs.py — do not edit by hand. -->",
        "# Tool catalog",
        "",
        "This file is generated from the `@hub.tool(...)` decorators in",
        "`src/pvehub_mcp/tools/*.py` by a static AST scan. It does not contact PVE or PBS and",
        "does not reflect runtime policy or token privileges: a tool listed here may still be",
        "blocked by policy, missing token permissions or missing SSH prerequisites.",
        "",
        "Regenerate with `make docs-tools` or `uv run python scripts/generate_tool_docs.py > docs/TOOLS.md`.",
        "",
        f"**{len(tools)} tools** in {len(with_tools)} of {len(modules)} tool modules.",
        "",
        "| Tool | Title | Category | PVE privilege/path | PBS privilege/path | Shell | Description |",
        "|---|---|---|---|---|---|---|",
    ]
    for tool in tools:
        description = _cell(tool.description) or "(no docstring)"
        note = _confirm_note(tool)
        if note:
            description = f"{description} {note}"
        lines.append(
            "| `{name}` | {title} | `{category}` | {pve} | {pbs} | {shell} | {description} |".format(
                name=_cell(tool.name),
                title=_cell(tool.title),
                category=_cell(tool.category),
                pve=_priv_cell(tool.pve),
                pbs=_priv_cell(tool.pbs),
                shell=f"`{_cell(tool.shell)}`" if tool.shell else EMPTY,
                description=description,
            )
        )

    service_tools = [tool for tool in tools if tool.service]
    if service_tools:
        lines.extend(
            [
                "",
                "## Service binding",
                "",
                "| Tool | Service |",
                "|---|---|",
            ]
        )
        for tool in service_tools:
            lines.append(f"| `{_cell(tool.name)}` | `{_cell(tool.service or '')}` |")

    if without:
        lines.extend(
            [
                "",
                "## Modules without tool declarations",
                "",
                "These modules expose `register(hub)` but declare no `@hub.tool(...)` yet",
                "(stubs or work in progress). They contribute no rows above.",
                "",
            ]
        )
        for module, _count in without:
            lines.append(f"- `{module}.py`")

    lines.append("")
    return "\n".join(lines), warnings


def main(argv: list[str] | None = None) -> int:
    default_src = Path(__file__).resolve().parents[1] / "src" / "pvehub_mcp" / "tools"
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--src",
        type=Path,
        default=default_src,
        help=f"directory with tool modules (default: {default_src})",
    )
    args = parser.parse_args(argv)

    src_dir: Path = args.src
    if not src_dir.is_dir():
        print(f"error: source directory not found: {src_dir}", file=sys.stderr)
        return 2

    output, warnings = generate(src_dir)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not output.strip():
        print("error: generated output is empty", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
