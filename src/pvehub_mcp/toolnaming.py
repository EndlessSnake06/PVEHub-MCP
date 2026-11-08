"""Derive human-readable tool titles from snake_case tool names.

Pure standard library, no imports from the package: this module must stay
importable from ``scripts/generate_tool_docs.py``, whose static AST scan must
not pull in the server.
"""

from __future__ import annotations

import re

# Multi-segment brand prefixes, matched before word splitting.
_BRAND_PREFIXES: tuple[tuple[str, str], ...] = (
    ("pvehub", "PVEHub"),
)

# Case-insensitive acronym map: lowercase token -> canonical casing.
_ACRONYMS: dict[str, str] = {
    "pve": "PVE",
    "pbs": "PBS",
    "lxc": "LXC",
    "vm": "VM",
    "vmid": "VMID",
    "sftp": "SFTP",
    "ssh": "SSH",
    "mcp": "MCP",
    "api": "API",
    "dns": "DNS",
    "tls": "TLS",
    "upid": "UPID",
    "ip": "IP",
    "id": "ID",
    "url": "URL",
    "ca": "CA",
    "json": "JSON",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _word(token: str) -> str:
    lowered = token.lower()
    if lowered in _ACRONYMS:
        return _ACRONYMS[lowered]
    return token.capitalize()


def _derive(name: str) -> str:
    tokens = _TOKEN_RE.findall(name)
    if not tokens:
        return name
    return " ".join(_word(token) for token in tokens)


def derive_title(name: str) -> str:
    """Derive a readable title from a snake_case tool name.

    Deterministic and pure: the same name always maps to the same title.
    Acronyms keep their canonical casing (``pve`` -> ``PVE``), the
    ``pvehub_`` brand prefix maps to the single word ``PVEHub``, and all
    other words are title-cased. The result never contains underscores.
    """
    for prefix, label in _BRAND_PREFIXES:
        if name.startswith(f"{prefix}_"):
            return f"{label} {_derive(name[len(prefix) + 1:])}"
    return _derive(name)
