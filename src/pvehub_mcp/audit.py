"""JSONL audit trail with secret redaction and bounded output."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SECRET_KEY_RE = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[-_]?key|private[-_]?key|authorization|cookie|csrf"
    r"|content_base64)"
)
_BODY_KEY_RE = re.compile(r"(?i)^(command|content|content_base64|input|input_data)$")
_SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)(PVEAPIToken|PBSAPIToken)=[^\s\"']+"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/\-]+=*"),
    re.compile(r"(?i)(Authorization:\s*Basic\s+)\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)([?&](?:password|secret|token)=)[^&\s]+"),
    re.compile(r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key)[= ])\S+"),
    re.compile(r"(?i)\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)\s*=\s*[^\s;]+"),
    # JSON/form style pairs inside command strings: "password": "x", token=abc
    re.compile(
        r"(?i)([\"']?(?:password|passwd|secret|token|api[-_]?key)[\"']?\s*[:=]\s*[\"']?)"
        r"[^\s\"',;&}]+"
    ),
]
_MAX_DEPTH = 64


def redact_value(value: Any, *, max_string: int = 2048, _depth: int = 0) -> Any:
    if _depth > _MAX_DEPTH:
        return "<nested value omitted>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                result[key_text] = "***"
            elif _BODY_KEY_RE.match(key_text) and isinstance(item, str):
                # Commands and file bodies can contain secrets in ways no regex catches.
                # Keep a bounded, redacted preview for commands; hash everything.
                import hashlib

                if key_text.lower() == "command":
                    redacted_preview = item[:160]
                    for pattern in _SECRET_VALUE_PATTERNS:
                        redacted_preview = (
                            pattern.sub(r"\1***", redacted_preview)
                            if pattern.groups
                            else pattern.sub("***", redacted_preview)
                        )
                else:
                    redacted_preview = "<redacted>"
                result[key_text] = {
                    "sha256": hashlib.sha256(item.encode("utf-8")).hexdigest(),
                    "length": len(item),
                    "preview": redacted_preview,
                }
            else:
                result[key_text] = redact_value(
                    item, max_string=max_string, _depth=_depth + 1
                )
        return result
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item, max_string=max_string, _depth=_depth + 1) for item in value]

    if isinstance(value, str):
        text = value
        for pattern in _SECRET_VALUE_PATTERNS:
            text = (
                pattern.sub(r"\1***", text)
                if pattern.groups
                else pattern.sub("***", text)
            )
        if len(text) > max_string:
            text = text[:max_string] + f"...[truncated {len(text) - max_string} chars]"
        return text
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_value(str(value), max_string=max_string, _depth=_depth + 1)


def _safe_redact(value: Any, *, max_string: int) -> Any:
    """Redact without ever raising into the caller (audit must be best-effort)."""

    try:
        return redact_value(value, max_string=max_string)
    except Exception:  # pragma: no cover - defensive, redaction is depth limited
        return "<value omitted: redaction failed>"


class AuditLogger:
    """Append-only JSONL logger. Failures never break a tool call."""

    def __init__(
        self,
        path: str | None,
        *,
        include_results: bool = False,
        max_string: int = 2048,
    ) -> None:
        self.path = Path(path) if path else None
        self.include_results = include_results
        self.max_string = max_string
        self.enabled = bool(path)
        self.error: str | None = None
        self._lock = asyncio.Lock()
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8"):
                    pass
                self.path.chmod(0o600)
            except OSError as exc:
                self.enabled = False
                self.error = f"audit log disabled: {exc}"
                logger.warning(self.error)

    async def write(
        self,
        *,
        tool: str,
        category: str,
        status: str,
        instance: str | None = None,
        target: str | None = None,
        params: dict[str, Any] | None = None,
        duration_ms: int | None = None,
        output_bytes: int | None = None,
        error: str | None = None,
        result: Any = None,
    ) -> None:
        if not self.enabled or self.path is None:
            return
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": tool,
            "category": category,
            "status": status,
        }
        if instance:
            entry["instance"] = instance
        if target:
            entry["target"] = target
        if params:
            entry["params"] = _safe_redact(params, max_string=self.max_string)
        if duration_ms is not None:
            entry["duration_ms"] = duration_ms
        if output_bytes is not None:
            entry["output_bytes"] = output_bytes
        if error:
            entry["error"] = _safe_redact(error, max_string=self.max_string)
        if self.include_results and result is not None:
            entry["result"] = _safe_redact(result, max_string=self.max_string)
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), default=str)
        try:
            async with self._lock:
                await asyncio.to_thread(self._append, line)
        except OSError as exc:  # never fail the tool because of audit I/O
            logger.warning("audit write failed: %s", exc)

    def _append(self, line: str) -> None:
        assert self.path is not None
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
