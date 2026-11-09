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
                result[key_text] = redact_value(item, max_string=max_string, _depth=_depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item, max_string=max_string, _depth=_depth + 1) for item in value]

    if isinstance(value, str):
        text = value
        for pattern in _SECRET_VALUE_PATTERNS:
            text = pattern.sub(r"\1***", text) if pattern.groups else pattern.sub("***", text)
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
    """Append-only JSONL logger with size-based rotation.

    Failures never break a tool call.  A write failure (full volume, lost
    permissions) is recorded in :attr:`error` so the capabilities report can
    surface it — a silently stopped audit is worse than no audit.
    """

    def __init__(
        self,
        path: str | None,
        *,
        include_results: bool = False,
        max_string: int = 2048,
        max_bytes: int = 10 * 1024 * 1024,
        keep: int = 5,
    ) -> None:
        self.path = Path(path) if path else None
        self.include_results = include_results
        self.max_string = max_string
        self.max_bytes = max_bytes
        self.keep = max(1, keep)
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

    @property
    def size_bytes(self) -> int:
        """Current size of the active log file (0 if missing)."""

        if self.path is None or not self.path.exists():
            return 0
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    async def write(
        self,
        *,
        tool: str,
        category: str,
        status: str,
        instance: str | None = None,
        target: str | dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        duration_ms: int | None = None,
        output_bytes: int | None = None,
        error: dict[str, Any] | None = None,
        result: Any = None,
        client: str | None = None,
        client_ip: str | None = None,
        pve_token: str | None = None,
    ) -> None:
        if not self.enabled or self.path is None:
            return
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # Present on every entry (D019): "unknown" when no client is
            # known (stdio transport, dev-mode loopback without a token).
            # Passthrough mode (D026, issue #30) has no named MCP client —
            # the PVE API token is the credential — so this stays "unknown"
            # there and the PVE token *identity* is carried separately in
            # the ``pve_token`` field (an ID, never the secret).
            "client": client or "unknown",
            # Same shape for the address (D024, issue #25): resolved from
            # the trusted-proxy rules, "unknown" when not resolvable
            # (stdio, no client in the ASGI scope, untrusted peer without a
            # usable identity).
            "client_ip": client_ip or "unknown",
            "tool": tool,
            "category": category,
            "status": status,
        }
        if instance:
            entry["instance"] = instance
        if pve_token:
            # D026 (issue #30): the *identity* of the PVE API token used for
            # the PVE call (user@realm!tokenid), redacted like everything
            # else. Never the secret — the secret only ever exists in the
            # client's Authorization header and in the client object's own
            # header (both memory-only, never serialized here).
            entry["pve_token"] = _safe_redact(pve_token, max_string=self.max_string)
        if target:
            entry["target"] = _safe_redact(target, max_string=self.max_string)
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
                await asyncio.to_thread(self._append_with_rotation, line)
        except OSError as exc:  # never fail the tool because of audit I/O
            self.error = f"audit write failed: {exc}"
            logger.warning("audit write failed: %s", exc)

    def _append_with_rotation(self, line: str) -> None:
        assert self.path is not None
        self._maybe_rotate()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        # Re-assert the file mode: external rotation (logrotate copytruncate)
        # or a fresh file after _maybe_rotate() must stay 0600.
        self.path.chmod(0o600)

    def _maybe_rotate(self) -> None:
        """Shift ``audit.jsonl`` to ``.1`` ... ``.keep`` when the size cap is hit.

        The oldest archive beyond ``keep`` is dropped.  Runs inside the write
        lock, so a concurrent writer can never observe a half-rotated file.
        """

        path = self.path
        assert path is not None
        if not path.exists() or path.stat().st_size < self.max_bytes:
            return
        oldest = path.with_name(f"{path.name}.{self.keep}")
        if oldest.exists():
            oldest.unlink()
        for index in range(self.keep - 1, 0, -1):
            src = path.with_name(f"{path.name}.{index}")
            if src.exists():
                src.rename(path.with_name(f"{path.name}.{index + 1}"))
        path.rename(path.with_name(f"{path.name}.1"))
        with path.open("a", encoding="utf-8"):
            pass
        path.chmod(0o600)


# ---------------------------------------------------------------------------
# Read side (issue #20, D020)
# ---------------------------------------------------------------------------

#: Hard cap for the tail reader's working set; the log may grow to
#: ``audit_max_bytes`` (default 10 MiB) before rotation kicks in.
TAIL_WINDOW_BYTES = 8 * 1024 * 1024


def read_audit_tail(
    path: Path,
    max_lines: int,
    *,
    window_bytes: int = TAIL_WINDOW_BYTES,
    max_string: int = 2048,
) -> list[dict[str, Any]]:
    """Return the last ``max_lines`` JSONL entries in **file order**.

    Reads from the end of the file in 64 KiB chunks (plus a hard
    ``window_bytes`` cap) so a 10 MiB log is not loaded into memory.  Malformed
    lines are skipped, never raised.  Every returned entry is re-redacted
    (defense in depth — the redaction is applied again on the way out, #20).
    """

    if not path.exists():
        return []
    size = path.stat().st_size
    start = max(0, size - window_bytes)
    with path.open("rb") as handle:
        handle.seek(start)
        chunk = handle.read()
    parts = chunk.split(b"\n")
    if start > 0:
        parts = parts[1:]  # the first fragment is a partial line
    entries: list[dict[str, Any]] = []
    for raw in reversed(parts):
        raw = raw.strip()
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(parsed, dict):
            continue
        entries.append(_safe_redact(parsed, max_string=max_string))
        if len(entries) >= max_lines:
            break
    entries.reverse()
    return entries
