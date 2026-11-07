"""Audit redaction tests."""

from __future__ import annotations

import json

import pytest

from pvehub_mcp.audit import AuditLogger, redact_value


def test_redact_command_and_content_bodies() -> None:
    redacted = redact_value(
        {
            "command": "export API_TOKEN=supersecret; echo ok",
            "content_base64": "c2VjcmV0",
        }
    )
    assert isinstance(redacted["command"], dict)
    assert "supersecret" not in redacted["command"]["preview"]
    assert redacted["command"]["length"] == len("export API_TOKEN=supersecret; echo ok")
    assert "c2VjcmV0" not in str(redacted["content_base64"])


def test_redact_secret_keys_and_values() -> None:
    payload = {
        "password": "hunter2",
        "nested": {"token": "abc", "safe": "value"},
        "header": "Authorization: PVEAPIToken=root@pam!x=supersecret",
        "bearer": "Bearer abc.def.ghi",
        "private": "-----BEGIN OPENSSH PRIVATE KEY-----\nxxx\n-----END OPENSSH PRIVATE KEY-----",
        "list": ["normal", {"api_key": "k"}],
    }
    redacted = redact_value(payload)
    assert redacted["password"] == "***"
    assert redacted["nested"]["token"] == "***"
    assert redacted["nested"]["safe"] == "value"
    assert "supersecret" not in redacted["header"]
    assert "abc.def.ghi" not in redacted["bearer"]
    assert "PRIVATE KEY" not in redacted["private"]
    assert redacted["list"][1]["api_key"] == "***"


@pytest.mark.asyncio
async def test_jsonl_audit_write_and_truncate(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(path), include_results=False)
    await logger.write(
        tool="pve_api_call",
        category="generic",
        status="ok",
        instance="main",
        target="path=/nodes",
        params={"password": "hunter2", "path": "/nodes", "long": "x" * 5000},
        duration_ms=5,
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool"] == "pve_api_call"
    assert entry["params"]["password"] == "***"
    assert "result" not in entry
    assert len(entry["params"]["long"]) < 5000


@pytest.mark.asyncio
async def test_audit_disabled_on_unwritable_path() -> None:
    logger = AuditLogger("/proc/definitely-not-writable/audit.jsonl")
    assert logger.enabled is False
    assert logger.error
    await logger.write(tool="x", category="read", status="ok")
