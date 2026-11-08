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
        "header": "Authorization: PVE" + "APIToken=pvehub@pve!mcp=" + "supersecret",
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


# -- client field (D019) -----------------------------------------------------


@pytest.mark.asyncio
async def test_client_field_always_present(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(path))
    await logger.write(tool="pvehub_capabilities", category="read", status="ok")
    await logger.write(
        tool="pvehub_capabilities", category="read", status="ok", client="webui"
    )
    entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert entries[0]["client"] == "unknown"
    assert entries[1]["client"] == "webui"


# -- rotation (D023, issue #19) ----------------------------------------------


@pytest.mark.asyncio
async def test_rotation_shifts_archives_and_drops_oldest(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    # 64-byte cap, keep=2: a single write of a ~200-byte line triggers
    # rotation on the NEXT write.
    logger = AuditLogger(str(path), max_bytes=64, keep=2)
    big = "x" * 200

    async def write_one(tag: str) -> None:
        await logger.write(
            tool="pvehub_capabilities",
            category="read",
            status="ok",
            params={"tag": tag, "pad": big},
        )

    await write_one("first")
    assert path.stat().st_size >= 64
    await write_one("second")  # active file exceeds cap -> rotate to .1
    await write_one("third")  # .1 exceeds cap -> shift to .2, .1
    await write_one("fourth")  # .2 would exceed -> drop .2 (keep=2)

    files = {child.name for child in tmp_path.iterdir()}
    assert files == {"audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"}
    # The oldest entry is gone, the newest is in the active file.
    active = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert [entry["params"]["tag"] for entry in active] == ["fourth"]
    for suffix in ("1", "2"):
        mode = (tmp_path / f"audit.jsonl.{suffix}").stat().st_mode & 0o777
        assert mode == 0o600
    assert (path.stat().st_mode & 0o777) == 0o600


@pytest.mark.asyncio
async def test_no_rotation_below_cap(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(path), max_bytes=10 * 1024 * 1024, keep=5)
    for _ in range(3):
        await logger.write(tool="t", category="read", status="ok")
    files = {child.name for child in tmp_path.iterdir()}
    assert files == {"audit.jsonl"}
    assert logger.size_bytes == len(path.read_text())


def test_size_bytes_property_reports_missing_file(tmp_path) -> None:
    logger = AuditLogger(str(tmp_path / "missing.jsonl"))
    assert logger.size_bytes == 0
    (tmp_path / "missing.jsonl").write_text("{}\n")
    assert logger.size_bytes == 3


@pytest.mark.asyncio
async def test_write_failure_is_recorded_in_logger_error(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(path))
    await logger.write(tool="t", category="read", status="ok")
    # Turn the log file into a directory: append now raises IsADirectoryError
    # (an OSError) and the logger must record it instead of dropping silently.
    path.unlink()
    path.mkdir()
    await logger.write(tool="t", category="read", status="ok")
    assert logger.error is not None
    assert "audit write failed" in logger.error
    # The logger stays enabled; a transient failure must not kill the audit.
    assert logger.enabled is True


@pytest.mark.asyncio
async def test_capabilities_report_exposes_audit_state(tmp_path) -> None:
    from pvehub_mcp.config import Settings
    from pvehub_mcp.policy import Policy, PolicyFile
    from pvehub_mcp.server import PVEHub

    config = {
        "transport": "stdio",
        "pve": [
            {
                "name": "test",
                "url": "https://pve.test:8006",
                "token_id": "pvehub@pve!mcp",
                "token_secret": "secret",
                "verify": False,
            }
        ],
        "audit_log": str(tmp_path / "audit.jsonl"),
        "state_dir": str(tmp_path),
        "capabilities_fail_open": True,
        "capabilities_refresh_seconds": 0,
    }
    hub = PVEHub(Settings.model_validate(config), Policy(file=PolicyFile()))
    report = hub.capabilities_report()
    audit_block = report["audit"]
    assert audit_block["enabled"] is True
    assert audit_block["path"] == str(tmp_path / "audit.jsonl")
    assert audit_block["keep"] == 5
    assert audit_block["max_bytes"] == 10 * 1024 * 1024
    assert audit_block["size_bytes"] == 0
    assert audit_block["error"] is None


# -- multi-key target (D023, issue #18) ---------------------------------------


def test_target_single_key_keeps_string_form() -> None:
    from pvehub_mcp.server import _target

    assert _target({"vmid": 100}) == "vmid=100"
    assert _target({"node": "pve1"}) == "node=pve1"
    assert _target({}) is None


def test_target_multiple_keys_returns_dict() -> None:
    from pvehub_mcp.server import _target

    result = _target({"vmid": 100, "node": "pve1", "command": "export API_TOKEN=supersecret"})
    assert isinstance(result, dict)
    assert result["vmid"] == "vmid=100"
    assert result["node"] == "node=pve1"
    # Redaction still applies inside the multi-key form; the command value
    # is masked wholesale (the "command=" rule swallows the whole value).
    assert "supersecret" not in result["command"]
    assert "API_TOKEN" not in result["command"]
