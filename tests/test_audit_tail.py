"""``read_audit_tail`` and the ``pvehub_audit_tail`` tool (D020, issue #20).

Unit tests exercise the read-side primitive directly (chunked backward
reading, re-redaction, corrupt lines, the byte window).  One end-to-end test
proves the whole chain: calls through the MCP client land in the log, come
back through the tool re-redacted and filterable (tool/category/status/
client/since), and the capabilities report and /ready endpoint expose the
audit and version state.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx
from mcp.client import Client

from pvehub_mcp.audit import read_audit_tail
from pvehub_mcp.config import PVEInstance
from pvehub_mcp.policy import Policy, PolicyFile

BASE = "https://pve.test:8006"
# Same path -> privilege mapping as tests/test_server.py: the capability
# check for pve_api_call resolves the target path against these, and the
# denial we want to audit is confirm_required, not a privilege miss.
PERMISSIONS = {
    "/": {"Sys.Audit": 1},
    "/vms": {"VM.Audit": 1},
    "/vms/100": {"VM.PowerMgmt": 1},
    "/storage": {"Datastore.Audit": 1},
}


def _data(result) -> dict:
    """Unwrap the ``{"ok": true, "data": ...}`` envelope of a tool result."""
    return json.loads(result.content[0].text)["data"]


def _entry(tool: str = "pvehub_capabilities", status: str = "ok", **extra: object) -> str:
    base: dict[str, object] = {
        "ts": "2026-11-08T00:00:00Z",
        "tool": tool,
        "category": "read",
        "status": status,
        "instance": "test",
        "client": "unknown",
        "duration_ms": 1,
    }
    base.update(extra)
    return json.dumps(base)


# -- read_audit_tail unit tests ---------------------------------------------


def test_tail_last_n_in_file_order(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = [_entry(**{"params": {"n": i}}) for i in range(1, 21)]
    path.write_text("\n".join(lines) + "\n")
    entries = read_audit_tail(path, 5)
    assert len(entries) == 5
    assert [entry["params"]["n"] for entry in entries] == list(range(16, 21))
    # ts passes through untouched (it is not a secret)
    assert entries[0]["ts"] == "2026-11-08T00:00:00Z"


def test_tail_returns_everything_below_max_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(_entry() for _ in range(600)) + "\n")
    # The 500-entry clamp lives in the tool, not in the primitive.
    assert len(read_audit_tail(path, 5000)) == 600
    assert len(read_audit_tail(path, 600)) == 600
    assert len(read_audit_tail(path, 10)) == 10


def test_tail_reapplies_redaction(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    # A hand-crafted (unredacted) line must come back redacted.
    raw = json.loads(_entry())
    raw["params"] = {"password": "hunter2", "command": "export API_TOKEN=supersecret; echo ok"}
    path.write_text(json.dumps(raw) + "\n")
    entries = read_audit_tail(path, 10)
    assert len(entries) == 1
    dumped = json.dumps(entries[0])
    assert "hunter2" not in dumped
    assert "supersecret" not in dumped


def test_tail_ignores_corrupt_and_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    good = _entry()
    path.write_text("\n".join(["", good, "{not json", "[1, 2]", good]) + "\n")
    entries = read_audit_tail(path, 50)
    assert len(entries) == 2
    assert all(entry["ts"] == "2026-11-08T00:00:00Z" for entry in entries)


def test_tail_missing_file_returns_empty(tmp_path: Path) -> None:
    # The primitive is a pure reader; the missing-file error is raised by the
    # tool (NotFound), which is covered end-to-end.
    assert read_audit_tail(tmp_path / "missing.jsonl", 10) == []


def test_missing_ts_passes_through_without_ts(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    parsed = json.loads(_entry())
    del parsed["ts"]
    path.write_text(json.dumps(parsed) + "\n")
    entries = read_audit_tail(path, 10)
    assert len(entries) == 1
    assert "ts" not in entries[0]


def test_scan_window_is_bounded(tmp_path: Path) -> None:
    """The backward scan must not read the whole file: with the default
    8 MiB window and ~1 KiB lines a 100 KiB file is scanned only partially."""
    path = tmp_path / "audit.jsonl"
    lines = [_entry(**{"params": {"pad": "x" * 1024, "n": i}}) for i in range(100)]
    path.write_text("\n".join(lines) + "\n")
    entries = read_audit_tail(path, 5000, window_bytes=64 * 1024)
    # 100 lines x ~1 KiB = ~100 KiB > 64 KiB window -> the oldest entries
    # are outside the window, but the recent ones are fully returned.
    assert 0 < len(entries) < 100
    assert entries[-1]["params"]["n"] == 99  # newest line is always intact


# -- pvehub_audit_tail tool: end-to-end --------------------------------------


@respx.mock
async def test_audit_tail_tool_end_to_end(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    from pvehub_mcp.config import Settings
    from pvehub_mcp.server import PVEHub

    settings = {
        "transport": "stdio",
        "pve": [
            PVEInstance(
                name="test",
                url=BASE,
                token_id="pvehub@pve!mcp",
                token_secret="secret",
                verify=False,
                max_retries=0,
            )
        ],
        "audit_log": str(tmp_path / "audit.jsonl"),
        "state_dir": str(tmp_path),
        "capabilities_fail_open": True,
        "capabilities_refresh_seconds": 0,
    }
    hub = PVEHub(Settings.model_validate(settings), Policy(file=PolicyFile()))
    hub.build()
    try:
        async with Client(hub.mcp) as client:
            # 1. Two real entries: one ok call, one policy-denied write whose
            #    params carry a secret that must never leak.  The generic API
            #    refuses password/secret/token params (policy layer), which is
            #    exactly the denial we audit here.
            first = await client.call_tool("pvehub_capabilities", {})
            assert not first.is_error
            denied = await client.call_tool(
                "pve_api_call",
                {
                    "method": "POST",
                    "path": "/nodes/pve1/qemu",
                    "params": {"password": "hunter2"},
                },
            )
            assert not denied.is_error

            # 2. Read them back: the tool's own call is logged *after* the
            #    response is built, so exactly the two entries above are
            #    visible.
            tail = await client.call_tool("pvehub_audit_tail", {"limit": 500})
            assert not tail.is_error
            payload = _data(tail)
            assert payload["count"] == len(payload["entries"]) == 2
            assert {entry["tool"] for entry in payload["entries"]} == {
                "pvehub_capabilities",
                "pve_api_call",
            }
            joined = json.dumps(payload)
            assert "hunter2" not in joined  # redacted on write and on read
            denied_entries = [
                entry for entry in payload["entries"] if entry["status"] == "denied"
            ]
            assert len(denied_entries) == 1
            assert denied_entries[0]["tool"] == "pve_api_call"
            assert denied_entries[0]["error"]["code"] == "policy_denied"
            assert "password" in denied_entries[0]["error"]["message"]
            assert all(entry["client"] == "unknown" for entry in payload["entries"])

            # 3. Filters.  (Every pvehub_audit_tail call is itself audited
            #    *after* its response is built, so exact counts are only
            #    deterministic for tool/status-scoped queries; the client
            #    checks use bounds + invariants instead.)
            by_client = await client.call_tool("pvehub_audit_tail", {"client": "unknown"})
            assert not by_client.is_error
            client_payload = _data(by_client)
            assert client_payload["count"] >= 2
            assert all(entry["client"] == "unknown" for entry in client_payload["entries"])
            webui = await client.call_tool("pvehub_audit_tail", {"client": "webui"})
            assert not webui.is_error
            assert _data(webui)["count"] == 0
            by_status = await client.call_tool("pvehub_audit_tail", {"status": "denied"})
            assert not by_status.is_error
            status_payload = _data(by_status)
            assert status_payload["count"] == 1
            assert status_payload["entries"][0]["tool"] == "pve_api_call"
            by_tool = await client.call_tool(
                "pvehub_audit_tail", {"tool": "pvehub_capabilities"}
            )
            assert not by_tool.is_error
            assert _data(by_tool)["count"] == 1
            future = await client.call_tool(
                "pvehub_audit_tail", {"since": "2027-01-01T00:00:00Z"}
            )
            assert not future.is_error
            assert _data(future)["count"] == 0
            # A valid since that excludes nothing: all entries are from 2026.
            recent = await client.call_tool(
                "pvehub_audit_tail", {"since": "2020-01-01T00:00:00Z"}
            )
            assert not recent.is_error
            assert _data(recent)["count"] >= 2

            # 4. Invalid arguments are structured errors, never tracebacks.
            for bad_args in ({"limit": 0}, {"limit": 501}, {"client": "Bad Name"}):
                invalid = await client.call_tool("pvehub_audit_tail", bad_args)
                assert not invalid.is_error
                error = json.loads(invalid.content[0].text)["error"]
                assert error["code"] == "invalid_argument"

            # 5. The capabilities report carries the audit state (rotation
            #    settings + the last write error, D019/D023).
            caps = await client.call_tool("pvehub_capabilities", {})
            assert not caps.is_error
            report = _data(caps)
            audit_block = report["audit"]
            assert audit_block["enabled"] is True
            assert audit_block["path"] == str(tmp_path / "audit.jsonl")
            assert audit_block["keep"] == 5
            assert audit_block["max_bytes"] == 10 * 1024 * 1024
            assert isinstance(audit_block["size_bytes"], int) and audit_block["size_bytes"] > 0
            assert audit_block["error"] is None
    finally:
        await hub.close()


@respx.mock
async def test_ready_exposes_version_and_audit_gate(tmp_path: Path) -> None:
    """/ready (authenticated) reports the version (issue #20) and the bearer
    middleware gates it with a constant-time check."""

    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    from pvehub_mcp.config import Settings
    from pvehub_mcp.server import PVEHub, build_http_app

    settings = {
        "transport": "http",
        "host": "127.0.0.1",
        "pve": [
            PVEInstance(
                name="test",
                url=BASE,
                token_id="pvehub@pve!mcp",
                token_secret="secret",
                verify=False,
                max_retries=0,
            )
        ],
        "mcp_auth_token": "legacy-token-01234567",
        "mcp_auth_tokens": {"webui": "webui-token-01234567"},
        "audit_log": str(tmp_path / "audit.jsonl"),
        "state_dir": str(tmp_path),
        "capabilities_fail_open": True,
        "capabilities_refresh_seconds": 0,
    }
    hub = PVEHub(Settings.model_validate(settings), Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://test") as http,
        ):
            # Liveness endpoint stays unauthenticated and minimal.
            health = await http.get("/health")
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}

            # Readiness requires a valid bearer token (legacy or named).
            for token in ("legacy-token-01234567", "webui-token-01234567"):
                ready = await http.get(
                    "/ready", headers={"Authorization": f"Bearer {token}"}
                )
                assert ready.status_code == 200
                body = ready.json()
                assert body.get("version")
                assert body["status"] in {"ok", "degraded"}

            unauthorized = await http.get("/ready")
            assert unauthorized.status_code == 401
            wrong = await http.get(
                "/ready", headers={"Authorization": "Bearer nope-0123456789"}
            )
            assert wrong.status_code == 401
    finally:
        await hub.close()


@respx.mock
async def test_audit_tail_tool_without_audit_log(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    from pvehub_mcp.config import Settings
    from pvehub_mcp.server import PVEHub

    settings = {
        "transport": "stdio",
        "pve": [
            {
                "name": "test",
                "url": BASE,
                "token_id": "pvehub@pve!mcp",
                "token_secret": "secret",
                "verify": False,
                "max_retries": 0,
            }
        ],
        "audit_log": None,
        "state_dir": str(tmp_path),
        "capabilities_fail_open": True,
        "capabilities_refresh_seconds": 0,
    }
    hub = PVEHub(Settings.model_validate(settings), Policy(file=PolicyFile()))
    hub.build()
    try:
        async with Client(hub.mcp) as client:
            result = await client.call_tool("pvehub_audit_tail", {})
            assert not result.is_error
            error = json.loads(result.content[0].text)["error"]
            assert error["code"] == "audit_disabled"
    finally:
        await hub.close()
