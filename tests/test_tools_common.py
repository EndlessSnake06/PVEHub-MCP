"""Tool helper tests."""

from __future__ import annotations

import json

from pvehub_mcp.tools.common import (
    fail,
    guest_summary,
    ok,
    parse_upid_node,
    pick,
)


def test_ok_envelope_and_truncation() -> None:
    payload = json.loads(ok({"value": "x" * 5000}, max_bytes=1024))
    assert payload["ok"] is True
    assert payload["truncated"] is True
    assert len(payload["data_preview"]) < 2000


def test_fail_envelope() -> None:
    payload = json.loads(fail("policy_denied", "blocked", reason="test"))
    assert payload["ok"] is False
    assert payload["error"]["code"] == "policy_denied"
    assert payload["error"]["details"]["reason"] == "test"


def test_summaries() -> None:
    guest = {
        "vmid": 100,
        "name": "web",
        "node": "pve1",
        "type": "qemu",
        "status": "running",
        "cpu": 0.1,
        "unknown": "drop",
    }
    summary = guest_summary(guest)
    assert summary["vmid"] == 100
    assert "unknown" not in summary
    assert pick(guest, ["vmid", "missing"]) == {"vmid": 100}


def test_parse_upid_node() -> None:
    assert parse_upid_node("UPID:pve1:0001:0002:0003:qmstart:100:root@pam:") == "pve1"
    assert parse_upid_node("not-a-upid") is None
