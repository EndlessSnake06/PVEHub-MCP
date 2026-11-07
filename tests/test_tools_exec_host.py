"""Tests for host and PBS shell tools."""

from __future__ import annotations

from typing import Any

import pytest

from pvehub_mcp.clients.ssh import ExecResult


async def test_exec_host_runs_on_node(exec_env: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_on_node(
        node: str, command: str, *, timeout: float = 60.0, max_output_bytes: int = 65536
    ) -> ExecResult:
        captured.update(
            node=node, command=command, timeout=timeout, max_output_bytes=max_output_bytes
        )
        return ExecResult(stdout="pve-manager/8.2\n", stderr="", exit_status=0, duration_ms=3)

    monkeypatch.setattr(exec_env.hub.ssh, "run_on_node", fake_run_on_node)

    result = await exec_env.call("exec_host", node="pve1", command="pveversion", confirm=True)

    assert result["ok"] is True
    assert captured == {
        "node": "pve1",
        "command": "pveversion",
        "timeout": 30.0,
        "max_output_bytes": 65536,
    }
    assert result["data"]["stdout"] == "pve-manager/8.2\n"
    assert result["data"]["node"] == "pve1"


async def test_exec_host_timeout_capped(exec_env: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_on_node(node: str, command: str, **kwargs: Any) -> ExecResult:
        captured.update(kwargs)
        return ExecResult(stdout="", stderr="", exit_status=0)

    monkeypatch.setattr(exec_env.hub.ssh, "run_on_node", fake_run_on_node)

    await exec_env.call("exec_host", node="pve1", command="true", timeout=3600, confirm=True)

    assert captured["timeout"] == 600.0


async def test_exec_host_requires_confirm(exec_env: Any) -> None:
    result = await exec_env.call("exec_host", node="pve1", command="id")

    assert result["ok"] is False
    assert result["error"]["code"] == "confirm_required"


async def test_exec_host_denylist(exec_env: Any) -> None:
    result = await exec_env.call("exec_host", node="pve1", command="shutdown -h now", confirm=True)

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"


async def test_exec_pbs_runs_on_pbs_host(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_on_pbs(
        command: str, *, timeout: float = 60.0, max_output_bytes: int = 65536
    ) -> ExecResult:
        captured.update(command=command, timeout=timeout, max_output_bytes=max_output_bytes)
        return ExecResult(
            stdout="proxmox-backup-server 3.2\n", stderr="", exit_status=0, duration_ms=4
        )

    monkeypatch.setattr(exec_env.hub.ssh, "run_on_pbs", fake_run_on_pbs)

    result = await exec_env.call(
        "exec_pbs", command="proxmox-backup-manager version", confirm=True
    )

    assert result["ok"] is True
    assert captured["command"] == "proxmox-backup-manager version"
    assert captured["timeout"] == 30.0
    assert result["data"]["pbs_host"] == "10.0.0.12"
    assert "proxmox-backup-server" in result["data"]["stdout"]


async def test_exec_pbs_requires_confirm(exec_env: Any) -> None:
    result = await exec_env.call("exec_pbs", command="hostname")

    assert result["ok"] is False
    assert result["error"]["code"] == "confirm_required"
