"""Tests for LXC exec: pct quoting (injection payloads) and tool gating."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from pvehub_mcp.clients.ssh import ExecResult, SSHClientPool
from pvehub_mcp.config import SSHSettings

INJECTION_PAYLOADS = ["'; rm -rf /", "`id`", "$(id)", "line1\nline2"]


def make_pool() -> SSHClientPool:
    return SSHClientPool(
        SSHSettings.model_validate(
            {"nodes": {"pve1": {"host": "10.0.0.11", "strict_host_key": False}}}
        )
    )


async def captured_lxc_command(payload: str, vmid: int = 100) -> str:
    pool = make_pool()
    captured: dict[str, str] = {}

    async def fake_run(
        target: Any,
        command: str,
        *,
        timeout: float = 60.0,
        max_output_bytes: int = 65536,
    ) -> ExecResult:
        captured["command"] = command
        return ExecResult(stdout="", stderr="", exit_status=0)

    pool.run = fake_run  # type: ignore[method-assign]
    await pool.exec_lxc("pve1", vmid, payload)
    return captured["command"]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
async def test_exec_lxc_quotes_payload_as_single_argument(payload: str) -> None:
    command = await captured_lxc_command(payload)

    assert command == f"pct exec 100 -- sh -c {shlex.quote(payload)}"
    # The decisive property: splitting the remote command line yields exactly the
    # payload as the final (single) argument, with no extra commands.
    assert shlex.split(command) == ["pct", "exec", "100", "--", "sh", "-c", payload]


async def test_exec_lxc_injection_payload_cannot_add_arguments() -> None:
    command = await captured_lxc_command("x; touch /tmp/pwned")

    parts = shlex.split(command)
    assert len(parts) == 7
    assert parts[-1] == "x; touch /tmp/pwned"
    assert "touch" not in parts[:-1]


def write_fake_pct(bin_dir: Path, capture: Path) -> None:
    script = bin_dir / "pct"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, subprocess, sys\n"
        'with open(os.environ["PCT_CAPTURE"], "w", encoding="utf-8") as fh:\n'
        "    json.dump(sys.argv[1:], fh)\n"
        'raise SystemExit(subprocess.call(["/bin/sh", "-c", sys.argv[6]]))\n',
        encoding="utf-8",
    )
    script.chmod(0o755)


async def run_with_fake_pct(command: str) -> tuple[int, str, list[str]]:
    # /tmp is often mounted noexec (e.g. in containers), so place the fake
    # executable next to the tests and clean it up afterwards.
    base = Path(tempfile.mkdtemp(prefix=".pct-", dir=Path(__file__).resolve().parent))
    try:
        bin_dir = base / "bin"
        bin_dir.mkdir()
        capture = base / "args.json"
        write_fake_pct(bin_dir, capture)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "PCT_CAPTURE": str(capture),
        }
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode is not None
        args = json.loads(capture.read_text(encoding="utf-8")) if capture.exists() else []
        if process.returncode != 0:
            return process.returncode, stderr.decode(), args
        return process.returncode, stdout.decode(), args
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("echo hello", "hello\n"),
        ("echo \"it's fine\"", "it's fine\n"),
        ("echo $((1+2))", "3\n"),
        ("printf 'line1\\nline2\\n'", "line1\nline2\n"),
    ],
)
async def test_exec_lxc_round_trip_through_fake_pct(
    payload: str, expected: str
) -> None:
    command = await captured_lxc_command(payload)

    returncode, stdout, args = await run_with_fake_pct(command)

    assert returncode == 0
    assert stdout == expected
    assert args == ["exec", "100", "--", "sh", "-c", payload]


async def test_exec_lxc_tool_uses_ssh_pool(exec_env: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_exec_lxc(
        node: str,
        vmid: int,
        command: str,
        *,
        timeout: float = 60.0,
        max_output_bytes: int = 65536,
        sudo: bool = False,
    ) -> ExecResult:
        captured.update(
            node=node,
            vmid=vmid,
            command=command,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
        )
        return ExecResult(stdout="ok\n", stderr="", exit_status=0, duration_ms=12)

    monkeypatch.setattr(exec_env.hub.ssh, "exec_lxc", fake_exec_lxc)

    result = await exec_env.call("exec_lxc", vmid=101, command="hostname", confirm=True)

    assert result["ok"] is True
    assert captured == {
        "node": "pve1",
        "vmid": 101,
        "command": "hostname",
        "timeout": 30.0,
        "max_output_bytes": 65536,
    }
    data = result["data"]
    assert data["stdout"] == "ok\n"
    assert data["exit_status"] == 0
    assert data["timed_out"] is False
    assert data["duration_ms"] == 12


async def test_exec_lxc_timeout_is_capped(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    async def fake_exec_lxc(
        node: str, vmid: int, command: str, *, timeout: float = 60.0, **kwargs: Any
    ) -> ExecResult:
        captured["timeout"] = timeout
        return ExecResult(stdout="", stderr="", exit_status=0)

    monkeypatch.setattr(exec_env.hub.ssh, "exec_lxc", fake_exec_lxc)

    await exec_env.call("exec_lxc", vmid=101, command="sleep 1", timeout=99999, confirm=True)

    assert captured["timeout"] == 600.0


async def test_exec_lxc_rejects_qemu_guest(exec_env: Any) -> None:
    result = await exec_env.call("exec_lxc", vmid=100, command="id", confirm=True)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"
    assert "expected 'lxc'" in result["error"]["message"]


async def test_exec_lxc_explicit_node_skips_resolution(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    async def fake_exec_lxc(
        node: str, vmid: int, command: str, **kwargs: Any
    ) -> ExecResult:
        captured["node"] = node
        return ExecResult(stdout="", stderr="", exit_status=0)

    monkeypatch.setattr(exec_env.hub.ssh, "exec_lxc", fake_exec_lxc)

    result = await exec_env.call(
        "exec_lxc", vmid=101, command="id", node="pve2", confirm=True
    )

    assert result["ok"] is True
    assert captured["node"] == "pve2"


async def test_exec_lxc_confirm_required(exec_env: Any) -> None:
    result = await exec_env.call("exec_lxc", vmid=101, command="id")

    assert result["ok"] is False
    assert result["error"]["code"] == "confirm_required"


async def test_exec_lxc_denylist(exec_env: Any) -> None:
    result = await exec_env.call(
        "exec_lxc", vmid=101, command="mkfs.ext4 /dev/sda1", confirm=True
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"
