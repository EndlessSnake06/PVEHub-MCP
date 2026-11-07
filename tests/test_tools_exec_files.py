"""Tests for file transfer tools: guest agent base64 limits and SFTP gating."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from pvehub_mcp.errors import PolicyError
from pvehub_mcp.tools import files as files_tool

API = "/api2/json"


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def form(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode("utf-8"))


# -- guest agent file read ---------------------------------------------------


async def test_file_read_guest_is_binary_safe(exec_env: Any) -> None:
    payload = b"\x00\xffbinary\x01"
    route = exec_env.mock.get(f"{API}/nodes/pve1/qemu/100/agent/file-read").mock(
        return_value=httpx.Response(200, json={"data": {"content": encode(payload)}})
    )

    result = await exec_env.call("file_read_guest", vmid=100, path="/etc/motd")

    assert result["ok"] is True
    data = result["data"]
    assert data["encoding"] == "base64"
    assert base64.b64decode(data["content"]) == payload
    assert data["bytes"] == len(payload)
    assert data["truncated"] is False
    params = route.calls[0].request.url.params
    assert params["file"] == "/etc/motd"
    assert params["decode"] == "0"
    assert params["count"] == str(1048576 + 1)


async def test_file_read_guest_truncates_to_requested_bytes(exec_env: Any) -> None:
    payload = b"0123456789"
    route = exec_env.mock.get(f"{API}/nodes/pve1/qemu/100/agent/file-read").mock(
        return_value=httpx.Response(200, json={"data": {"content": encode(payload)}})
    )

    result = await exec_env.call(
        "file_read_guest", vmid=100, path="/var/log/syslog", max_bytes=4
    )

    assert base64.b64decode(result["data"]["content"]) == b"0123"
    assert result["data"]["truncated"] is True
    assert result["data"]["max_bytes"] == 4
    assert route.calls[0].request.url.params["count"] == "5"


async def test_file_read_guest_caps_max_bytes_at_16mib(exec_env: Any) -> None:
    route = exec_env.mock.get(f"{API}/nodes/pve1/qemu/100/agent/file-read").mock(
        return_value=httpx.Response(200, json={"data": {"content": encode(b"x")}})
    )

    result = await exec_env.call(
        "file_read_guest", vmid=100, path="/big", max_bytes=32 * 1024 * 1024
    )

    assert result["data"]["max_bytes"] == 16 * 1024 * 1024
    assert route.calls[0].request.url.params["count"] == str(16 * 1024 * 1024)


async def test_file_read_guest_rejects_non_qemu(exec_env: Any) -> None:
    result = await exec_env.call("file_read_guest", vmid=101, path="/etc/motd")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"


async def test_file_read_guest_path_validation(exec_env: Any) -> None:
    result = await exec_env.call("file_read_guest", vmid=100, path="")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"


# -- guest agent file write --------------------------------------------------


async def test_file_write_guest_requires_confirm_before_http(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/file-write").mock(
        return_value=httpx.Response(200, json={"data": None})
    )

    result = await exec_env.call(
        "file_write_guest", vmid=100, path="/tmp/x", content_base64=encode(b"hi")
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "confirm_required"
    assert route.called is False


async def test_file_write_guest_posts_base64(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/file-write").mock(
        return_value=httpx.Response(200, json={"data": None})
    )

    result = await exec_env.call(
        "file_write_guest",
        vmid=100,
        path="/tmp/hello.txt",
        content_base64=encode(b"hello"),
        confirm=True,
    )

    assert result["ok"] is True
    assert result["data"]["written"] is True
    assert result["data"]["bytes"] == 5
    sent = form(route.calls[0].request)
    assert sent["file"] == ["/tmp/hello.txt"]
    assert sent["content"] == [encode(b"hello")]
    assert sent["encode"] == ["1"]


async def test_file_write_guest_rejects_invalid_base64(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/file-write").mock(
        return_value=httpx.Response(200, json={"data": None})
    )

    result = await exec_env.call(
        "file_write_guest",
        vmid=100,
        path="/tmp/x",
        content_base64="not base64!!",
        confirm=True,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"
    assert route.called is False


async def test_file_write_guest_size_cap(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(files_tool, "MAX_FILE_BYTES", 4)
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/file-write").mock(
        return_value=httpx.Response(200, json={"data": None})
    )

    result = await exec_env.call(
        "file_write_guest",
        vmid=100,
        path="/tmp/x",
        content_base64=encode(b"12345"),
        confirm=True,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"
    assert "limit" in result["error"]["message"]
    assert route.called is False


# -- SFTP pull/push ----------------------------------------------------------


async def test_file_pull_host_returns_base64(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    async def fake_read(target: Any, remote_path: str, *, max_bytes: int) -> bytes:
        captured.update(target=target, path=remote_path, max_bytes=max_bytes)
        return b"hello\n"

    monkeypatch.setattr(exec_env.hub.ssh, "read_file", fake_read)

    result = await exec_env.call(
        "file_pull_host", node="pve1", remote_path="/etc/pve/nodes/pve1/config"
    )

    assert result["ok"] is True
    assert captured["target"].host == "10.0.0.11"
    assert captured["path"] == "/etc/pve/nodes/pve1/config"
    assert captured["max_bytes"] == 1048576
    assert base64.b64decode(result["data"]["content"]) == b"hello\n"


async def test_file_pull_host_caps_max_bytes(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    async def fake_read(target: Any, remote_path: str, *, max_bytes: int) -> bytes:
        captured["max_bytes"] = max_bytes
        return b""

    monkeypatch.setattr(exec_env.hub.ssh, "read_file", fake_read)

    await exec_env.call(
        "file_pull_host", node="pve1", remote_path="/etc/pve/x", max_bytes=99 * 1024 * 1024
    )

    assert captured["max_bytes"] == 16 * 1024 * 1024


async def test_file_pull_host_enforces_allowed_roots(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    async def fake_read(*args: Any, **kwargs: Any) -> bytes:
        nonlocal called
        called = True
        return b"secret"

    monkeypatch.setattr(exec_env.hub.ssh, "read_file", fake_read)

    result = await exec_env.call(
        "file_pull_host", node="pve1", remote_path="/root/.ssh/id_ed25519"
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"
    assert called is False


async def test_file_pull_host_rejects_oversized_file(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_read(target: Any, remote_path: str, *, max_bytes: int) -> bytes:
        raise PolicyError(f"file exceeds max_bytes ({max_bytes})")

    monkeypatch.setattr(exec_env.hub.ssh, "read_file", fake_read)

    result = await exec_env.call("file_pull_host", node="pve1", remote_path="/etc/pve/x")

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"


async def test_file_push_host_writes_decoded_bytes(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    async def fake_write(target: Any, remote_path: str, data: bytes, *, max_bytes: int) -> None:
        captured.update(target=target, path=remote_path, data=data, max_bytes=max_bytes)

    monkeypatch.setattr(exec_env.hub.ssh, "write_file", fake_write)

    result = await exec_env.call(
        "file_push_host",
        node="pve1",
        remote_path="/var/tmp/pvehub/backup.txt",
        content_base64=encode(b"hello"),
        confirm=True,
    )

    assert result["ok"] is True
    assert result["data"]["written"] is True
    assert captured["data"] == b"hello"
    assert captured["target"].host == "10.0.0.11"


async def test_file_push_host_requires_confirm(exec_env: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def fake_write(*args: Any, **kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(exec_env.hub.ssh, "write_file", fake_write)

    result = await exec_env.call(
        "file_push_host",
        node="pve1",
        remote_path="/var/tmp/pvehub/x",
        content_base64=encode(b"hello"),
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "confirm_required"
    assert called is False


async def test_file_push_host_enforces_allowed_roots(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = await exec_env.call(
        "file_push_host",
        node="pve1",
        remote_path="/root/authorized_keys",
        content_base64=encode(b"ssh-ed25519 AAAA"),
        confirm=True,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"


async def test_file_push_host_size_cap(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(files_tool, "MAX_FILE_BYTES", 4)

    result = await exec_env.call(
        "file_push_host",
        node="pve1",
        remote_path="/var/tmp/pvehub/x",
        content_base64=encode(b"12345"),
        confirm=True,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"


async def test_file_write_guest_accepts_wrapped_base64(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/file-write").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    wrapped = "aGVs\nbG8=\n"

    result = await exec_env.call(
        "file_write_guest",
        vmid=100,
        path="/tmp/hello.txt",
        content_base64=wrapped,
        confirm=True,
    )

    assert result["ok"] is True
    assert form(route.calls[0].request)["content"] == ["aGVsbG8="]
    assert result["data"]["bytes"] == 5
