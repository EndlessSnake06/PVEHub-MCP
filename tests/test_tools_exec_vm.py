"""Tests for the QEMU guest-agent exec tool (respx-mocked PVE API)."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from pvehub_mcp.errors import InvalidArgument
from pvehub_mcp.tools.exec_vm import exec_timeout

API = "/api2/json"


def form(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode("utf-8"))


async def test_exec_vm_polls_until_exit(exec_env: Any) -> None:
    exec_route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 4242}})
    )
    status_route = exec_env.mock.get(
        f"{API}/nodes/pve1/qemu/100/agent/exec-status"
    ).mock(
        side_effect=[
            httpx.Response(200, json={"data": {"exited": 0}}),
            httpx.Response(
                200,
                json={
                    "data": {
                        "exited": 1,
                        "exitcode": 0,
                        "out-data": "uid=0(root)\n",
                        "err-data": "",
                    }
                },
            ),
        ]
    )

    result = await exec_env.call("exec_vm", vmid=100, command="id", confirm=True)

    assert result["ok"] is True
    data = result["data"]
    assert data["exitcode"] == 0
    assert data["stdout"] == "uid=0(root)\n"
    assert data["stderr"] == ""
    assert data["pid"] == 4242
    assert data["timed_out"] is False
    assert data["node"] == "pve1"
    assert exec_route.call_count == 1
    assert status_route.call_count == 2

    sent = form(exec_route.calls[0].request)
    assert sent["command"] == ["/bin/sh", "-c", "id"]
    assert exec_route.calls[0].request.headers["content-type"].startswith(
        "application/x-www-form-urlencoded"
    )
    assert status_route.calls[0].request.url.params["pid"] == "4242"


async def test_exec_vm_timeout_returns_timed_out(exec_env: Any) -> None:
    exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 7}})
    )
    status_route = exec_env.mock.get(
        f"{API}/nodes/pve1/qemu/100/agent/exec-status"
    ).mock(
        return_value=httpx.Response(
            200, json={"data": {"exited": 0, "out-data": "partial"}}
        )
    )

    result = await exec_env.call(
        "exec_vm", vmid=100, command="sleep 300", timeout=1, confirm=True
    )

    assert result["ok"] is True
    assert result["data"]["timed_out"] is True
    assert result["data"]["exitcode"] is None
    assert result["data"]["stdout"] == "partial"
    assert status_route.call_count >= 2


async def test_exec_vm_nonzero_exit_is_not_an_error(exec_env: Any) -> None:
    exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 9}})
    )
    exec_env.mock.get(f"{API}/nodes/pve1/qemu/100/agent/exec-status").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "exited": 1,
                    "exitcode": 2,
                    "out-data": "",
                    "err-data": "boom\n",
                }
            },
        )
    )

    result = await exec_env.call("exec_vm", vmid=100, command="false", confirm=True)

    assert result["ok"] is True
    assert result["data"]["exitcode"] == 2
    assert result["data"]["stderr"] == "boom\n"
    assert result["data"]["timed_out"] is False


async def test_exec_vm_agent_unavailable_maps_to_clear_error(exec_env: Any) -> None:
    exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(500, json={"data": None})
    )

    result = await exec_env.call("exec_vm", vmid=100, command="id", confirm=True)

    assert result["ok"] is False
    assert result["error"]["code"] == "agent_unavailable"
    assert "guest agent" in result["error"]["message"]
    assert "qemu-guest-agent" in result["error"]["details"]["hint"]


async def test_exec_vm_rejects_lxc_guest(exec_env: Any) -> None:
    result = await exec_env.call("exec_vm", vmid=101, command="id", confirm=True)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"
    assert "expected 'qemu'" in result["error"]["message"]


async def test_exec_vm_requires_confirm_before_any_http(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 1}})
    )

    result = await exec_env.call("exec_vm", vmid=100, command="id")

    assert result["ok"] is False
    assert result["error"]["code"] == "confirm_required"
    assert route.called is False


async def test_exec_vm_allowed_vmids_blocks_out_of_range(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/250/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 1}})
    )

    result = await exec_env.call("exec_vm", vmid=250, command="id", confirm=True)

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"
    assert "allowed_vmids" in result["error"]["message"]
    assert route.called is False


async def test_exec_vm_denylist_blocks_command(exec_env: Any) -> None:
    route = exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 1}})
    )

    result = await exec_env.call("exec_vm", vmid=100, command="rm -rf /", confirm=True)

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"
    assert "denylist" in result["error"]["message"]
    assert route.called is False


async def test_exec_vm_output_is_truncated_to_policy_limit(
    exec_env_small_output: Any,
) -> None:
    exec_env = exec_env_small_output
    exec_env.mock.post(f"{API}/nodes/pve1/qemu/100/agent/exec").mock(
        return_value=httpx.Response(200, json={"data": {"pid": 11}})
    )
    exec_env.mock.get(f"{API}/nodes/pve1/qemu/100/agent/exec-status").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "exited": 1,
                    "exitcode": 0,
                    "out-data": "x" * 5000,
                    "err-data": "",
                }
            },
        )
    )

    result = await exec_env.call("exec_vm", vmid=100, command="yes", confirm=True)

    assert result["ok"] is True
    assert result["data"]["truncated"] is True
    stdout = result["data"]["stdout"]
    assert len(stdout.encode("utf-8")) == 1024


async def test_exec_vm_rejects_node_mismatch(exec_env: Any) -> None:
    result = await exec_env.call(
        "exec_vm", vmid=100, command="id", node="pve9", confirm=True
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_argument"
    assert "pve1" in result["error"]["message"]


async def test_exec_timeout_defaults_and_caps(exec_env: Any) -> None:
    assert exec_timeout(exec_env.hub, None) == 30
    assert exec_timeout(exec_env.hub, 120) == 120
    assert exec_timeout(exec_env.hub, 99999) == 600
    for bad in (0, -1):
        with pytest.raises(InvalidArgument, match="positive"):
            exec_timeout(exec_env.hub, bad)
