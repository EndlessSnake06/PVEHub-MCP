"""QEMU guest-agent command execution.

The guest agent is reachable through the PVE REST API only; the VM must run
``qemu-guest-agent`` and the agent channel must be enabled. PVE checks
``VM.Monitor`` on ``/vms/{vmid}`` for ``agent/exec``, ``agent/exec-status``,
``agent/file-read`` and ``agent/file-write`` (verified against the PVE
``Agent.pm`` permission definitions).

This module also hosts the small shared helpers used by :mod:`files` for the
guest-agent file endpoints (guest resolution, timeout/output clamping, agent
error mapping) so that both modules use identical limits.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ..errors import InvalidArgument, PVEHubError, UpstreamError
from .common import ok, parse_bool

#: Hard ceiling for a single exec call, regardless of the requested timeout.
MAX_TIMEOUT_SECONDS = 600

#: Guest-agent poll interval while a command is running.
POLL_INTERVAL_SECONDS = 0.5

#: Both ``agent/file-read`` (``count``) and ``agent/file-write`` are limited to 16 MiB.
MAX_FILE_BYTES = 16 * 1024 * 1024

_AGENT_ERROR_MARKERS = (
    "guest agent",
    "qemu guest agent",
    "agent not running",
    "no qemu guest agent",
    "qmp command",
    "qga",
)


class AgentUnavailable(PVEHubError):
    """The guest agent is not configured or not running inside the VM."""

    code = "agent_unavailable"


def exec_timeout(hub: Any, timeout: int | None) -> float:
    """Return the effective timeout, capped at :data:`MAX_TIMEOUT_SECONDS`."""

    default = float(hub.policy.file.exec.timeout_seconds)
    if timeout is None:
        return default
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise InvalidArgument("timeout must be an integer number of seconds")
    if timeout <= 0:
        raise InvalidArgument("timeout must be a positive number of seconds")
    return float(min(timeout, MAX_TIMEOUT_SECONDS))


def output_limit(hub: Any) -> int:
    """Per-stream output cap from policy (``exec.max_output_bytes``)."""

    return int(hub.policy.file.exec.max_output_bytes)


async def resolve_guest(
    hub: Any, vmid: int, instance: str | None, *, kind: str
) -> tuple[dict[str, Any], str]:
    """Resolve a guest through ``/cluster/resources`` and validate its type.

    Returns ``(resource, node)``. Raises :class:`InvalidArgument` when the guest
    exists but is not of the requested type (qemu vs. lxc).
    """

    resource = await hub.resolve_guest(vmid, instance=instance)
    guest_type = resource.get("type")
    if guest_type != kind:
        raise InvalidArgument(
            f"guest {vmid} is of type {guest_type or 'unknown'!r}, expected {kind!r}; "
            f"use the matching tool (exec_vm for QEMU, exec_lxc for LXC)",
            details={"vmid": vmid, "type": guest_type, "expected": kind},
        )
    node = resource.get("node")
    if not isinstance(node, str) or not node:
        raise PVEHubError(
            f"guest {vmid} has no node in /cluster/resources; cannot target it",
            details={"vmid": vmid},
        )
    return resource, node


def _map_agent_error(exc: UpstreamError, vmid: int) -> PVEHubError:
    message = str(exc)
    lowered = message.lower()
    status = exc.details.get("status")
    # PVE reports a missing/stopped agent as HTTP 500 with a short or empty body,
    # so treat any 500 from an agent endpoint as an agent availability problem.
    if any(marker in lowered for marker in _AGENT_ERROR_MARKERS) or status == 500:
        return AgentUnavailable(
            f"guest agent in VM {vmid} is not available: {exc.message}",
            details={
                "vmid": vmid,
                "hint": (
                    "install and start qemu-guest-agent inside the VM and enable the "
                    "agent channel (qm set <vmid> --agent enabled=1)"
                ),
            },
        )
    return exc


async def agent_post(
    hub: Any,
    *,
    vmid: int,
    node: str,
    method: str,
    params: dict[str, Any],
    instance: str | None = None,
) -> Any:
    """POST to a guest-agent endpoint with agent error mapping."""

    client = hub.pve(instance)
    path = f"/nodes/{node}/qemu/{vmid}/agent/{method}"
    try:
        return await client.post(path, params)
    except UpstreamError as exc:
        raise _map_agent_error(exc, vmid) from exc


async def agent_get(
    hub: Any,
    *,
    vmid: int,
    node: str,
    method: str,
    params: dict[str, Any] | None = None,
    instance: str | None = None,
) -> Any:
    """GET a guest-agent endpoint with agent error mapping."""

    client = hub.pve(instance)
    path = f"/nodes/{node}/qemu/{vmid}/agent/{method}"
    try:
        return await client.get(path, params=params)
    except UpstreamError as exc:
        raise _map_agent_error(exc, vmid) from exc


async def agent_exec(
    hub: Any,
    *,
    vmid: int,
    node: str,
    command: str,
    timeout: float,
    instance: str | None = None,
) -> dict[str, Any]:
    """Execute ``command`` via ``/bin/sh -c`` in the guest and poll until exit.

    A timeout does not raise: the result carries ``timed_out: true`` plus the
    output collected up to that point. The guest agent offers no API to kill a
    running pid, so the process keeps running inside the guest.
    """

    limit = output_limit(hub)
    started = await agent_post(
        hub,
        vmid=vmid,
        node=node,
        method="exec",
        params={"command": ["/bin/sh", "-c", command]},
        instance=instance,
    )
    pid = started.get("pid") if isinstance(started, dict) else None
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise PVEHubError(
            f"guest agent exec in VM {vmid} returned no pid",
            details={"vmid": vmid, "response": started},
        )

    deadline = time.monotonic() + timeout
    status: dict[str, Any] = {}
    timed_out = False
    while True:
        raw = await agent_get(
            hub,
            vmid=vmid,
            node=node,
            method="exec-status",
            params={"pid": pid},
            instance=instance,
        )
        status = raw if isinstance(raw, dict) else {}
        if parse_bool(status.get("exited")):
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        await asyncio.sleep(min(POLL_INTERVAL_SECONDS, remaining))

    stdout, stdout_clipped = _clip(status.get("out-data"), limit)
    stderr, stderr_clipped = _clip(status.get("err-data"), limit)
    exitcode = status.get("exitcode")
    if isinstance(exitcode, bool) or not isinstance(exitcode, int):
        exitcode_value: int | None = None
    else:
        exitcode_value = exitcode
    truncated = (
        stdout_clipped
        or stderr_clipped
        or parse_bool(status.get("out-truncated"))
        or parse_bool(status.get("err-truncated"))
    )
    return {
        "vmid": vmid,
        "node": node,
        "pid": pid,
        "exitcode": exitcode_value,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": truncated,
        "timed_out": timed_out,
    }


def _clip(value: Any, limit: int) -> tuple[str, bool]:
    """Bound a text stream to ``limit`` UTF-8 bytes."""

    if value is None:
        return "", False
    text = value if isinstance(value, str) else str(value)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="replace"), True


def register(hub: Any) -> None:
    @hub.tool(  # noqa: S604 - 'shell' is the SSH transport gate, not subprocess
        name="exec_vm",
        category="exec",
        pve=[("VM.Monitor", "/vms/{vmid}")],
        shell="vm",
    )
    async def exec_vm(
        vmid: int,
        command: str,
        node: str | None = None,
        timeout: int | None = None,
        instance: str | None = None,
        confirm: bool = False,
    ) -> str:
        """Run a shell command inside a QEMU VM through the guest agent (requires confirm).

        The command is executed as ``/bin/sh -c <command>``. Output is capped by
        exec.max_output_bytes, the call by exec.timeout_seconds (request max 600 s).
        A timeout returns timed_out=true instead of raising. Requires a running
        qemu-guest-agent and VM.Monitor on /vms/{vmid}.
        """
        hub.policy.check_command(command)
        _resource, guest_node = await resolve_guest(hub, vmid, instance, kind="qemu")
        if node is not None and node != guest_node:
            raise InvalidArgument(
                f"guest {vmid} runs on node {guest_node!r}, not {node!r}",
                details={"vmid": vmid, "node": node, "actual_node": guest_node},
            )
        result = await agent_exec(
            hub,
            vmid=vmid,
            node=guest_node,
            command=command,
            timeout=exec_timeout(hub, timeout),
            instance=instance,
        )
        return ok(result, max_bytes=hub.settings.max_output_bytes)
