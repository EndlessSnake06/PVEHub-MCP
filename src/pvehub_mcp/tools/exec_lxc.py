"""LXC command execution through ``pct exec`` over SSH.

The PVE API cannot execute commands inside a container; the node shell is used.
:class:`~pvehub_mcp.clients.ssh.SSHClientPool` builds
``pct exec <vmid> -- sh -c <shlex.quote(command)>`` so the user command is always
one argument and never spliced into the remote shell.
"""

from __future__ import annotations

from typing import Any

from ..errors import InvalidArgument
from .common import ok
from .exec_vm import exec_timeout, output_limit, resolve_guest


def register(hub: Any) -> None:
    @hub.tool(  # noqa: S604 - 'shell' is the SSH transport gate, not subprocess
        name="exec_lxc",
        category="exec",
        shell="lxc",
        service="pve",
    )
    async def exec_lxc(
        vmid: int,
        command: str,
        node: str | None = None,
        timeout: int | None = None,
        instance: str | None = None,
        confirm: bool = False,
    ) -> str:
        """Run a shell command inside an LXC container via SSH + pct exec (requires confirm).

        The command runs as ``pct exec <vmid> -- sh -c <quoted command>`` on the
        node, i.e. as root inside the container. When node is omitted the guest is
        resolved through /cluster/resources and must be an LXC container. Output is
        capped by exec.max_output_bytes; the call by exec.timeout_seconds (max 600 s).
        """
        hub.policy.check_command(command)
        target_node = node
        if target_node is None:
            _resource, guest_node = await resolve_guest(hub, vmid, instance, kind="lxc")
            target_node = guest_node
        elif not isinstance(target_node, str) or not target_node.strip():
            raise InvalidArgument("node must be a non-empty node name")
        result = await hub.ssh.exec_lxc(
            target_node,
            vmid,
            command,
            timeout=exec_timeout(hub, timeout),
            max_output_bytes=output_limit(hub),
        )
        payload = {"vmid": vmid, "node": target_node, **result.as_dict()}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
