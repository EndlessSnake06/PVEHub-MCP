"""PVE node host command execution over SSH (opt-in via ``exec.host``)."""

from __future__ import annotations

from typing import Any

from .common import ok
from .exec_vm import exec_timeout, output_limit


def register(hub: Any) -> None:
    @hub.tool(  # noqa: S604 - 'shell' is the SSH transport gate, not subprocess
        name="exec_host",
        category="exec",
        shell="host",
        service="pve",
    )
    async def exec_host(
        node: str,
        command: str,
        timeout: int | None = None,
        confirm: bool = False,
    ) -> str:
        """Run a shell command on a PVE node host over SSH (requires confirm).

        Disabled unless exec.host is enabled in policy; the node must be listed
        under ssh.nodes with a key, known_hosts entry and a user allowed to run
        the command. Output is capped by exec.max_output_bytes.
        """
        hub.policy.check_command(command)
        result = await hub.ssh.run_on_node(
            node,
            command,
            timeout=exec_timeout(hub, timeout),
            max_output_bytes=output_limit(hub),
        )
        payload = {"node": node, **result.as_dict()}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
