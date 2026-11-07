"""PBS host command execution over SSH (opt-in via ``exec.pbs_host``)."""

from __future__ import annotations

from typing import Any

from .common import ok
from .exec_vm import exec_timeout, output_limit


def register(hub: Any) -> None:
    @hub.tool(  # noqa: S604 - 'shell' is the SSH transport gate, not subprocess
        name="exec_pbs",
        category="exec",
        shell="pbs",
        service="pbs",
    )
    async def exec_pbs(
        command: str,
        timeout: int | None = None,
        confirm: bool = False,
    ) -> str:
        """Run a shell command on the PBS host over SSH (requires confirm).

        Disabled unless exec.pbs_host is enabled in policy and ssh.pbs is
        configured. Intended for read-only diagnostics such as proxmox-backup-manager
        and systemctl status; output is capped by exec.max_output_bytes.
        """
        hub.policy.check_command(command)
        result = await hub.ssh.run_on_pbs(
            command,
            timeout=exec_timeout(hub, timeout),
            max_output_bytes=output_limit(hub),
        )
        pbs_host = hub.settings.ssh.pbs.host if hub.settings.ssh.pbs else None
        payload = {"pbs_host": pbs_host, **result.as_dict()}
        return ok(payload, max_bytes=hub.settings.max_output_bytes)
