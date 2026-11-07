"""SSH pool: host commands, ``pct exec`` for LXC, SFTP file transfer.

Security properties:

- dedicated key, ``known_hosts`` verification (enabled unless explicitly disabled)
- connection, command and output limits
- LXC commands are wrapped as ``pct exec <vmid> -- sh -c <shlex.quote(command)>``
- no command string is built by concatenating unquoted user input
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import asyncssh

from ..config import SSHSettings, SSHTarget
from ..errors import InvalidArgument, PolicyError, SSHUnavailable

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_status: int | None
    truncated: bool = False
    timed_out: bool = False
    duration_ms: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_status": self.exit_status,
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
        }


class SSHClientPool:
    def __init__(self, settings: SSHSettings) -> None:
        self.settings = settings
        self._connections: dict[tuple[str, int, str], asyncssh.SSHClientConnection] = {}
        self._locks: dict[tuple[str, int, str], asyncio.Lock] = {}

    # -- target resolution -------------------------------------------------
    def node_target(self, node: str) -> SSHTarget:
        target = self.settings.node(node)
        if target is None:
            raise SSHUnavailable(
                f"no SSH target configured for PVE node {node!r}; add it under ssh.nodes"
            )
        return target

    def pbs_target(self) -> SSHTarget:
        if self.settings.pbs is None:
            raise SSHUnavailable("no SSH target configured for the PBS host (ssh.pbs)")
        return self.settings.pbs

    # -- connection --------------------------------------------------------
    async def _connect(self, target: SSHTarget) -> asyncssh.SSHClientConnection:
        key = (target.host, target.port, target.user)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            existing = self._connections.get(key)
            if existing is not None and not existing.is_closed():
                return existing
            key_path = Path(target.key_path)
            if not key_path.exists():
                raise SSHUnavailable(f"SSH key not found: {target.key_path}")
            known_hosts: str | None
            if target.strict_host_key:
                if not Path(target.known_hosts).exists():
                    raise SSHUnavailable(
                        f"known_hosts file not found: {target.known_hosts} "
                        "(set strict_host_key: false only for isolated test environments)"
                    )
                known_hosts = target.known_hosts
            else:
                known_hosts = None
                logger.warning("SSH host key verification disabled for %s", target.host)
            try:
                conn = await asyncssh.connect(
                    target.host,
                    port=target.port,
                    username=target.user,
                    client_keys=[target.key_path],
                    known_hosts=known_hosts,
                    connect_timeout=target.connect_timeout,
                    login_timeout=target.connect_timeout,
                    keepalive_interval=30,
                    encoding=None,
                )
            except (asyncssh.Error, OSError) as exc:
                raise SSHUnavailable(
                    f"SSH connection to {target.user}@{target.host}:{target.port} failed: {exc}"
                ) from exc
            self._connections[key] = conn
            return conn

    async def close(self) -> None:
        for conn in list(self._connections.values()):
            conn.close()
        self._connections.clear()

    # -- command execution -------------------------------------------------
    async def run(
        self,
        target: SSHTarget,
        command: str,
        *,
        timeout: float = 60.0,
        max_output_bytes: int = 65536,
    ) -> ExecResult:
        if not command.strip():
            raise InvalidArgument("command must not be empty")
        conn = await self._connect(target)
        started = time.monotonic()
        process = await conn.create_process(command, encoding=None)
        stdout = bytearray()
        stderr = bytearray()
        truncated = False

        async def drain(reader: Any, buffer: bytearray) -> None:
            nonlocal truncated
            while True:
                chunk = await reader.read(8192)
                if not chunk:
                    break
                if len(buffer) < max_output_bytes:
                    buffer.extend(chunk[: max_output_bytes - len(buffer)])
                if len(buffer) >= max_output_bytes:
                    truncated = True

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    drain(process.stdout, stdout),
                    drain(process.stderr, stderr),
                    process.wait(),
                ),
                timeout=timeout,
            )
            exit_status = process.exit_status
            timed_out = False
        except TimeoutError:
            process.kill()
            with contextlib.suppress(TimeoutError, asyncssh.Error):
                await asyncio.wait_for(process.wait(), timeout=2)
            exit_status = None
            timed_out = True
        duration = int((time.monotonic() - started) * 1000)
        return ExecResult(
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            exit_status=exit_status,
            truncated=truncated,
            timed_out=timed_out,
            duration_ms=duration,
        )

    async def exec_lxc(
        self,
        node: str,
        vmid: int,
        command: str,
        *,
        timeout: float = 60.0,
        max_output_bytes: int = 65536,
        sudo: bool = False,
    ) -> ExecResult:
        target = self.node_target(node)
        prefix = "sudo -n " if sudo else ""
        wrapped = f"{prefix}pct exec {int(vmid)} -- sh -c {shlex.quote(command)}"
        return await self.run(
            target, wrapped, timeout=timeout, max_output_bytes=max_output_bytes
        )

    async def run_on_node(
        self,
        node: str,
        command: str,
        *,
        timeout: float = 60.0,
        max_output_bytes: int = 65536,
    ) -> ExecResult:
        return await self.run(
            self.node_target(node),
            command,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
        )

    async def run_on_pbs(
        self,
        command: str,
        *,
        timeout: float = 60.0,
        max_output_bytes: int = 65536,
    ) -> ExecResult:
        return await self.run(
            self.pbs_target(), command, timeout=timeout, max_output_bytes=max_output_bytes
        )

    # -- SFTP --------------------------------------------------------------
    async def read_file(
        self,
        target: SSHTarget,
        remote_path: str,
        *,
        max_bytes: int = 1048576,
    ) -> bytes:
        conn = await self._connect(target)
        try:
            async with conn.start_sftp_client() as sftp, sftp.open(remote_path, "rb") as handle:
                data: Any = await handle.read(max_bytes + 1)
        except (asyncssh.Error, OSError) as exc:
            raise SSHUnavailable(f"SFTP read failed for {remote_path}: {exc}") from exc
        if len(data) > max_bytes:
            raise PolicyError(f"file exceeds max_bytes ({max_bytes})")
        if isinstance(data, str):
            return data.encode("utf-8")
        return cast(bytes, data)

    async def write_file(
        self,
        target: SSHTarget,
        remote_path: str,
        data: bytes,
        *,
        max_bytes: int = 1048576,
    ) -> None:
        if len(data) > max_bytes:
            raise PolicyError(f"file exceeds max_bytes ({max_bytes})")
        conn = await self._connect(target)
        try:
            async with conn.start_sftp_client() as sftp, sftp.open(remote_path, "wb") as handle:
                await handle.write(data)
        except (asyncssh.Error, OSError) as exc:
            raise SSHUnavailable(f"SFTP write failed for {remote_path}: {exc}") from exc
