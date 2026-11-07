"""File transfer: QEMU guest-agent read/write and SFTP pull/push for hosts.

Guest-agent limits (PVE ``Agent.pm``): ``agent/file-read`` returns base64 when
``decode=0`` and accepts ``count`` up to 16 MiB; ``agent/file-write`` expects a
base64 payload (``encode=1``) and enforces the same 16 MiB cap. Both require
``VM.Monitor`` on ``/vms/{vmid}``.

Host transfers go through SFTP with ``policy.check_file_path`` applied to the
remote path (``exec.files.allowed_roots``).

LXC containers are deliberately not covered here. ``pct exec`` can only return
``pct``'s stdout, which is truncated at ``exec.max_output_bytes``; base64 output
of any real file would therefore be cut silently, and pushing content through
argv is bounded by ``ARG_MAX`` and visible in the process list. A correct
implementation needs ``pct pull``/``pct push`` against files on the node, which
is a two-step operation outside this tool surface: use ``file_pull_host``/
``file_push_host`` for the node path, then ``exec_host`` with ``pct pull`` or
``pct push``.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import PurePosixPath
from typing import Any

from ..errors import InvalidArgument, PolicyError
from .common import ok
from .exec_vm import MAX_FILE_BYTES, agent_get, agent_post, resolve_guest

DEFAULT_FILE_BYTES = 1048576


def _check_path(path: str) -> None:
    if not isinstance(path, str) or not path.strip():
        raise InvalidArgument("path must be a non-empty string")
    if "\x00" in path:
        raise InvalidArgument("path contains a NUL byte")


def _check_sftp_path(path: str) -> None:
    """Reject traversal before ``policy.check_file_path`` prefix matching.

    ``policy.check_file_path`` compares the raw path against allowed roots, so a
    path such as ``/etc/pve/../root/.ssh`` would pass a prefix check. Refuse any
    ``..`` component for SFTP targets.
    """

    _check_path(path)
    if ".." in PurePosixPath(path).parts:
        raise PolicyError(
            f"path {path!r} must not contain '..' segments",
            details={"path": path},
        )


def _check_max_bytes(max_bytes: int) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise InvalidArgument("max_bytes must be an integer")
    if max_bytes <= 0:
        raise InvalidArgument("max_bytes must be positive")
    return min(max_bytes, MAX_FILE_BYTES)


def _decode_base64(
    content_base64: str, *, limit: int, field: str = "content_base64"
) -> bytes:
    if not isinstance(content_base64, str):
        raise InvalidArgument(f"{field} must be a base64 string")
    # Accept line-wrapped base64 (the output of the standard `base64` CLI).
    cleaned = "".join(content_base64.split())
    # Reject oversized payloads before decoding so a huge request cannot exhaust
    # memory: base64 uses 4 characters per 3 bytes (plus padding).
    max_encoded = ((limit + 2) // 3) * 4 + 4
    if len(cleaned) > max_encoded:
        raise InvalidArgument(
            f"content exceeds the limit of {limit} bytes",
            details={"encoded_length": len(cleaned), "max_bytes": limit},
        )
    try:
        data = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidArgument(f"{field} is not valid base64: {exc}") from exc
    if len(data) > limit:
        raise InvalidArgument(
            f"content exceeds the limit of {limit} bytes",
            details={"bytes": len(data), "max_bytes": limit},
        )
    return data


def register(hub: Any) -> None:
    @hub.tool(  # noqa: S604 - 'shell' is the SSH/agent transport gate, not subprocess
        name="file_read_guest",
        category="read",
        pve=[("VM.Monitor", "/vms/{vmid}")],
        shell="vm",
    )
    async def file_read_guest(
        vmid: int,
        path: str,
        node: str | None = None,
        max_bytes: int = DEFAULT_FILE_BYTES,
        instance: str | None = None,
    ) -> str:
        """Read a file from a QEMU VM through the guest agent.

        Returns base64 content (binary-safe). max_bytes is capped at 16 MiB; the
        result reports truncated=true when the file is larger than the effective
        limit. The serialized response is also bounded by PVEHUB_MAX_OUTPUT_BYTES,
        so raise that setting (about 1.4x the file size) for large reads. Requires
        a running qemu-guest-agent and VM.Monitor on /vms/{vmid}.
        """
        _check_path(path)
        limit = _check_max_bytes(max_bytes)
        _resource, guest_node = await resolve_guest(hub, vmid, instance, kind="qemu")
        if node is not None and node != guest_node:
            raise InvalidArgument(
                f"guest {vmid} runs on node {guest_node!r}, not {node!r}",
                details={"vmid": vmid, "node": node, "actual_node": guest_node},
            )
        response = await agent_get(
            hub,
            vmid=vmid,
            node=guest_node,
            method="file-read",
            params={
                "file": path,
                "decode": 0,
                "count": min(limit + 1, MAX_FILE_BYTES),
            },
            instance=instance,
        )
        raw = response.get("content") if isinstance(response, dict) else None
        encoded = raw if isinstance(raw, str) else ""
        try:
            data = base64.b64decode(encoded, validate=False)
        except (binascii.Error, ValueError) as exc:
            raise InvalidArgument(
                f"guest agent returned malformed base64 for {path!r}: {exc}"
            ) from exc
        truncated = len(data) > limit
        if truncated:
            data = data[:limit]
        return ok(
            {
                "vmid": vmid,
                "node": guest_node,
                "path": path,
                "encoding": "base64",
                "content": base64.b64encode(data).decode("ascii"),
                "bytes": len(data),
                "truncated": truncated,
                "max_bytes": limit,
            },
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(  # noqa: S604 - 'shell' is the SSH/agent transport gate, not subprocess
        name="file_write_guest",
        category="write",
        pve=[("VM.Monitor", "/vms/{vmid}")],
        shell="vm",
    )
    async def file_write_guest(
        vmid: int,
        path: str,
        content_base64: str,
        node: str | None = None,
        instance: str | None = None,
        confirm: bool = False,
    ) -> str:
        """Write a file inside a QEMU VM through the guest agent (write category).

        content_base64 must be standard base64; the decoded payload is capped at
        16 MiB (guest-agent limit). The file is created or truncated. Pass
        confirm=true when the policy requires confirmation for writes. Requires a
        running qemu-guest-agent and VM.Monitor on /vms/{vmid}.
        """
        _check_path(path)
        data = _decode_base64(content_base64, limit=MAX_FILE_BYTES)
        _resource, guest_node = await resolve_guest(hub, vmid, instance, kind="qemu")
        if node is not None and node != guest_node:
            raise InvalidArgument(
                f"guest {vmid} runs on node {guest_node!r}, not {node!r}",
                details={"vmid": vmid, "node": node, "actual_node": guest_node},
            )
        await agent_post(
            hub,
            vmid=vmid,
            node=guest_node,
            method="file-write",
            params={
                "file": path,
                "content": base64.b64encode(data).decode("ascii"),
                "encode": 1,
            },
            instance=instance,
        )
        return ok(
            {
                "vmid": vmid,
                "node": guest_node,
                "path": path,
                "bytes": len(data),
                "written": True,
            },
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(  # noqa: S604 - 'shell' is the SSH/agent transport gate, not subprocess
        name="file_pull_host",
        category="read",
        shell="files",
        service="pve",
    )
    async def file_pull_host(
        node: str,
        remote_path: str,
        max_bytes: int = DEFAULT_FILE_BYTES,
    ) -> str:
        """Read a file from a PVE node over SFTP, returned as base64.

        max_bytes defaults to 1 MiB and is capped at 16 MiB; larger files are
        rejected instead of truncated. The serialized response is also bounded by
        PVEHUB_MAX_OUTPUT_BYTES (raise it for large files). The path must be inside
        exec.files.allowed_roots when that list is set.
        """
        _check_sftp_path(remote_path)
        limit = _check_max_bytes(max_bytes)
        hub.policy.check_file_path(remote_path)
        target = hub.ssh.node_target(node)
        data = await hub.ssh.read_file(target, remote_path, max_bytes=limit)
        return ok(
            {
                "node": node,
                "path": remote_path,
                "encoding": "base64",
                "content": base64.b64encode(data).decode("ascii"),
                "bytes": len(data),
            },
            max_bytes=hub.settings.max_output_bytes,
        )

    @hub.tool(  # noqa: S604 - 'shell' is the SSH/agent transport gate, not subprocess
        name="file_push_host",
        category="write",
        shell="files",
        service="pve",
    )
    async def file_push_host(
        node: str,
        remote_path: str,
        content_base64: str,
        confirm: bool = False,
    ) -> str:
        """Write a base64 payload to a file on a PVE node over SFTP (write category).

        The decoded payload is capped at 16 MiB. The target file is created or
        overwritten. Pass confirm=true when the policy requires confirmation for
        writes; the path must be inside exec.files.allowed_roots when that list
        is set.
        """
        _check_sftp_path(remote_path)
        data = _decode_base64(content_base64, limit=MAX_FILE_BYTES)
        hub.policy.check_file_path(remote_path)
        target = hub.ssh.node_target(node)
        await hub.ssh.write_file(target, remote_path, data, max_bytes=MAX_FILE_BYTES)
        return ok(
            {
                "node": node,
                "path": remote_path,
                "bytes": len(data),
                "written": True,
            },
            max_bytes=hub.settings.max_output_bytes,
        )
