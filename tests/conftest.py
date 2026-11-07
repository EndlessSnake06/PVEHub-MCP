"""Shared fixtures for the shell/exec and file-transfer tool tests.

The fixtures build a real :class:`~pvehub_mcp.server.PVEHub` (real policy, real
wrapper, real audit) but capture the registered tool callables instead of
building the MCP transport. PVE/PBS HTTP calls are served by ``respx``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from pvehub_mcp.config import Settings
from pvehub_mcp.server import PVEHub

PVE_URL = "https://pve.test:8006"
PBS_URL = "https://pbs.test:8007"
API = "/api2/json"

POLICY = """\
exec:
  host: true
  lxc: true
  vm: true
  pbs_host: true
  allowed_vmids: ["100-199"]
  timeout_seconds: 30
  max_output_bytes: 65536
  command_denylist: ["rm -rf /", "mkfs*", "dd if=*", ":(){:|:&};:", "shutdown*", "reboot*"]
  files:
    allowed_roots: ["/var/tmp/pvehub", "/etc/pve"]
safety:
  require_confirm_for: ["destructive", "exec", "write"]
"""

GUESTS = [
    {"vmid": 100, "name": "vm100", "node": "pve1", "type": "qemu", "status": "running"},
    {"vmid": 101, "name": "ct101", "node": "pve1", "type": "lxc", "status": "running"},
]


class ToolRecorder:
    """Minimal ``MCPServer`` stand-in that captures wrapped tool functions."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Awaitable[str]]] = {}

    def add_tool(
        self,
        fn: Callable[..., Awaitable[str]],
        *,
        name: str,
        description: str,
        annotations: Any,
        structured_output: bool,
    ) -> None:
        self.tools[name] = fn

    def resource(self, *args: Any, **kwargs: Any) -> Callable[[Any], Any]:
        """Accept resource registrations from ``resources.register`` (unused here)."""

        def decorator(fn: Any) -> Any:
            return fn

        return decorator

    def prompt(self, *args: Any, **kwargs: Any) -> Callable[[Any], Any]:
        """Accept prompt registrations from ``prompts.register`` (unused here)."""

        def decorator(fn: Any) -> Any:
            return fn

        return decorator


@dataclass
class ExecEnv:
    hub: PVEHub
    tools: dict[str, Callable[..., Awaitable[str]]]
    mock: respx.MockRouter

    async def call(self, name: str, **kwargs: Any) -> dict[str, Any]:
        raw = await self.tools[name](**kwargs)
        return json.loads(raw)


def build_settings(tmp_path: Path, policy_text: str = POLICY) -> Settings:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_text, encoding="utf-8")
    return Settings.model_validate(
        {
            "pve": [
                {
                    "name": "test",
                    "url": PVE_URL,
                    "token_id": "root@pam!pvehub",
                    "token_secret": "s3cret",
                }
            ],
            "pbs": [
                {
                    "name": "pbs",
                    "url": PBS_URL,
                    "token_id": "root@pam!pvehub",
                    "token_secret": "s3cret",
                }
            ],
            "ssh": {
                "nodes": {
                    "pve1": {
                        "host": "10.0.0.11",
                        "key_path": "/keys/id_ed25519",
                        "known_hosts": "/keys/known_hosts",
                        "strict_host_key": False,
                    }
                },
                "pbs": {
                    "host": "10.0.0.12",
                    "key_path": "/keys/id_ed25519",
                    "known_hosts": "/keys/known_hosts",
                    "strict_host_key": False,
                },
            },
            "policy_file": str(policy_file),
            "audit_log": str(tmp_path / "audit.jsonl"),
            "state_dir": str(tmp_path / "state"),
        }
    )


@asynccontextmanager
async def environment(settings: Settings) -> AsyncIterator[ExecEnv]:
    hub = PVEHub(settings)
    recorder = ToolRecorder()
    hub._mcp = recorder  # type: ignore[assignment]
    with respx.mock(assert_all_called=False) as mock:
        mock_services(mock)
        await hub.initialize()
        try:
            yield ExecEnv(hub=hub, tools=recorder.tools, mock=mock)
        finally:
            await hub.close()


def mock_services(mock: respx.MockRouter) -> None:
    mock.get(f"{PVE_URL}{API}/access/permissions").mock(
        return_value=httpx.Response(
            200, json={"data": {"/": {"VM.Monitor": 1, "propagate": 1}}}
        )
    )
    mock.get(f"{PVE_URL}{API}/cluster/resources").mock(
        return_value=httpx.Response(200, json={"data": GUESTS})
    )
    mock.get(f"{PBS_URL}/api2/extjs/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {}})
    )


@pytest.fixture
def make_settings(tmp_path: Path) -> Callable[..., Settings]:
    def factory(policy_text: str = POLICY) -> Settings:
        return build_settings(tmp_path, policy_text)

    return factory


@pytest.fixture
async def registered_tools(
    make_settings: Callable[..., Settings],
) -> AsyncIterator[dict[str, Any]]:
    """Real MCPServer registration: maps tool name to the SDK ``Tool`` object."""

    hub = PVEHub(make_settings())
    hub.build()
    with respx.mock(assert_all_called=False) as mock:
        mock_services(mock)
        await hub.initialize()
        try:
            tools = {tool.name: tool for tool in await hub.mcp.list_tools()}
            yield tools
        finally:
            await hub.close()


@pytest.fixture
async def exec_env(make_settings: Callable[..., Settings]) -> AsyncIterator[ExecEnv]:
    async with environment(make_settings()) as env:
        yield env


@pytest.fixture
async def exec_env_small_output(
    make_settings: Callable[..., Settings],
) -> AsyncIterator[ExecEnv]:
    policy = POLICY.replace("  max_output_bytes: 65536", "  max_output_bytes: 1024")
    async with environment(make_settings(policy)) as env:
        yield env
