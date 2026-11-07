"""Shared fixtures for the curated tool tests.

The PVE fixtures build a real :class:`PVEHub` against a mocked PVE API; the PBS fixtures do
the same for PBS. The exec tests use their own recorder-based environment further below.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from httpx import Response

from pvehub_mcp.config import PBSInstance, Settings
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import PVEHub

# -- PVE -------------------------------------------------------------------
BASE = "https://pve.test:8006"

FULL_PERMISSIONS: dict[str, dict[str, int]] = {
    "/": {
        "Sys.Audit": 1,
        "VM.Audit": 1,
        "VM.PowerMgmt": 1,
        "VM.Snapshot": 1,
        "VM.Snapshot.Rollback": 1,
        "VM.Clone": 1,
        "VM.Allocate": 1,
        "VM.Migrate": 1,
        "VM.Config.Disk": 1,
        "VM.Backup": 1,
        "VM.Monitor": 1,
        "Datastore.Audit": 1,
        "Datastore.AllocateSpace": 1,
        "VM.GuestAgent.Audit": 1,
        "VM.GuestAgent.FileRead": 1,
        "VM.GuestAgent.FileWrite": 1,
        "VM.GuestAgent.Unrestricted": 1,
        "Sys.Modify": 1,
        "Sys.Syslog": 1,
        "propagate": 1,
    }
}

AUDIT_ONLY_PERMISSIONS: dict[str, dict[str, int]] = {
    "/": {"Sys.Audit": 1, "VM.Audit": 1, "propagate": 1}
}


def _pve_settings(tmp_path: Any) -> Settings:
    return Settings.model_validate(
        {
            "transport": "stdio",
            "pve": [
                {
                    "name": "test",
                    "url": BASE,
                    "token_id": "root@pam!pvehub",
                    "token_secret": "test-secret",
                }
            ],
            "policy_file": str(tmp_path / "policy.yaml"),
            "audit_log": None,
            "state_dir": str(tmp_path),
            "capabilities_refresh_seconds": 0,
            "capabilities_fail_open": True,
            "task_timeout_seconds": 5,
        }
    )


async def _build(
    tmp_path: Any,
    router: respx.MockRouter,
    *,
    permissions: dict[str, dict[str, int]] | None = None,
    policy: Policy | None = None,
) -> PVEHub:
    router.get("/api2/json/access/permissions").mock(
        return_value=Response(200, json={"data": permissions or FULL_PERMISSIONS})
    )
    hub = PVEHub(_pve_settings(tmp_path), policy)
    hub.build()
    await hub.initialize()
    return hub


@pytest.fixture
async def pve(tmp_path: Any) -> AsyncIterator[tuple[PVEHub, respx.MockRouter]]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        hub = await _build(tmp_path, router)
        try:
            yield hub, router
        finally:
            await hub.close()


@pytest.fixture
async def pve_read_only(tmp_path: Any) -> AsyncIterator[tuple[PVEHub, respx.MockRouter]]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        hub = await _build(tmp_path, router, policy=Policy(file=PolicyFile(read_only=True)))
        try:
            yield hub, router
        finally:
            await hub.close()


@pytest.fixture
async def pve_audit_only(tmp_path: Any) -> AsyncIterator[tuple[PVEHub, respx.MockRouter]]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        hub = await _build(tmp_path, router, permissions=AUDIT_ONLY_PERMISSIONS)
        try:
            yield hub, router
        finally:
            await hub.close()


# -- PBS -------------------------------------------------------------------
BASE_URL = "https://pbs.test"
TOKEN_ID = "root@pam!pvehub"
ALL_PRIVILEGES = (
    "Datastore.Audit",
    "Datastore.Modify",
    "Datastore.Prune",
    "Datastore.Verify",
    "Remote.Audit",
    "Remote.Modify",
    "Remote.Read",
    "Sys.Audit",
)


def build_hub(*, read_only: bool = False) -> PVEHub:
    settings = Settings(
        transport="stdio",
        pbs=[
            PBSInstance(
                name="pbs1",
                url=BASE_URL,
                token_id=TOKEN_ID,
                token_secret="test-secret",
            )
        ],
        audit_log=None,
        capabilities_fail_open=True,
        capabilities_refresh_seconds=0,
    )
    hub = PVEHub(settings, Policy(file=PolicyFile(read_only=read_only)))
    hub.build()
    return hub


def grant_permissions(router: respx.Router, privileges: tuple[str, ...] = ALL_PRIVILEGES) -> None:
    permissions = {"/": {**{privilege: True for privilege in privileges}, "propagate": True}}
    router.get("/api2/extjs/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": permissions})
    )


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock_router:
        yield mock_router


@pytest.fixture
async def hub_factory(router: respx.Router) -> Any:
    hubs: list[PVEHub] = []

    async def factory(
        *,
        read_only: bool = False,
        privileges: tuple[str, ...] = ALL_PRIVILEGES,
    ) -> PVEHub:
        hub = build_hub(read_only=read_only)
        grant_permissions(router, privileges)
        await hub.initialize()
        hubs.append(hub)
        return hub

    yield factory
    for hub in hubs:
        await hub.close()


@pytest.fixture
async def hub(hub_factory: Callable[..., Awaitable[PVEHub]]) -> PVEHub:
    return await hub_factory()


# -- common ----------------------------------------------------------------
CallTool = Callable[..., Awaitable[dict[str, Any]]]


@pytest.fixture
def call() -> CallTool:
    async def _call(hub: PVEHub, tool: str, **arguments: Any) -> dict[str, Any]:
        result = await hub.mcp.call_tool(tool, arguments)
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert isinstance(payload, dict)
        return payload

    return _call


@pytest.fixture
def form() -> Callable[[httpx.Request], dict[str, list[str]]]:
    def _form(request: httpx.Request) -> dict[str, list[str]]:
        return parse_qs(request.content.decode())

    return _form


# -- shell / exec ----------------------------------------------------------
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
            200,
            json={
                "data": {
                    "/": {
                        "VM.Monitor": 1,
                        "VM.GuestAgent.Audit": 1,
                        "VM.GuestAgent.FileRead": 1,
                        "VM.GuestAgent.FileWrite": 1,
                        "VM.GuestAgent.Unrestricted": 1,
                        "propagate": 1,
                    }
                }
            },
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
