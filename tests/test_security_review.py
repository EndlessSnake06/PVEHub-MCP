"""Regression tests for the findings documented in ``docs/SECURITY_REVIEW.md``."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from httpx import Response
from pydantic import ValidationError

from pvehub_mcp import resources
from pvehub_mcp.audit import redact_value
from pvehub_mcp.clients.base import quote_path
from pvehub_mcp.clients.ssh import ExecResult, SSHClientPool
from pvehub_mcp.config import Settings, SSHSettings
from pvehub_mcp.errors import InvalidArgument, PolicyError
from pvehub_mcp.policy import Policy, PolicyFile, normalize_api_path
from pvehub_mcp.server import PVEHub, _transport_security, build_http_app
from pvehub_mcp.validation import api_segment, task_upid

ROOT = Path(__file__).resolve().parents[1]


def _settings(**overrides: Any) -> Settings:
    data: dict[str, Any] = {
        "transport": "stdio",
        "pve": [
            {
                "name": "test",
                "url": "https://pve.test:8006",
                "token_id": "root@pam!pvehub",
                "token_secret": "s3cret",
            }
        ],
        "audit_log": None,
        "state_dir": "/tmp/pvehub-security-tests",
    }
    data.update(overrides)
    return Settings.model_validate(data)


# -- path-segment validation -------------------------------------------------


def test_api_segment_rejects_traversal_and_url_metacharacters() -> None:
    for bad in ("..", ".", "a/b", "a\\b", "a%2fb", "a?b", "a#b", "a\nb", "", " x"):
        with pytest.raises(InvalidArgument):
            api_segment(bad, "node")
    assert api_segment("pve-1.example", "node") == "pve-1.example"


def test_task_upid_rejects_traversal() -> None:
    with pytest.raises(InvalidArgument):
        task_upid("../../../access/users/root@pam")
    with pytest.raises(InvalidArgument):
        task_upid("UPID:pve1:1:2:3:qmstart:100:root@pam:/../x")
    with pytest.raises(InvalidArgument):
        task_upid("not-a-upid")
    good = "UPID:pve1:00000030:00000031:65000000:qmstart:100:root@pam:"
    assert task_upid(good) == good


def test_quote_path_rejects_dot_segments_and_backslashes() -> None:
    for bad in (
        "/nodes/../access/ticket",
        "/nodes/./access",
        "/nodes\\..\\access",
        "/nodes/\x00/status",
    ):
        with pytest.raises(InvalidArgument):
            quote_path(bad)
    assert quote_path("/nodes/pve1/status") == "/nodes/pve1/status"


def test_normalize_api_path_rejects_encoded_nul() -> None:
    assert normalize_api_path("/nodes/%00/status") is None


# -- curated tool path traversal ---------------------------------------------


async def test_snapshot_delete_rejects_traversal(pve: Any, call: Any) -> None:
    hub, router = pve
    delete = router.delete(url__regex=r".*").mock(return_value=Response(200, json={"data": "UPID:x"}))

    payload = await call(
        hub,
        "pve_guest_snapshot_delete",
        vmid=100,
        snapname="../../../../../access/users/root@pam",
        confirm=True,
    )

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert delete.called is False


async def test_snapshot_rollback_rejects_traversal(pve: Any, call: Any) -> None:
    hub, router = pve
    post = router.post(url__regex=r".*").mock(return_value=Response(200, json={"data": "UPID:x"}))

    payload = await call(
        hub,
        "pve_guest_snapshot_rollback",
        vmid=100,
        snapname="../../101/snapshot/clean",
        confirm=True,
    )

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert post.called is False


async def test_task_stop_rejects_traversal(pve: Any, call: Any) -> None:
    hub, router = pve
    delete = router.delete(url__regex=r".*").mock(return_value=Response(200, json={"data": None}))

    payload = await call(
        hub,
        "pve_task_stop",
        node="pve1",
        upid="../../../access/users/root@pam",
        confirm=True,
    )

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert delete.called is False


async def test_task_status_rejects_traversal(pve: Any, call: Any) -> None:
    hub, router = pve
    get = router.get(url__regex=r".*/tasks/.*").mock(return_value=Response(200, json={"data": {}}))

    payload = await call(hub, "pve_task_status", node="pve1", upid="../../../../access/users")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert get.called is False


async def test_storage_status_rejects_node_traversal(pve: Any, call: Any) -> None:
    hub, router = pve
    get = router.get(url__regex=r".*").mock(return_value=Response(200, json={"data": {}}))

    payload = await call(hub, "pve_storage_status", node="../../access/users", storage="local")

    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert get.called is False


# -- generic API gates -------------------------------------------------------


def test_generic_vmid_parameters_respect_allowed_vmids() -> None:
    policy = Policy(file=PolicyFile.model_validate({"generic_api": {"deny_methods": []}}))

    policy.check_generic("POST", "/nodes/pve1/qemu", {"vmid": 150, "storage": "local"})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/qemu", {"vmid": 5000})
    with pytest.raises(InvalidArgument):
        policy.check_generic("POST", "/nodes/pve1/qemu", {"vmid": "5000"})


def test_generic_secret_parameters_reject_prefixed_keys() -> None:
    policy = Policy(file=PolicyFile())

    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/access/users", {"new_password": "x"})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/access/users", {"nested": {"apiKey": "x"}})


# -- audit redaction ---------------------------------------------------------


def test_redact_command_strings_with_json_and_basic_auth() -> None:
    text = (
        "curl -d '{\"password\":\"hunter2\"}' "
        "-H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' "
        "-H 'X-Token: abc123'"
    )

    redacted = redact_value(text)

    assert "hunter2" not in redacted
    assert "dXNlcjpwYXNzd29yZA==" not in redacted
    assert "abc123" not in redacted


def test_redact_bulk_file_payload() -> None:
    assert redact_value({"content_base64": "aGVsbG8="}) == {"content_base64": "***"}


def test_redact_deeply_nested_value_does_not_overflow() -> None:
    value: dict[str, Any] = {}
    cursor = value
    for _ in range(500):
        cursor["x"] = {}
        cursor = cursor["x"]

    assert redact_value(value) is not None


async def test_audit_target_is_redacted(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    hub = PVEHub(_settings(audit_log=str(audit_path)))
    hub.build()

    @hub.tool(name="test_secret_command", category="exec")
    async def test_secret_command(command: str, confirm: bool = False) -> str:
        """Test-only exec tool."""
        return json.dumps({"ok": True})

    await hub.mcp.call_tool(
        "test_secret_command",
        {"command": "curl --password hunter2 https://example.invalid", "confirm": True},
    )

    line = audit_path.read_text(encoding="utf-8")
    assert "test_secret_command" in line
    assert "hunter2" not in line
    assert "***" in line


# -- resources ---------------------------------------------------------------


class _ResourceRecorder:
    def __init__(self) -> None:
        self.uris: list[str] = []

    def resource(self, uri: str, *args: Any, **kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.uris.append(uri)
            return fn

        return decorator


def _resource_hub(policy: Policy) -> tuple[Any, _ResourceRecorder]:
    recorder = _ResourceRecorder()
    hub = SimpleNamespace(
        mcp=recorder, policy=policy, pve_clients={}, pbs_clients={}
    )
    return hub, recorder


def test_resources_registered_by_default() -> None:
    hub, recorder = _resource_hub(Policy(file=PolicyFile()))
    resources.register(hub)
    assert set(recorder.uris) == {
        "proxmox://nodes",
        "proxmox://guests",
        "proxmox://storage",
        "pbs://datastores",
    }


def test_resources_respect_tool_allowlist() -> None:
    policy = Policy(file=PolicyFile.model_validate({"tools": {"allow": ["pvehub_capabilities"]}}))
    hub, recorder = _resource_hub(policy)
    resources.register(hub)
    assert recorder.uris == []


def test_resources_respect_denied_read_category() -> None:
    policy = Policy(file=PolicyFile.model_validate({"categories": {"deny": ["read"]}}))
    hub, recorder = _resource_hub(policy)
    resources.register(hub)
    assert recorder.uris == []


# -- transport security ------------------------------------------------------


def test_loopback_bind_enables_dns_rebinding_protection() -> None:
    security = _transport_security(
        _settings(transport="http", host="127.0.0.1", mcp_auth_required=False)
    )

    assert security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in security.allowed_hosts
    assert "localhost:*" in security.allowed_hosts


def test_non_loopback_without_allowlist_stays_opt_in(caplog: pytest.LogCaptureFixture) -> None:
    security = _transport_security(
        _settings(transport="http", host="0.0.0.0", mcp_auth_token="token-0123456789abcdef")
    )

    assert security.enable_dns_rebinding_protection is False


def test_explicit_allowlist_enables_protection() -> None:
    security = _transport_security(
        _settings(
            transport="http",
            host="0.0.0.0",
            mcp_auth_token="token-0123456789abcdef",
            allowed_hosts=["pvehub.example.com"],
        )
    )

    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == ["pvehub.example.com"]


def test_empty_bearer_token_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(transport="http", host="127.0.0.1", mcp_auth_token="")
    with pytest.raises(ValidationError):
        _settings(transport="http", host="0.0.0.0", mcp_auth_token="   ")


@respx.mock
async def test_http_rejects_foreign_host_header_on_loopback(tmp_path: Path) -> None:
    respx.get("https://pve.test:8006/api2/json/access/permissions").mock(
        return_value=Response(200, json={"data": {}})
    )
    settings = _settings(
        transport="http", host="127.0.0.1", state_dir=str(tmp_path), mcp_auth_required=False
    )
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client,
    ):
        rejected = await client.post("/mcp", json={}, headers={"host": "evil.example"})
        assert rejected.status_code == 421
        accepted = await client.post(
            "/mcp", json={}, headers={"host": "127.0.0.1:8080"}
        )
        assert accepted.status_code != 421
    await hub.close()


# -- SSH connection policy ---------------------------------------------------


def test_ssh_cache_key_includes_host_key_policy() -> None:
    pool = SSHClientPool(
        SSHSettings.model_validate(
            {
                "nodes": {
                    "permissive": {"host": "10.0.0.11", "strict_host_key": False},
                    "strict": {
                        "host": "10.0.0.11",
                        "known_hosts": "/ssh/known_hosts",
                        "strict_host_key": True,
                    },
                }
            }
        )
    )

    assert pool._cache_key(pool.node_target("permissive")) != pool._cache_key(
        pool.node_target("strict")
    )


async def test_exec_lxc_honours_configured_sudo() -> None:
    pool = SSHClientPool(
        SSHSettings.model_validate(
            {"nodes": {"pve1": {"host": "10.0.0.11", "sudo": True, "strict_host_key": False}}}
        )
    )
    captured: dict[str, str] = {}

    async def fake_run(target: Any, command: str, **kwargs: Any) -> ExecResult:
        captured["command"] = command
        return ExecResult(stdout="", stderr="", exit_status=0)

    pool.run = fake_run  # type: ignore[method-assign]

    await pool.exec_lxc("pve1", 100, "id")

    assert captured["command"] == "sudo -n pct exec 100 -- sh -c id"


# -- packaging ---------------------------------------------------------------


def test_env_example_requires_explicit_bearer_token() -> None:
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    token_lines = [line for line in lines if line.startswith("PVEHUB_MCP_AUTH_TOKEN=")]
    assert token_lines == ["PVEHUB_MCP_AUTH_TOKEN="]
    required_lines = [line for line in lines if line.startswith("PVEHUB_MCP_AUTH_REQUIRED=")]
    assert required_lines == ["PVEHUB_MCP_AUTH_REQUIRED=true"]


def test_file_path_policy_rejects_dot_segments() -> None:
    policy = Policy(
        file=PolicyFile.model_validate({"exec": {"files": {"allowed_roots": ["/srv/data"]}}})
    )

    policy.check_file_path("/srv/data/file.txt")
    with pytest.raises(PolicyError):
        policy.check_file_path("/srv/data/../etc/shadow")


# -- SFTP symlink resolution -------------------------------------------------


async def test_file_pull_host_rejects_symlink_escape(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    async def fake_realpath(target: Any, path: str, *, for_write: bool = False) -> str:
        return "/etc/shadow"

    async def fake_read(*args: Any, **kwargs: Any) -> bytes:
        nonlocal called
        called = True
        return b"secret"

    monkeypatch.setattr(exec_env.hub.ssh, "realpath", fake_realpath)
    monkeypatch.setattr(exec_env.hub.ssh, "read_file", fake_read)

    result = await exec_env.call(
        "file_pull_host", node="pve1", remote_path="/var/tmp/pvehub/link"
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"
    assert called is False


async def test_file_push_host_rejects_symlinked_parent(
    exec_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    async def fake_realpath(target: Any, path: str, *, for_write: bool = False) -> str:
        return "/root/.ssh/authorized_keys"

    async def fake_write(*args: Any, **kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(exec_env.hub.ssh, "realpath", fake_realpath)
    monkeypatch.setattr(exec_env.hub.ssh, "write_file", fake_write)

    result = await exec_env.call(
        "file_push_host",
        node="pve1",
        remote_path="/var/tmp/pvehub/key",
        content_base64="aGVsbG8=",
        confirm=True,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "policy_denied"
    assert called is False
