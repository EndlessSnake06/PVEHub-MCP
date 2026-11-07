"""Policy engine tests."""

from __future__ import annotations

import pytest

from pvehub_mcp.errors import ConfirmRequired, InvalidArgument, PolicyError
from pvehub_mcp.policy import Policy, PolicyFile, normalize_api_path


def _policy(**kwargs: object) -> Policy:
    return Policy(file=PolicyFile.model_validate(kwargs), source="test")


def test_read_only_blocks_mutating_categories() -> None:
    policy = _policy(read_only=True)
    assert policy.tool_decision("pve_guest_status", "read").allowed
    assert not policy.tool_decision("pve_guest_delete", "destructive").allowed
    with pytest.raises(PolicyError):
        policy.check_call("pve_guest_power", "lifecycle", {"vmid": 100})


def test_tool_deny_and_allowlist() -> None:
    policy = _policy(tools={"deny": ["pve_host_exec"]})
    assert not policy.tool_decision("pve_host_exec", "exec").allowed
    allowlist = _policy(tools={"allow": ["pve_guests_list"]})
    assert allowlist.tool_decision("pve_guests_list", "read").allowed
    assert not allowlist.tool_decision("pve_guest_status", "read").allowed


def test_category_deny() -> None:
    policy = _policy(categories={"deny": ["destructive"]})
    assert not policy.tool_decision("pve_guest_delete", "destructive").allowed


def test_confirm_required_and_dry_run_bypass() -> None:
    policy = _policy()
    with pytest.raises(ConfirmRequired):
        policy.check_call("pve_guest_delete", "destructive", {"vmid": 100})
    policy.check_call("pve_guest_delete", "destructive", {"vmid": 100, "confirm": True})
    policy.check_call("pve_guest_delete", "destructive", {"vmid": 100, "dry_run": True})
    with pytest.raises(ConfirmRequired):
        policy.check_call(
            "pve_guest_delete",
            "destructive",
            {"vmid": 100, "dry_run": True},
            dry_run_supported=False,
        )


def test_allowed_vmids() -> None:
    policy = _policy(exec={"allowed_vmids": ["100-110", "200"]})
    policy.check_call("pve_guest_delete", "destructive", {"vmid": 105, "confirm": True})
    policy.check_call("pve_guest_delete", "destructive", {"vmid": 200, "confirm": True})
    with pytest.raises(PolicyError):
        policy.check_call("pve_guest_delete", "destructive", {"vmid": 111, "confirm": True})


def test_generic_read_only_and_method_deny() -> None:
    policy = _policy(read_only=True)
    policy.check_generic("GET", "/nodes")
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/qemu/100/status/start")

    policy = _policy()
    with pytest.raises(PolicyError):
        policy.check_generic("DELETE", "/nodes/pve1/qemu/100")


def test_generic_hard_denied_paths() -> None:
    policy = _policy()
    for path in (
        "/access/ticket",
        "/nodes/pve1/vncshell",
        "/nodes/pve1/spiceshell",
        "/nodes/pve1/termproxy",
        "/nodes/pve1/qemu/100/agent/exec",
        "/nodes/pve1/qemu/100/agent/file-write",
    ):
        with pytest.raises(PolicyError):
            policy.check_generic("POST", path)


def test_generic_path_traversal_and_encoding() -> None:
    policy = _policy()
    for path in (
        "/nodes/../access/ticket",
        "/nodes/%2e%2e/access/ticket",
        "//access//ticket",
        "/nodes/%252e%252e/access/ticket",
    ):
        with pytest.raises((PolicyError, InvalidArgument)):
            policy.check_generic("POST", path)


def test_generic_secret_parameters_rejected() -> None:
    policy = _policy()
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/access/users", {"password": "x"})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes", {"nested": {"token": "x"}})


def test_generic_vmid_gate() -> None:
    policy = _policy(exec={"allowed_vmids": ["100-110"]})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/qemu/999/status/start")


def test_generic_vmid_parameter_gate() -> None:
    policy = _policy(exec={"allowed_vmids": ["100-110"]})
    policy.check_generic("POST", "/nodes/pve1/qemu", {"vmid": 105})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/qemu", {"vmid": 500})
    with pytest.raises(PolicyError):
        policy.check_generic(
            "POST", "/nodes/pve1/qemu/105/clone", {"newid": 500}
        )
    with pytest.raises(InvalidArgument):
        policy.check_generic("POST", "/nodes/pve1/qemu", {"vmid": "abc"})
    policy.check_generic("POST", "/nodes/pve1/vzdump", {"vmid": [105, 106]})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/vzdump", {"vmid": [105, 500]})
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/vzdump", {"all": 1})


def test_command_denylist() -> None:
    policy = _policy()
    with pytest.raises(PolicyError):
        policy.check_command("rm -rf /")
    with pytest.raises(PolicyError):
        policy.check_command("sudo mkfs.ext4 /dev/sda1")
    policy.check_command("echo hello")


def test_file_roots() -> None:
    policy = _policy(exec={"files": {"allowed_roots": ["/srv/data"]}})
    policy.check_file_path("/srv/data/file.txt")
    with pytest.raises(PolicyError):
        policy.check_file_path("/etc/shadow")


def test_normalize_api_path() -> None:
    assert normalize_api_path("/nodes//pve1/status") == "/nodes/pve1/status"
    assert normalize_api_path("/nodes/%70ve1/status") == "/nodes/pve1/status"
    assert normalize_api_path("/nodes/../etc") is None
    assert normalize_api_path("nodes") is None
