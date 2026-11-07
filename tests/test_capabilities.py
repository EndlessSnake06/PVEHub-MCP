"""Capability discovery and privilege mapping tests."""

from __future__ import annotations

import pytest

from pvehub_mcp.capabilities import CapabilityManager, CapabilitySnapshot, Privilege
from pvehub_mcp.errors import InvalidArgument, PermissionDenied


def _snapshot(permissions: dict[str, dict[str, int]], error: str | None = None) -> CapabilitySnapshot:
    return CapabilitySnapshot(kind="pve", instance="main", permissions=permissions, error=error)


def test_exact_and_propagated_permissions() -> None:
    snapshot = _snapshot(
        {
            "/": {"Sys.Audit": 1},
            "/vms": {"VM.Audit": 1, "VM.PowerMgmt": 0},
            "/vms/100": {"VM.PowerMgmt": 1},
        }
    )
    assert snapshot.granted("Sys.Audit", "/nodes/pve1")
    assert snapshot.granted("VM.Audit", "/vms/101")
    assert snapshot.granted("VM.PowerMgmt", "/vms/100")
    # non-propagating parent must not grant a sibling VM
    assert not snapshot.granted("VM.PowerMgmt", "/vms/101")


def test_non_propagating_parent_does_not_grant_child() -> None:
    snapshot = _snapshot({"/vms": {"VM.Audit": 0}})
    assert not snapshot.granted("VM.Audit", "/vms/100")


def test_has_any() -> None:
    snapshot = _snapshot({"/vms/100": {"VM.Audit": 1}, "/storage": {"Datastore.Audit": 1}})
    assert snapshot.has_any("VM.Audit")
    assert snapshot.has_any("Datastore.Audit", "/storage")
    assert not snapshot.has_any("VM.PowerMgmt")


def test_visibility_and_call_checks() -> None:
    manager = CapabilityManager({}, {}, fail_open=False)
    manager.pve["main"] = _snapshot({"/vms/100": {"VM.Audit": 1, "VM.PowerMgmt": 1}})
    assert manager.visible(kind="pve", requirements=[Privilege("VM.Audit", "/vms/100")])[0]
    assert not manager.visible(kind="pve", requirements=[Privilege("VM.Clone", "/vms/100")])[0]
    manager.check_pve("main", [Privilege("VM.PowerMgmt", "/vms/{vmid}")], {"vmid": 100})
    with pytest.raises(PermissionDenied) as exc:
        manager.check_pve("main", [Privilege("VM.PowerMgmt", "/vms/{vmid}")], {"vmid": 101})
    assert "VM.PowerMgmt on /vms/101" in str(exc.value)


def test_discovery_failure_fail_open_and_closed() -> None:
    open_manager = CapabilityManager({}, {}, fail_open=True)
    open_manager.pve["main"] = _snapshot({}, error="401")
    open_manager.check_pve("main", [Privilege("VM.Audit", "/vms")], {})
    assert open_manager.visible(kind="pve", requirements=[Privilege("VM.Audit", "/vms")])[0]

    closed_manager = CapabilityManager({}, {}, fail_open=False)
    closed_manager.pve["main"] = _snapshot({}, error="401")
    with pytest.raises(PermissionDenied):
        closed_manager.check_pve("main", [Privilege("VM.Audit", "/vms")], {})
    assert not closed_manager.visible(kind="pve", requirements=[Privilege("VM.Audit", "/vms")])[0]


def test_unresolved_placeholder_is_rejected() -> None:
    manager = CapabilityManager({}, {}, fail_open=True)
    manager.pve["main"] = _snapshot({"/vms": {"VM.Audit": 1}})
    with pytest.raises(InvalidArgument):
        manager.check_pve("main", [Privilege("VM.Audit", "/vms/{vmid}")], {})
