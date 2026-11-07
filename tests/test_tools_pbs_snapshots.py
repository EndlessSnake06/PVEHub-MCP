"""Tests for pbs_snapshots: list, protect, forget, prune, GC and verify."""

from __future__ import annotations

import httpx

SNAPSHOTS = "/api2/extjs/admin/datastore/ds1/snapshots"
UPID = "UPID:pbs1:00001234:00001234:00000001:65000000:garbage_collection:ds1:root@pam!pvehub:"


async def test_snapshots_list_filters_and_summarizes(hub, router, call) -> None:
    route = router.get(SNAPSHOTS).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "backup-type": "vm",
                        "backup-id": "100",
                        "backup-time": 1700000000,
                        "size": 1234,
                        "protected": False,
                        "owner": "root@pam",
                        "verification": {"state": "ok"},
                        "files": ["index.json.blob", "drive-scsi0.img.fidx"],
                        "fingerprint": "aa:bb:cc",
                    },
                    {
                        "backup-type": "ct",
                        "backup-id": "101",
                        "backup-time": 1700000100,
                    },
                ]
            },
        )
    )
    payload = await call(
        hub,
        "pbs_snapshots_list",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        ns="team",
        limit=1,
    )
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["total"] == 2
    assert payload["data"]["truncated"] is True
    snapshot = payload["data"]["snapshots"][0]
    assert snapshot["backup-id"] == "100"
    assert snapshot["verification"] == {"state": "ok"}
    assert "files" not in snapshot
    assert "fingerprint" not in snapshot
    params = route.calls.last.request.url.params
    assert params["backup-type"] == "vm"
    assert params["backup-id"] == "100"
    assert params["ns"] == "team"


async def test_snapshot_forget_requires_confirm(hub, router, call) -> None:
    route = router.delete(SNAPSHOTS).mock(return_value=httpx.Response(200, json={"data": None}))
    payload = await call(
        hub,
        "pbs_snapshot_forget",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        backup_time=1700000000,
    )
    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert route.call_count == 0


async def test_snapshot_forget_dry_run_does_not_call_api(hub, router, call) -> None:
    route = router.delete(SNAPSHOTS).mock(return_value=httpx.Response(200, json={"data": None}))
    payload = await call(
        hub,
        "pbs_snapshot_forget",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        backup_time=1700000000,
        ns="team",
        dry_run=True,
    )
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["ns"] == "team"
    assert route.call_count == 0


async def test_snapshot_forget_confirm(hub, router, call) -> None:
    route = router.delete(SNAPSHOTS).mock(return_value=httpx.Response(200, json={"data": None}))
    payload = await call(
        hub,
        "pbs_snapshot_forget",
        store="ds1",
        backup_type="ct",
        backup_id="101",
        backup_time=1700000100,
        ns="team/dev",
        confirm=True,
    )
    assert payload["ok"] is True
    assert payload["data"]["forgotten"] is True
    params = route.calls.last.request.url.params
    assert params["backup-type"] == "ct"
    assert params["backup-id"] == "101"
    assert params["backup-time"] == "1700000100"
    assert params["ns"] == "team/dev"


async def test_snapshot_protect(hub, router, call, form) -> None:
    route = router.put("/api2/extjs/admin/datastore/ds1/protected").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    payload = await call(
        hub,
        "pbs_snapshot_protect",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        backup_time=1700000000,
        protected=True,
    )
    assert payload["ok"] is True
    assert payload["data"]["protected"] is True
    body = form(route.calls.last.request)
    assert body["protected"] == ["1"]
    assert body["backup-id"] == ["100"]


async def test_prune_defaults_to_dry_run(hub, router, call, form) -> None:
    route = router.post("/api2/extjs/admin/datastore/ds1/prune").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"backup-type": "vm", "backup-id": "100", "backup-time": 1, "keep": True}]},
        )
    )
    payload = await call(
        hub,
        "pbs_prune",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        keep_last=2,
        keep_daily=7,
    )
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["results"][0]["keep"] is True
    body = form(route.calls.last.request)
    assert body["dry-run"] == ["1"]
    assert body["keep-last"] == ["2"]
    assert body["keep-daily"] == ["7"]
    assert "confirm" not in body


async def test_prune_requires_confirm_when_not_dry_run(hub, router, call) -> None:
    route = router.post("/api2/extjs/admin/datastore/ds1/prune").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    payload = await call(
        hub,
        "pbs_prune",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        keep_last=1,
        dry_run=False,
    )
    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert route.call_count == 0


async def test_prune_confirmed_removes_snapshots(hub, router, call, form) -> None:
    route = router.post("/api2/extjs/admin/datastore/ds1/prune").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    payload = await call(
        hub,
        "pbs_prune",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        keep_last=1,
        dry_run=False,
        confirm=True,
    )
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is False
    body = form(route.calls.last.request)
    assert body["dry-run"] == ["0"]
    assert body["keep-last"] == ["1"]


async def test_prune_requires_retention_value(hub, call) -> None:
    payload = await call(hub, "pbs_prune", store="ds1", backup_type="vm", backup_id="100")
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_gc_dry_run_returns_status(hub, router, call) -> None:
    status_route = router.get("/api2/extjs/admin/datastore/ds1/gc").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"store": "ds1", "last-run-state": "ok", "disk-bytes": 10}},
        )
    )
    post_route = router.post("/api2/extjs/admin/datastore/ds1/gc").mock(
        return_value=httpx.Response(200, json={"data": UPID})
    )
    payload = await call(hub, "pbs_gc", store="ds1", dry_run=True)
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["status"]["last-run-state"] == "ok"
    assert status_route.call_count == 1
    assert post_route.call_count == 0


async def test_gc_start_waits_for_task(hub, router, call) -> None:
    router.post("/api2/extjs/admin/datastore/ds1/gc").mock(
        return_value=httpx.Response(200, json={"data": UPID})
    )
    router.get(f"/api2/extjs/nodes/pbs1/tasks/{UPID}/status").mock(
        return_value=httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK"}})
    )
    log_route = router.get(f"/api2/extjs/nodes/pbs1/tasks/{UPID}/log").mock(
        return_value=httpx.Response(200, json={"data": [{"t": "GC finished"}]})
    )
    payload = await call(hub, "pbs_gc", store="ds1", confirm=True)
    assert payload["ok"] is True
    task = payload["data"]["task"]
    assert task["completed"] is True
    assert task["success"] is True
    assert task["log_tail"] == "GC finished"
    assert log_route.calls.last.request.url.params["limit"] == "15"


async def test_verify_rejects_partial_snapshot_reference(hub, call) -> None:
    payload = await call(hub, "pbs_verify", store="ds1", backup_type="vm")
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_verify_single_snapshot_without_wait(hub, router, call, form) -> None:
    route = router.post("/api2/extjs/admin/datastore/ds1/verify").mock(
        return_value=httpx.Response(200, json={"data": UPID})
    )
    payload = await call(
        hub,
        "pbs_verify",
        store="ds1",
        backup_type="vm",
        backup_id="100",
        backup_time=1700000000,
        wait=False,
    )
    assert payload["ok"] is True
    assert payload["data"]["upid"] == UPID
    assert payload["data"]["task"] is None
    body = form(route.calls.last.request)
    assert body["backup-type"] == ["vm"]
    assert body["backup-id"] == ["100"]
    assert body["backup-time"] == ["1700000000"]
    assert body["ignore-verified"] == ["1"]
