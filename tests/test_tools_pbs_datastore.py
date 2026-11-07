"""Tests for pbs_datastore: datastores, namespaces and health."""

from __future__ import annotations

import httpx

DATASTORE_PATH = "/api2/extjs/admin/datastore"


async def test_datastores_list(hub, router, call) -> None:
    router.get(DATASTORE_PATH).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"store": "ds1", "comment": "primary", "mount-status": "mounted"},
                    {"store": "ds2", "maintenance": "offline"},
                ]
            },
        )
    )
    payload = await call(hub, "pbs_datastores_list")
    assert payload["ok"] is True
    assert payload["data"]["count"] == 2
    assert payload["data"]["datastores"][0] == {
        "store": "ds1",
        "comment": "primary",
        "mount-status": "mounted",
    }


async def test_datastore_status(hub, router, call) -> None:
    route = router.get(f"{DATASTORE_PATH}/ds1/status").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"store": "ds1", "used": 10, "total": 100, "counts": {"vm": 1}}},
        )
    )
    payload = await call(hub, "pbs_datastore_status", store="ds1", verbose=True)
    assert payload["ok"] is True
    assert payload["data"]["status"]["used"] == 10
    assert route.calls.last.request.url.params["verbose"] == "1"


async def test_namespaces_list(hub, router, call) -> None:
    route = router.get(f"{DATASTORE_PATH}/ds1/namespace").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"ns": "team"}, {"ns": "team/dev", "comment": "dev"}]},
        )
    )
    payload = await call(hub, "pbs_namespaces_list", store="ds1", parent="team", max_depth=3)
    assert payload["data"]["count"] == 2
    assert payload["data"]["namespaces"][1]["ns"] == "team/dev"
    params = route.calls.last.request.url.params
    assert params["parent"] == "team"
    assert params["max-depth"] == "3"


async def test_namespace_create(hub, router, call, form) -> None:
    route = router.post(f"{DATASTORE_PATH}/ds1/namespace").mock(
        return_value=httpx.Response(200, json={"data": "dev"})
    )
    payload = await call(hub, "pbs_namespace_create", store="ds1", name="dev", parent="team")
    assert payload["ok"] is True
    assert payload["data"]["namespace"] == "dev"
    body = form(route.calls.last.request)
    assert body["name"] == ["dev"]
    assert body["parent"] == ["team"]


async def test_namespace_delete_requires_confirm(hub, router, call) -> None:
    route = router.delete(f"{DATASTORE_PATH}/ds1/namespace").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    payload = await call(hub, "pbs_namespace_delete", store="ds1", ns="team/dev")
    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert route.call_count == 0


async def test_namespace_delete_dry_run_does_not_call_api(hub, router, call) -> None:
    route = router.delete(f"{DATASTORE_PATH}/ds1/namespace").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    payload = await call(hub, "pbs_namespace_delete", store="ds1", ns="team/dev", dry_run=True)
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["would_call"].endswith("/admin/datastore/ds1/namespace")
    assert route.call_count == 0


async def test_namespace_delete_confirm(hub, router, call) -> None:
    route = router.delete(f"{DATASTORE_PATH}/ds1/namespace").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    payload = await call(
        hub,
        "pbs_namespace_delete",
        store="ds1",
        ns="team/dev",
        delete_groups=True,
        confirm=True,
    )
    assert payload["ok"] is True
    assert payload["data"]["deleted"] is True
    params = route.calls.last.request.url.params
    assert params["ns"] == "team/dev"
    assert params["delete-groups"] == "1"
    assert params["error-on-protected"] == "1"


async def test_health_combines_usage_and_failed_tasks(hub, router, call) -> None:
    router.get(DATASTORE_PATH).mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"store": "ds1"}, {"store": "ds2"}]},
        )
    )
    router.get("/api2/extjs/status/datastore-usage").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "store": "ds1",
                        "total": 1000,
                        "used": 400,
                        "avail": 600,
                        "gc-status": {"last-run-state": "ok", "duration": 12},
                    }
                ]
            },
        )
    )
    tasks_route = router.get("/api2/extjs/nodes/localhost/tasks").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "upid": "UPID:pbs1:00001234:00001234:00000001:65000000:verify:ds1:root@pam!pvehub:",
                        "node": "pbs1",
                        "worker_type": "verify",
                        "status": "stopped",
                    }
                ]
            },
        )
    )
    payload = await call(hub, "pbs_health", max_stores=10, failed_tasks=3)
    assert payload["ok"] is True
    stores = payload["data"]["stores"]
    assert [item["store"] for item in stores] == ["ds1", "ds2"]
    assert stores[0]["used"] == 400
    assert stores[0]["gc"]["last-run-state"] == "ok"
    assert payload["data"]["failed_tasks"][0]["worker_type"] == "verify"
    params = tasks_route.calls.last.request.url.params
    assert params["errors"] == "1"
    assert params["limit"] == "3"


async def test_read_only_hides_write_and_destructive_tools(hub_factory) -> None:
    hub = await hub_factory(read_only=True)
    assert "pbs_datastores_list" in hub.registered
    assert "pbs_datastore_status" in hub.registered
    assert "pbs_health" in hub.registered
    for name in (
        "pbs_namespace_create",
        "pbs_namespace_delete",
        "pbs_snapshot_forget",
        "pbs_snapshot_protect",
        "pbs_prune",
        "pbs_gc",
        "pbs_verify",
        "pbs_job_run",
    ):
        assert name not in hub.registered
    reasons = {item.name: item.reason for item in hub.blocked}
    assert "read_only" in reasons["pbs_snapshot_forget"]


async def test_full_catalog_registered(hub) -> None:
    expected = {
        "pbs_datastores_list",
        "pbs_datastore_status",
        "pbs_namespaces_list",
        "pbs_namespace_create",
        "pbs_namespace_delete",
        "pbs_health",
        "pbs_snapshots_list",
        "pbs_snapshot_forget",
        "pbs_snapshot_protect",
        "pbs_prune",
        "pbs_gc",
        "pbs_verify",
        "pbs_prune_jobs_list",
        "pbs_verify_jobs_list",
        "pbs_sync_jobs_list",
        "pbs_job_run",
        "pbs_remotes_list",
        "pbs_tasks_list",
        "pbs_task_status",
        "pbs_task_log",
    }
    assert expected <= set(hub.registered)

