"""Tests for the task tools."""

from __future__ import annotations

from typing import Any

from httpx import Response

TASK_UPID = "UPID:pve1:00000030:00000031:65000000:qmstart:100:root@pam:"


async def test_tasks_list_sorted_and_limited(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/nodes/pve1/tasks").mock(
        return_value=Response(
            200,
            json={
                "data": [
                    {"upid": "UPID:old", "node": "pve1", "type": "qmstart", "starttime": 100},
                    {"upid": "UPID:new", "node": "pve1", "type": "vzdump", "starttime": 300},
                    {"upid": "UPID:mid", "node": "pve1", "type": "qmstop", "starttime": 200},
                ]
            },
        )
    )

    payload = await call(hub, "pve_tasks_list", node="pve1", limit=2)

    assert [task["upid"] for task in payload["data"]["tasks"]] == ["UPID:new", "UPID:mid"]
    assert payload["data"]["nodes"] == ["pve1"]


async def test_tasks_list_without_node_merges_nodes(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get("/api2/json/nodes").mock(
        return_value=Response(200, json={"data": [{"node": "pve1"}, {"node": "pve2"}]})
    )
    router.get("/api2/json/nodes/pve1/tasks").mock(
        return_value=Response(
            200, json={"data": [{"upid": "UPID:a", "node": "pve1", "starttime": 100}]}
        )
    )
    router.get("/api2/json/nodes/pve2/tasks").mock(
        return_value=Response(
            200, json={"data": [{"upid": "UPID:b", "node": "pve2", "starttime": 200}]}
        )
    )

    payload = await call(hub, "pve_tasks_list")

    assert payload["data"]["nodes"] == ["pve1", "pve2"]
    assert [task["upid"] for task in payload["data"]["tasks"]] == ["UPID:b", "UPID:a"]


async def test_task_status(pve: Any, call: Any) -> None:
    hub, router = pve
    router.get(f"/api2/json/nodes/pve1/tasks/{TASK_UPID}/status").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "upid": TASK_UPID,
                    "node": "pve1",
                    "type": "qmstart",
                    "status": "running",
                    "starttime": 1700000000,
                }
            },
        )
    )

    payload = await call(hub, "pve_task_status", node="pve1", upid=TASK_UPID)

    assert payload["data"]["status"]["upid"] == TASK_UPID
    assert payload["data"]["status"]["running"] is True


async def test_task_log_returns_tail(pve: Any, call: Any) -> None:
    hub, router = pve
    route = router.get(f"/api2/json/nodes/pve1/tasks/{TASK_UPID}/log").mock(
        return_value=Response(200, json={"data": [{"n": 1, "t": "line one"}, {"n": 2, "t": "line two"}]})
    )

    payload = await call(hub, "pve_task_log", node="pve1", upid=TASK_UPID, limit=10)

    assert payload["data"]["log"] == "line one\nline two"
    params = route.calls[0].request.url.params
    assert params["start"] == "0"
    assert params["limit"] == "10"


async def test_task_stop_requires_confirm(pve: Any, call: Any) -> None:
    hub, router = pve
    delete = router.delete(f"/api2/json/nodes/pve1/tasks/{TASK_UPID}").mock(
        return_value=Response(200, json={"data": None})
    )

    payload = await call(hub, "pve_task_stop", node="pve1", upid=TASK_UPID)

    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert not delete.called


async def test_task_stop_dry_run_makes_no_call(pve: Any, call: Any) -> None:
    hub, router = pve
    delete = router.delete(f"/api2/json/nodes/pve1/tasks/{TASK_UPID}").mock(
        return_value=Response(200, json={"data": None})
    )

    payload = await call(hub, "pve_task_stop", node="pve1", upid=TASK_UPID, dry_run=True)

    assert payload["data"]["dry_run"] is True
    assert not delete.called


async def test_task_stop_confirmed(pve: Any, call: Any) -> None:
    hub, router = pve
    delete = router.delete(f"/api2/json/nodes/pve1/tasks/{TASK_UPID}").mock(
        return_value=Response(200, json={"data": None})
    )

    payload = await call(hub, "pve_task_stop", node="pve1", upid=TASK_UPID, confirm=True)

    assert payload["ok"] is True
    assert payload["data"]["stopped"] is True
    assert delete.called
