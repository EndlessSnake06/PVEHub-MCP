"""Tests for pbs_tasks: task list, status and log."""

from __future__ import annotations

import httpx

UPID = "UPID:pbs1:00001234:00001234:00000001:65000000:verify:ds1:root@pam!pvehub:"


async def test_tasks_list_defaults_to_localhost(hub, router, call) -> None:
    route = router.get("/api2/extjs/nodes/localhost/tasks").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "upid": UPID,
                        "node": "pbs1",
                        "worker_type": "verify",
                        "worker_id": "ds1",
                        "user": "root@pam",
                        "status": "stopped",
                        "starttime": 1700000000,
                        "endtime": 1700000010,
                        "pid": 1234,
                    }
                ]
            },
        )
    )
    payload = await call(hub, "pbs_tasks_list", errors=True, limit=10)
    assert payload["ok"] is True
    assert payload["data"]["node"] == "localhost"
    assert payload["data"]["tasks"][0]["worker_type"] == "verify"
    assert "pid" not in payload["data"]["tasks"][0]
    params = route.calls.last.request.url.params
    assert params["errors"] == "1"
    assert params["running"] == "0"
    assert params["limit"] == "10"


async def test_task_status(hub, router, call) -> None:
    route = router.get(f"/api2/extjs/nodes/localhost/tasks/{UPID}/status").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"status": "running", "node": "pbs1", "pid": 1234}},
        )
    )
    payload = await call(hub, "pbs_task_status", upid=UPID)
    assert payload["ok"] is True
    assert payload["data"]["status"]["status"] == "running"
    assert route.call_count == 1


async def test_task_log_tail_limit(hub, router, call) -> None:
    route = router.get(f"/api2/extjs/nodes/localhost/tasks/{UPID}/log").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"t": "first line"}, {"n": 1, "t": "second line"}]},
        )
    )
    payload = await call(hub, "pbs_task_log", upid=UPID, start=0, limit=2)
    assert payload["ok"] is True
    assert payload["data"]["log"] == "first line\nsecond line"
    params = route.calls.last.request.url.params
    assert params["start"] == "0"
    assert params["limit"] == "2"


async def test_task_status_rejects_invalid_upid(hub, call) -> None:
    payload = await call(hub, "pbs_task_status", upid="not-a-upid")
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
