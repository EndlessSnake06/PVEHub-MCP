"""Tests for pbs_jobs: job lists, manual runs and remotes."""

from __future__ import annotations

import httpx

JOB_ID = "nightly"


async def test_prune_jobs_list(hub, router, call) -> None:
    router.get("/api2/extjs/config/prune").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": JOB_ID,
                        "store": "ds1",
                        "ns": "team",
                        "schedule": "daily",
                        "keep-last": 3,
                        "keep-daily": 7,
                        "disable": False,
                        "comment": "nightly retention",
                        "next-run": 1700000000,
                    }
                ]
            },
        )
    )
    payload = await call(hub, "pbs_prune_jobs_list")
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    job = payload["data"]["jobs"][0]
    assert job["id"] == JOB_ID
    assert job["keep-daily"] == 7
    assert "next-run" not in job


async def test_verify_jobs_list(hub, router, call) -> None:
    router.get("/api2/extjs/config/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "verify-weekly",
                        "store": "ds1",
                        "schedule": "weekly",
                        "verify-threads": 4,
                        "ignore-verified": True,
                        "last-run-state": "ok",
                    }
                ]
            },
        )
    )
    payload = await call(hub, "pbs_verify_jobs_list")
    assert payload["data"]["jobs"][0]["id"] == "verify-weekly"
    assert payload["data"]["jobs"][0]["verify-threads"] == 4


async def test_sync_jobs_list_direction(hub, router, call) -> None:
    route = router.get("/api2/extjs/config/sync").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "pull-main",
                        "store": "ds1",
                        "remote": "offsite",
                        "remote-store": "backup",
                        "sync-direction": "pull",
                        "remove-vanished": False,
                    }
                ]
            },
        )
    )
    payload = await call(hub, "pbs_sync_jobs_list", sync_direction="push")
    assert payload["ok"] is True
    assert payload["data"]["sync_direction"] == "push"
    assert payload["data"]["jobs"][0]["remote"] == "offsite"
    assert route.calls.last.request.url.params["sync-direction"] == "push"


async def test_job_run_requires_confirm(hub, router, call) -> None:
    route = router.post(f"/api2/extjs/admin/prune/{JOB_ID}/run").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    payload = await call(hub, "pbs_job_run", job_type="prune", id=JOB_ID)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "confirm_required"
    assert route.call_count == 0


async def test_job_run_starts_job(hub, router, call) -> None:
    route = router.post(f"/api2/extjs/admin/verify/{JOB_ID}/run").mock(
        return_value=httpx.Response(200, json={"data": None})
    )
    payload = await call(hub, "pbs_job_run", job_type="verify", id=JOB_ID, confirm=True)
    assert payload["ok"] is True
    assert payload["data"]["started"] is True
    assert payload["data"]["job_type"] == "verify"
    assert route.call_count == 1


async def test_job_run_rejects_unknown_type(hub, call) -> None:
    payload = await call(hub, "pbs_job_run", job_type="gc", id=JOB_ID, confirm=True)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"


async def test_remotes_list_redacts_credentials(hub, router, call) -> None:
    router.get("/api2/extjs/config/remote").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "name": "offsite",
                        "host": "pbs.example.net",
                        "port": 8007,
                        "auth-id": "backup@pbs!sync",
                        "fingerprint": "AA:BB",
                        "password": "super-secret",
                    }
                ]
            },
        )
    )
    payload = await call(hub, "pbs_remotes_list")
    assert payload["ok"] is True
    remote = payload["data"]["remotes"][0]
    assert remote["name"] == "offsite"
    assert remote["password"] == "***"
    assert remote["auth-id"] == "backup@pbs!sync"
