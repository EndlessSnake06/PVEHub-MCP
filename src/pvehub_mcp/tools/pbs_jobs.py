"""Curated PBS job and remote tools."""

from __future__ import annotations

from typing import Any

from ..audit import redact_value
from ..errors import ConfirmRequired, InvalidArgument
from . import pbs_common
from .common import ok, pick

_PRUNE_FIELDS = (
    "id",
    "store",
    "ns",
    "schedule",
    "disable",
    "keep-last",
    "keep-hourly",
    "keep-daily",
    "keep-weekly",
    "keep-monthly",
    "keep-yearly",
    "max-depth",
    "comment",
)

_VERIFY_FIELDS = (
    "id",
    "store",
    "ns",
    "schedule",
    "ignore-verified",
    "verify-threads",
    "read-threads",
    "outdated-after",
    "max-depth",
    "comment",
)

_SYNC_FIELDS = (
    "id",
    "store",
    "remote",
    "remote-store",
    "remote-ns",
    "ns",
    "schedule",
    "sync-direction",
    "remove-vanished",
    "encrypted-only",
    "verified-only",
    "transfer-last",
    "rate-in",
    "rate-out",
    "comment",
)


def _jobs(data: Any, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        return []
    return [pick(item, fields) for item in data if isinstance(item, dict)]


def register(hub: Any) -> None:
    @hub.tool(
        name="pbs_prune_jobs_list",
        category="read",
        pbs=[("Datastore.Audit", "/datastore")],
        service="pbs",
    )
    async def pbs_prune_jobs_list(instance: str | None = None) -> str:
        """List scheduled prune jobs."""
        client = hub.pbs(instance)
        data = await client.get("/config/prune")
        jobs = _jobs(data, _PRUNE_FIELDS)
        return ok({"jobs": jobs, "count": len(jobs)}, max_bytes=pbs_common.max_bytes(hub))

    @hub.tool(
        name="pbs_verify_jobs_list",
        category="read",
        pbs=[("Datastore.Audit", "/datastore")],
        service="pbs",
    )
    async def pbs_verify_jobs_list(instance: str | None = None) -> str:
        """List scheduled verification jobs."""
        client = hub.pbs(instance)
        data = await client.get("/config/verify")
        jobs = _jobs(data, _VERIFY_FIELDS)
        return ok({"jobs": jobs, "count": len(jobs)}, max_bytes=pbs_common.max_bytes(hub))

    @hub.tool(
        name="pbs_sync_jobs_list",
        category="read",
        pbs=[("Datastore.Audit", "/datastore"), ("Remote.Audit", "/remote")],
        service="pbs",
    )
    async def pbs_sync_jobs_list(
        sync_direction: str = "all",
        instance: str | None = None,
    ) -> str:
        """List scheduled sync jobs (pull, push, or all)."""
        direction = sync_direction.strip().lower() if isinstance(sync_direction, str) else ""
        if direction not in {"all", "pull", "push"}:
            raise InvalidArgument("sync_direction must be one of: all, pull, push")
        client = hub.pbs(instance)
        data = await client.get("/config/sync", params={"sync-direction": direction})
        jobs = _jobs(data, _SYNC_FIELDS)
        return ok(
            {"jobs": jobs, "count": len(jobs), "sync_direction": direction},
            max_bytes=pbs_common.max_bytes(hub),
        )

    @hub.tool(
        name="pbs_job_run",
        category="write",
        pbs=[("Datastore.Modify", "/datastore")],
        service="pbs",
    )
    async def pbs_job_run(
        job_type: str,
        id: str,
        confirm: bool = False,
        instance: str | None = None,
    ) -> str:
        """Run a scheduled prune, verify or sync job now (requires confirm=true)."""
        kind = job_type.strip().lower() if isinstance(job_type, str) else ""
        if kind not in pbs_common.JOB_TYPES:
            raise InvalidArgument("job_type must be one of: prune, verify, sync")
        identifier = pbs_common.job_id(id)
        if not confirm:
            raise ConfirmRequired(
                f"pbs_job_run ({kind}) requires confirm=true",
                details={"tool": "pbs_job_run", "job_type": kind, "id": identifier},
            )
        client = hub.pbs(instance)
        result = await client.post(f"/admin/{kind}/{identifier}/run")
        return ok(
            {"job_type": kind, "id": identifier, "started": True, "result": result},
            max_bytes=pbs_common.max_bytes(hub),
        )

    @hub.tool(
        name="pbs_remotes_list",
        category="read",
        pbs=[("Remote.Audit", "/remote")],
        service="pbs",
    )
    async def pbs_remotes_list(instance: str | None = None) -> str:
        """List configured sync remotes (credentials redacted)."""
        client = hub.pbs(instance)
        data = await client.get("/config/remote")
        remotes = redact_value(data) if isinstance(data, list) else []
        return ok({"remotes": remotes, "count": len(remotes)}, max_bytes=pbs_common.max_bytes(hub))
