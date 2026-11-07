"""Token permission discovery and tool availability.

Proxmox returns effective permissions as ``{path: {privilege: propagate}}`` from
``GET /access/permissions``. A privilege on a path applies to that path and, when the
propagate flag is set, to all child paths. ``/`` is the root ACL.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .clients.pbs import PBSClient
from .clients.pve import PVEClient
from .errors import InvalidArgument, PermissionDenied
from .policy import normalize_api_path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Privilege:
    """A privilege required on an API path (path may contain ``{placeholders}``)."""

    priv: str
    path: str

    def resolve(self, values: dict[str, Any]) -> str:
        resolved = self.path
        for key, value in values.items():
            resolved = resolved.replace("{" + key + "}", str(value))
        if "{" in resolved:
            missing = [part for part in resolved.split("{")[1:]]
            raise InvalidArgument(
                f"cannot resolve privilege path {self.path!r} (missing {missing[0].split('}')[0]!r})"
            )
        normalized = normalize_api_path(resolved)
        if normalized is None:
            raise InvalidArgument(f"invalid privilege path {resolved!r}")
        return normalized


@dataclass
class CapabilitySnapshot:
    kind: str
    instance: str
    permissions: dict[str, dict[str, Any]] = field(default_factory=dict)
    fetched_at: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def privileges(self) -> list[str]:
        names: set[str] = set()
        for perms in self.permissions.values():
            names.update(perms)
        return sorted(names)

    def granted(self, priv: str, path: str) -> bool:
        target = normalize_api_path(path)
        if target is None:
            return False
        entries = {
            normalize_api_path(candidate) or "/": perms
            for candidate, perms in self.permissions.items()
            if isinstance(perms, dict)
        }
        exact = entries.get(target)
        if exact is not None and _truthy(exact.get(priv)):
            return True
        # ancestors, longest first
        ancestors = sorted(
            (candidate for candidate in entries if _covers(candidate, target) and candidate != target),
            key=len,
            reverse=True,
        )
        for ancestor in ancestors:
            perms = entries[ancestor]
            if _truthy(perms.get(priv)) and (_truthy(perms.get("propagate")) or ancestor == "/"):
                return True
            if ancestor == "/" and _truthy(perms.get(priv)):
                return True
        # Some PBS/PVE versions return flattened effective permissions without propagate
        # flags. A parent entry with the privilege is then treated as effective.
        for ancestor in ancestors:
            if _truthy(entries[ancestor].get(priv)) and ancestor.count("/") < target.count("/"):
                return True
        return False

    def has_any(self, priv: str, under: str | None = None) -> bool:
        prefix = normalize_api_path(under) if under else None
        for path, perms in self.permissions.items():
            normalized = normalize_api_path(path) or "/"
            if prefix and not (normalized == prefix or normalized.startswith(prefix.rstrip("/") + "/")):
                continue
            if isinstance(perms, dict) and _truthy(perms.get(priv)):
                return True
        return False


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


def _covers(ancestor: str, target: str) -> bool:
    if ancestor == "/":
        return True
    return target == ancestor or target.startswith(ancestor.rstrip("/") + "/")


class CapabilityManager:
    def __init__(
        self,
        pve_clients: dict[str, PVEClient],
        pbs_clients: dict[str, PBSClient],
        *,
        fail_open: bool = True,
        refresh_seconds: int = 300,
    ) -> None:
        self.pve_clients = pve_clients
        self.pbs_clients = pbs_clients
        self.fail_open = fail_open
        self.refresh_seconds = refresh_seconds
        self.pve: dict[str, CapabilitySnapshot] = {}
        self.pbs: dict[str, CapabilitySnapshot] = {}
        self.last_refresh: float = 0.0
        self._task: asyncio.Task[None] | None = None

    async def refresh(self) -> None:
        await asyncio.gather(
            *[self._refresh_one("pve", name, client) for name, client in self.pve_clients.items()],
            *[self._refresh_one("pbs", name, client) for name, client in self.pbs_clients.items()],
        )
        self.last_refresh = time.time()

    async def _refresh_one(
        self, kind: str, name: str, client: PVEClient | PBSClient
    ) -> None:
        try:
            permissions = await client.permissions()
            snapshot = CapabilitySnapshot(
                kind=kind,
                instance=name,
                permissions=permissions,
                fetched_at=time.time(),
            )
            logger.info(
                "%s %s: %d permission paths, %d privileges",
                kind,
                name,
                len(permissions),
                len(snapshot.privileges),
            )
        except Exception as exc:  # discovery must never crash the server
            logger.warning("%s %s: permission discovery failed: %s", kind, name, exc)
            snapshot = CapabilitySnapshot(
                kind=kind,
                instance=name,
                fetched_at=time.time(),
                error=str(exc),
            )
        target = self.pve if kind == "pve" else self.pbs
        target[name] = snapshot

    async def start_periodic_refresh(self) -> None:
        if self.refresh_seconds <= 0 or self._task is not None:
            return
        self._task = asyncio.create_task(self._refresh_loop(), name="pvehub-capabilities-refresh")

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self.refresh_seconds)
            try:
                await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("periodic capability refresh failed")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.debug("capability refresh task ended with error", exc_info=True)
            self._task = None

    # -- registration ------------------------------------------------------
    def visible(
        self,
        *,
        kind: str,
        requirements: Sequence[Privilege],
    ) -> tuple[bool, str]:
        snapshots = self.pve if kind == "pve" else self.pbs
        if not snapshots:
            return False, f"no {kind.upper()} instance configured"
        if not requirements:
            return True, ""
        for snapshot in snapshots.values():
            if snapshot.error:
                if self.fail_open:
                    return True, f"{kind} capability discovery failed: {snapshot.error}"
                continue
            if all(snapshot.has_any(req.priv) for req in requirements):
                return True, ""
        if any(snapshot.error for snapshot in snapshots.values()) and self.fail_open:
            return True, f"{kind} capability discovery incomplete"
        missing = ", ".join(sorted({req.priv for req in requirements}))
        return False, f"token lacks required {kind} privileges: {missing}"

    # -- call time ---------------------------------------------------------
    def check_pve(
        self,
        instance: str,
        requirements: Sequence[Privilege],
        values: dict[str, Any],
    ) -> None:
        self._check("pve", self.pve, instance, requirements, values)

    def check_pbs(
        self,
        instance: str,
        requirements: Sequence[Privilege],
        values: dict[str, Any],
    ) -> None:
        self._check("pbs", self.pbs, instance, requirements, values)

    def _check(
        self,
        kind: str,
        snapshots: dict[str, CapabilitySnapshot],
        instance: str,
        requirements: Sequence[Privilege],
        values: dict[str, Any],
    ) -> None:
        if not requirements:
            return
        snapshot = snapshots.get(instance)
        if snapshot is None:
            if self.fail_open:
                logger.warning("%s %s: no capability snapshot; allowing call (fail_open)", kind, instance)
                return
            raise PermissionDenied(f"{kind} {instance}: permissions not discovered")
        if snapshot.error:
            if self.fail_open:
                logger.warning(
                    "%s %s: capability discovery failed (%s); allowing call (fail_open)",
                    kind,
                    instance,
                    snapshot.error,
                )
                return
            raise PermissionDenied(
                f"{kind} {instance}: permission discovery failed: {snapshot.error}"
            )
        missing: list[str] = []
        for requirement in requirements:
            path = requirement.resolve(values)
            if not snapshot.granted(requirement.priv, path):
                missing.append(f"{requirement.priv} on {path}")
        if missing:
            raise PermissionDenied(
                f"{kind} {instance}: missing token privilege: " + ", ".join(missing),
                details={"instance": instance, "missing": missing},
            )

    # -- reporting ---------------------------------------------------------
    def report(self) -> dict[str, Any]:
        return {
            "pve": [_snapshot_report(snapshot) for snapshot in self.pve.values()],
            "pbs": [_snapshot_report(snapshot) for snapshot in self.pbs.values()],
            "last_refresh": int(self.last_refresh) if self.last_refresh else None,
            "refresh_seconds": self.refresh_seconds,
            "fail_open": self.fail_open,
        }

    def require_instance(self, kind: str, name: str | None, clients: dict[str, Any]) -> str:
        if name is None:
            if not clients:
                raise InvalidArgument(f"no {kind.upper()} instance configured")
            return next(iter(clients))
        if name not in clients:
            raise InvalidArgument(
                f"unknown {kind.upper()} instance {name!r}; configured: {', '.join(clients)}"
            )
        return name


def _snapshot_report(snapshot: CapabilitySnapshot) -> dict[str, Any]:
    return {
        "instance": snapshot.instance,
        "ok": snapshot.ok,
        "error": snapshot.error,
        "paths": len(snapshot.permissions),
        "privileges": snapshot.privileges,
        "fetched_at": int(snapshot.fetched_at) if snapshot.fetched_at else None,
    }
