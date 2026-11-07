"""Server assembly: MCP instance, auth, tool registration, health."""

from __future__ import annotations

import functools
import json
import logging
import secrets
from collections.abc import Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .audit import AuditLogger
from .capabilities import CapabilityManager, Privilege
from .clients.pbs import PBSClient
from .clients.pve import PVEClient
from .clients.ssh import SSHClientPool
from .config import Settings
from .errors import InvalidArgument, NotFound, PolicyError, PVEHubError
from .policy import Category, Policy
from .tools.common import dumps, fail

logger = logging.getLogger(__name__)

__version__ = "0.1.0"


@dataclass
class RegisteredTool:
    name: str
    category: Category
    description: str
    pve_privileges: tuple[Privilege, ...] = ()
    pbs_privileges: tuple[Privilege, ...] = ()
    shell: str | None = None


@dataclass
class BlockedTool:
    name: str
    category: Category
    reason: str


class PVEHub:
    """Owns clients, policy, capabilities and the MCP server instance."""

    def __init__(self, settings: Settings, policy: Policy | None = None) -> None:
        self.settings = settings
        self.policy = policy or Policy.load(settings.policy_file)
        self.audit = AuditLogger(
            settings.audit_log,
            include_results=settings.audit_include_results,
            max_string=max(2048, settings.max_output_bytes // 8),
        )
        self.ssh = SSHClientPool(settings.ssh)
        self.pve_clients: dict[str, PVEClient] = {}
        self.pbs_clients: dict[str, PBSClient] = {}
        self.capabilities: CapabilityManager | None = None
        self.registered: dict[str, RegisteredTool] = {}
        self.blocked: list[BlockedTool] = []
        self._initialized = False
        self._mcp: MCPServer | None = None

    # -- client factories --------------------------------------------------
    async def initialize(self) -> None:
        if self._initialized:
            return
        self.pve_clients = {
            instance.name: PVEClient(
                name=instance.name,
                url=instance.url,
                api_path=instance.api_path,
                token_id=instance.token_id,
                token_secret=instance.token_secret.get_secret_value(),
                verify=instance.verify,
                ca_file=instance.ca_file,
                fingerprint=instance.fingerprint,
                timeout_seconds=instance.timeout_seconds,
                max_retries=instance.max_retries,
                state_dir=self.settings.state_dir,
            )
            for instance in self.settings.pve
        }
        self.pbs_clients = {
            instance.name: PBSClient(
                name=instance.name,
                url=instance.url,
                api_path=instance.api_path,
                token_id=instance.token_id,
                token_secret=instance.token_secret.get_secret_value(),
                verify=instance.verify,
                ca_file=instance.ca_file,
                fingerprint=instance.fingerprint,
                timeout_seconds=instance.timeout_seconds,
                max_retries=instance.max_retries,
                state_dir=self.settings.state_dir,
            )
            for instance in self.settings.pbs
        }
        self.capabilities = CapabilityManager(
            self.pve_clients,
            self.pbs_clients,
            fail_open=self.settings.capabilities_fail_open,
            refresh_seconds=self.settings.capabilities_refresh_seconds,
        )
        await self.capabilities.refresh()
        self._register_all()
        await self.capabilities.start_periodic_refresh()
        self._initialized = True

    async def close(self) -> None:
        if self.capabilities is not None:
            await self.capabilities.stop()
        for client in [*self.pve_clients.values(), *self.pbs_clients.values()]:
            await client.aclose()
        await self.ssh.close()

    @property
    def mcp(self) -> MCPServer:
        if self._mcp is None:
            raise RuntimeError("MCP server not built")
        return self._mcp

    def build(self) -> MCPServer:
        if self._mcp is not None:
            return self._mcp
        self._mcp = MCPServer(
            name="pvehub-mcp",
            title="PVEHub-MCP",
            version=__version__,
            instructions=(
                "Proxmox VE and Proxmox Backup Server control plane. Read tools are safe; "
                "write/lifecycle/destructive/exec tools require confirm=true. Use the "
                "pvehub_capabilities tool to see policy blocks and missing token privileges. "
                "Shell tools require SSH (LXC/host/PBS) or a running QEMU guest agent (VMs)."
            ),
            lifespan=self._lifespan,
            log_level=self.settings.log_level,
        )
        return self._mcp

    @asynccontextmanager
    async def _lifespan(self, _server: MCPServer) -> Any:
        await self.initialize()
        try:
            yield
        finally:
            await self.close()

    # -- client accessors --------------------------------------------------
    def pve(self, instance: str | None = None) -> PVEClient:
        name = self._instance_name("pve", instance, self.pve_clients)
        return self.pve_clients[name]

    def pbs(self, instance: str | None = None) -> PBSClient:
        name = self._instance_name("pbs", instance, self.pbs_clients)
        return self.pbs_clients[name]

    def _instance_name(
        self, kind: str, instance: str | None, clients: dict[str, Any]
    ) -> str:
        if not clients:
            raise InvalidArgument(f"no {kind.upper()} instance configured")
        if instance is None:
            return next(iter(clients))
        if instance not in clients:
            raise InvalidArgument(
                f"unknown {kind.upper()} instance {instance!r}; configured: {', '.join(clients)}"
            )
        return instance

    async def resolve_guest(self, vmid: int, instance: str | None = None) -> dict[str, Any]:
        client = self.pve(instance)
        resources = await client.get("/cluster/resources", params={"type": "vm"})
        if isinstance(resources, list):
            for resource in resources:
                if isinstance(resource, dict) and resource.get("vmid") == vmid:
                    return resource
        raise NotFound(f"guest {vmid} not found in PVE instance {client.name}")

    async def resolve_node(self, node: str, instance: str | None = None) -> dict[str, Any]:
        client = self.pve(instance)
        nodes = await client.get("/nodes")
        if isinstance(nodes, list):
            for item in nodes:
                if isinstance(item, dict) and item.get("node") == node:
                    return item
        raise NotFound(f"node {node!r} not found in PVE instance {client.name}")

    # -- registration ------------------------------------------------------
    def tool(
        self,
        *,
        name: str,
        category: Category,
        pve: Sequence[tuple[str, str]] = (),
        pbs: Sequence[tuple[str, str]] = (),
        shell: str | None = None,
        service: str | None = None,
        dry_run: bool = False,
    ) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            self._register(
                fn,
                name=name,
                category=category,
                pve=pve,
                pbs=pbs,
                shell=shell,
                service=service,
                dry_run=dry_run,
            )
            return fn

        return decorator

    def _register(
        self,
        fn: Callable[..., Awaitable[Any]],
        *,
        name: str,
        category: Category,
        pve: Sequence[tuple[str, str]],
        pbs: Sequence[tuple[str, str]],
        shell: str | None,
        service: str | None,
        dry_run: bool,
    ) -> None:
        decision = self.policy.tool_decision(name, category)
        if not decision.allowed:
            self.blocked.append(BlockedTool(name, category, f"policy: {decision.reason}"))
            logger.info("tool %s blocked by policy: %s", name, decision.reason)
            return
        if service == "pve" and not self.pve_clients:
            self.blocked.append(BlockedTool(name, category, "capability: no PVE instance configured"))
            return
        if service == "pbs" and not self.pbs_clients:
            self.blocked.append(BlockedTool(name, category, "capability: no PBS instance configured"))
            return
        if shell is not None:
            ok_shell, reason = self._shell_available(shell)
            if not ok_shell:
                self.blocked.append(BlockedTool(name, category, f"prerequisite: {reason}"))
                logger.info("tool %s blocked: %s", name, reason)
                return
        pve_reqs = tuple(Privilege(priv, path) for priv, path in pve)
        pbs_reqs = tuple(Privilege(priv, path) for priv, path in pbs)
        if pve_reqs:
            visible, reason = self.capabilities.visible(kind="pve", requirements=pve_reqs)  # type: ignore[union-attr]
            if not visible:
                self.blocked.append(BlockedTool(name, category, f"capability: {reason}"))
                logger.info("tool %s blocked: %s", name, reason)
                return
        if pbs_reqs:
            visible, reason = self.capabilities.visible(kind="pbs", requirements=pbs_reqs)  # type: ignore[union-attr]
            if not visible:
                self.blocked.append(BlockedTool(name, category, f"capability: {reason}"))
                logger.info("tool %s blocked: %s", name, reason)
                return
        wrapped = self._wrap(fn, name=name, category=category, pve=pve_reqs, pbs=pbs_reqs)
        description = (fn.__doc__ or name).strip()
        annotations = ToolAnnotations(
            title=name,
            readOnlyHint=category == "read",
            destructiveHint=category == "destructive",
            idempotentHint=category in {"read", "generic"},
            openWorldHint=False,
        )
        self.mcp.add_tool(
            wrapped,
            name=name,
            description=description,
            annotations=annotations,
            structured_output=False,
        )
        self.registered[name] = RegisteredTool(
            name=name,
            category=category,
            description=description,
            pve_privileges=pve_reqs,
            pbs_privileges=pbs_reqs,
            shell=shell,
        )

    def _shell_available(self, shell: str) -> tuple[bool, str]:
        ssh_ready = bool(self.settings.ssh.nodes or self.settings.ssh.pbs)
        if ssh_ready and shell in {"host", "lxc", "pbs", "files"}:
            missing = self.settings.ssh.missing_prerequisites()
            if missing:
                return False, "SSH prerequisites missing: " + "; ".join(missing)
        if shell == "host":
            if not self.policy.file.exec.host:
                return False, "exec.host is disabled"
            if not ssh_ready:
                return False, "no SSH target configured"
            return True, ""
        if shell == "lxc":
            if not self.policy.file.exec.lxc:
                return False, "exec.lxc is disabled"
            if not ssh_ready:
                return False, "no SSH target configured"
            return True, ""
        if shell == "vm":
            if not self.policy.file.exec.vm:
                return False, "exec.vm is disabled"
            if not self.pve_clients:
                return False, "no PVE instance configured"
            return True, ""
        if shell == "pbs":
            if not self.policy.file.exec.pbs_host:
                return False, "exec.pbs_host is disabled"
            if self.settings.ssh.pbs is None:
                return False, "no SSH target configured for PBS (ssh.pbs)"
            return True, ""
        if shell == "guest":
            if not self.pve_clients:
                return False, "no PVE instance configured"
            return True, ""
        if shell == "files":
            if not ssh_ready:
                return False, "no SSH target configured"
            return True, ""
        return False, f"unknown shell prerequisite {shell!r}"

    def _wrap(
        self,
        fn: Callable[..., Awaitable[Any]],
        *,
        name: str,
        category: Category,
        pve: tuple[Privilege, ...],
        pbs: tuple[Privilege, ...],
    ) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)
        async def wrapper(**kwargs: Any) -> str:
            started = __import__("time").monotonic()
            instance = kwargs.get("instance")
            target = _target(kwargs)
            status = "ok"
            try:
                self.policy.check_call(name, category, kwargs)
                if pve:
                    pve_client = self.pve(instance)
                    self.capabilities.check_pve(pve_client.name, pve, kwargs)  # type: ignore[union-attr]
                    instance = pve_client.name
                elif pbs:
                    pbs_client = self.pbs(instance)
                    self.capabilities.check_pbs(pbs_client.name, pbs, kwargs)  # type: ignore[union-attr]
                    instance = pbs_client.name
                result = await fn(**kwargs)
                text = result if isinstance(result, str) else dumps(result)
                if len(text.encode("utf-8")) > self.settings.max_output_bytes:
                    text = _shrink(text, self.settings.max_output_bytes)
                return text
            except PolicyError as exc:
                status = "denied"
                return fail(exc.code, exc.message, **exc.details)
            except PVEHubError as exc:
                status = "error"
                return fail(exc.code, exc.message, **exc.details)
            except Exception as exc:
                logger.exception("tool %s failed", name)
                status = "error"
                return fail("internal_error", f"{exc.__class__.__name__}: {exc}")
            finally:
                duration = int((__import__("time").monotonic() - started) * 1000)
                await self.audit.write(
                    tool=name,
                    category=category,
                    status=status,
                    instance=instance if isinstance(instance, str) else None,
                    target=target,
                    params=kwargs,
                    duration_ms=duration,
                )

        return wrapper

    def _register_all(self) -> None:
        from . import prompts, resources
        from .tools import (
            exec_host,
            exec_lxc,
            exec_pbs,
            exec_vm,
            files,
            meta,
            pbs_datastore,
            pbs_generic,
            pbs_jobs,
            pbs_snapshots,
            pbs_tasks,
            pve_access,
            pve_backup,
            pve_cluster,
            pve_generic,
            pve_guests,
            pve_network,
            pve_storage,
            pve_tasks,
        )

        meta.register(self)
        pve_generic.register(self)
        pve_cluster.register(self)
        pve_guests.register(self)
        pve_storage.register(self)
        pve_backup.register(self)
        pve_network.register(self)
        pve_access.register(self)
        pve_tasks.register(self)
        pbs_generic.register(self)
        pbs_datastore.register(self)
        pbs_snapshots.register(self)
        pbs_jobs.register(self)
        pbs_tasks.register(self)
        exec_vm.register(self)
        exec_lxc.register(self)
        exec_host.register(self)
        exec_pbs.register(self)
        files.register(self)
        resources.register(self)
        prompts.register(self)

    # -- reporting ---------------------------------------------------------
    def capabilities_report(self) -> dict[str, Any]:
        shell = {
            "ssh_configured": bool(self.settings.ssh.nodes or self.settings.ssh.pbs),
            "ssh_targets": sorted(self.settings.ssh.nodes),
            "pbs_target": bool(self.settings.ssh.pbs),
            "host": self.policy.file.exec.host,
            "lxc": self.policy.file.exec.lxc,
            "vm": self.policy.file.exec.vm,
            "pbs_host": self.policy.file.exec.pbs_host,
            "allowed_vmids": self.policy.file.exec.allowed_vmids,
            "missing": self.settings.ssh.missing_prerequisites()
            if (self.settings.ssh.nodes or self.settings.ssh.pbs)
            else [],
        }
        return {
            "version": __version__,
            "policy": {
                "source": self.policy.source,
                "sha256": self.policy.sha256,
                "read_only": self.policy.file.read_only,
                "denied_tools": self.policy.file.tools.deny,
                "allowed_tools": self.policy.file.tools.allow,
                "denied_categories": self.policy.file.categories.deny,
                "require_confirm_for": self.policy.file.safety.require_confirm_for,
                "generic_deny_methods": self.policy.file.generic_api.deny_methods,
            },
            "tools": {
                "registered": len(self.registered),
                "names": sorted(self.registered),
                "blocked": [
                    {"name": item.name, "category": item.category, "reason": item.reason}
                    for item in self.blocked
                ],
            },
            "capabilities": self.capabilities.report() if self.capabilities else None,
            "shell": shell,
            "audit": {"enabled": self.audit.enabled, "path": str(self.audit.path) if self.audit.path else None},
        }

    def health(self) -> dict[str, Any]:
        status = "ok"
        if self.capabilities:
            snapshots = [*self.capabilities.pve.values(), *self.capabilities.pbs.values()]
            if any(snapshot.error for snapshot in snapshots):
                status = "degraded"
        return {
            "status": status,
            "version": __version__,
            "transport": self.settings.transport,
            "tools": len(self.registered),
        }


class BearerAuthMiddleware:
    """Constant-time bearer check for the MCP endpoint."""

    def __init__(self, app: Any, token: str, protected_prefix: str = "/mcp") -> None:
        self.app = app
        self.token = token
        self.protected_prefix = protected_prefix

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or not scope.get("path", "").startswith(self.protected_prefix):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        expected = f"Bearer {self.token}"
        if not secrets.compare_digest(supplied, expected):
            response = JSONResponse(
                {"error": "unauthorized", "message": "missing or invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def build_http_app(hub: PVEHub) -> Starlette:
    transport_security = None
    if hub.settings.allowed_hosts:
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=hub.settings.allowed_hosts,
            allowed_origins=hub.settings.allowed_hosts,
        )
    else:
        transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = hub.mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        host=hub.settings.host,
        transport_security=transport_security,
    )

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse(hub.health())

    app.router.routes.insert(0, Route("/health", health, methods=["GET"]))
    if hub.settings.mcp_auth_token is not None:
        app.add_middleware(
            BearerAuthMiddleware,
            token=hub.settings.mcp_auth_token.get_secret_value(),
            protected_prefix="/mcp",
        )
    return app


def _target(kwargs: dict[str, Any]) -> str | None:
    for key in ("vmid", "node", "store", "name", "path", "command"):
        value = kwargs.get(key)
        if value is not None:
            return f"{key}={value}"
    return None


def _shrink(text: str, limit: int) -> str:
    try:
        payload = json.loads(text)
    except ValueError:
        return text[:limit] + "\n...[truncated]"
    if isinstance(payload, dict) and "data" in payload:
        preview = dumps(payload["data"])[: max(512, limit // 2)]
        payload["data"] = {"truncated": True, "preview": preview}
        payload["truncated"] = True
    else:
        payload = {"ok": False, "error": {"code": "output_too_large", "message": "response truncated"}}
    return dumps(payload)
