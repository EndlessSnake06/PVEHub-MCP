"""Server assembly: MCP instance, auth, tool registration, health."""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ._version import __version__ as __version__
from .audit import AuditLogger, redact_value
from .capabilities import CapabilityManager, Privilege
from .clientid import LEGACY, client_context, current_client, resolve_client
from .clients.pbs import PBSClient
from .clients.pve import PVEClient
from .clients.ssh import SSHClientPool
from .config import Settings
from .errors import (
    AuthenticationError,
    InvalidArgument,
    NotFound,
    PermissionDenied,
    PolicyError,
    PVEHubError,
)
from .memory import (
    MemoryStore,
    derive_subjects,
    event_summary,
    should_record_event,
)
from .passthrough import (
    PVEToken,
    TokenState,
    TokenValidationCache,
    make_snapshot,
    parse_pve_bearer,
    pve_bearer_context,
    pve_scoped_context,
)
from .policy import Category, Policy
from .proxy import is_trusted, parse_trusted_proxies, resolve_client_ip
from .toolnaming import derive_title
from .tools.common import dumps, fail

logger = logging.getLogger(__name__)

# Stable, greppable notes appended to the description of every tool whose
# category is in ``safety.require_confirm_for``. The static doc generator
# (scripts/generate_tool_docs.py) mirrors these strings: it must not import
# the server, so keep the two copies in sync.
CONFIRM_NOTE = "This tool is protected: the call is rejected unless confirm=true is passed."
CONFIRM_DRY_RUN_NOTE = " Use dry_run=true to preview the effect without executing."


@dataclass
class RegisteredTool:
    name: str
    category: Category
    description: str
    title: str
    confirm_required: bool
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
        # D024 (issue #25): the trusted-proxy set is parsed once here —
        # config validation guarantees it is valid (or empty) by the time
        # Settings is constructed, so this cannot fail.
        self._trusted_nets = parse_trusted_proxies(",".join(settings.trusted_proxies))
        self.policy = policy or Policy.load(settings.policy_file)
        self.audit = AuditLogger(
            settings.audit_log,
            include_results=settings.audit_include_results,
            max_string=max(2048, settings.max_output_bytes // 8),
            max_bytes=settings.audit_max_bytes,
            keep=settings.audit_keep,
        )
        # Memory layer (epic #31). The store opens its SQLite file here; an
        # unwritable path disables the feature without stopping the server.
        self.memory = MemoryStore(
            settings.memory_db_path,
            enabled=settings.memory_enabled,
            note_max_bytes=settings.memory_note_max_bytes,
            enrich_enabled=settings.memory_enrich,
            enrich_max_bytes=settings.memory_enrich_max_bytes,
            enrich_max_notes=settings.memory_enrich_max_notes,
            max_output_bytes=settings.max_output_bytes,
            retention_days=settings.memory_retention_days,
            event_retention_days=settings.memory_event_retention_days,
            tombstone_days=settings.memory_tombstone_days,
            cleanup_interval_seconds=settings.memory_cleanup_interval_seconds,
            max_notes=settings.memory_max_notes,
        )
        self.ssh = SSHClientPool(settings.ssh)
        self.pve_clients: dict[str, PVEClient] = {}
        self.pbs_clients: dict[str, PBSClient] = {}
        self.capabilities: CapabilityManager | None = None
        self.registered: dict[str, RegisteredTool] = {}
        self.blocked: list[BlockedTool] = []
        self._initialized = False
        self._mcp: MCPServer | None = None
        # D026 (issue #30): token pass-through. The flag is fixed at
        # construction (config-validated); the per-(instance, token)
        # validation cache is created in initialize() once the PVE
        # instances exist.
        self._passthrough = settings.mcp_auth_mode == "passthrough"
        self._token_cache: TokenValidationCache | None = None

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
        # D026 (issue #30): the per-(instance, token) validation cache. It is
        # only created in passthrough mode — in static mode the configured
        # service token is the (single) credential and nothing is validated
        # per request.
        if self._passthrough:
            self._token_cache = TokenValidationCache(
                ttl_seconds=float(self.settings.mcp_token_validation_ttl),
            )
        self._register_all()
        await self.capabilities.start_periodic_refresh()
        # Cleanup once at startup (expired notes, retention, tombstones) and
        # then periodically; both are best-effort and never block startup.
        if self.memory.enabled:
            try:
                await self.memory.cleanup()
            except Exception:
                logger.exception("memory cleanup at startup failed")
            await self.memory.start_cleanup_task()
        self._initialized = True

    async def close(self) -> None:
        if self.capabilities is not None:
            await self.capabilities.stop()
        for client in [*self.pve_clients.values(), *self.pbs_clients.values()]:
            await client.aclose()
        # D026 (issue #30): per-request PVE clients are one-per
        # (instance, token); they close with the validation cache.
        if self._token_cache is not None:
            for state in await self._token_cache.clear():
                try:
                    await state.client.aclose()
                except Exception:
                    logger.debug("closing per-request PVE client failed", exc_info=True)
        await self.ssh.close()
        await self.memory.close()

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
        # D026 (issue #30): in passthrough mode the (unchanged) tool code
        # must call PVE with the *requesting client's own* API token, not
        # the configured service token. The wrapper validated the bearer and
        # stored the resulting TokenState in pve_scoped_context before the
        # tool ran; hand that per-request client out.
        #
        # Fail-closed: with no validated per-request token for this
        # instance there is no legal PVE call — the configured service token
        # is never used as a fallback.
        if self._passthrough:
            state = pve_scoped_context.get()
            if state is not None and state.instance == name:
                return state.client
            raise AuthenticationError(
                f"pve {name}: no validated PVE API token in the current request "
                "context; passthrough mode does not fall back to the configured "
                "service token"
            )
        return self.pve_clients[name]

    def pbs(self, instance: str | None = None) -> PBSClient:
        # D026 (issue #30): a PVE API token is not valid on the PBS API. In
        # passthrough mode the only credential in a request is a PVE token,
        # so there is no legal PBS call — fail-closed (PBS tools are also
        # blocked at registration, so this is defense in depth).
        if self._passthrough:
            raise AuthenticationError(
                "pbs: PVE API tokens are not valid on the PBS API; passthrough "
                "mode does not use the configured PBS service token"
            )
        name = self._instance_name("pbs", instance, self.pbs_clients)
        return self.pbs_clients[name]

    def _instance_name(self, kind: str, instance: str | None, clients: dict[str, Any]) -> str:
        if not clients:
            raise InvalidArgument(f"no {kind.upper()} instance configured")
        if instance is None:
            return next(iter(clients))
        if instance not in clients:
            raise InvalidArgument(
                f"unknown {kind.upper()} instance {instance!r}; configured: {', '.join(clients)}"
            )
        return instance

    # -- token pass-through (D026, issue #30) ------------------------------
    def _request_pve_token(self, ctx: Context | None) -> PVEToken | None:
        """The per-request PVE API token (D026, issue #30), or ``None``.

        The bearer is read from the raw HTTP request — the only channel that
        reaches the tool even when the SDK runs the call in a task other than
        the middleware's (see :func:`_raw_request`). If the middleware's
        parsed token is already in the current context (same task), it is
        preferred; otherwise the raw header is re-parsed.

        Fail-closed: a malformed bearer raises
        :class:`~pvehub_mcp.errors.AuthenticationError`. The middleware has
        already answered the structural case with a 401 at the edge; this is
        defense in depth. Returns ``None`` only when there is no HTTP request
        at all (stdio) — config validation forbids passthrough on stdio, so
        this path is unreachable in a valid passthrough deployment.
        """
        token = pve_bearer_context.get()
        if token is not None:
            return token
        request = _raw_request(ctx)
        if request is None:
            return None
        raw = request.headers.get("authorization", "")
        token = parse_pve_bearer(raw)
        if token is None:
            raise AuthenticationError(
                "invalid PVE API token in the Authorization header (expected: "
                "Bearer <token-id>=<token-secret>); passthrough mode is fail-closed "
                "and does not fall back to the configured service token"
            )
        return token

    def _scoped_pve(self, instance: str, token: PVEToken) -> PVEClient:
        """A :class:`PVEClient` bound to ``token`` for ``instance`` (D026).

        The instance's network configuration (URL, TLS, timeout, retries) is
        reused from the configured instance; only the credentials become the
        request's token. This is the client the (unchanged) tool code calls:
        its ``Authorization`` header carries the request's token, so PVE
        authorizes every call against the requesting client's own ACL.
        """
        cfg = self.settings.pve_instance(instance)
        return PVEClient(
            name=cfg.name,
            url=cfg.url,
            api_path=cfg.api_path,
            token_id=token.token_id,
            token_secret=token.token_secret,
            verify=cfg.verify,
            ca_file=cfg.ca_file,
            fingerprint=cfg.fingerprint,
            timeout_seconds=cfg.timeout_seconds,
            max_retries=cfg.max_retries,
            state_dir=self.settings.state_dir,
        )

    async def _validate_pve_token(
        self,
        instance: str | None,
        token: PVEToken,
    ) -> TokenState:
        """Validate ``token`` against the PVE ``instance`` (D026, issue #30).

        Fail-closed and cached per (instance, token-identity):

        * A cached, still-valid entry is returned without a round-trip. The
          cache key contains the full token identity, so a rotated token is a
          different key (re-validated immediately) and two clients with
          different tokens never share an entry or a permission snapshot.
        * Otherwise one round-trip to ``GET /access/permissions`` plays double
          duty: a 401 means the token is rejected (fail-closed, no fallback
          to the configured token); a 403 means the token is valid but lacks
          ``Sys.Audit`` (a valid identity — the per-token snapshot records the
          discovery failure and PVE keeps enforcing per call, with the
          call-time gate applying the fail_open policy); a 200 yields the
          per-token permission snapshot.
        * The resulting :class:`TokenState` carries the per-request client
          (bound to the token); the caller stores it in
          :data:`pve_scoped_context` so the (unchanged) tool code and
          :meth:`pve` transparently use the request's credentials.
        """
        name = self._instance_name("pve", instance, self.pve_clients)
        if self._token_cache is None:
            raise AuthenticationError(
                f"pve {name}: passthrough validation is unavailable (token cache not initialized)"
            )
        cached = await self._token_cache.get(token.key(name))
        if cached is not None:
            return cached
        client = self._scoped_pve(name, token)
        try:
            permissions = await client.permissions()
        except AuthenticationError as exc:
            await client.aclose()
            raise AuthenticationError(
                f"pve {name}: PVE rejected the bearer token {token.token_id} "
                "(HTTP 401); passthrough mode is fail-closed and does not fall back "
                "to the configured service token"
            ) from exc
        except PermissionDenied:
            # PVE authenticates before it ACLs, so a 403 proves the token is
            # valid but lacks Sys.Audit. The identity is trusted; discovery
            # is recorded as failed and PVE keeps enforcing per call.
            logger.warning(
                "pve %s: PVE API token %s lacks Sys.Audit; per-token capability "
                "discovery unavailable (PVE enforces per call)",
                name,
                token.token_id,
            )
            snapshot = make_snapshot(
                instance=name,
                error="HTTP 403 on /access/permissions (token lacks Sys.Audit); PVE enforces per call",
            )
        else:
            snapshot = make_snapshot(instance=name, permissions=permissions)
        state = TokenState(instance=name, token=token, client=client, snapshot=snapshot)
        for evicted in await self._token_cache.put(state):
            try:
                await evicted.client.aclose()
            except Exception:
                logger.debug("closing evicted per-request PVE client failed", exc_info=True)
        return state

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
        title: str | None = None,
        pve: Sequence[tuple[str, str]] = (),
        pbs: Sequence[tuple[str, str]] = (),
        shell: str | None = None,
        service: str | None = None,
        dry_run: bool = False,
    ) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """Register a tool function.

        ``title`` is an optional human-readable display name for the tool.
        When omitted, the title is derived from ``name`` (``toolnaming``),
        which produces consistent, readable labels (``pve_guest_delete`` ->
        ``PVE Guest Delete``) without a per-tool hand-written string.
        """

        def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            self._register(
                fn,
                name=name,
                category=category,
                title=title,
                pve=pve,
                pbs=pbs,
                shell=shell,
                service=service,
                dry_run=dry_run,
            )
            return fn

        return decorator

    def block_tool(self, name: str, category: Category, reason: str) -> None:
        """Report a tool that is not exposed, with the reason (#34)."""

        self.blocked.append(BlockedTool(name, category, reason))
        logger.info("tool %s blocked: %s", name, reason)

    def _register(
        self,
        fn: Callable[..., Awaitable[Any]],
        *,
        name: str,
        category: Category,
        title: str | None,
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
        # D026 (issue #30): passthrough mode is PVE-only. A PVE API token is
        # not valid on the PBS API, and the only credential in a passthrough
        # request is a PVE token — so no PBS tool is exposed in passthrough
        # mode (fail-closed; the reason is reported like any other block).
        if self._passthrough and service == "pbs":
            self.blocked.append(
                BlockedTool(
                    name,
                    category,
                    "passthrough: PVE API tokens are not valid on the PBS API "
                    "(run in static mode for PBS access)",
                )
            )
            logger.info("tool %s blocked: passthrough (PBS)", name)
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
        # D026 (issue #30): in passthrough mode the request's PVE token is
        # unknown at registration time, so the configured service token's
        # permission snapshot must not gate tool visibility (it is not the
        # request's credential). Visibility is therefore not permission-
        # filtered in passthrough mode; the call-time per-token gate
        # (check_pve_token_snapshot) is the security boundary and PVE keeps
        # enforcing every call with the request's own ACL.
        if pve_reqs and not self._passthrough:
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
        title_text = (title or "").strip() or derive_title(name)
        confirm_required = category in self.policy.file.safety.require_confirm_for
        description = (fn.__doc__ or name).strip()
        if confirm_required:
            note = CONFIRM_NOTE
            if "dry_run" in inspect.signature(fn).parameters:
                note += CONFIRM_DRY_RUN_NOTE
            description = f"{description}\n\n{note}"
        annotations = ToolAnnotations(
            title=title_text,
            readOnlyHint=category in {"read", "memory"},
            destructiveHint=category == "destructive",
            idempotentHint=category in {"read", "generic", "memory"},
            openWorldHint=False,
        )
        self.mcp.add_tool(
            wrapped,
            name=name,
            title=title_text,
            description=description,
            annotations=annotations,
            meta={"category": category, "confirm_required": confirm_required},
            structured_output=False,
        )
        self.registered[name] = RegisteredTool(
            name=name,
            category=category,
            description=description,
            title=title_text,
            confirm_required=confirm_required,
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
        # functools.wraps() is deliberately NOT used: it would copy fn's
        # __annotations__ over this wrapper's ``ctx: Context | None``
        # signature and silently disable the SDK's Context injection (the
        # SDK resolves injectable parameters through
        # typing.get_type_hints(), which follows __wrapped__ into the
        # original function — see the comment below the __annotations__
        # assignment for the full mechanics).
        async def wrapper(ctx: Context | None = None, **kwargs: Any) -> str:
            started = __import__("time").monotonic()
            instance = kwargs.get("instance")
            target = _target(kwargs)
            # D019 (issue #21): the middleware set the client name for http
            # requests; stdio/loopback dev setups resolve to "unknown".
            client = current_client()
            status = "ok"
            error: dict[str, Any] | None = None
            response: str | None = None
            # D026 (issue #30): passthrough request-local state. The reset
            # token is captured when the validated TokenState is published into
            # pve_scoped_context (so the unchanged tool code and the pve()
            # accessor transparently use the request's own PVE API token) and
            # is undone in the finally block. pve_token_id is the *identity*
            # (user@realm!tokenid) for the audit entry — never the secret.
            pve_scoped_token = None
            pve_token_id: str | None = None
            try:
                supports_dry_run = "dry_run" in inspect.signature(fn).parameters
                self.policy.check_call(name, category, kwargs, dry_run_supported=supports_dry_run)
                if pve:
                    if self._passthrough:
                        # D026 (issue #30): the bearer *is* the PVE API token.
                        # Validate it against the PVE (fail-closed, cached per
                        # full token identity), publish the resulting
                        # TokenState so the (unchanged) tool code calls PVE
                        # with *this* token, then gate on the per-token
                        # permission snapshot (PVE still enforces per call).
                        token = self._request_pve_token(ctx)
                        if token is None:
                            raise AuthenticationError(
                                "pve: no PVE API token in the current request; "
                                "passthrough mode is fail-closed and does not "
                                "fall back to the configured service token"
                            )
                        state = await self._validate_pve_token(instance, token)
                        pve_scoped_token = pve_scoped_context.set(state)
                        pve_token_id = token.token_id
                        pve_client = state.client
                        self.capabilities.check_pve_token_snapshot(  # type: ignore[union-attr]
                            state.instance, state.snapshot, pve, kwargs
                        )
                    else:
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
                # Enrichment runs after the size cap and is strictly fail-open:
                # a broken memory path returns the original text unchanged.
                text = await self.memory.enrich(name, kwargs, text)
                response = text
                return text
            except PolicyError as exc:
                status = "denied"
                error = {"code": exc.code, "message": exc.message}
                response = fail(exc.code, exc.message, **exc.details)
                return response
            except PVEHubError as exc:
                status = "error"
                error = {"code": exc.code, "message": exc.message}
                response = fail(exc.code, exc.message, **exc.details)
                return response
            except Exception as exc:
                logger.exception("tool %s failed", name)
                status = "error"
                error = {"code": "internal_error", "message": f"{exc.__class__.__name__}: {exc}"}
                response = fail("internal_error", f"{exc.__class__.__name__}: {exc}")
                return response
            finally:
                # D026 (issue #30): release the per-request PVE token from the
                # request context so a subsequent tool call (same task) cannot
                # accidentally reuse it.
                if pve_scoped_token is not None:
                    pve_scoped_context.reset(pve_scoped_token)
                duration = int((__import__("time").monotonic() - started) * 1000)
                # D024 (issue #25): resolve the client address through the
                # trusted-proxy rules; "unknown" when not resolvable, like
                # the client name above (stdio, missing socket peer).
                client_ip = _client_ip(ctx, self._trusted_nets)
                await self.audit.write(
                    tool=name,
                    category=category,
                    status=status,
                    instance=instance if isinstance(instance, str) else None,
                    target=target,
                    params=kwargs,
                    duration_ms=duration,
                    output_bytes=len(response.encode("utf-8")) if response is not None else None,
                    error=error,
                    result=response,
                    client=client,
                    client_ip=client_ip,
                    # D026 (issue #30): the PVE API token *identity* used for
                    # the call (passthrough only; None in static mode). The
                    # secret is never written.
                    pve_token=pve_token_id,
                )
                # Issue #33: metadata only, never command text or guest output.
                if should_record_event(category, kwargs):
                    await self.memory.record_event(
                        tool=name,
                        category=category,
                        status=status,
                        client=client,
                        subjects=derive_subjects(kwargs, include_path=category != "exec"),
                        summary=event_summary(name, category, status, kwargs),
                        instance=instance if isinstance(instance, str) else None,
                        duration_ms=duration,
                        error_code=str(error["code"]) if error else None,
                    )

        # The SDK locates the injectable parameter via
        # typing.get_type_hints(), which for string annotations follows
        # __wrapped__ to the ORIGINAL function and evaluates the string in
        # that function's module (pvehub_mcp.tools.*) — "Context" is not
        # imported there, so the string would raise NameError and the
        # injection would silently disable.  The real type object needs no
        # evaluation and is passed through verbatim.  The unsubscripted
        # class must stay in the annotation: a parametrized generic
        # (Context[Any, Any]) would not match the SDK's isclass()/
        # issubclass() check.
        wrapper.__name__ = fn.__name__
        wrapper.__qualname__ = fn.__qualname__
        wrapper.__module__ = fn.__module__
        wrapper.__doc__ = fn.__doc__
        wrapper.__annotations__ = {"ctx": Context | None, "kwargs": Any, "return": str}
        # func_metadata() derives the input schema through
        # inspect.signature(), which follows __wrapped__ to the original
        # function — the tool schema therefore stays identical to before.
        # (setattr: the mypy model of a function type has no __wrapped__
        # attribute; the SDK's schema derivation needs it at runtime.)
        setattr(wrapper, "__wrapped__", fn)  # noqa: B010

        return wrapper

    def _register_all(self) -> None:
        from . import prompts, resources
        from .tools import (
            exec_host,
            exec_lxc,
            exec_pbs,
            exec_vm,
            files,
            memory,
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
        memory.register(self)
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
            # D026 (issue #30): how the MCP endpoint authenticates callers.
            # In passthrough mode the PVE API token is the credential (the
            # per-request validation and its TTL are what matter), so the
            # configured named-token state is irrelevant and omitted.
            "auth": {
                "mode": self.settings.mcp_auth_mode,
                "required": self.settings.mcp_auth_required,
                "token_validation_ttl": self.settings.mcp_token_validation_ttl
                if self.settings.mcp_auth_mode == "passthrough"
                else None,
            },
            "shell": shell,
            # Issue #32: state of the memory layer, including the reason when
            # it is disabled (read-only FS, missing permissions, wrong path).
            "memory": self.memory.report(),
            # D023 (issue #19): rotation settings and the last write error so
            # a silently stopped audit is visible, not only in the container log.
            "audit": {
                "enabled": self.audit.enabled,
                "path": str(self.audit.path) if self.audit.path else None,
                "size_bytes": self.audit.size_bytes,
                "max_bytes": self.audit.max_bytes,
                "keep": self.audit.keep,
                "error": self.audit.error,
            },
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
    """Constant-time bearer check with per-client audit attribution (D019).

    ``credentials`` maps client name -> bearer token; the legacy single token
    is exposed under the reserved name :data:`pvehub_mcp.clientid.LEGACY`.
    On success the resolved client name is stored in
    :data:`pvehub_mcp.clientid.client_context` for the duration of the
    request, so the tool wrapper can attribute every audit entry (issue #21).
    The ``/mcp`` prefix is owned by the MCP SDK app; additional exact paths
    (the ``/ready`` readiness endpoint) are listed in ``protected_paths``.
    """

    def __init__(
        self,
        app: Any,
        credentials: dict[str, str],
        protected_prefix: str = "/mcp",
        protected_paths: frozenset[str] = frozenset(),
    ) -> None:
        self.app = app
        self.credentials = credentials
        self.protected_prefix = protected_prefix
        self.protected_paths = protected_paths

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not (path.startswith(self.protected_prefix) or path in self.protected_paths):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        client = resolve_client(supplied, self.credentials)
        if client is None:
            response = JSONResponse(
                {"error": "unauthorized", "message": "missing or invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        token = client_context.set(client)
        try:
            await self.app(scope, receive, send)
        finally:
            client_context.reset(token)


class PassthroughBearerMiddleware:
    """Structural bearer gate for passthrough mode (D026, issue #30).

    In passthrough mode the *PVE API token* is the credential: there is no
    named MCP client and no configured MCP bearer to match against. This
    middleware enforces only the *shape* of the ``Authorization`` header (a
    well-formed PVE API token) and answers a 401 for a missing or malformed
    bearer before any PVE round-trip. It does **not** validate the token
    against PVE — that happens per request in the tool wrapper, where the
    target PVE instance is known (a PVE token is only meaningful against the
    PVE that issued it).

    The parsed token is stored in
    :data:`pvehub_mcp.passthrough.pve_bearer_context` for the request (a
    same-task convenience); the wrapper re-derives it from the raw HTTP
    request when the SDK runs the tool in a task other than the
    middleware's, so the raw request remains the authoritative channel. The
    client *name* is not resolvable in passthrough mode (no named MCP
    client), so :data:`pvehub_mcp.clientid.client_context` keeps its
    ``"unknown"`` default and the PVE token *identity* is carried in the
    audit's ``pve_token`` field instead.
    """

    def __init__(
        self,
        app: Any,
        *,
        protected_prefix: str = "/mcp",
        protected_paths: frozenset[str] = frozenset(),
    ) -> None:
        self.app = app
        self.protected_prefix = protected_prefix
        self.protected_paths = protected_paths

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not (path.startswith(self.protected_prefix) or path in self.protected_paths):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        token = parse_pve_bearer(supplied)
        if token is None:
            response = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "missing or malformed PVE API token (expected: "
                    "Bearer <user@realm!tokenid>=<secret>)",
                },
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        tok = pve_bearer_context.set(token)
        try:
            await self.app(scope, receive, send)
        finally:
            pve_bearer_context.reset(tok)


class TrustedProxyMiddleware:
    """Reject direct (non-proxy) access to the protected MCP routes (D024).

    Only active when ``require_trusted_proxy`` is set; with the default
    configuration this middleware does nothing and the behaviour is
    unchanged.  It runs **outside** the bearer middleware (installed
    second), so a direct request from an untrusted network gets a 403
    *before* any 401.  ``/health`` is deliberately exempt: the container
    healthcheck may probe from the bridge network and must not be turned
    into a failed container — liveness without a token is acceptable (no
    secret is exposed), readiness on ``/ready`` stays protected.
    """

    def __init__(
        self,
        app: Any,
        networks: tuple[Any, ...],
        *,
        require: bool,
        protected_prefix: str = "/mcp",
        protected_paths: frozenset[str] = frozenset(),
    ) -> None:
        self.app = app
        self.networks = networks
        self.require = require
        self.protected_prefix = protected_prefix
        self.protected_paths = protected_paths

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if not self.require or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not (path.startswith(self.protected_prefix) or path in self.protected_paths):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        peer = client[0] if client else ""
        if peer and is_trusted(peer, self.networks):
            await self.app(scope, receive, send)
            return
        # No client in the scope (some test harnesses) or an untrusted
        # peer: the 403 is the documented contract for both — without a
        # verifiable socket peer we cannot trust anything.
        response = JSONResponse(
            {
                "error": "proxy_required",
                "message": "this endpoint is only reachable via a configured "
                "trusted proxy (PVEHUB_TRUSTED_PROXIES)",
            },
            status_code=403,
        )
        await response(scope, receive, send)


def _raw_request(ctx: Context | None) -> Request | None:
    """Extract the raw starlette request from the injected MCP context.

    The MCP SDK attaches the per-message HTTP request to the request
    context (``ServerRequestContext.request``) for both the legacy and the
    modern streamable-http path — this is the only channel that reaches the
    tool call even when the SDK runs the call in a task that is not the
    middleware task (where a ContextVar set by middleware would be lost).
    Returns ``None`` outside of an HTTP request (stdio transport, or an SDK
    version whose request context has no raw request attached).
    """
    if ctx is None:
        return None
    try:
        request_context = ctx.request_context
    except (ValueError, AttributeError):
        return None
    request = getattr(request_context, "request", None)
    return request if isinstance(request, Request) else None


def _client_ip(ctx: Context | None, trusted_nets: tuple[Any, ...]) -> str | None:
    """Resolve the client address for audit attribution (D024, issue #25).

    Applies the trusted-proxy rules from :mod:`pvehub_mcp.proxy`; returns
    ``None`` (→ "unknown" in the audit entry) when the request cannot be
    resolved — stdio transport, or an ASGI scope without a socket client.
    """
    request = _raw_request(ctx)
    if request is None:
        return None
    peer = request.client.host if request.client is not None else ""
    if not peer:
        return None
    return resolve_client_ip(peer, request.headers.get("x-forwarded-for"), trusted_nets)


def _transport_security(settings: Settings) -> TransportSecuritySettings:
    """Build DNS-rebinding settings.

    A loopback-only server is the default and needs no bearer token, so it must
    still reject foreign ``Host`` headers (a browser can be tricked into talking
    to 127.0.0.1 via DNS rebinding).  For non-loopback binds the operator has to
    list the hostnames clients use; an empty list keeps the old behaviour and
    logs a warning because the bearer token is the only remaining control.
    """

    if settings.allowed_hosts:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
            allowed_origins=list(settings.allowed_hosts),
        )
    if settings.host in {"127.0.0.1", "::1", "localhost"}:
        hosts = [
            "127.0.0.1",
            "127.0.0.1:*",
            "localhost",
            "localhost:*",
            "[::1]",
            "[::1]:*",
        ]
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=hosts,
            allowed_origins=hosts,
        )
    logger.warning(
        "DNS-rebinding protection is disabled (allowed_hosts is empty); "
        "set PVEHUB_ALLOWED_HOSTS to the hostnames clients use"
    )
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def build_http_app(hub: PVEHub) -> Starlette:
    transport_security = _transport_security(hub.settings)
    app = hub.mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        host=hub.settings.host,
        transport_security=transport_security,
    )

    async def health(_request: Request) -> JSONResponse:
        # Liveness only: always 200 while the process runs. Backend health is
        # reported by the authenticated /ready endpoint and the pvehub_health
        # tool; /health deliberately exposes no version or tool count.
        return JSONResponse({"status": "ok"})

    async def ready(_request: Request) -> JSONResponse:
        body = hub.health()
        status_code = 200 if body.get("status") == "ok" else 503
        return JSONResponse(body, status_code=status_code)

    app.router.routes.insert(0, Route("/ready", ready, methods=["GET"]))
    app.router.routes.insert(0, Route("/health", health, methods=["GET"]))
    if hub._passthrough:
        # D026 (issue #30): the PVE API token is the credential — there is no
        # named MCP client and no configured MCP bearer to match. The
        # structural bearer gate runs on /mcp and /ready; the per-request PVE
        # validation (fail-closed, per-token cache) happens in the tool
        # wrapper, where the target PVE instance is known.
        app.add_middleware(
            PassthroughBearerMiddleware,
            protected_prefix="/mcp",
            protected_paths=frozenset({"/ready"}),
        )
    else:
        credentials: dict[str, str] = {}
        if hub.settings.mcp_auth_token is not None:
            credentials[LEGACY] = hub.settings.mcp_auth_token.get_secret_value()
        credentials.update(hub.settings.mcp_auth_tokens)
        if credentials:
            app.add_middleware(
                BearerAuthMiddleware,
                credentials=credentials,
                protected_prefix="/mcp",
                protected_paths=frozenset({"/ready"}),
            )
        else:
            logger.warning(
                "MCP endpoint /mcp is UNAUTHENTICATED (mcp_auth_required=false); "
                "loopback development setups only - do not expose this port"
            )
    # D024 (issue #25): the trusted-proxy gate is installed *after* the
    # bearer middleware, i.e. as the outermost layer, so a direct request
    # from an untrusted network gets a 403 before any 401.
    if hub.settings.require_trusted_proxy or hub.settings.trusted_proxies:
        app.add_middleware(
            TrustedProxyMiddleware,
            hub._trusted_nets,
            require=hub.settings.require_trusted_proxy,
            protected_prefix="/mcp",
            protected_paths=frozenset({"/ready"}),
        )
    return app


_TARGET_KEYS = ("vmid", "node", "store", "name", "path", "command")


def _target(kwargs: dict[str, Any]) -> str | dict[str, str] | None:
    """Collect **all** present target keys, redacted (D023, issue #18).

    A single key keeps the legacy string form so existing log consumers keep
    working; two or more keys are returned as a ``{key: "key=value"}`` dict.
    """

    parts: dict[str, str] = {}
    for key in _TARGET_KEYS:
        value = kwargs.get(key)
        if value is not None:
            redacted = redact_value(f"{key}={value}")
            parts[key] = redacted if isinstance(redacted, str) else str(redacted)
    if not parts:
        return None
    if len(parts) == 1:
        return next(iter(parts.values()))
    return parts


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
