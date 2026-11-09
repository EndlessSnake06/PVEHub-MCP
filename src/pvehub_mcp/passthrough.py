"""Bearer-token pass-through: the MCP bearer *is* the PVE API token.

D026 (issue #30): in ``passthrough`` mode the server does not call PVE with a
globally configured service token. Every request arrives carrying the
*requesting client's own* PVE API token in the ``Authorization`` header
(``Bearer <token-id>=<token-secret>``); the server validates that token
against the PVE it is about to call, reuses it for every PVE request of that
call, and never falls back to a configured token (fail-closed).

What lives here:

* :func:`parse_pve_bearer` — the structural contract of the bearer. Used by
  the edge middleware (401 for missing/malformed) and by the tool wrapper
  (defense in depth when the middleware was bypassed).
* :class:`TokenState` — the result of one validation: the per-request
  :class:`~pvehub_mcp.clients.pve.PVEClient` bound to this exact token, the
  per-token :class:`~pvehub_mcp.capabilities.CapabilitySnapshot`, and the
  instance name it was validated against.
* :class:`TokenValidationCache` — a bounded, TTL-based cache of per
  (instance, token) validations. The key includes the *full* token identity,
  so two clients with different PVE tokens never share a validated state or a
  permission snapshot (issue #30, acceptance criterion 5).
* :data:`pve_bearer_context` / :data:`pve_scoped_context` — the two
  request-local channels. The middleware stores the *parsed* token in
  :data:`pve_bearer_context`; the wrapper validates it and stores the
  resulting :class:`TokenState` in :data:`pve_scoped_context`, which
  :meth:`pvehub_mcp.server.PVEHub.pve` consults so the (unchanged) tool code
  transparently uses a client bound to *that* token.

What does **not** live here: the validation round-trip itself (that is
:meth:`pvehub_mcp.server.PVEHub._validate_pve_token`, because it needs the
instance configuration) and the per-token capability gate (that is
:meth:`pvehub_mcp.capabilities.CapabilityManager.check_pve_token_snapshot`).
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass

from .capabilities import CapabilitySnapshot
from .clients.pve import PVEClient

__all__ = [
    "PVEToken",
    "TokenState",
    "TokenValidationCache",
    "make_snapshot",
    "parse_pve_bearer",
    "pve_bearer_context",
    "pve_scoped_context",
]

#: Minimum length of a PVE API token secret (PVE issues 32 hex chars; the
#: floor stays below that so the check is structural, not cryptographic).
_MIN_SECRET_LEN = 16


@dataclass(frozen=True)
class PVEToken:
    """A parsed PVE API token: ``user@realm!tokenid`` + secret."""

    token_id: str
    token_secret: str

    def key(self, instance: str) -> tuple[str, str, str]:
        """Cache key: the *full* token identity, namespaced by instance.

        The key deliberately contains the whole secret, so a rotated token is
        a different key and is re-validated immediately, and two clients with
        different tokens never collide on a cache entry.
        """

        return (instance, self.token_id, self.token_secret)


def parse_pve_bearer(header: str) -> PVEToken | None:
    """Parse an ``Authorization: Bearer <token-id>=<token-secret>`` header.

    Returns a :class:`PVEToken` only when the header is structurally a PVE
    API token: the ``Bearer`` prefix, an id containing ``@`` (user + realm)
    and ``!`` (the token separator PVE uses), no whitespace in id or secret,
    and a secret of at least :data:`_MIN_SECRET_LEN` characters.  Anything
    else — missing header, a plain service token, a typo, a short secret —
    returns ``None`` so the caller can fail closed (401 at the edge).
    """

    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    payload = parts[1].strip()
    token_id, sep, token_secret = payload.rpartition("=")
    if not sep or not token_id or not token_secret:
        return None
    if "@" not in token_id or "!" not in token_id:
        return None
    if any(ch.isspace() for ch in token_id + token_secret):
        return None
    if len(token_secret) < _MIN_SECRET_LEN:
        return None
    return PVEToken(token_id=token_id, token_secret=token_secret)


@dataclass
class TokenState:
    """A validated per-request PVE token and its (per-token) capabilities.

    ``client`` is a :class:`~pvehub_mcp.clients.pve.PVEClient` bound to this
    exact token (its ``Authorization`` header carries it); ``snapshot`` holds
    the effective permissions PVE reported *for this token* — it is never
    shared with any other token; ``instance`` is the PVE instance name the
    token was validated against, so the accessor can refuse to hand a client
    out for a *different* instance (fail-closed).
    """

    instance: str
    token: PVEToken
    client: PVEClient
    snapshot: CapabilitySnapshot
    #: Set by the cache at ``put`` time, in the cache's clock domain.
    validated_at: float = 0.0


#: Parsed bearer for the current request. Set by the edge middleware, read by
#: the tool wrapper. Never set on the stdio transport (no HTTP request).
pve_bearer_context: ContextVar[PVEToken | None] = ContextVar("pvehub_pve_bearer", default=None)


#: Validated per-request token state for the current request. Set by the tool
#: wrapper *after* validation; :meth:`pvehub_mcp.server.PVEHub.pve` consults
#: it so the (unchanged) tool code transparently uses the per-request client.
pve_scoped_context: ContextVar[TokenState | None] = ContextVar("pvehub_pve_scoped", default=None)


class TokenValidationCache:
    """Bounded, TTL-based cache of per-(instance, token) PVE validations.

    * The key is :meth:`PVEToken.key` — full token identity, namespaced by
      PVE instance.  Two clients with different tokens never share an entry
      (issue #30: the cache key must contain the token identity).
    * A hit is only returned while ``now - validated_at < ttl``; an expired
      entry is dropped and the next call re-validates.  A rotated secret is a
      different key and is re-validated immediately.
    * The cache is bounded (``max_entries``): the oldest entry is evicted and
      returned so the caller can close its HTTP client.
    * All mutation happens under one lock, so concurrent requests for the
      same token validate exactly once.

    The cache *owns* the clock: ``validated_at`` is assigned here from
    ``clock`` and the TTL check compares in the same domain, so the math is
    consistent and the clock is injectable for tests.  The default clock is
    :func:`time.monotonic`.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float,
        max_entries: int = 32,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._entries: OrderedDict[tuple[str, str, str], TokenState] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: tuple[str, str, str]) -> TokenState | None:
        """Return the cached, still-valid entry for ``key`` (or ``None``)."""

        async with self._lock:
            state = self._entries.get(key)
            if state is None:
                return None
            if self._clock() - state.validated_at >= self._ttl:
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return state

    async def put(self, state: TokenState) -> list[TokenState]:
        """Store ``state`` (stamping ``validated_at``); return evicted entries.

        Evicted entries are returned so the caller can close their HTTP
        clients.
        """

        key = state.token.key(state.instance)
        async with self._lock:
            state.validated_at = self._clock()
            self._entries[key] = state
            self._entries.move_to_end(key)
            evicted: list[TokenState] = []
            while len(self._entries) > self._max:
                _, old = self._entries.popitem(last=False)
                evicted.append(old)
            return evicted

    async def clear(self) -> list[TokenState]:
        """Drop everything (server shutdown); return all entries for closing."""

        async with self._lock:
            evicted = list(self._entries.values())
            self._entries.clear()
            return evicted

    def __len__(self) -> int:
        return len(self._entries)


def make_snapshot(
    *,
    instance: str,
    permissions: dict[str, dict[str, object]] | None = None,
    error: str | None = None,
) -> CapabilitySnapshot:
    """Build a per-token :class:`CapabilitySnapshot` for the validation cache.

    ``permissions`` is the raw ``/access/permissions`` body (a *200*); when
    the token authenticated but lacks ``Sys.Audit`` (a *403*), pass
    ``error`` instead — PVE keeps enforcing per call and the fail_open policy
    decides the call-time gate.
    """

    return CapabilitySnapshot(
        kind="pve",
        instance=instance,
        permissions=permissions if permissions is not None else {},
        fetched_at=time.time(),
        error=error,
    )
