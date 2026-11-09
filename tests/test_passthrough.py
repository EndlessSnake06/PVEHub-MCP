"""Bearer-token pass-through tests (D026, issue #30).

In ``passthrough`` mode the MCP bearer *is* the PVE API token: the server
validates the requesting client's own token against the PVE it is about to
call, uses it for every PVE request of that call, and never falls back to a
configured service token (fail-closed).  Coverage here:

* :func:`parse_pve_bearer` — the structural contract of the bearer.
* :class:`PVEToken` / :class:`TokenValidationCache` — per-(instance, token)
  isolation, TTL, eviction.
* :func:`make_snapshot` — the 200 and the 403 (no Sys.Audit) cases.
* :class:`~pvehub_mcp.config.Settings` validation — the passthrough preconditions.
* :class:`PassthroughBearerMiddleware` — the edge 401 and the context channel.
* :func:`build_http_app` — the real HTTP surface in passthrough mode.
* :class:`PVEHub` — the fail-closed ``pve()``/``pbs()`` accessors, the
  per-request token resolution, the PVE validation round-trip (200/401/403),
  the ``capabilities_report`` auth block, and the PBS blocking at registration.

No PVE token or secret in this file is a real credential.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from starlette.requests import Request

from pvehub_mcp.capabilities import CapabilitySnapshot
from pvehub_mcp.clients.pve import PVEClient
from pvehub_mcp.config import PVEInstance, Settings
from pvehub_mcp.errors import AuthenticationError
from pvehub_mcp.passthrough import (
    PVEToken,
    TokenState,
    TokenValidationCache,
    make_snapshot,
    parse_pve_bearer,
    pve_bearer_context,
    pve_scoped_context,
)
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import (
    PassthroughBearerMiddleware,
    PVEHub,
    build_http_app,
)

BASE = "https://pve.test:8006"

# The *configured* service token — in passthrough mode it must never be used.
CONFIGURED_ID = "pvehub@pve!mcp"
CONFIGURED_SECRET = "configured-service-secret"

# A well-formed *request* token carried in the Authorization header. It is a
# different identity from the configured one, which is exactly the point: the
# scoped client must be bound to THIS token, not the configured one.
REQ_ID = "alice@pve!mcp-audit"
REQ_SECRET = "req-secret-0123456789ab"
REQ_BEARER = f"Bearer {REQ_ID}={REQ_SECRET}"

# A second, distinct token — used to prove cache isolation between clients.
REQ2_ID = "bob@pve!mcp-audit"
REQ2_SECRET = "req2-secret-abcdef012345"
REQ2_BEARER = f"Bearer {REQ2_ID}={REQ2_SECRET}"


# -- helpers -----------------------------------------------------------------


def _pve_instance(**overrides: object) -> PVEInstance:
    data: dict[str, Any] = {
        "name": "test",
        "url": BASE,
        "token_id": CONFIGURED_ID,
        "token_secret": CONFIGURED_SECRET,
        "verify": False,
        "max_retries": 0,
    }
    data.update(overrides)
    return PVEInstance.model_validate(data)


def _pbs_instance_dict() -> dict[str, Any]:
    return {
        "name": "backup",
        "url": "https://pbs.test:8007",
        "token_id": "pvehub@pbs!mcp",
        "token_secret": "pbs-secret-value",
        "verify": False,
        "max_retries": 0,
    }


def _passthrough_settings(tmp_path: Path, **overrides: object) -> Settings:
    data: dict[str, Any] = {
        "transport": "http",
        "host": "127.0.0.1",
        "pve": [_pve_instance()],
        "mcp_auth_mode": "passthrough",
        "mcp_auth_required": True,
        # In passthrough mode the PVE API token is the credential, so no MCP
        # bearer is required (config validation exempts this case).
        "mcp_auth_token": None,
        "mcp_auth_tokens": {},
        "audit_log": None,
        "state_dir": str(tmp_path),
        "memory_db": str(tmp_path / "memory.db"),
        "capabilities_refresh_seconds": 0,
        "capabilities_fail_open": True,
        "task_timeout_seconds": 5,
    }
    data.update(overrides)
    return Settings.model_validate(data)


def _scoped_client(tmp_path: Path, token: PVEToken, name: str = "test") -> PVEClient:
    """A per-request PVE client bound to ``token`` (no network in ctor)."""

    return PVEClient(
        name=name,
        url=BASE,
        api_path="/api2/json",
        token_id=token.token_id,
        token_secret=token.token_secret,
        verify=False,
        max_retries=0,
        state_dir=str(tmp_path),
    )


def _minimal_passthrough_hub(tmp_path: Path) -> PVEHub:
    """A passthrough hub without ``initialize()``.

    Populates just enough state for the accessor / token-resolution /
    validation unit tests: the configured instance (so ``_instance_name``
    resolves) and a fresh validation cache.  ``capabilities`` stays ``None``
    (not needed by the code paths under test).
    """

    hub = PVEHub(_passthrough_settings(tmp_path), Policy(file=PolicyFile()))
    hub.pve_clients = {
        "test": PVEClient(
            name="test",
            url=BASE,
            api_path="/api2/json",
            token_id=CONFIGURED_ID,
            token_secret=CONFIGURED_SECRET,
            verify=False,
            max_retries=0,
            state_dir=str(tmp_path),
        )
    }
    assert hub._passthrough is True
    hub._token_cache = TokenValidationCache(ttl_seconds=60)
    return hub


def _raw_http_request(authorization: str) -> Request:
    headers: list[tuple[bytes, bytes]] = [(b"host", b"test")]
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/mcp",
        "query_string": b"",
        "headers": headers,
    }
    return Request(scope)


def _raw_ctx(authorization: str) -> SimpleNamespace:
    """An MCP context whose raw request carries ``authorization``."""

    return SimpleNamespace(request_context=SimpleNamespace(request=_raw_http_request(authorization)))


# -- parse_pve_bearer --------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected_id", "expected_secret"),
    [
        (REQ_BEARER, REQ_ID, REQ_SECRET),
        ("bearer " + REQ_BEARER.removeprefix("Bearer "), REQ_ID, REQ_SECRET),
        (f"Bearer   {REQ_ID}={REQ_SECRET}", REQ_ID, REQ_SECRET),
        # A token id may itself contain '=' only in the (last) id/secret split.
        (f"Bearer {REQ_ID}=x{REQ_SECRET}", REQ_ID, "x" + REQ_SECRET),
    ],
)
def test_parse_valid_bearer(header: str, expected_id: str, expected_secret: str) -> None:
    token = parse_pve_bearer(header)
    assert token is not None
    assert token.token_id == expected_id
    assert token.token_secret == expected_secret


@pytest.mark.parametrize(
    "header",
    [
        "",  # missing header
        "Bearer",  # no payload
        "Basic dXNlcjpwYXNz",  # wrong scheme
        f"Bearer {REQ_ID}",  # no '=' (id/secret separator)
        f"Bearer ={REQ_SECRET}",  # empty id
        f"Bearer {REQ_ID}=",  # empty secret
        f"Bearer root={REQ_SECRET}",  # no '@' (no realm)
        f"Bearer root@pam={REQ_SECRET}",  # no '!' (no token separator)
        f"Bearer {REQ_ID}={REQ_SECRET[:15]}",  # secret too short (15 < 16)
        f"Bearer {REQ_ID[:5]} {REQ_ID[5:]}={REQ_SECRET}",  # whitespace in id
        f"Bearer {REQ_ID}={REQ_SECRET[:8]} {REQ_SECRET[8:]}",  # whitespace in secret
        "not-a-header",  # no Bearer prefix
    ],
)
def test_parse_rejects_malformed(header: str) -> None:
    assert parse_pve_bearer(header) is None


# -- PVEToken.key / TokenValidationCache -------------------------------------


def test_token_key_is_full_identity() -> None:
    a = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    b = PVEToken(token_id=REQ_ID, token_secret="rotated-secret-0000000")
    c = PVEToken(token_id=REQ2_ID, token_secret=REQ_SECRET)
    # A rotated secret is a different key (re-validated immediately).
    assert a.key("test") != b.key("test")
    # A different identity is a different key (no cross-client sharing).
    assert a.key("test") != c.key("test")
    # A different instance is a different key (namespaced).
    assert a.key("test") != a.key("other")
    assert a.key("test") == ("test", REQ_ID, REQ_SECRET)


async def test_cache_isolated_per_token() -> None:
    clock = {"t": 0.0}
    cache = TokenValidationCache(ttl_seconds=60, clock=lambda: clock["t"])
    a = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    b = PVEToken(token_id=REQ2_ID, token_secret=REQ_SECRET)
    client_a = PVEClient(
        name="test",
        url=BASE,
        api_path="/api2/json",
        token_id=REQ_ID,
        token_secret=REQ_SECRET,
        verify=False,
        max_retries=0,
        state_dir="/tmp/pvehub-pt",
    )
    client_b = PVEClient(
        name="test",
        url=BASE,
        api_path="/api2/json",
        token_id=REQ2_ID,
        token_secret=REQ_SECRET,
        verify=False,
        max_retries=0,
        state_dir="/tmp/pvehub-pt",
    )
    snap_a = make_snapshot(instance="test", permissions={"a": {}})
    snap_b = make_snapshot(instance="test", permissions={"b": {}})
    state_a = TokenState(instance="test", token=a, client=client_a, snapshot=snap_a)
    state_b = TokenState(instance="test", token=b, client=client_b, snapshot=snap_b)
    assert await cache.put(state_a) == []
    assert await cache.put(state_b) == []
    # Each key returns its own entry; nothing is shared.
    hit_a = await cache.get(a.key("test"))
    hit_b = await cache.get(b.key("test"))
    assert hit_a is state_a
    assert hit_b is state_b
    assert hit_a.snapshot is snap_a
    assert hit_b.snapshot is snap_b
    await client_a.aclose()
    await client_b.aclose()


async def test_cache_ttl_expiry() -> None:
    clock = {"t": 0.0}
    cache = TokenValidationCache(ttl_seconds=30, clock=lambda: clock["t"])
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    client = _scoped_client(Path("/tmp/pvehub-pt"), token)
    state = TokenState(
        instance="test",
        token=token,
        client=client,
        snapshot=make_snapshot(instance="test", permissions={}),
    )
    await cache.put(state)
    clock["t"] = 29.0
    assert (await cache.get(token.key("test"))) is state
    clock["t"] = 30.0  # at the TTL boundary the entry is expired
    assert await cache.get(token.key("test")) is None
    assert len(cache) == 0
    await client.aclose()


async def test_cache_evicts_oldest_and_reports_it() -> None:
    clock = {"t": 0.0}
    cache = TokenValidationCache(ttl_seconds=60, max_entries=2, clock=lambda: clock["t"])
    clients = []
    for i, (tid, sec) in enumerate(
        [
            ("t1@pve!x", "s1-0000000000000000"),
            ("t2@pve!x", "s2-0000000000000000"),
            ("t3@pve!x", "s3-0000000000000000"),
        ]
    ):
        token = PVEToken(token_id=tid, token_secret=sec)
        client = PVEClient(
            name="test",
            url=BASE,
            api_path="/api2/json",
            token_id=tid,
            token_secret=sec,
            verify=False,
            max_retries=0,
            state_dir="/tmp/pvehub-pt",
        )
        clients.append(client)
        clock["t"] = float(i)
        state = TokenState(
            instance="test",
            token=token,
            client=client,
            snapshot=make_snapshot(instance="test", permissions={}),
        )
        evicted = await cache.put(state)
        if i < 2:
            assert evicted == []
        else:
            # The oldest (t1) is evicted and handed back for closing.
            assert len(evicted) == 1
            assert evicted[0].token.token_id == "t1@pve!x"
    assert len(cache) == 2
    for client in clients:
        await client.aclose()


async def test_cache_clear_returns_everything() -> None:
    clock = {"t": 0.0}
    cache = TokenValidationCache(ttl_seconds=60, clock=lambda: clock["t"])
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    client = _scoped_client(Path("/tmp/pvehub-pt"), token)
    state = TokenState(
        instance="test",
        token=token,
        client=client,
        snapshot=make_snapshot(instance="test", permissions={}),
    )
    await cache.put(state)
    assert len(cache) == 1
    drained = await cache.clear()
    assert drained == [state]
    assert len(cache) == 0
    await client.aclose()


def test_cache_rejects_bad_params() -> None:
    with pytest.raises(ValueError):
        TokenValidationCache(ttl_seconds=0)
    with pytest.raises(ValueError):
        TokenValidationCache(ttl_seconds=60, max_entries=0)


# -- make_snapshot -----------------------------------------------------------


def test_make_snapshot_from_200_permissions() -> None:
    snap = make_snapshot(instance="test", permissions={"/": {"Sys.Audit": 1}})
    assert isinstance(snap, CapabilitySnapshot)
    assert snap.kind == "pve"
    assert snap.instance == "test"
    assert snap.permissions == {"/": {"Sys.Audit": 1}}
    assert snap.error is None


def test_make_snapshot_records_403_discovery_failure() -> None:
    snap = make_snapshot(instance="test", error="HTTP 403 on /access/permissions")
    assert snap.permissions == {}
    assert snap.error is not None
    assert "403" in snap.error


# -- Settings validation -----------------------------------------------------


def test_passthrough_requires_a_pve_instance() -> None:
    # A PBS instance alone satisfies the generic "at least one instance" rule,
    # so the passthrough-specific "requires a PVE instance" rule is what
    # rejects this (passthrough is PVE-only; PBS tools are blocked).
    with pytest.raises(ValidationError, match="at least one PVE instance"):
        Settings.model_validate(
            {
                "transport": "http",
                "host": "127.0.0.1",
                "pve": [],
                "pbs": [_pbs_instance_dict()],
                "mcp_auth_mode": "passthrough",
            }
        )


def test_passthrough_requires_http_transport() -> None:
    with pytest.raises(ValidationError, match="requires the http transport"):
        Settings.model_validate(
            {
                "transport": "stdio",
                "pve": [_pve_instance()],
                "mcp_auth_mode": "passthrough",
            }
        )


def test_passthrough_requires_mcp_auth_required() -> None:
    with pytest.raises(ValidationError, match="requires mcp_auth_required=true"):
        Settings.model_validate(
            {
                "transport": "http",
                "host": "127.0.0.1",
                "pve": [_pve_instance()],
                "mcp_auth_mode": "passthrough",
                "mcp_auth_required": False,
            }
        )


def test_passthrough_requires_ttl_at_least_one() -> None:
    with pytest.raises(ValidationError, match="at least 1 second"):
        Settings.model_validate(
            {
                "transport": "http",
                "host": "127.0.0.1",
                "pve": [_pve_instance()],
                "mcp_auth_mode": "passthrough",
                "mcp_token_validation_ttl": 0,
            }
        )


def test_passthrough_does_not_require_an_mcp_bearer(tmp_path: Path) -> None:
    # The PVE API token is the credential: no MCP bearer is needed, and a
    # valid passthrough config with no mcp_auth_token is accepted.
    settings = _passthrough_settings(tmp_path)
    assert settings.mcp_auth_mode == "passthrough"
    assert settings.mcp_auth_token is None
    assert settings.mcp_auth_tokens == {}
    assert settings.mcp_auth_required is True
    assert settings.mcp_token_validation_ttl == 60


# -- PassthroughBearerMiddleware --------------------------------------------


async def test_middleware_rejects_missing_bearer() -> None:
    status: dict[str, int] = {}
    reached = False

    async def inner(scope: dict, receive: object, send: object) -> None:
        nonlocal reached
        reached = True

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status["code"] = message["status"]

    middleware = PassthroughBearerMiddleware(inner)
    scope = {"type": "http", "path": "/mcp", "headers": []}
    await middleware(scope, None, send)
    assert status.get("code") == 401
    assert reached is False


async def test_middleware_rejects_non_pve_bearer() -> None:
    # A well-formed *MCP* bearer that is not a PVE API token is still a 401:
    # in passthrough mode the only accepted shape is a PVE API token.
    status: dict[str, int] = {}
    reached = False

    async def inner(scope: dict, receive: object, send: object) -> None:
        nonlocal reached
        reached = True

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status["code"] = message["status"]

    middleware = PassthroughBearerMiddleware(inner)
    scope = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"authorization", b"Bearer some-mcp-token-01234567")],
    }
    await middleware(scope, None, send)
    assert status.get("code") == 401
    assert reached is False


async def test_middleware_sets_bearer_context_and_resets() -> None:
    seen: list[PVEToken | None] = []

    async def inner(scope: dict, receive: object, send: object) -> None:
        async def probe() -> None:
            seen.append(pve_bearer_context.get())

        await probe()  # child task: contextvars propagate to it

    middleware = PassthroughBearerMiddleware(inner)
    scope = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"authorization", REQ_BEARER.encode())],
    }
    await middleware(scope, None, None)
    assert len(seen) == 1
    assert seen[0] is not None
    assert seen[0].token_id == REQ_ID
    assert seen[0].token_secret == REQ_SECRET
    # The context is reset after the request.
    assert pve_bearer_context.get() is None


async def test_middleware_passes_through_unprotected_paths() -> None:
    status: dict[str, int] = {}

    async def inner(scope: dict, receive: object, send: object) -> None:
        status["reached"] = 200

    middleware = PassthroughBearerMiddleware(inner)
    scope = {"type": "http", "path": "/health", "headers": []}
    await middleware(scope, None, None)
    assert status == {"reached": 200}


# -- build_http_app (real HTTP surface) --------------------------------------


@respx.mock
async def test_http_app_passthrough_ready_gate() -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    hub = PVEHub(
        _passthrough_settings(Path("/tmp/pvehub-pt-app")),
        Policy(file=PolicyFile()),
    )
    hub.build()
    app = build_http_app(hub)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            missing = await client.get("/ready")
            assert missing.status_code == 401
            non_pve = await client.get("/ready", headers={"Authorization": "Bearer some-mcp-token-01234567"})
            assert non_pve.status_code == 401
            # A structurally valid PVE token passes the edge gate (readiness
            # itself does not validate the token against PVE).
            ok = await client.get("/ready", headers={"Authorization": REQ_BEARER})
            assert ok.status_code == 200
    finally:
        await hub.close()


# -- PVEHub accessors (fail-closed) -----------------------------------------


async def test_pbs_is_blocked_in_passthrough(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    with pytest.raises(AuthenticationError, match="not valid on the PBS API"):
        hub.pbs()


async def test_pve_fails_closed_without_scoped_context(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    with pytest.raises(AuthenticationError, match="no validated PVE API token"):
        hub.pve()


async def test_pve_hands_out_the_request_client(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    client = _scoped_client(tmp_path, token)
    state = TokenState(
        instance="test",
        token=token,
        client=client,
        snapshot=make_snapshot(instance="test", permissions={}),
    )
    reset = pve_scoped_context.set(state)
    try:
        handed = hub.pve()
        assert handed is client
        # The crux of the feature: the handed-out client carries the
        # request's token in its Authorization header, never the configured
        # service token.
        assert handed.auth_header == f"PVEAPIToken={REQ_ID}={REQ_SECRET}"
        assert CONFIGURED_ID not in handed.auth_header
    finally:
        pve_scoped_context.reset(reset)
        await client.aclose()


async def test_pve_refuses_a_state_for_another_instance(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    client = _scoped_client(tmp_path, token, name="other")
    state = TokenState(
        instance="other",
        token=token,
        client=client,
        snapshot=make_snapshot(instance="other", permissions={}),
    )
    reset = pve_scoped_context.set(state)
    try:
        with pytest.raises(AuthenticationError, match="no validated PVE API token"):
            hub.pve()
    finally:
        pve_scoped_context.reset(reset)
        await client.aclose()


# -- _request_pve_token ------------------------------------------------------


async def test_request_token_from_bearer_context(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    reset = pve_bearer_context.set(token)
    try:
        got = hub._request_pve_token(None)  # no request; context is enough
        assert got is token
    finally:
        pve_bearer_context.reset(reset)


async def test_request_token_from_raw_request(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    # No middleware context (different task) — the raw request is the
    # authoritative channel and must still yield the token.
    got = hub._request_pve_token(_raw_ctx(REQ_BEARER))
    assert got is not None
    assert got.token_id == REQ_ID
    assert got.token_secret == REQ_SECRET


async def test_request_token_malformed_raw_request_raises(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    with pytest.raises(AuthenticationError, match="invalid PVE API token"):
        hub._request_pve_token(_raw_ctx("Bearer some-mcp-token-01234567"))


async def test_request_token_without_http_is_none(tmp_path: Path) -> None:
    hub = _minimal_passthrough_hub(tmp_path)
    # No context and no raw request (stdio) — returns None, it does not
    # raise, because config validation forbids passthrough on stdio.
    assert hub._request_pve_token(None) is None


# -- _validate_pve_token (PVE round-trip) -----------------------------------


@respx.mock
async def test_validate_token_200_binds_request_token(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    state = await hub._validate_pve_token(None, token)
    try:
        assert state.instance == "test"
        assert state.token is token
        # The per-request client is bound to the request's token.
        assert state.client.auth_header == f"PVEAPIToken={REQ_ID}={REQ_SECRET}"
        assert CONFIGURED_ID not in state.client.auth_header
        # The snapshot reflects the token's own permissions (200 case).
        assert state.snapshot.error is None
        assert state.snapshot.permissions == {"/": {"Sys.Audit": 1}}
        # The validation is cached under the full token identity.
        cached = await hub._token_cache.get(token.key("test"))
        assert cached is state
    finally:
        await state.client.aclose()


@respx.mock
async def test_validate_token_401_is_fail_closed(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(401, json={"data": {"error": "invalid token"}})
    )
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    with pytest.raises(AuthenticationError, match="rejected the bearer token"):
        await hub._validate_pve_token(None, token)
    # A rejected token is not cached.
    assert len(hub._token_cache) == 0


@respx.mock
async def test_validate_token_403_records_discovery_failure(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(403, json={"data": {"error": "forbidden"}})
    )
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    state = await hub._validate_pve_token(None, token)
    try:
        # A 403 proves the token authenticated (PVE authenticates before it
        # ACLs) but lacks Sys.Audit: the identity is trusted, the snapshot
        # records the discovery failure, and the client is still bound to the
        # request's token (PVE keeps enforcing per call).
        assert state.snapshot.error is not None
        assert "403" in state.snapshot.error
        assert state.snapshot.permissions == {}
        assert state.client.auth_header == f"PVEAPIToken={REQ_ID}={REQ_SECRET}"
    finally:
        await state.client.aclose()


@respx.mock
async def test_validate_token_cache_hit_avoids_second_roundtrip(tmp_path: Path) -> None:
    route = respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    hub = _minimal_passthrough_hub(tmp_path)
    token = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    state = await hub._validate_pve_token(None, token)
    try:
        assert route.call_count == 1
        # A second validation for the same (instance, token) is a cache hit —
        # no additional round-trip, same client handed out.
        again = await hub._validate_pve_token(None, token)
        assert again is state
        assert route.call_count == 1
    finally:
        await state.client.aclose()


@respx.mock
async def test_validate_token_distinct_tokens_do_not_share(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    hub = _minimal_passthrough_hub(tmp_path)
    a = PVEToken(token_id=REQ_ID, token_secret=REQ_SECRET)
    b = PVEToken(token_id=REQ2_ID, token_secret=REQ2_SECRET)
    state_a = await hub._validate_pve_token(None, a)
    state_b = await hub._validate_pve_token(None, b)
    try:
        assert state_a is not state_b
        assert state_a.client.auth_header == f"PVEAPIToken={REQ_ID}={REQ_SECRET}"
        assert state_b.client.auth_header == f"PVEAPIToken={REQ2_ID}={REQ2_SECRET}"
        # Two distinct entries, one per full token identity.
        assert len(hub._token_cache) == 2
    finally:
        await state_a.client.aclose()
        await state_b.client.aclose()


# -- capabilities_report auth block -----------------------------------------


@respx.mock
async def test_capabilities_report_exposes_auth_block(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    hub = PVEHub(
        _passthrough_settings(tmp_path),
        Policy(file=PolicyFile()),
    )
    hub.build()
    try:
        await hub.initialize()
        report = hub.capabilities_report()
        auth = report["auth"]
        assert auth["mode"] == "passthrough"
        assert auth["required"] is True
        assert auth["token_validation_ttl"] == 60
    finally:
        await hub.close()


@respx.mock
async def test_capabilities_report_static_mode(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    settings = Settings.model_validate(
        {
            "transport": "stdio",
            "pve": [_pve_instance()],
            "mcp_auth_mode": "static",
            "state_dir": str(tmp_path),
            "memory_db": str(tmp_path / "memory.db"),
            "capabilities_refresh_seconds": 0,
            "capabilities_fail_open": True,
            "task_timeout_seconds": 5,
        }
    )
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    try:
        await hub.initialize()
        report = hub.capabilities_report()
        assert report["auth"]["mode"] == "static"
        assert report["auth"]["token_validation_ttl"] is None
    finally:
        await hub.close()


# -- registration: PBS blocking in passthrough ------------------------------


@respx.mock
async def test_pbs_tools_blocked_at_registration_in_passthrough(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    hub = PVEHub(
        _passthrough_settings(tmp_path),
        Policy(file=PolicyFile()),
    )
    hub.build()
    try:
        await hub.initialize()
        # Every PVE tool is still registered (passthrough is PVE-only, not
        # PVE-reduced).
        assert "pvehub_capabilities" in hub.registered
        blocked_passthrough = [b for b in hub.blocked if b.reason.startswith("passthrough:")]
        # The generic PBS tools are not exposed in passthrough mode.
        for name in ("pbs_api_call", "pbs_api_schema"):
            assert name not in hub.registered
            assert any(b.name == name for b in blocked_passthrough)
        # A healthy number of PBS tools were blocked for the right reason.
        assert len(blocked_passthrough) >= 10
        for b in blocked_passthrough:
            assert b.name not in hub.registered
    finally:
        await hub.close()


# -- audit: pve_token identity, never the secret ---------------------------


@respx.mock
async def test_audit_logs_token_identity_not_secret(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1}}})
    )
    settings = _passthrough_settings(tmp_path, audit_log=str(tmp_path / "audit.jsonl"))
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    # Drive one passthrough PVE tool call end to end: the wrapper resolves
    # the bearer from the raw request, validates it, publishes the scoped
    # context, and records the token *identity* in the audit entry.
    try:
        await hub.initialize()
        # Emulate the tool wrapper's request-local setup around a direct
        # access to the (now scoped) client, exactly as the wrapped pve
        # branch does.
        raw_ctx = _raw_ctx(REQ_BEARER)
        resolved = hub._request_pve_token(raw_ctx)
        assert resolved is not None
        state = await hub._validate_pve_token(None, resolved)
        reset = pve_scoped_context.set(state)
        try:
            client = hub.pve()  # resolves the scoped client
            assert client is state.client
        finally:
            pve_scoped_context.reset(reset)
        await hub.audit.write(
            tool="pvehub_capabilities",
            category="read",
            status="ok",
            instance=None,
            target=None,
            params={},
            duration_ms=1,
            client="unknown",
            client_ip=None,
            pve_token=resolved.token_id,
        )
    finally:
        await hub.close()

    entries = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines() if line.strip()]
    assert entries, "expected an audit entry"
    entry = entries[-1]
    # The identity is present...
    assert entry["pve_token"] == REQ_ID
    # ...and the secret never appears anywhere in the entry.
    blob = json.dumps(entry)
    assert REQ_SECRET not in blob
    assert entry["client"] == "unknown"
