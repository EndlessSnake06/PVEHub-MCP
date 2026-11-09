"""Trusted-proxy support and client-IP audit attribution (D024, issue #25).

Covers the full chain:

* the pure resolution logic (``pvehub_mcp.proxy``) — forgery table;
* configuration validation (fail-loud on bad CIDRs, 403-without-trust-set);
* the 403 middleware (untrusted peer, missing socket peer, /health exempt);
* an end-to-end session through a real uvicorn server (``proxy_headers=False``)
  behind a "local reverse proxy": the audit entries must carry the resolved
  client IP, and direct access from an untrusted peer must get 403.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
from pathlib import Path

import httpx
import pytest
import respx
import uvicorn
from mcp.client import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import ValidationError

from pvehub_mcp.config import PVEInstance, Settings, _apply_env
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.proxy import (
    TrustedProxyError,
    is_trusted,
    parse_trusted_proxies,
    resolve_client_ip,
)
from pvehub_mcp.server import PVEHub, TrustedProxyMiddleware, build_http_app

BASE = "https://pve.test:8006"
PERMISSIONS = {"/": {"Sys.Audit": 1}}
LEGACY_TOKEN = "legacy-token-01234567"
PROXY_CIDR = "10.88.0.0/16"
EXTERNAL_IP = "203.0.113.77"


def _settings(tmp_path: str | Path | None = None, **overrides: object) -> Settings:
    data: dict[str, object] = {
        "transport": "http",
        "host": "127.0.0.1",
        "pve": [
            PVEInstance(
                name="test",
                url=BASE,
                token_id="pvehub@pve!mcp",
                token_secret="secret",
                verify=False,
                max_retries=0,
            )
        ],
        "mcp_auth_token": LEGACY_TOKEN,
        "audit_log": None,
        "state_dir": "/tmp/pvehub-trusted-proxy",
        "capabilities_fail_open": True,
        "capabilities_refresh_seconds": 0,
    }
    if tmp_path is not None:
        data["audit_log"] = str(Path(tmp_path) / "audit.jsonl")
    data.update(overrides)
    return Settings.model_validate(data)


# -- parse_trusted_proxies --------------------------------------------------


def test_parse_trusted_proxies_v4_cidr() -> None:
    nets = parse_trusted_proxies("10.88.0.0/16, 192.168.7.0/24")
    assert nets == (ipaddress.ip_network("10.88.0.0/16"), ipaddress.ip_network("192.168.7.0/24"))


def test_parse_trusted_proxies_bare_ip_becomes_32() -> None:
    nets = parse_trusted_proxies("10.88.1.5")
    assert nets == (ipaddress.ip_network("10.88.1.5/32"),)


def test_parse_trusted_proxies_v6() -> None:
    nets = parse_trusted_proxies("2001:db8::/32, 2001:db8::5")
    assert nets == (
        ipaddress.ip_network("2001:db8::/32"),
        ipaddress.ip_network("2001:db8::5/128"),
    )


def test_parse_trusted_proxies_whitespace_and_empty() -> None:
    assert parse_trusted_proxies("") == ()
    assert parse_trusted_proxies("   ,  ,") == ()
    assert parse_trusted_proxies(" 10.88.0.0/16 , 192.168.7.0/24 ") == (
        ipaddress.ip_network("10.88.0.0/16"),
        ipaddress.ip_network("192.168.7.0/24"),
    )


@pytest.mark.parametrize(
    "bad",
    ["garbage", "300.1.1.1/8", "10.0.0.0/33", "10.0.0.1/16", "2001:db8::/129"],
)
def test_parse_trusted_projects_rejects_malformed_entries(bad: str) -> None:
    with pytest.raises(TrustedProxyError, match="invalid trusted proxy entry"):
        parse_trusted_proxies(f"10.88.0.0/16, {bad}")


def test_parse_reports_the_offending_entry() -> None:
    with pytest.raises(TrustedProxyError, match=re.escape("300.1.1.1/8")):
        parse_trusted_proxies("10.88.0.0/16, 300.1.1.1/8")


# -- is_trusted --------------------------------------------------------------


def test_is_trusted_inside_and_outside() -> None:
    nets = parse_trusted_proxies("10.88.0.0/16, 2001:db8::/32")
    assert is_trusted("10.88.255.4", nets)
    assert is_trusted("2001:db8::9", nets)
    assert not is_trusted("10.89.0.1", nets)
    assert not is_trusted("127.0.0.1", nets)
    # Unparseable input is never trusted.
    assert not is_trusted("not-an-ip", nets)
    # An empty trust set trusts nothing.
    assert not is_trusted("10.88.0.1", ())


# -- resolve_client_ip: the forgery table ------------------------------------

TRUSTED = parse_trusted_proxies("10.88.0.0/16")


def test_no_trust_set_peer_is_attributed_and_xff_ignored() -> None:
    # Default (no trusted proxies): X-Forwarded-For is never consulted, even
    # when it contains entries that look like they should be trusted.
    assert resolve_client_ip("203.0.113.9", None, ()) == "203.0.113.9"
    assert (
        resolve_client_ip("203.0.113.9", f"198.51.100.7, {EXTERNAL_IP}", ()) == "203.0.113.9"
    )


def test_untrusted_peer_xff_forgery_ignored() -> None:
    # A direct client can forge arbitrary entries — including ones inside a
    # trusted range. The untrusted peer wins.
    forged = f"{EXTERNAL_IP}, 10.88.0.1, 198.51.100.99"
    assert resolve_client_ip("203.0.113.9", forged, TRUSTED) == "203.0.113.9"


def test_trusted_peer_without_xff_peer_is_attributed() -> None:
    assert resolve_client_ip("10.88.1.5", None, TRUSTED) == "10.88.1.5"
    assert resolve_client_ip("10.88.1.5", "   ", TRUSTED) == "10.88.1.5"


def test_trusted_proxy_single_hop_client_is_resolved() -> None:
    # One proxy in front: it appends the real client, nothing else.
    assert resolve_client_ip("10.88.1.5", EXTERNAL_IP, TRUSTED) == EXTERNAL_IP


def test_trusted_proxy_multi_hop_skips_rightmost_trusted() -> None:
    # Two trusted proxies: the rightmost entry is the nearest proxy's own
    # address and must be skipped; the client is the first untrusted entry
    # from the right.
    chain = f"{EXTERNAL_IP}, 10.88.1.5, 10.88.2.9"
    assert resolve_client_ip("10.88.2.9", chain, TRUSTED) == EXTERNAL_IP


def test_trusted_proxy_all_entries_trusted_leftmost_wins() -> None:
    # The client is inside the trusted network (internal client behind an
    # internal proxy): every entry is trusted, the leftmost is the client.
    chain = "10.88.9.7, 10.88.1.5"
    assert resolve_client_ip("10.88.1.5", chain, TRUSTED) == "10.88.9.7"


def test_trusted_proxy_malformed_entries_are_skipped() -> None:
    # Garbage entries cannot poison the resolution: they are dropped, the
    # remaining (trusted) entries are evaluated, and if nothing usable is
    # left the peer is the fallback.
    assert resolve_client_ip("10.88.1.5", "garbage, more-garbage", TRUSTED) == "10.88.1.5"
    assert (
        resolve_client_ip("10.88.1.5", "garbage, 10.88.9.7", TRUSTED) == "10.88.9.7"
    )


def test_trusted_proxy_ipv6() -> None:
    nets = parse_trusted_proxies("2001:db8::/32")
    assert resolve_client_ip("2001:db8::10", "2001:db8::77", nets) == "2001:db8::77"


def test_missing_peer_returns_none() -> None:
    assert resolve_client_ip("", None, TRUSTED) is None
    assert resolve_client_ip("", EXTERNAL_IP, TRUSTED) is None


# -- configuration ------------------------------------------------------------


def test_settings_accepts_valid_trusted_proxies() -> None:
    settings = _settings(trusted_proxies=[PROXY_CIDR], require_trusted_proxy=True)
    assert settings.trusted_proxies == [PROXY_CIDR]
    assert settings.require_trusted_proxy is True
    # PVEHub parses the set once at construction.
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    assert hub._trusted_nets == (ipaddress.ip_network(PROXY_CIDR),)


def test_settings_rejects_malformed_trusted_proxies() -> None:
    with pytest.raises(ValidationError, match="invalid trusted_proxies"):
        _settings(trusted_proxies=["10.88.0.0/16", "not-a-cidr"])


def test_settings_rejects_require_without_trust_set() -> None:
    with pytest.raises(ValidationError, match="non-empty trusted_proxies"):
        _settings(trusted_proxies=[], require_trusted_proxy=True)


def test_trusted_proxy_env_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PVEHUB_TRUSTED_PROXIES", f" {PROXY_CIDR} , 192.168.7.0/24")
    monkeypatch.setenv("PVEHUB_REQUIRE_TRUSTED_PROXY", "true")
    data: dict[str, object] = {}
    _apply_env(data)
    assert data["trusted_proxies"] == [PROXY_CIDR, "192.168.7.0/24"]
    assert data["require_trusted_proxy"] is True


def test_trusted_proxy_defaults_are_off() -> None:
    settings = _settings()
    assert settings.trusted_proxies == []
    assert settings.require_trusted_proxy is False
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    assert hub._trusted_nets == ()


# -- TrustedProxyMiddleware (ASGI level) --------------------------------------


def _middleware_scope(path: str, client: tuple[str, int] | None) -> dict[str, object]:
    scope: dict[str, object] = {"type": "http", "path": path, "headers": []}
    if client is not None:
        scope["client"] = client
    return scope


async def _run_middleware(
    path: str,
    client: tuple[str, int] | None,
    *,
    require: bool,
    protected_paths: frozenset[str] | None = None,
) -> dict[str, object]:
    """Run the middleware around a fake inner app; record what happened."""
    outcome: dict[str, object] = {"chunks": []}

    async def inner(scope: dict, receive: object, send: object) -> None:
        outcome["reached"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"inner-ok"})

    def _make_send() -> object:
        async def send(message: dict) -> None:
            if message["type"] == "http.response.start":
                outcome["status"] = message["status"]
            elif message["type"] == "http.response.body":
                outcome["chunks"].append(message.get("body", b""))

        return send

    middleware = TrustedProxyMiddleware(
        inner,
        parse_trusted_proxies(PROXY_CIDR),
        require=require,
        protected_paths=protected_paths or frozenset(),
    )
    scope = _middleware_scope(path, client)
    await middleware(scope, None, _make_send())
    outcome["body"] = b"".join(outcome["chunks"])
    del outcome["chunks"]
    return outcome


async def test_middleware_403_for_untrusted_peer() -> None:
    outcome = await _run_middleware("/mcp", ("203.0.113.9", 51234), require=True)
    assert "reached" not in outcome
    assert outcome["status"] == 403
    payload = json.loads(outcome["body"])  # type: ignore[arg-type]
    assert payload["error"] == "proxy_required"
    assert "PVEHUB_TRUSTED_PROXIES" in payload["message"]


async def test_middleware_403_when_no_socket_peer() -> None:
    # A scope without a client entry cannot be verified: 403, not pass.
    outcome = await _run_middleware("/mcp", None, require=True)
    assert "reached" not in outcome
    assert outcome["status"] == 403


async def test_middleware_passes_trusted_peer() -> None:
    outcome = await _run_middleware("/mcp", ("10.88.1.5", 51234), require=True)
    assert outcome.get("reached") is True
    assert outcome.get("status") == 200
    assert outcome.get("body") == b"inner-ok"


async def test_middleware_protects_ready() -> None:
    # /ready is listed in protected_paths exactly as build_http_app wires it.
    outcome = await _run_middleware(
        "/ready", ("203.0.113.9", 51234), require=True, protected_paths=frozenset({"/ready"})
    )
    assert "reached" not in outcome
    assert outcome["status"] == 403


async def test_middleware_exempts_health() -> None:
    # The container healthcheck must keep working from the bridge network.
    outcome = await _run_middleware("/health", ("172.18.0.1", 51234), require=True)
    assert outcome.get("reached") is True
    assert outcome.get("body") == b"inner-ok"


async def test_middleware_is_a_noop_by_default() -> None:
    outcome = await _run_middleware("/mcp", ("203.0.113.9", 51234), require=False)
    assert outcome.get("reached") is True
    assert outcome.get("body") == b"inner-ok"


# -- app-level: 403 for untrusted, pass for trusted ---------------------------


@respx.mock
async def test_app_403_for_untrusted_peer(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    settings = _settings(tmp_path, trusted_proxies=[PROXY_CIDR], require_trusted_proxy=True)
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    # A peer outside the trust set: 403 even with a valid bearer token —
    # the socket peer, not the token, is what is rejected.
    transport = httpx.ASGITransport(
        app=app, client=("203.0.113.9", 51234)  # type: ignore[arg-type]
    )
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            mcp = await client.post(
                "/mcp", json={}, headers={"Authorization": f"Bearer {LEGACY_TOKEN}"}
            )
            assert mcp.status_code == 403
            assert mcp.json()["error"] == "proxy_required"

            ready = await client.get(
                "/ready", headers={"Authorization": f"Bearer {LEGACY_TOKEN}"}
            )
            assert ready.status_code == 403

            # /health is exempt: liveness must survive for the container.
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}
    finally:
        await hub.close()


@respx.mock
async def test_app_passes_trusted_peer(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    settings = _settings(tmp_path, trusted_proxies=[PROXY_CIDR], require_trusted_proxy=True)
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    transport = httpx.ASGITransport(
        app=app, client=("10.88.1.5", 51234)  # type: ignore[arg-type]
    )
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            mcp = await client.post(
                "/mcp", json={}, headers={"Authorization": f"Bearer {LEGACY_TOKEN}"}
            )
            # Not 403 (proxy gate) and not 401 (bearer): the request reached
            # the MCP app, which rejects the empty body its own way.
            assert mcp.status_code not in (401, 403)
    finally:
        await hub.close()


# -- end to end: real uvicorn, trusted local proxy, audit attribution --------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _serve(app: object, port: int) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    # proxy_headers=False: forwarded headers are handled explicitly by the
    # server (D024) — exactly how __main__.py runs the production server.
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", proxy_headers=False)
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:
            raise TimeoutError("uvicorn did not start")
        await asyncio.sleep(0.01)
    return server, task


async def test_e2e_trusted_proxy_resolves_client_ip(tmp_path: Path) -> None:
    """Full MCP session through a real uvicorn server, behind a 'local
    reverse proxy' (127.0.0.1/32 trusted, X-Forwarded-For carries the real
    client). Every audit entry must carry the resolved client IP.

    No respx here: the PVE discovery call to pve.test fails fast (NXDOMAIN)
    and the hub runs fail-open — the audit attribution under test does not
    depend on the PVE API. The socket to 127.0.0.1 must stay a real
    connection, so respx (which would intercept it) is deliberately absent.
    """
    port = _free_port()
    settings = _settings(
        tmp_path,
        host="127.0.0.1",
        port=port,
        trusted_proxies=["127.0.0.1/32"],
        require_trusted_proxy=True,
    )
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    server, task = await _serve(app, port)
    base = f"http://127.0.0.1:{port}"
    try:
        # A real reverse proxy (e.g. nginx) appends its own address to the
        # right of the client's: the rightmost entry is the proxy's, the
        # leftmost is the client.
        headers = {
            "Authorization": f"Bearer {LEGACY_TOKEN}",
            "X-Forwarded-For": f"{EXTERNAL_IP}, 127.0.0.1",
        }
        async with (
            httpx.AsyncClient(base_url=base, headers=headers) as http,
            streamable_http_client(f"{base}/mcp", http_client=http) as (
                read_stream,
                write_stream,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            result = await session.call_tool("pvehub_capabilities", {})
            assert result.content, "expected a tool result"
    finally:
        server.should_exit = True
        await task
        await hub.close()

    audit_file = tmp_path / "audit.jsonl"
    entries = [
        json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()
    ]
    assert entries, "expected at least one audit entry"
    tool_entries = [e for e in entries if e["tool"] == "pvehub_capabilities"]
    assert tool_entries, "expected an audit entry for the tool call"
    for entry in entries:
        assert entry["client"] == "default", entry
        # The socket peer (127.0.0.1) is trusted, so the real client from
        # the forwarded header is attributed — never the proxy's own address.
        assert entry["client_ip"] == EXTERNAL_IP, entry


async def test_e2e_without_trust_set_xff_is_ignored(tmp_path: Path) -> None:
    """Default configuration (no trusted proxies): X-Forwarded-For is never
    consulted; the socket peer is attributed. Behaviour unchanged.

    No respx: see the note in the other E2E test — the socket must stay
    real and the PVE call must fail fast on its own.
    """
    port = _free_port()
    settings = _settings(tmp_path, host="127.0.0.1", port=port)
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    server, task = await _serve(app, port)
    base = f"http://127.0.0.1:{port}"
    try:
        headers = {
            "Authorization": f"Bearer {LEGACY_TOKEN}",
            "X-Forwarded-For": f"{EXTERNAL_IP}, 1.2.3.4",
        }
        async with (
            httpx.AsyncClient(base_url=base, headers=headers) as http,
            streamable_http_client(f"{base}/mcp", http_client=http) as (
                read_stream,
                write_stream,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            result = await session.call_tool("pvehub_capabilities", {})
            assert result.content, "expected a tool result"
    finally:
        server.should_exit = True
        await task
        await hub.close()

    audit_file = tmp_path / "audit.jsonl"
    entries = [
        json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()
    ]
    tool_entries = [e for e in entries if e["tool"] == "pvehub_capabilities"]
    assert tool_entries
    for entry in tool_entries:
        # No trust set: the socket peer (127.0.0.1) is the address — the
        # forged/real XFF chain is ignored.
        assert entry["client_ip"] == "127.0.0.1", entry
