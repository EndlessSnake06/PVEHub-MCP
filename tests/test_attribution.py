"""End-to-end client attribution (D019, issue #21).

Covers the whole chain: named/legacy bearer tokens are resolved by the
middleware, the client name propagates through the request context to the
tool wrapper, and every audit entry carries the ``client`` field.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from mcp.client import Client
from pydantic import ValidationError

from pvehub_mcp.clientid import current_client
from pvehub_mcp.config import PVEInstance, Settings, _as_token_map
from pvehub_mcp.policy import Policy, PolicyFile
from pvehub_mcp.server import BearerAuthMiddleware, PVEHub, build_http_app

BASE = "https://pve.test:8006"
PERMISSIONS = {"/": {"Sys.Audit": 1}}
LEGACY_TOKEN = "legacy-token-01234567"
WEBUI_TOKEN = "webui-token-01234567"
HERMES_TOKEN = "hermes-token-01234567"


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
        "mcp_auth_tokens": {"webui": WEBUI_TOKEN, "hermes": HERMES_TOKEN},
        "audit_log": None,
        "state_dir": "/tmp/pvehub-attribution",
        "capabilities_fail_open": True,
        "capabilities_refresh_seconds": 0,
    }
    if tmp_path is not None:
        data["audit_log"] = str(Path(tmp_path) / "audit.jsonl")
    data.update(overrides)
    return Settings.model_validate(data)


# -- settings-level validation ---------------------------------------------


def test_http_with_named_tokens_only_is_allowed() -> None:
    # Named tokens are a first-class alternative to the legacy token for the
    # http transport; rotating one client's token does not break the others.
    settings = _settings(mcp_auth_token=None, mcp_auth_tokens={"webui": WEBUI_TOKEN})
    assert settings.mcp_auth_token is None
    assert settings.mcp_auth_tokens == {"webui": WEBUI_TOKEN}


def test_named_token_rejects_reserved_default_name() -> None:
    with pytest.raises(ValidationError, match="default"):
        _settings(mcp_auth_tokens={"default": WEBUI_TOKEN})


def test_named_token_rejects_short_token() -> None:
    with pytest.raises(ValidationError, match="16 characters"):
        _settings(mcp_auth_tokens={"webui": "short"})


def test_named_token_rejects_bad_charset() -> None:
    with pytest.raises(ValidationError):
        _settings(mcp_auth_tokens={"Webui": WEBUI_TOKEN})


def test_named_token_must_not_equal_legacy_token() -> None:
    with pytest.raises(ValidationError, match="identify exactly one client"):
        _settings(mcp_auth_tokens={"webui": LEGACY_TOKEN})


def test_http_still_requires_at_least_one_token() -> None:
    with pytest.raises(ValidationError, match="PVEHUB_MCP_AUTH"):
        _settings(mcp_auth_token=None, mcp_auth_tokens={})


def test_named_tokens_env_is_parsed() -> None:
    parsed = _as_token_map("webui:webui-token-01234567,hermes:hermes-token-01234567")
    assert parsed == {"webui": WEBUI_TOKEN, "hermes": HERMES_TOKEN}
    assert _as_token_map(None) == {}
    assert _as_token_map("   ") == {}


# -- middleware behaviour ----------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected_client"),
    [
        (f"Bearer {LEGACY_TOKEN}", "default"),
        (f"Bearer {WEBUI_TOKEN}", "webui"),
        (f"Bearer {HERMES_TOKEN}", "hermes"),
    ],
)
async def test_middleware_sets_client_context(header: str, expected_client: str) -> None:
    """The resolved name is visible in the request context — including in a
    child task, which is exactly where the MCP SDK runs tool calls."""

    seen: list[str] = []

    async def inner(scope: dict, receive: object, send: object) -> None:
        async def probe() -> None:
            seen.append(current_client())

        await probe()  # child task: contextvars propagate to it

    middleware = BearerAuthMiddleware(
        inner,
        credentials={"default": LEGACY_TOKEN, "webui": WEBUI_TOKEN, "hermes": HERMES_TOKEN},
    )
    scope = {"type": "http", "path": "/mcp", "headers": [(b"authorization", header.encode())]}
    await middleware(scope, None, None)
    assert seen == [expected_client]
    # The context is reset after the request.
    assert current_client() == "unknown"


async def test_middleware_rejects_unknown_token() -> None:
    status: dict[str, int] = {}

    async def inner(scope: dict, receive: object, send: object) -> None:
        status["reached"] = 200

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status["code"] = message["status"]

    middleware = BearerAuthMiddleware(inner, credentials={"default": LEGACY_TOKEN})
    scope = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"authorization", b"Bearer wrong-token-01234567")],
    }
    await middleware(scope, None, send)
    assert status.get("code") == 401
    assert "reached" not in status


async def test_middleware_passes_through_unprotected_paths() -> None:
    status: dict[str, int] = {}

    async def inner(scope: dict, receive: object, send: object) -> None:
        status["reached"] = 200

    middleware = BearerAuthMiddleware(inner, credentials={"default": LEGACY_TOKEN})
    scope = {"type": "http", "path": "/health", "headers": []}
    await middleware(scope, None, None)
    assert status == {"reached": 200}


# -- real http app: every client can authenticate ---------------------------


@respx.mock
async def test_http_app_accepts_legacy_and_named_tokens(tmp_path: Path) -> None:
    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    settings = _settings(tmp_path)
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    app = build_http_app(hub)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            for header in (
                f"Bearer {LEGACY_TOKEN}",
                f"Bearer {WEBUI_TOKEN}",
                f"Bearer {HERMES_TOKEN}",
            ):
                response = await client.get("/ready", headers={"Authorization": header})
                assert response.status_code == 200, header

            wrong = await client.get(
                "/ready", headers={"Authorization": "Bearer nope-0123456789"}
            )
            assert wrong.status_code == 401
            missing = await client.get("/ready")
            assert missing.status_code == 401
    finally:
        await hub.close()


# -- wrapper: audit entries carry the client field ---------------------------


@respx.mock
async def test_stdio_calls_are_attributed_unknown(tmp_path: Path) -> None:
    """Without a middleware (stdio transport) the client falls back to
    "unknown" — the field is still present on every entry."""

    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    settings = _settings(
        tmp_path,
        transport="stdio",
        mcp_auth_token=None,
        mcp_auth_tokens={},
    )
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    try:
        async with Client(hub.mcp) as client:
            result = await client.call_tool("pvehub_capabilities", {})
            assert not result.is_error
    finally:
        await hub.close()

    audit_file = tmp_path / "audit.jsonl"
    entries = [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]
    assert entries, "expected at least one audit entry"
    for entry in entries:
        assert entry["client"] == "unknown"


@respx.mock
async def test_audit_entry_has_error_dict_output_bytes_and_result(tmp_path: Path) -> None:
    """#18: forced denials carry error.code/error.message; successful calls
    carry output_bytes and (with PVEHUB_AUDIT_INCLUDE_RESULTS) the redacted
    result."""

    respx.get(f"{BASE}/api2/json/access/permissions").mock(
        return_value=httpx.Response(200, json={"data": PERMISSIONS})
    )
    settings = _settings(
        tmp_path,
        transport="stdio",
        mcp_auth_token=None,
        mcp_auth_tokens={},
        audit_include_results=True,
    )
    hub = PVEHub(settings, Policy(file=PolicyFile()))
    hub.build()
    try:
        async with Client(hub.mcp) as client:
            # Read tool: ok path.
            read = await client.call_tool("pvehub_capabilities", {})
            assert not read.is_error
            # Generic write without confirm: confirm_required denial.
            denied = await client.call_tool(
                "pve_api_call", {"method": "POST", "path": "/nodes/pve1/qemu"}
            )
            assert not denied.is_error
    finally:
        await hub.close()

    audit_file = tmp_path / "audit.jsonl"
    entries = [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]
    by_status: dict[str, list[dict]] = {}
    for entry in entries:
        by_status.setdefault(entry["status"], []).append(entry)

    ok_entries = by_status.get("ok", [])
    assert ok_entries, "expected ok entries"
    for entry in ok_entries:
        assert entry["client"] == "unknown"
        assert isinstance(entry.get("output_bytes"), int)
        assert entry["output_bytes"] > 0
        assert "result" in entry  # include_results=True

    denied_entries = by_status.get("denied", [])
    assert denied_entries, "expected a denied entry"
    for entry in denied_entries:
        assert entry["error"]["code"] == "confirm_required"
        assert isinstance(entry["error"]["message"], str) and entry["error"]["message"]
