"""HTTP client contract tests with respx."""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from pvehub_mcp.clients.base import quote_path
from pvehub_mcp.clients.pbs import PBSClient
from pvehub_mcp.clients.pve import PVEClient, parse_apidoc_js
from pvehub_mcp.errors import AuthenticationError, InvalidArgument, NotFound, PermissionDenied


def pve_client(**kwargs: object) -> PVEClient:
    data = {
        "name": "test",
        "url": "https://pve.test:8006",
        "api_path": "/api2/json",
        "token_id": "pvehub@pve!mcp",
        "token_secret": "secret",
        "verify": True,
        "max_retries": 0,
        "state_dir": "/tmp/pvehub-test-state",
    }
    data.update(kwargs)
    return PVEClient(**data)  # type: ignore[arg-type]


def pbs_client(**kwargs: object) -> PBSClient:
    data = {
        "name": "pbs",
        "url": "https://pbs.test:8007",
        "api_path": "/api2/extjs",
        "token_id": "pvehub@pbs!mcp",
        "token_secret": "secret",
        "verify": True,
        "max_retries": 0,
        "state_dir": "/tmp/pvehub-test-state",
    }
    data.update(kwargs)
    return PBSClient(**data)  # type: ignore[arg-type]


@respx.mock
async def test_pve_auth_header_and_data_unwrap() -> None:
    route = respx.get("https://pve.test:8006/api2/json/version").mock(
        return_value=httpx.Response(200, json={"data": {"version": "8.2"}})
    )
    client = pve_client()
    assert await client.get("/version") == {"version": "8.2"}
    assert route.calls[0].request.headers["Authorization"] == "PVEAPIToken=pvehub@pve!mcp=secret"
    await client.aclose()


@respx.mock
async def test_pve_form_encoding_for_writes() -> None:
    captured: dict[str, list[str]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"data": "UPID:pve1:0001:0002:0003:qmstart:100:root@pam:"})

    respx.post("https://pve.test:8006/api2/json/nodes/pve1/qemu/100/status/start").mock(
        side_effect=handler
    )
    client = pve_client()
    upid = await client.post(
        "/nodes/pve1/qemu/100/status/start",
        {"force": True, "timeout": 30, "skiplock": False, "tags": ["a", "b"]},
    )
    assert upid.startswith("UPID:")
    assert captured["force"] == ["1"]
    assert captured["timeout"] == ["30"]
    assert captured["skiplock"] == ["0"]
    assert captured["tags"] == ["a", "b"]
    await client.aclose()


@respx.mock
async def test_pbs_auth_header_uses_colon() -> None:
    route = respx.get("https://pbs.test:8007/api2/extjs/version").mock(
        return_value=httpx.Response(200, json={"data": {"version": "3.2"}})
    )
    client = pbs_client()
    await client.get("/version")
    assert route.calls[0].request.headers["Authorization"] == "PBSAPIToken=pvehub@pbs!mcp:secret"
    await client.aclose()


@respx.mock
async def test_error_mapping() -> None:
    respx.get("https://pve.test:8006/api2/json/nodes").mock(
        return_value=httpx.Response(401, text="authentication failed")
    )
    respx.get("https://pve.test:8006/api2/json/storage").mock(
        return_value=httpx.Response(403, json={"errors": {"storage": "no permission"}})
    )
    respx.get("https://pve.test:8006/api2/json/nodes/missing").mock(
        return_value=httpx.Response(404, text="not found")
    )
    client = pve_client()
    with pytest.raises(AuthenticationError):
        await client.get("/nodes")
    with pytest.raises(PermissionDenied) as exc:
        await client.get("/storage")
    assert "no permission" in str(exc.value)
    with pytest.raises(NotFound):
        await client.get("/nodes/missing")
    await client.aclose()


@respx.mock
async def test_get_retries_on_503() -> None:
    route = respx.get("https://pve.test:8006/api2/json/version")
    route.side_effect = [
        httpx.Response(503, text="busy"),
        httpx.Response(200, json={"data": {"version": "8.2"}}),
    ]
    client = pve_client(max_retries=1)
    assert await client.get("/version") == {"version": "8.2"}
    assert route.call_count == 2
    await client.aclose()


@respx.mock
async def test_delete_parameters_are_query_parameters() -> None:
    captured: dict[str, list[str]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(parse_qs(request.url.query.decode()))
        return httpx.Response(200, json={"data": None})

    respx.delete("https://pve.test:8006/api2/json/nodes/pve1/qemu/100").mock(
        side_effect=handler
    )
    client = pve_client()
    await client.delete("/nodes/pve1/qemu/100", {"purge": True, "destroy-unreferenced-disks": True})
    assert captured["purge"] == ["1"]
    assert captured["destroy-unreferenced-disks"] == ["1"]
    await client.aclose()


@respx.mock
async def test_schema_parse_and_describe(tmp_path) -> None:
    schema = [
        {
            "path": "/nodes",
            "text": "nodes",
            "children": [
                {
                    "path": "/nodes/{node}/status",
                    "text": "status",
                    "info": {
                        "GET": {
                            "description": "Read node status",
                            "parameters": {
                                "properties": {"node": {"type": "string", "optional": 0}}
                            },
                            "returns": {"type": "object"},
                        }
                    },
                }
            ],
        }
    ]
    respx.get("https://pve.test:8006/pve-docs/api-viewer/apidoc.js").mock(
        return_value=httpx.Response(
            200, text="const apiSchema = " + json.dumps(schema) + ";\n"
        )
    )
    client = pve_client(state_dir=str(tmp_path))
    described = await client.api_schema("/nodes/pve1/status")
    assert "GET" in described["methods"]
    assert described["methods"]["GET"]["params"]["node"]["type"] == "string"
    assert (tmp_path / "apidoc-test.json").exists()
    await client.aclose()


@respx.mock
async def test_task_polling_and_log_tail() -> None:
    status_route = respx.get(
        "https://pve.test:8006/api2/json/nodes/pve1/tasks/UPID:pve1:1/status"
    )
    status_route.side_effect = [
        httpx.Response(200, json={"data": {"status": "running"}}),
        httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK"}}),
    ]
    respx.get("https://pve.test:8006/api2/json/nodes/pve1/tasks/UPID:pve1:1/log").mock(
        return_value=httpx.Response(
            200, json={"data": [{"n": 1, "t": "starting"}, {"n": 2, "t": "done"}]}
        )
    )
    client = pve_client()
    result = await client.wait_task("pve1", "UPID:pve1:1", timeout=5, poll_interval=0.25)
    assert result["completed"] is True
    assert result["success"] is True
    assert "done" in result["log_tail"]
    await client.aclose()


def test_quote_path_rejects_traversal() -> None:
    assert quote_path("/nodes/pve1/status") == "/nodes/pve1/status"
    for path in ("/nodes/../access", "/nodes/%2e%2e/access", "/nodes/%252e%252e/access", "/nodes/a%2fb"):
        with pytest.raises(InvalidArgument):
            quote_path(path)


def test_parse_apidoc_with_prefix_and_suffix() -> None:
    assert parse_apidoc_js("var apiSchema = [{\"path\": \"/\"}];\nfoo();") == [{"path": "/"}]
