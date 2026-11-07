"""Optional live integration tests (read-only).

Run only when a test environment is explicitly provided:

    PVEHUB_IT=1 \
    PVEHUB_PVE_URL=https://pve.example:8006 \
    PVEHUB_PVE_TOKEN_ID=pvehub@pve!test \
    PVEHUB_PVE_TOKEN_SECRET=... \
    pytest -m integration

The tests never mutate anything. They are skipped by default.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration

pytest.importorskip("httpx")


def _enabled() -> bool:
    return os.environ.get("PVEHUB_IT") == "1"


@pytest.mark.skipif(not _enabled(), reason="set PVEHUB_IT=1 and provide test credentials")
async def test_pve_read_only_endpoints() -> None:
    from pvehub_mcp.clients.pve import PVEClient

    url = os.environ["PVEHUB_PVE_URL"]
    token_id = os.environ["PVEHUB_PVE_TOKEN_ID"]
    secret = os.environ["PVEHUB_PVE_TOKEN_SECRET"]
    client = PVEClient(
        name="integration",
        url=url,
        api_path="/api2/json",
        token_id=token_id,
        token_secret=secret,
        verify=os.environ.get("PVEHUB_PVE_VERIFY", "true").lower() != "false",
        state_dir="/tmp",
    )
    try:
        version = await client.get("/version")
        assert "version" in version
        nodes = await client.get("/nodes")
        assert isinstance(nodes, list)
        resources = await client.get("/cluster/resources", params={"type": "vm"})
        assert isinstance(resources, list)
        permissions = await client.permissions()
        assert isinstance(permissions, dict)
    finally:
        await client.aclose()


@pytest.mark.skipif(not _enabled(), reason="set PVEHUB_IT=1 and provide test credentials")
async def test_pbs_read_only_endpoints() -> None:
    from pvehub_mcp.clients.pbs import PBSClient

    url = os.environ.get("PVEHUB_PBS_URL")
    if not url:
        pytest.skip("PVEHUB_PBS_URL not set")
    client = PBSClient(
        name="integration",
        url=url,
        api_path="/api2/extjs",
        token_id=os.environ["PVEHUB_PBS_TOKEN_ID"],
        token_secret=os.environ["PVEHUB_PBS_TOKEN_SECRET"],
        verify=os.environ.get("PVEHUB_PBS_VERIFY", "true").lower() != "false",
        state_dir="/tmp",
    )
    try:
        version = await client.get("/version")
        assert "version" in version
        datastores = await client.get("/admin/datastore")
        assert isinstance(datastores, list)
        permissions = await client.permissions()
        assert isinstance(permissions, dict)
    finally:
        await client.aclose()
