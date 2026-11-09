"""Checks for the packaging assets added with the container/compose deliverables.

These tests do not need PVE, PBS, SSH or Docker: they parse the shipped files and
exercise the policy engine against the example policies.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

import pvehub_mcp
from pvehub_mcp.errors import PolicyError
from pvehub_mcp.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "config" / "examples"


@pytest.mark.parametrize(
    ("name", "read_only"),
    [("readonly", True), ("operator", False), ("admin", False)],
)
def test_example_policies_load(name: str, read_only: bool) -> None:
    policy = Policy.load(EXAMPLES / f"{name}.yaml", env={})
    assert policy.file.read_only is read_only
    assert policy.file.tools.allow == []
    assert policy.file.tools.deny == []


def test_readonly_policy_blocks_mutating_categories() -> None:
    policy = Policy.load(EXAMPLES / "readonly.yaml", env={})
    assert policy.tool_decision("pve_guest_status", "read").allowed
    for category in ("lifecycle", "write", "destructive", "exec"):
        assert not policy.tool_decision("some_tool", category).allowed  # type: ignore[arg-type]
    policy.check_generic("GET", "/nodes")
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/qemu/100/status/start")


def test_operator_policy_keeps_destructive_and_host_shell_off() -> None:
    policy = Policy.load(EXAMPLES / "operator.yaml", env={})
    assert not policy.tool_decision("pve_guest_delete", "destructive").allowed
    assert policy.tool_decision("pve_guest_start", "lifecycle").allowed
    assert policy.file.exec.host is False
    assert policy.file.exec.pbs_host is False
    assert policy.file.exec.lxc is True
    assert policy.file.exec.vm is True
    with pytest.raises(PolicyError):
        policy.check_generic("DELETE", "/nodes/pve1/qemu/100/config")
    policy.check_generic("POST", "/nodes/pve1/qemu/100/status/start")


def test_admin_policy_allows_destructive_but_not_console_tickets() -> None:
    policy = Policy.load(EXAMPLES / "admin.yaml", env={})
    assert policy.tool_decision("pve_guest_delete", "destructive").allowed
    assert policy.file.exec.host is True
    assert policy.file.exec.pbs_host is True
    assert policy.file.generic_api.deny_methods == []
    policy.check_generic("DELETE", "/nodes/pve1/qemu/100/config")
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/access/ticket")
    with pytest.raises(PolicyError):
        policy.check_generic("POST", "/nodes/pve1/vncshell")


def test_compose_service_contract() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["pvehub-mcp"]
    assert service["image"] == "pvehub-mcp:0.1.3"
    assert service["build"]["context"] == "."
    assert service["env_file"] == [".env"]
    assert service["ports"] == ["8080:8080"]
    assert service["volumes"] == [
        "./config:/config:ro",
        "./ssh:/ssh:ro",
        "pvehub-data:/data",
    ]
    assert service["read_only"] is True
    assert service["tmpfs"] == ["/tmp:size=64m,mode=1777"]
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["restart"] == "unless-stopped"
    assert "healthcheck" in service
    assert "pvehub-data" in compose["volumes"]


def test_dockerfile_contract() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("\nFROM ") == 2
    assert "python:3.12-slim" in dockerfile
    assert "ghcr.io/astral-sh/uv:0.12.23" in dockerfile
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "EXPOSE 8080" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "urllib.request" in dockerfile
    assert 'ENTRYPOINT ["pvehub-mcp"]' in dockerfile


def test_ci_workflow_has_required_jobs() -> None:
    workflow = yaml.safe_load((ROOT / ".gitea" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert set(jobs) == {"lint", "typecheck", "test", "docker", "compose"}
    assert "uv run ruff check src tests" in jobs["lint"]["steps"][-1]["run"]
    assert "uv run mypy src" in jobs["typecheck"]["steps"][-1]["run"]
    assert "uv run pytest" in jobs["test"]["steps"][-1]["run"]
    assert "docker build" in jobs["docker"]["steps"][-1]["run"]


def test_package_version_matches_pyproject() -> None:
    """A release must not ship a runtime version that differs from the packaged one."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == pvehub_mcp.__version__


def test_generated_tool_docs_are_current() -> None:
    docs = ROOT / "docs" / "TOOLS.md"
    assert docs.exists()
    content = docs.read_text(encoding="utf-8")
    assert content.startswith("<!-- Generated by scripts/generate_tool_docs.py")
    assert (
        "| Tool | Title | Category | PVE privilege/path | PBS privilege/path | Shell | Description |"
        in content
    )

    result = subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script
        [sys.executable, str(ROOT / "scripts" / "generate_tool_docs.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip()
    assert result.stdout == content
