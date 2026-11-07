"""Configuration loading tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pvehub_mcp.config import PVEInstance, Settings, SSHSettings, SSHTarget, load_settings
from pvehub_mcp.errors import ConfigError


def _pve(**overrides: object) -> PVEInstance:
    data = {
        "name": "test",
        "url": "https://pve.example:8006",
        "token_id": "pvehub@pve!mcp",
        "token_secret": "secret-value",
        "verify": True,
    }
    data.update(overrides)
    return PVEInstance.model_validate(data)


def test_minimal_settings_and_secret_repr() -> None:
    settings = Settings(pve=[_pve()], transport="stdio")
    assert settings.pve_instance(None).name == "test"
    assert "secret-value" not in repr(settings)
    assert settings.pve[0].token_secret.get_secret_value() == "secret-value"


def test_non_loopback_requires_auth_token() -> None:
    with pytest.raises(ValidationError):
        Settings(pve=[_pve()], transport="http", host="0.0.0.0")


def test_loopback_without_token_is_allowed() -> None:
    settings = Settings(pve=[_pve()], transport="http", host="127.0.0.1")
    assert settings.mcp_auth_token is None


def test_http_url_requires_explicit_opt_in() -> None:
    with pytest.raises(ValidationError):
        Settings(pve=[_pve(url="http://pve.example:8006")], transport="stdio")
    settings = Settings(
        pve=[_pve(url="http://pve.example:8006")],
        transport="stdio",
        allow_insecure_http=True,
    )
    assert settings.pve[0].url.startswith("http://")


def test_ssh_node_inherits_global_defaults() -> None:
    ssh = SSHSettings(
        user="global",
        key_path="/keys/id",
        known_hosts="/keys/known_hosts",
        port=2222,
        nodes={"pve1": SSHTarget(host="10.0.0.11")},
    )
    target = ssh.node("pve1")
    assert target is not None
    assert target.user == "global"
    assert target.port == 2222
    assert target.key_path == "/keys/id"

    override = SSHSettings(
        user="global",
        nodes={"pve1": SSHTarget(host="10.0.0.11", user="root", port=22)},
    )
    target = override.node("pve1")
    assert target is not None
    assert target.user == "root"
    assert target.port == 22


def test_load_settings_from_yaml_and_env(tmp_path, monkeypatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        """
transport: stdio
pve:
  - name: main
    url: https://pve.example:8006
    token_id: pvehub@pve!mcp
    token_secret: from-yaml
pbs:
  - name: backup
    url: https://pbs.example:8007
    token_id: pvehub@pbs!mcp
    token_secret: pbs-secret
ssh:
  user: automation
  key_path: /tmp/key
  known_hosts: /tmp/known_hosts
  nodes:
    pve1:
      host: 10.0.0.11
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("PVEHUB_CONFIG_FILE", str(config))
    monkeypatch.setenv("PVEHUB_PVE_TOKEN_SECRET", "from-env")
    monkeypatch.setenv("PVEHUB_LOG_LEVEL", "DEBUG")
    settings = load_settings()
    assert settings.pve[0].token_secret.get_secret_value() == "from-env"
    assert settings.pbs[0].name == "backup"
    assert settings.log_level == "DEBUG"
    assert settings.ssh.user == "automation"


def test_duplicate_instance_names_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(pve=[_pve(), _pve()], transport="stdio")


def test_unknown_instance_error() -> None:
    settings = Settings(pve=[_pve()], transport="stdio")
    with pytest.raises(ConfigError):
        settings.pve_instance("missing")
