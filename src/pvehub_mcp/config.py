"""Configuration loading: defaults < YAML < environment.

Secrets are stored as :class:`pydantic.SecretStr` and never rendered in logs, reprs or
audit entries.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .errors import ConfigError

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            return os.environ.get(match.group(1), "")

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def _as_bool(value: str | bool | int) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_token_map(value: str | dict[str, str] | None) -> dict[str, str]:
    """Parse ``PVEHUB_MCP_AUTH_TOKENS`` (``name:token,name2:token2``) into a dict.

    The structural parsing (split points, missing colon, empty parts) is
    delegated to :func:`pvehub_mcp.clientid.parse_token_pairs`; the config
    validators add the name charset / length / collision rules.
    """

    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if not str(value).strip():
        return {}
    from .clientid import parse_token_pairs

    return dict(parse_token_pairs(str(value)))


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in value.split(",") if part.strip()]


class TLSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verify: bool | str = True
    ca_file: str | None = None
    fingerprint: str | None = None

    @field_validator("fingerprint")
    @classmethod
    def _check_fingerprint(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        cleaned = value.strip().lower()
        if cleaned.startswith("sha256:"):
            cleaned = cleaned[7:]
        cleaned = cleaned.replace(":", "").replace(" ", "")
        if len(cleaned) != 64 or any(ch not in "0123456789abcdef" for ch in cleaned):
            raise ValueError("fingerprint must be a SHA-256 hex digest (64 hex characters)")
        return cleaned


class PVEInstance(TLSConfig):
    name: str = "default"
    url: str
    token_id: str
    token_secret: SecretStr
    api_path: str = "/api2/json"
    timeout_seconds: float = 30.0
    max_retries: int = 2

    @field_validator("url")
    @classmethod
    def _strip_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        parsed = urlparse(value)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("url must be an absolute http(s) URL")
        return value

    @field_validator("api_path")
    @classmethod
    def _api_path(cls, value: str) -> str:
        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("api_path must start with '/' and not end with '/'")
        return value

    @field_validator("token_id")
    @classmethod
    def _token_id(cls, value: str) -> str:
        if "!" not in value or "@" not in value:
            raise ValueError("token_id must look like USER@REALM!TOKENID")
        return value

    @model_validator(mode="after")
    def _secret_required(self) -> PVEInstance:
        if not self.token_secret.get_secret_value():
            raise ValueError("token_secret must not be empty")
        return self


class PBSInstance(PVEInstance):
    api_path: str = "/api2/extjs"


class SSHTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    port: int = 22
    user: str = "pvehub"
    key_path: str = "/ssh/id_ed25519"
    known_hosts: str = "/ssh/known_hosts"
    strict_host_key: bool = True
    connect_timeout: float = 10.0
    sudo: bool = False

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("ssh host must be a non-empty hostname or IP")
        return value


class SSHNode(SSHTarget):
    pass


class SSHSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: str = "pvehub"
    key_path: str = "/ssh/id_ed25519"
    known_hosts: str = "/ssh/known_hosts"
    port: int = 22
    strict_host_key: bool = True
    connect_timeout: float = 10.0
    nodes: dict[str, SSHTarget] = Field(default_factory=dict)
    pbs: SSHTarget | None = None

    def node(self, name: str) -> SSHTarget | None:
        target = self.nodes.get(name)
        if target is None:
            return None
        updates: dict[str, Any] = {}
        if "user" not in target.model_fields_set:
            updates["user"] = self.user
        if "key_path" not in target.model_fields_set:
            updates["key_path"] = self.key_path
        if "known_hosts" not in target.model_fields_set:
            updates["known_hosts"] = self.known_hosts
        if "port" not in target.model_fields_set:
            updates["port"] = self.port
        if "strict_host_key" not in target.model_fields_set:
            updates["strict_host_key"] = self.strict_host_key
        if "connect_timeout" not in target.model_fields_set:
            updates["connect_timeout"] = self.connect_timeout
        return target.model_copy(update=updates)

    @property
    def configured(self) -> bool:
        return bool(self.nodes or self.pbs)

    def missing_prerequisites(self) -> list[str]:
        missing: list[str] = []
        if not self.nodes and self.pbs is None:
            return ["ssh.nodes or ssh.pbs"]
        targets: list[SSHTarget] = []
        for name in self.nodes:
            resolved = self.node(name)
            if resolved is not None:
                targets.append(resolved)
        if self.pbs is not None:
            targets.append(self.pbs)
        for target in targets:
            if not Path(target.key_path).exists():
                missing.append(f"ssh key not found: {target.key_path}")
            if target.strict_host_key and not Path(target.known_hosts).exists():
                missing.append(f"known_hosts not found: {target.known_hosts}")
        return sorted(set(missing))


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: Literal["http", "stdio"] = "http"
    host: str = "127.0.0.1"
    port: int = 8080
    mcp_auth_token: SecretStr | None = None
    #: Named MCP tokens for per-client audit attribution (D019, issue #21).
    #: Maps client name -> bearer token; the legacy single token is exposed to
    #: the middleware as the reserved client ``default``.
    mcp_auth_tokens: dict[str, str] = Field(default_factory=dict)
    mcp_auth_required: bool = True
    allowed_hosts: list[str] = Field(default_factory=list)

    pve: list[PVEInstance] = Field(default_factory=list)
    pbs: list[PBSInstance] = Field(default_factory=list)
    ssh: SSHSettings = Field(default_factory=SSHSettings)

    policy_file: str = "/config/policy.yaml"
    audit_log: str | None = "/data/audit.jsonl"
    audit_include_results: bool = False
    #: Size cap for the active audit file in bytes (D023, issue #19).
    audit_max_bytes: int = 10 * 1024 * 1024
    #: Number of rotated archives to keep (audit.jsonl.1 ... .keep).
    audit_keep: int = 5
    state_dir: str = "/data"
    task_timeout_seconds: float = 300.0
    max_output_bytes: int = 65536
    capabilities_refresh_seconds: int = 300
    capabilities_fail_open: bool = True
    wait_default: bool = True
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    allow_insecure_http: bool = False

    @field_validator("mcp_auth_token")
    @classmethod
    def _token_not_blank(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            raise ValueError("mcp_auth_token must not be empty")
        return value

    @field_validator("mcp_auth_tokens")
    @classmethod
    def _named_tokens(cls, value: dict[str, str]) -> dict[str, str]:
        from .clientid import valid_client_name

        for name, token in value.items():
            if not valid_client_name(name):
                raise ValueError(
                    f"named-token client {name!r} is invalid; use 1-32 characters of "
                    "[a-z0-9_-] starting with a letter or digit, and not the reserved name 'default'"
                )
            if not token.strip():
                raise ValueError(f"named-token for client {name!r} must not be empty")
            if len(token) < 16:
                raise ValueError(f"named-token for client {name!r} must be at least 16 characters")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if not self.pve and not self.pbs:
            raise ValueError("at least one PVE or PBS instance must be configured")
        for instance in [*self.pve, *self.pbs]:
            parsed = urlparse(instance.url)
            if parsed.scheme == "http" and not self.allow_insecure_http:
                raise ValueError(
                    f"instance {instance.name!r} uses http; set allow_insecure_http=true "
                    "only for isolated test environments"
                )
        if self.mcp_auth_token is not None:
            token = self.mcp_auth_token.get_secret_value()
            if not token.strip():
                raise ValueError("mcp_auth_token must not be empty")
            if len(token) < 16:
                raise ValueError("mcp_auth_token must be at least 16 characters")
            # A named token must not collide with the legacy token: the same
            # secret under two names would make the audit attribution ambiguous.
            for name, named_token in self.mcp_auth_tokens.items():
                if secrets.compare_digest(named_token, token):
                    raise ValueError(
                        f"named-token for client {name!r} equals mcp_auth_token; "
                        "each token must identify exactly one client"
                    )
        if (
            self.transport == "http"
            and self.mcp_auth_required
            and self.mcp_auth_token is None
            and not self.mcp_auth_tokens
        ):
            raise ValueError(
                "mcp_auth_token or mcp_auth_tokens is required for the http transport; "
                "set PVEHUB_MCP_AUTH_TOKEN or PVEHUB_MCP_AUTH_TOKENS, or "
                "PVEHUB_MCP_AUTH_REQUIRED=false (loopback development setups only)"
            )
        if (
            self.transport == "http"
            and not _is_loopback(self.host)
            and self.mcp_auth_token is None
            and not self.mcp_auth_tokens
        ):
            raise ValueError(
                "refusing to bind a non-loopback address without mcp_auth_token/mcp_auth_tokens"
            )
        for group in (self.pve, self.pbs):
            names = [instance.name for instance in group]
            if len(names) != len(set(names)):
                raise ValueError(f"duplicate instance names: {names}")
        if self.max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        if self.audit_max_bytes < 1024:
            raise ValueError("audit_max_bytes must be at least 1024")
        if self.audit_keep < 1:
            raise ValueError("audit_keep must be at least 1")
        return self

    def pve_instance(self, name: str | None) -> PVEInstance:
        return _pick(self.pve, name, "PVE")

    def pbs_instance(self, name: str | None) -> PBSInstance:
        return _pick(self.pbs, name, "PBS")


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def _pick[T: (PVEInstance, PBSInstance)](instances: list[T], name: str | None, kind: str) -> T:
    if not instances:
        raise ConfigError(f"no {kind} instance configured")
    if name is None:
        return instances[0]
    for instance in instances:
        if instance.name == name:
            return instance
    valid = ", ".join(instance.name for instance in instances)
    raise ConfigError(f"unknown {kind} instance {name!r}; configured: {valid}")


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must contain a mapping")
    return cast(dict[str, Any], _expand_env(data))


def _apply_env(data: dict[str, Any]) -> dict[str, Any]:
    mapping: dict[str, tuple[str, Any]] = {
        "PVEHUB_TRANSPORT": ("transport", str),
        "PVEHUB_HOST": ("host", str),
        "PVEHUB_PORT": ("port", int),
        "PVEHUB_MCP_AUTH_TOKEN": ("mcp_auth_token", str),
        "PVEHUB_MCP_AUTH_TOKENS": ("mcp_auth_tokens", _as_token_map),
        "PVEHUB_MCP_AUTH_REQUIRED": ("mcp_auth_required", _as_bool),
        "PVEHUB_ALLOWED_HOSTS": ("allowed_hosts", _as_list),
        "PVEHUB_POLICY_FILE": ("policy_file", str),
        "PVEHUB_AUDIT_LOG": ("audit_log", str),
        "PVEHUB_AUDIT_INCLUDE_RESULTS": ("audit_include_results", _as_bool),
        "PVEHUB_AUDIT_MAX_BYTES": ("audit_max_bytes", int),
        "PVEHUB_AUDIT_KEEP": ("audit_keep", int),
        "PVEHUB_STATE_DIR": ("state_dir", str),
        "PVEHUB_TASK_TIMEOUT_SECONDS": ("task_timeout_seconds", float),
        "PVEHUB_MAX_OUTPUT_BYTES": ("max_output_bytes", int),
        "PVEHUB_CAPABILITIES_REFRESH_SECONDS": ("capabilities_refresh_seconds", int),
        "PVEHUB_CAPABILITIES_FAIL_OPEN": ("capabilities_fail_open", _as_bool),
        "PVEHUB_WAIT_DEFAULT": ("wait_default", _as_bool),
        "PVEHUB_LOG_LEVEL": ("log_level", str),
        "PVEHUB_ALLOW_INSECURE_HTTP": ("allow_insecure_http", _as_bool),
    }
    for env_name, (key, caster) in mapping.items():
        raw = _env(env_name)
        if raw is not None:
            data[key] = caster(raw)

    # Single-instance shortcuts. They override the first instance if one exists.
    _apply_instance_env(
        data,
        "pve",
        {
            "name": ("PVEHUB_PVE_NAME", str),
            "url": ("PVEHUB_PVE_URL", str),
            "token_id": ("PVEHUB_PVE_TOKEN_ID", str),
            "token_secret": ("PVEHUB_PVE_TOKEN_SECRET", str),
            "verify": ("PVEHUB_PVE_VERIFY", _as_bool),
            "ca_file": ("PVEHUB_PVE_CA_FILE", str),
            "fingerprint": ("PVEHUB_PVE_FINGERPRINT", str),
            "timeout_seconds": ("PVEHUB_PVE_TIMEOUT_SECONDS", float),
            "max_retries": ("PVEHUB_PVE_MAX_RETRIES", int),
        },
        "PVEHUB_PVE_INSTANCES_JSON",
    )
    _apply_instance_env(
        data,
        "pbs",
        {
            "name": ("PVEHUB_PBS_NAME", str),
            "url": ("PVEHUB_PBS_URL", str),
            "token_id": ("PVEHUB_PBS_TOKEN_ID", str),
            "token_secret": ("PVEHUB_PBS_TOKEN_SECRET", str),
            "verify": ("PVEHUB_PBS_VERIFY", _as_bool),
            "ca_file": ("PVEHUB_PBS_CA_FILE", str),
            "fingerprint": ("PVEHUB_PBS_FINGERPRINT", str),
            "timeout_seconds": ("PVEHUB_PBS_TIMEOUT_SECONDS", float),
            "max_retries": ("PVEHUB_PBS_MAX_RETRIES", int),
        },
        "PVEHUB_PBS_INSTANCES_JSON",
    )

    existing_ssh = data.get("ssh")
    ssh: dict[str, Any] = existing_ssh if isinstance(existing_ssh, dict) else {}
    for env_name, key, caster in [
        ("PVEHUB_SSH_USER", "user", str),
        ("PVEHUB_SSH_KEY_PATH", "key_path", str),
        ("PVEHUB_SSH_KNOWN_HOSTS", "known_hosts", str),
        ("PVEHUB_SSH_PORT", "port", int),
        ("PVEHUB_SSH_STRICT_HOST_KEY_CHECKING", "strict_host_key", _as_bool),
        ("PVEHUB_SSH_CONNECT_TIMEOUT", "connect_timeout", float),
    ]:
        raw = _env(env_name)
        if raw is not None:
            ssh[key] = caster(raw)  # type: ignore[operator]
    nodes_json = _env("PVEHUB_SSH_NODES_JSON")
    if nodes_json:
        try:
            nodes = json.loads(nodes_json)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"PVEHUB_SSH_NODES_JSON is not valid JSON: {exc}") from exc
        if not isinstance(nodes, dict):
            raise ConfigError("PVEHUB_SSH_NODES_JSON must be a JSON object")
        ssh["nodes"] = nodes
    pbs_host = _env("PVEHUB_SSH_PBS_HOST")
    if pbs_host:
        existing_pbs = ssh.get("pbs")
        pbs_target: dict[str, Any] = dict(existing_pbs) if isinstance(existing_pbs, dict) else {}
        pbs_target["host"] = pbs_host
        if _env("PVEHUB_SSH_PBS_USER"):
            pbs_target["user"] = _env("PVEHUB_SSH_PBS_USER")
        if _env("PVEHUB_SSH_PBS_KEY_PATH"):
            pbs_target["key_path"] = _env("PVEHUB_SSH_PBS_KEY_PATH")
        ssh["pbs"] = pbs_target
    if ssh:
        data["ssh"] = ssh
    return data


def _apply_instance_env(
    data: dict[str, Any],
    key: str,
    fields: dict[str, tuple[str, Any]],
    json_env: str,
) -> None:
    instances_json = _env(json_env)
    if instances_json:
        try:
            parsed = json.loads(instances_json)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{json_env} is not valid JSON: {exc}") from exc
        if not isinstance(parsed, list):
            raise ConfigError(f"{json_env} must be a JSON array")
        data[key] = parsed
        return

    overrides: dict[str, Any] = {}
    for field, (env_name, caster) in fields.items():
        raw = _env(env_name)
        if raw is not None:
            overrides[field] = caster(raw)
    if not overrides:
        return
    existing = data.get(key)
    if isinstance(existing, list) and existing:
        merged = dict(existing[0])
        merged.update(overrides)
        data[key] = [merged, *existing[1:]]
    else:
        data[key] = [overrides]


def load_settings(env_file: str | None = None) -> Settings:
    """Load settings from YAML and environment.

    Order: built-in defaults < YAML < environment. ``PVEHUB_CONFIG_FILE`` selects the YAML
    file; if unset, ``/config/config.yaml`` and ``./config/config.yaml`` are tried.
    """

    if env_file is not None:
        _load_dotenv(Path(env_file))

    config_file = _env("PVEHUB_CONFIG_FILE")
    candidates: list[Path] = []
    if config_file:
        candidates.append(Path(config_file))
    else:
        candidates.extend([Path("/config/config.yaml"), Path("config/config.yaml")])

    data: dict[str, Any] = {}
    for candidate in candidates:
        if candidate.exists():
            data = _read_yaml(candidate)
            break
    data = _apply_env(data)
    try:
        return Settings.model_validate(data)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(f"invalid configuration: {exc}") from exc


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
