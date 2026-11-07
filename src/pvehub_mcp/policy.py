"""Policy engine: categories, allow/deny lists, generic API rules, exec gates.

Policy is evaluated at registration time (which tools exist) and again on every call
(defense in depth).
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import ConfigError, ConfirmRequired, InvalidArgument, PolicyError

Category = Literal["read", "lifecycle", "write", "destructive", "exec", "generic"]
CATEGORIES: tuple[Category, ...] = (
    "read",
    "lifecycle",
    "write",
    "destructive",
    "exec",
    "generic",
)

# Always denied through the generic bridge, regardless of policy. These endpoints hand out
# session tickets or interactive shells and would bypass the tool-level gating.
HARD_DENY_PATHS: tuple[str, ...] = (
    "/access/ticket",
    "/access/users/*/token/*",
    "/access/users/*/token",
    "/nodes/*/vncshell",
    "/nodes/*/spiceshell",
    "/nodes/*/termproxy",
    "/nodes/*/qemu/*/monitor",
    "/nodes/*/qemu/*/agent/exec",
    "/nodes/*/qemu/*/agent/file-write",
)

_DEFAULT_DENY_PATHS = [
    "/access/ticket",
    "/access/users/*/token/*",
    "/access/users/*/token",
    "/nodes/*/vncshell",
    "/nodes/*/spiceshell",
    "/nodes/*/termproxy",
    "/nodes/*/qemu/*/monitor",
    "/nodes/*/qemu/*/agent/exec",
    "/nodes/*/qemu/*/agent/file-write",
]


class VMIDRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: int
    end: int

    @field_validator("end")
    @classmethod
    def _order(cls, value: int, info: Any) -> int:
        start = info.data.get("start")
        if start is not None and value < start:
            raise ValueError("range end must be >= start")
        return value

    def contains(self, vmid: int) -> bool:
        return self.start <= vmid <= self.end


def parse_vmid_ranges(values: list[str] | str | None) -> list[VMIDRange]:
    if values is None:
        return []
    items = [values] if isinstance(values, str) else values
    ranges: list[VMIDRange] = []
    for item in items:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                if not start_s.isdigit() or not end_s.isdigit():
                    raise ValueError(f"invalid vmid range: {part!r}")
                ranges.append(VMIDRange(start=int(start_s), end=int(end_s)))
            elif part.isdigit():
                ranges.append(VMIDRange(start=int(part), end=int(part)))
            else:
                raise ValueError(f"invalid vmid range: {part!r}")
    return ranges


class ToolsPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deny: list[str] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)


class CategoriesPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deny: list[Category] = Field(default_factory=list)


class GenericAPIPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deny_paths: list[str] = Field(default_factory=lambda: list(_DEFAULT_DENY_PATHS))
    deny_methods: list[str] = Field(default_factory=lambda: ["DELETE"])

    @field_validator("deny_methods")
    @classmethod
    def _methods(cls, value: list[str]) -> list[str]:
        allowed = {"GET", "POST", "PUT", "DELETE", "PATCH"}
        result = [method.upper() for method in value]
        unknown = set(result) - allowed
        if unknown:
            raise ValueError(f"unknown HTTP methods in policy: {sorted(unknown)}")
        return result


class FilesPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_roots: list[str] = Field(default_factory=list)


class ExecPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: bool = False
    lxc: bool = True
    vm: bool = True
    pbs_host: bool = False
    allowed_vmids: list[str] = Field(default_factory=lambda: ["100-199"])
    command_denylist: list[str] = Field(
        default_factory=lambda: ["rm -rf /", "mkfs*", "dd if=*", ":(){:|:&};:", "shutdown*", "reboot*"]
    )
    timeout_seconds: int = 60
    max_output_bytes: int = 65536
    files: FilesPolicy = Field(default_factory=FilesPolicy)

    @field_validator("allowed_vmids", mode="before")
    @classmethod
    def _ranges(cls, value: Any) -> Any:
        parse_vmid_ranges(value)
        return value

    def vmid_allowed(self, vmid: int) -> bool:
        ranges = parse_vmid_ranges(self.allowed_vmids)
        return any(item.contains(vmid) for item in ranges)


def _default_confirm_categories() -> list[Category]:
    return ["destructive", "exec"]


class SafetyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    require_confirm_for: list[Category] = Field(default_factory=_default_confirm_categories)
    dry_run_supported: bool = True


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    read_only: bool = False
    tools: ToolsPolicy = Field(default_factory=ToolsPolicy)
    categories: CategoriesPolicy = Field(default_factory=CategoriesPolicy)
    generic_api: GenericAPIPolicy = Field(default_factory=GenericAPIPolicy)
    exec: ExecPolicy = Field(default_factory=ExecPolicy)
    safety: SafetyPolicy = Field(default_factory=SafetyPolicy)


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    reason: str = ""


@dataclass
class Policy:
    """Effective policy plus helper checks."""

    file: PolicyFile = field(default_factory=PolicyFile)
    source: str = "defaults"
    sha256: str = ""

    @classmethod
    def load(cls, path: str | Path, env: dict[str, str] | None = None) -> Policy:
        env = dict(os.environ if env is None else env)
        source = str(path)
        raw: dict[str, Any] = {}
        text = ""
        file_path = Path(path)
        if file_path.exists():
            try:
                text = file_path.read_text(encoding="utf-8")
                loaded = yaml.safe_load(text) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise ConfigError(f"cannot read policy {file_path}: {exc}") from exc
            if not isinstance(loaded, dict):
                raise ConfigError(f"policy {file_path} must contain a mapping")
            raw = loaded
        elif path:
            source = f"defaults ({path} not found)"
        raw = _apply_env_overrides(raw, env)
        try:
            file = PolicyFile.model_validate(raw)
        except Exception as exc:
            raise ConfigError(f"invalid policy: {exc}") from exc
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""
        return cls(file=file, source=source, sha256=digest)

    # -- registration ------------------------------------------------------
    def tool_decision(self, name: str, category: Category) -> ToolDecision:
        if self.file.tools.allow and name not in self.file.tools.allow:
            return ToolDecision(False, "not in tools.allow")
        if name in self.file.tools.deny:
            return ToolDecision(False, "in tools.deny")
        if category in self.file.categories.deny:
            return ToolDecision(False, f"category {category!r} denied")
        if self.file.read_only and category not in {"read", "generic"}:
            return ToolDecision(False, "read_only")
        if category == "generic" and self.file.read_only:
            # generic is allowed but restricted to GET at call time
            return ToolDecision(True, "read_only: GET only")
        return ToolDecision(True)

    # -- per call ----------------------------------------------------------
    def check_call(self, name: str, category: Category, args: dict[str, Any]) -> None:
        decision = self.tool_decision(name, category)
        if not decision.allowed:
            raise PolicyError(
                f"tool {name!r} is blocked by policy ({decision.reason})",
                details={"tool": name, "reason": decision.reason},
            )
        if self.file.read_only and category in {"lifecycle", "write", "destructive", "exec"}:
            raise PolicyError(f"read-only mode blocks category {category!r}")
        if category in {"lifecycle", "write", "destructive", "exec"}:
            self._check_vmid_arg(name, args)
        if category in self.file.safety.require_confirm_for:
            dry_run = bool(args.get("dry_run"))
            if dry_run and self.file.safety.dry_run_supported:
                return
            if not args.get("confirm"):
                raise ConfirmRequired(
                    f"tool {name!r} ({category}) requires confirm=true",
                    details={"tool": name, "category": category},
                )

    def _check_vmid_arg(self, name: str, args: dict[str, Any]) -> None:
        vmid = args.get("vmid")
        if vmid is None:
            return
        if not isinstance(vmid, int):
            raise InvalidArgument("vmid must be an integer")
        if not self.file.exec.vmid_allowed(vmid):
            raise PolicyError(
                f"vmid {vmid} is outside exec.allowed_vmids ({', '.join(self.file.exec.allowed_vmids)})",
                details={"tool": name, "vmid": vmid},
            )

    # -- generic API -------------------------------------------------------
    def check_generic(self, method: str, path: str, params: dict[str, Any] | None = None) -> None:
        method = method.upper()
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            raise InvalidArgument(f"unsupported HTTP method {method!r}")
        if self.file.read_only and method != "GET":
            raise PolicyError("read-only mode allows generic API GET only")
        if method in self.file.generic_api.deny_methods:
            raise PolicyError(f"generic API method {method} is denied by policy")
        normalized = normalize_api_path(path)
        if normalized is None:
            raise InvalidArgument("invalid API path")
        for pattern in HARD_DENY_PATHS:
            if _path_matches(normalized, pattern):
                raise PolicyError(f"generic API path {normalized} is permanently denied")
        for pattern in self.file.generic_api.deny_paths:
            if _path_matches(normalized, pattern):
                raise PolicyError(f"generic API path {normalized} is denied by policy")
        if method != "GET":
            vmid = _vmid_from_path(normalized)
            if vmid is not None and not self.file.exec.vmid_allowed(vmid):
                raise PolicyError(
                    f"vmid {vmid} in {normalized} is outside exec.allowed_vmids"
                )
            if params and str(params.get("all", "")).lower() in {"1", "true", "yes"}:
                raise PolicyError(
                    "generic API mass operation (all=1) is blocked by policy",
                    details={"path": normalized},
                )
            for key in ("vmid", "newid"):
                if not params or key not in params:
                    continue
                for requested in _coerce_vmids(params[key], key):
                    if not self.file.exec.vmid_allowed(requested):
                        raise PolicyError(
                            f"{key} {requested} is outside exec.allowed_vmids",
                            details={key: requested},
                        )
        if params and _contains_secret_param(params):
            raise PolicyError("generic API parameters must not contain password/secret/token keys")

    def check_command(self, command: str) -> None:
        if "\x00" in command:
            raise InvalidArgument("command contains a NUL byte")
        if not command.strip():
            raise InvalidArgument("command must not be empty")
        lowered = command.lower()
        for pattern in self.file.exec.command_denylist:
            pattern = pattern.strip()
            if not pattern:
                continue
            lowered_pattern = pattern.lower()
            matched = fnmatch.fnmatch(lowered, lowered_pattern)
            if not matched and any(ch in pattern for ch in "*?["):
                matched = fnmatch.fnmatch(lowered, f"*{lowered_pattern}*")
            if not matched and not any(ch in pattern for ch in "*?["):
                matched = lowered_pattern in lowered
            if matched:
                raise PolicyError(
                    f"command matches denylist pattern {pattern!r}",
                    details={"pattern": pattern},
                )

    def check_file_path(self, path: str) -> None:
        if "\x00" in path:
            raise InvalidArgument("path contains a NUL byte")
        roots = self.file.exec.files.allowed_roots
        if not roots:
            return
        normalized = str(Path(path))
        if not any(normalized == root or normalized.startswith(root.rstrip("/") + "/") for root in roots):
            raise PolicyError(f"path {path!r} is outside files.allowed_roots")


def _apply_env_overrides(raw: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    data = copy.deepcopy(raw)
    tools = data.setdefault("tools", {})
    if not isinstance(tools, dict):
        tools = {}
        data["tools"] = tools
    categories = data.setdefault("categories", {})
    if not isinstance(categories, dict):
        categories = {}
        data["categories"] = categories
    generic = data.setdefault("generic_api", {})
    if not isinstance(generic, dict):
        generic = {}
        data["generic_api"] = generic
    exec_cfg = data.setdefault("exec", {})
    if not isinstance(exec_cfg, dict):
        exec_cfg = {}
        data["exec"] = exec_cfg
    safety = data.setdefault("safety", {})
    if not isinstance(safety, dict):
        safety = {}
        data["safety"] = safety

    def get(name: str) -> str | None:
        value = env.get(name)
        return value if value not in (None, "") else None

    def as_list(value: str) -> list[str]:
        return [part.strip() for part in value.split(",") if part.strip()]

    def as_bool(value: str) -> bool:
        return value.strip().lower() in {"1", "true", "yes", "on"}

    if get("PVEHUB_READ_ONLY") is not None:
        data["read_only"] = as_bool(get("PVEHUB_READ_ONLY") or "")
    if get("PVEHUB_DENY_TOOLS") is not None:
        tools["deny"] = as_list(get("PVEHUB_DENY_TOOLS") or "")
    if get("PVEHUB_ALLOW_TOOLS") is not None:
        tools["allow"] = as_list(get("PVEHUB_ALLOW_TOOLS") or "")
    if get("PVEHUB_DENY_CATEGORIES") is not None:
        categories["deny"] = as_list(get("PVEHUB_DENY_CATEGORIES") or "")
    if get("PVEHUB_GENERIC_DENY_PATHS") is not None:
        generic["deny_paths"] = as_list(get("PVEHUB_GENERIC_DENY_PATHS") or "")
    if get("PVEHUB_GENERIC_DENY_METHODS") is not None:
        generic["deny_methods"] = as_list(get("PVEHUB_GENERIC_DENY_METHODS") or "")
    for env_name, key in [
        ("PVEHUB_EXEC_HOST", "host"),
        ("PVEHUB_EXEC_LXC", "lxc"),
        ("PVEHUB_EXEC_VM", "vm"),
        ("PVEHUB_EXEC_PBS_HOST", "pbs_host"),
    ]:
        if get(env_name) is not None:
            exec_cfg[key] = as_bool(get(env_name) or "")
    if get("PVEHUB_EXEC_ALLOWED_VMIDS") is not None:
        exec_cfg["allowed_vmids"] = as_list(get("PVEHUB_EXEC_ALLOWED_VMIDS") or "")
    if get("PVEHUB_EXEC_TIMEOUT_SECONDS") is not None:
        exec_cfg["timeout_seconds"] = int(get("PVEHUB_EXEC_TIMEOUT_SECONDS") or "60")
    if get("PVEHUB_EXEC_MAX_OUTPUT_BYTES") is not None:
        exec_cfg["max_output_bytes"] = int(get("PVEHUB_EXEC_MAX_OUTPUT_BYTES") or "65536")
    if get("PVEHUB_REQUIRE_CONFIRM") is not None:
        safety["require_confirm_for"] = as_list(get("PVEHUB_REQUIRE_CONFIRM") or "")
    return data


def normalize_api_path(path: str) -> str | None:
    """Normalize an API path for matching; return ``None`` for dangerous input."""

    if not path or "\x00" in path or not path.startswith("/"):
        return None
    candidate = path.split("?", 1)[0].split("#", 1)[0]
    # Decode up to two layers; reject anything that still looks encoded.
    for _ in range(2):
        decoded = unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    if "%" in candidate:
        return None
    candidate = re.sub(r"/{2,}", "/", candidate)
    parts: list[str] = []
    for part in candidate.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            return None
        parts.append(part)
    return "/" + "/".join(parts)


def _path_matches(path: str, pattern: str) -> bool:
    pattern_norm = normalize_api_path(pattern) or ""
    if not pattern_norm:
        return False
    if fnmatch.fnmatchcase(path.lower(), pattern_norm.lower()):
        return True
    # A pattern without a trailing wildcard also covers child paths.
    return not pattern_norm.endswith("*") and path.lower().startswith(
        pattern_norm.lower() + "/"
    )


_VM_PATH_RE = re.compile(r"^/(?:nodes/[^/]+/(?:qemu|lxc)|vms)/([0-9]+)(?:/|$)")


def _vmid_from_path(path: str) -> int | None:
    match = _VM_PATH_RE.match(path)
    return int(match.group(1)) if match else None


def _coerce_vmids(value: Any, field: str) -> list[int]:
    if isinstance(value, (list, tuple)):
        raw_values = list(value)
    elif isinstance(value, str) and "," in value:
        raw_values = [part.strip() for part in value.split(",") if part.strip()]
    else:
        raw_values = [value]
    result: list[int] = []
    for item in raw_values:
        try:
            result.append(int(item))
        except (TypeError, ValueError) as exc:
            raise InvalidArgument(f"generic API parameter {field} must contain integers") from exc
    return result


def _contains_secret_param(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in {"password", "passwd", "secret", "token"}:
                return True
            if _contains_secret_param(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_param(item) for item in value)
    return False
