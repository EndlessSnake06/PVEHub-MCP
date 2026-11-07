"""Shared async HTTP client for PVE and PBS."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from typing import Any
from urllib.parse import quote

import httpx

from ..errors import (
    AuthenticationError,
    InvalidArgument,
    NotFound,
    PermissionDenied,
    UpstreamError,
)
from ..tls import build_verify

logger = logging.getLogger(__name__)


def encode_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Encode values the way the Proxmox API expects form/query parameters.

    - booleans become ``1``/``0``
    - lists become repeated keys (httpx encodes a list value as repeated parameters)
    - mappings become compact JSON strings
    - ``None`` values are dropped
    """

    if not params:
        return {}
    encoded: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            encoded[key] = "1" if value else "0"
        elif isinstance(value, (dict, list, tuple)):
            if isinstance(value, (list, tuple)) and all(
                not isinstance(item, (dict, list, tuple)) for item in value
            ):
                encoded[key] = [str(item) for item in value]
            else:
                encoded[key] = json.dumps(value, separators=(",", ":"), default=str)
        else:
            encoded[key] = str(value)
    return encoded


def quote_path(path: str) -> str:
    if not path.startswith("/"):
        raise InvalidArgument("API path must start with '/'")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise InvalidArgument("API path must not contain control characters")
    if "\\" in path:
        raise InvalidArgument("API path must not contain backslashes")
    # httpx removes literal dot segments before sending.  Rejecting them here keeps
    # every API call inside the configured api_path, even if a tool forgets to
    # validate one of its path arguments.
    if any(part in {".", ".."} for part in path.split("/")):
        raise InvalidArgument("API path must not contain '.' or '..' segments")
    return quote(path, safe="/!$&'()*+,;=:@-._~")



class BaseProxmoxClient:
    kind = "proxmox"

    def __init__(
        self,
        *,
        name: str,
        url: str,
        api_path: str,
        auth_header: str,
        verify: bool | str = True,
        ca_file: str | None = None,
        fingerprint: str | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.name = name
        self.url = url.rstrip("/")
        self.api_path = api_path
        self.auth_header = auth_header
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, max_retries)
        self._verify = build_verify(verify=verify, ca_file=ca_file, fingerprint=fingerprint)
        headers = {
            "Authorization": auth_header,
            "Accept": "application/json",
            "User-Agent": "pvehub-mcp/0.1.0",
        }
        self._client = httpx.AsyncClient(
            base_url=self.url,
            headers=headers,
            verify=self._verify,
            timeout=httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds)),
            follow_redirects=False,
            transport=transport,
        )

    @property
    def origin(self) -> str:
        return self.url

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        retry: bool | None = None,
    ) -> Any:
        method = method.upper()
        url = self.api_path + quote_path(path)
        encoded = encode_params(params if method in {"GET", "DELETE"} else data)
        attempts = self.max_retries + 1 if (retry if retry is not None else method == "GET") else 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=encoded if method in {"GET", "DELETE"} else None,
                    data=encoded if method not in {"GET", "DELETE"} else None,
                )
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    await _sleep_backoff(attempt)
                    continue
                raise UpstreamError(
                    f"{self.kind} {self.name}: connection failed: {exc.__class__.__name__}"
                ) from exc
            except httpx.HTTPError as exc:
                raise UpstreamError(f"{self.kind} {self.name}: request failed: {exc}") from exc

            if response.status_code in {502, 503, 504} and attempt + 1 < attempts:
                await _sleep_backoff(attempt)
                continue
            return self._parse(response)
        raise UpstreamError(f"{self.kind} {self.name}: request failed: {last_error}")

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self._request("POST", path, data=data, retry=False)

    async def put(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self._request("PUT", path, data=data, retry=False)

    async def delete(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self._request("DELETE", path, params=data, retry=False)

    def _parse(self, response: httpx.Response) -> Any:
        request_path = response.request.url.path
        if response.status_code in {401}:
            raise AuthenticationError(
                f"{self.kind} {self.name}: authentication failed (HTTP 401); check token id/secret "
                "and token permissions",
                details={"instance": self.name, "path": request_path},
            )
        if response.status_code == 403:
            message = _error_message(response)
            raise PermissionDenied(
                f"{self.kind} {self.name}: permission denied for {request_path}: {message}",
                details={"instance": self.name, "path": request_path},
            )
        if response.status_code == 404:
            raise NotFound(
                f"{self.kind} {self.name}: not found: {request_path}",
                details={"instance": self.name, "path": request_path},
            )
        if response.status_code >= 400:
            message = _error_message(response)
            raise UpstreamError(
                f"{self.kind} {self.name}: HTTP {response.status_code} for {request_path}: {message}",
                details={"instance": self.name, "path": request_path, "status": response.status_code},
            )
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                payload = response.json()
            except ValueError as exc:
                raise UpstreamError(f"{self.kind} {self.name}: invalid JSON response") from exc
        else:
            text = response.text
            if len(text) > 1_000_000:
                text = text[:1_000_000]
            return text
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload


def _error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:500] or response.reason_phrase
    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, dict) and errors:
            return "; ".join(f"{key}: {value}" for key, value in errors.items())[:800]
        message = payload.get("message")
        if message:
            return str(message)[:800]
    return str(payload)[:800]


async def _sleep_backoff(attempt: int) -> None:
    delay = min(5.0, 0.4 * (2**attempt)) + random.uniform(0, 0.2)  # noqa: S311
    await asyncio.sleep(delay)


class SchemaIndex:
    """Index over a Proxmox ``apidoc.js`` schema tree."""

    def __init__(self, tree: list[dict[str, Any]], *, kind: str) -> None:
        self.kind = kind
        self.tree = tree
        self.paths: dict[str, dict[str, Any]] = {}
        self._walk(tree)
        self._templates = list(self.paths.items())

    def _walk(self, nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            path = node.get("path")
            if isinstance(path, str):
                self.paths[path] = node
            children = node.get("children")
            if isinstance(children, list):
                self._walk(children)

    def get(self, path: str) -> dict[str, Any] | None:
        normalized = path.rstrip("/") or "/"
        found = self.paths.get(normalized)
        if found is not None:
            return found
        # resolve a concrete path against a template such as /nodes/{node}/status
        for template, node in self._templates:
            if "{" not in template:
                continue
            pattern = _template_regex(template)
            if pattern.match(normalized):
                return node
        return None

    def methods(self, path: str) -> dict[str, Any]:
        node = self.get(path)
        if node is None:
            raise NotFound(f"unknown {self.kind} API path: {path}")
        info = node.get("info")
        return info if isinstance(info, dict) else {}

    def describe(self, path: str) -> dict[str, Any]:
        node = self.get(path)
        if node is None:
            raise NotFound(f"unknown {self.kind} API path: {path}")
        raw_info = node.get("info")
        info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
        methods: dict[str, Any] = {}
        for method, meta in info.items():
            if not isinstance(meta, dict):
                continue
            methods[method.upper()] = {
                "description": _one_line(meta.get("description", ""), 400),
                "protected": bool(meta.get("protected")),
                "params": _describe_params(meta.get("parameters", {})),
                "returns": _return_type(meta.get("returns")),
            }
        children = [
            child.get("path")
            for child in node.get("children", [])
            if isinstance(child, dict) and child.get("path")
        ]
        return {"path": node.get("path"), "methods": methods, "children": children[:50]}

    def search(self, term: str, limit: int = 30) -> list[str]:
        term = term.lower()
        hits = [path for path in self.paths if term in path.lower()]
        return sorted(hits)[:limit]


def _template_regex(template: str) -> re.Pattern[str]:
    parts = re.split(r"(\{[^}]+\})", template)
    pattern = "^"
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            pattern += r"[^/]+"
        else:
            pattern += re.escape(part)
    return re.compile(pattern + "$")


def _one_line(text: Any, limit: int) -> str:
    return " ".join(str(text).split())[:limit]


def _describe_params(parameters: Any) -> dict[str, Any]:
    if not isinstance(parameters, dict):
        return {}
    props = parameters.get("properties")
    source = props if isinstance(props, dict) else parameters
    result: dict[str, Any] = {}
    for name, meta in source.items():
        if not isinstance(meta, dict):
            continue
        item: dict[str, Any] = {"type": meta.get("type", "string")}
        if meta.get("optional"):
            item["optional"] = True
        if "default" in meta:
            item["default"] = meta["default"]
        if "enum" in meta:
            item["enum"] = meta["enum"][:30]
        if "minimum" in meta:
            item["min"] = meta["minimum"]
        if "maximum" in meta:
            item["max"] = meta["maximum"]
        if meta.get("description"):
            item["description"] = _one_line(meta["description"], 200)
        result[name] = item
    return result


def _return_type(returns: Any) -> Any:
    if isinstance(returns, dict):
        return returns.get("type", "object")
    return returns
