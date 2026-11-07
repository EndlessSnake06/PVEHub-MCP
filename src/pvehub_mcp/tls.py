"""TLS helpers, including optional certificate fingerprint pinning."""

from __future__ import annotations

import hashlib
import logging
import ssl
from typing import Any

from .errors import ConfigError

logger = logging.getLogger(__name__)


def normalize_fingerprint(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned.startswith("sha256:"):
        cleaned = cleaned[7:]
    cleaned = cleaned.replace(":", "").replace(" ", "")
    if len(cleaned) != 64 or any(ch not in "0123456789abcdef" for ch in cleaned):
        raise ConfigError("fingerprint must be a SHA-256 hex digest")
    return cleaned


class PinnedSSLContext(ssl.SSLContext):
    """SSL context that verifies a certificate fingerprint on every handshake."""

    _pvehub_fingerprint: str

    def __new__(cls, fingerprint: str, *, ca_file: str | None = None, verify: bool = True) -> PinnedSSLContext:
        return super().__new__(cls, ssl.PROTOCOL_TLS_CLIENT)

    def __init__(self, fingerprint: str, *, ca_file: str | None = None, verify: bool = True) -> None:
        # ssl.SSLContext is a C type: __new__ already initialised the context with
        # PROTOCOL_TLS_CLIENT, calling __init__ again would fail.
        self._pvehub_fingerprint = normalize_fingerprint(fingerprint)
        if verify:
            self.check_hostname = True
            self.verify_mode = ssl.CERT_REQUIRED
            self.load_default_certs()
            if ca_file:
                self.load_verify_locations(cafile=ca_file)
        else:
            self.check_hostname = False
            self.verify_mode = ssl.CERT_NONE

    def wrap_socket(  # type: ignore[override]
        self,
        sock: Any,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: Any = None,
    ) -> ssl.SSLSocket:
        wrapped = super().wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            session=session,
        )
        if do_handshake_on_connect:
            self._verify(wrapped.getpeercert(binary_form=True))
        return wrapped

    def wrap_bio(  # type: ignore[override]
        self,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: Any = None,
    ) -> ssl.SSLObject:
        obj = super().wrap_bio(
            incoming,
            outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
            session=session,
        )
        original = obj.do_handshake
        state = {"verified": False}

        def pinned_handshake() -> None:
            original()
            if not state["verified"]:
                self._verify(obj.getpeercert(binary_form=True))
                state["verified"] = True

        obj.do_handshake = pinned_handshake  # type: ignore[method-assign]
        return obj

    def _verify(self, der: bytes | None) -> None:
        actual = hashlib.sha256(der or b"").hexdigest()
        if actual != self._pvehub_fingerprint:
            raise ssl.SSLError(
                "certificate fingerprint mismatch "
                f"(expected {self._pvehub_fingerprint}, got {actual})"
            )


def build_verify(
    *,
    verify: bool | str,
    ca_file: str | None = None,
    fingerprint: str | None = None,
) -> bool | str | ssl.SSLContext:
    if fingerprint:
        if verify is False:
            logger.warning("TLS certificate verification disabled; fingerprint pinning is active")
        return PinnedSSLContext(fingerprint, ca_file=ca_file, verify=bool(verify))
    if verify is False:
        logger.warning("TLS certificate verification disabled by configuration")
        return False
    if ca_file:
        if not verify:
            return False
        return ca_file
    return verify
