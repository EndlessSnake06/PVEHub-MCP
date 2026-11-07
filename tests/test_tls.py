"""TLS helper tests (no network)."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from pvehub_mcp.errors import ConfigError
from pvehub_mcp.tls import PinnedSSLContext, build_verify, normalize_fingerprint

DER = b"not-a-real-certificate"


def test_normalize_fingerprint() -> None:
    digest = hashlib.sha256(DER).hexdigest()
    assert normalize_fingerprint(":".join(digest[i : i + 2] for i in range(0, 64, 2))) == digest
    assert normalize_fingerprint("sha256:" + digest.upper()) == digest
    with pytest.raises(ConfigError):
        normalize_fingerprint("abc")


def test_pinned_context_accepts_and_rejects() -> None:
    digest = hashlib.sha256(DER).hexdigest()
    context = PinnedSSLContext(digest, verify=False)
    context._verify(DER)
    with pytest.raises(ssl.SSLError):
        context._verify(b"different")


def test_build_verify_options(tmp_path) -> None:
    assert build_verify(verify=False) is False
    assert build_verify(verify=True) is True
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy", encoding="utf-8")
    assert build_verify(verify=True, ca_file=str(ca)) == str(ca)
    pinned = build_verify(verify=False, fingerprint=hashlib.sha256(DER).hexdigest())
    assert isinstance(pinned, PinnedSSLContext)
