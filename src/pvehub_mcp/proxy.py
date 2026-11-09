"""Trusted-proxy resolution for client-IP audit attribution (D024, issue #25).

When the MCP server sits behind a reverse proxy (Caddy, Traefik, nginx), the
direct TCP peer is the proxy, not the real client.  To make
``X-Forwarded-For`` usable for audit attribution without becoming a forgery
target, the trust decision is explicit and deterministic:

* ``trusted_proxies`` (comma-separated CIDRs) defines the trusted reverse
  proxies.  A bare IP address is treated as /32 (IPv4) or /128 (IPv6).
* The direct TCP peer must be inside that set before any forwarded header is
  consulted.  A request arriving from an untrusted peer is attributed to the
  peer itself — a forged header cannot change that.
* The ``X-Forwarded-For`` chain is read **right to left**: the rightmost
  entry that is *not* in the trusted set is the client.  Rationale: a hop can
  only append entries to the *right* of its own position, so the entry a
  trusted hop observed on the wire (the first untrusted entry from the right)
  is that hop's real address, not a forged one.  If *every* entry is trusted
  (the client is inside the trusted network), the leftmost entry is the
  client.

This module is deliberately dependency-free so it can be unit-tested without
network or SDK imports.
"""

from __future__ import annotations

import ipaddress

__all__ = [
    "TrustedProxyError",
    "is_trusted",
    "parse_trusted_proxies",
    "resolve_client_ip",
]


class TrustedProxyError(ValueError):
    """A trusted-proxies entry is not a valid CIDR or IP address."""


def parse_trusted_proxies(
    raw: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a comma-separated list of CIDRs (or bare IPs) into networks.

    A bare IP becomes a /32 (IPv4) or /128 (IPv6) network.  Whitespace around
    entries is ignored; empty entries are skipped.  Raises
    :class:`TrustedProxyError` at the first malformed entry (fail-loud: a
    misconfigured trust set is a security bug, not a default).
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=True))
        except ValueError as exc:
            raise TrustedProxyError(f"invalid trusted proxy entry {part!r}: {exc}") from exc
    return tuple(networks)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_trusted(
    value: str,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    """True if ``value`` is an IP address inside one of the trusted networks."""
    if not networks or not _is_ip(value):
        return False
    return any(ipaddress.ip_address(value) in network for network in networks)


def resolve_client_ip(
    peer: str,
    xff: str | None,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> str | None:
    """Resolve the client address to write into audit entries.

    ``peer`` is the direct TCP peer (``request.client``), ``xff`` the raw
    ``X-Forwarded-For`` header value (or ``None``), ``networks`` the parsed
    trust set.  Returns ``None`` when no address is resolvable; the audit
    layer maps that to ``"unknown"`` exactly like it does for the ``client``
    name.
    """
    if not peer:
        return None
    if not networks or not is_trusted(peer, networks):
        # No trust set, or the peer is not a trusted proxy: attribute the
        # peer.  A forged X-Forwarded-For from an untrusted peer cannot
        # change the outcome.
        return peer
    # The peer is a trusted proxy: consult the XFF chain, right to left.
    chain: list[str] = []
    for entry in (xff or "").split(","):
        entry = entry.strip()
        if entry and _is_ip(entry):
            chain.append(entry)
    if not chain:
        # Trusted peer, no usable forwarded header: the peer is the best we
        # have (e.g. an internal proxy that strips the header).
        return peer
    for entry in reversed(chain):
        if not is_trusted(entry, networks):
            return entry
    # Every entry is trusted: the leftmost entry is the (internal) client.
    return chain[0]
