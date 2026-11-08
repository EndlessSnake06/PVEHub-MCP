"""Client attribution for the audit trail (D019, issue #21).

The http transport accepts one *legacy* bearer token plus any number of
*named* tokens.  When a request authenticates, the middleware resolves the
matched token to a client name and stores it in a :class:`~contextvars.ContextVar`.
The tool wrapper reads it and writes it to every audit entry as ``client``.

The resolution is deliberately split into small pure functions so the
constant-time comparison and the name validation can be unit tested without a
running server.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from contextvars import ContextVar

#: Client name of the audit entry when no authenticated client is known
#: (stdio transport, ``mcp_auth_required=false`` loopback dev setups, ...).
UNKNOWN = "unknown"

#: Reserved name of the legacy single token (``PVEHUB_MCP_AUTH_TOKEN``).
LEGACY = "default"

#: Client names must be short, lowercase, and free of characters that would
#: break JSON/log tooling.  Kept tight so the value is safe to index on.
CLIENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

#: ``ContextVar`` carrying the resolved client name for the current request.
#: Set by the bearer middleware; never set for the stdio transport (no HTTP
#: request exists there).
client_context: ContextVar[str | None] = ContextVar("pvehub_client", default=None)


def current_client() -> str:
    """Return the client name for this context, or :data:`UNKNOWN`."""

    return client_context.get() or UNKNOWN


def valid_client_name(name: str) -> bool:
    """Name must match :data:`CLIENT_NAME_RE` and not be the reserved legacy name."""

    return bool(CLIENT_NAME_RE.match(name)) and name != LEGACY


def parse_token_pairs(raw: str) -> list[tuple[str, str]]:
    """Parse ``name:token,name2:token2`` into ``(name, token)`` pairs.

    Splits on the first comma of each entry and on the *first* colon, so token
    values may contain colons.  Entries without a colon, with an empty name or
    an empty token are rejected with :class:`ValueError` — the config layer
    turns that into a :class:`~pvehub_mcp.errors.ConfigError`.
    """

    pairs: list[tuple[str, str]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, token = entry.partition(":")
        name, token = name.strip(), token.strip()
        if not sep or not name or not token:
            raise ValueError(f"invalid named-token entry {entry!r}; expected name:token")
        pairs.append((name, token))
    return pairs


def resolve_client(supplied: str, credentials: Mapping[str, str]) -> str | None:
    """Map a raw ``Authorization`` header to a client name, constant-time.

    ``credentials`` maps client name -> token (``default`` is the legacy
    single token).  The header must be exactly ``Bearer <token>``; the token is
    compared with :func:`secrets.compare_digest` against **every** candidate
    (not just the first match) so the timing does not reveal which name a
    matching token belongs to.  Returns the client name or ``None``.
    """

    if not supplied.startswith("Bearer "):
        return None
    token = supplied[len("Bearer ") :].strip()
    if not token:
        return None
    matched: str | None = None
    for name, candidate in credentials.items():
        if secrets.compare_digest(token, candidate):
            matched = name
    return matched
