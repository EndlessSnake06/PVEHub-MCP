"""Unit tests for client attribution: parsing, validation, resolution (D019, #21)."""

from __future__ import annotations

import pytest

from pvehub_mcp import clientid
from pvehub_mcp.clientid import (
    LEGACY,
    UNKNOWN,
    client_context,
    current_client,
    parse_token_pairs,
    resolve_client,
    valid_client_name,
)

# -- parse_token_pairs ------------------------------------------------------


def test_parse_single_pair() -> None:
    assert parse_token_pairs("webui:tok-0123456789abcdef") == [("webui", "tok-0123456789abcdef")]


def test_parse_multiple_pairs() -> None:
    pairs = parse_token_pairs("webui:tok-aaaaaaaaaaaa1,hermes:tok-bbbbbbbbbbbb2")
    assert pairs == [("webui", "tok-aaaaaaaaaaaa1"), ("hermes", "tok-bbbbbbbbbbbb2")]


def test_parse_token_may_contain_colons() -> None:
    # The split happens on the FIRST colon only; token values may contain ':'.
    assert parse_token_pairs("webui:tok:with:colons-123456") == [("webui", "tok:with:colons-123456")]


def test_parse_skips_blank_entries() -> None:
    assert parse_token_pairs("webui:tok-0123456789abcdef,,hermes: tok-0123456789abcdef ,") == [
        ("webui", "tok-0123456789abcdef"),
        ("hermes", "tok-0123456789abcdef"),
    ]


def test_parse_empty_string_is_empty() -> None:
    assert parse_token_pairs("") == []
    assert parse_token_pairs("   ") == []


def test_parse_missing_colon_rejected() -> None:
    with pytest.raises(ValueError, match="name:token"):
        parse_token_pairs("webui-no-colon")


def test_parse_empty_name_rejected() -> None:
    with pytest.raises(ValueError):
        parse_token_pairs(":tok-0123456789abcdef")


def test_parse_empty_token_rejected() -> None:
    with pytest.raises(ValueError):
        parse_token_pairs("webui:")


# -- valid_client_name ------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["webui", "hermes", "agent-1", "a", "a-b_c9"],
)
def test_valid_names(name: str) -> None:
    assert valid_client_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "default",  # reserved for the legacy token
        "Webui",  # uppercase
        "-webui",  # leading dash
        "_webui",  # leading underscore
        "web ui",  # whitespace
        "a" * 33,  # too long
        "",  # empty
    ],
)
def test_invalid_names(name: str) -> None:
    assert not valid_client_name(name)


def test_max_name_length_is_32() -> None:
    assert valid_client_name("a" * 32)


# -- resolve_client ---------------------------------------------------------


def test_resolve_valid_legacy_token() -> None:
    credentials = {LEGACY: "legacy-token-01234567"}
    assert resolve_client("Bearer legacy-token-01234567", credentials) == LEGACY


def test_resolve_valid_named_token() -> None:
    credentials = {LEGACY: "legacy-token-01234567", "webui": "webui-token-01234567"}
    assert resolve_client("Bearer webui-token-01234567", credentials) == "webui"


def test_resolve_wrong_token_is_none() -> None:
    credentials = {LEGACY: "legacy-token-01234567", "webui": "webui-token-01234567"}
    assert resolve_client("Bearer wrong-token-01234567", credentials) is None


def test_resolve_missing_bearer_scheme_is_none() -> None:
    credentials = {LEGACY: "legacy-token-01234567"}
    assert resolve_client("legacy-token-01234567", credentials) is None
    assert resolve_client("Basic dXNlcjpwYXNz", credentials) is None
    assert resolve_client("", credentials) is None


def test_resolve_empty_token_is_none() -> None:
    credentials = {LEGACY: "legacy-token-01234567"}
    assert resolve_client("Bearer", credentials) is None
    assert resolve_client("Bearer   ", credentials) is None


def test_resolve_empty_credentials_is_none() -> None:
    assert resolve_client("Bearer legacy-token-01234567", {}) is None


# -- contextvar -------------------------------------------------------------


def test_current_client_defaults_to_unknown() -> None:
    assert current_client() == UNKNOWN
    assert clientid.client_context.get() is None


def test_current_client_reflects_set_and_reset() -> None:
    token = client_context.set("webui")
    try:
        assert current_client() == "webui"
    finally:
        client_context.reset(token)
    assert current_client() == UNKNOWN
