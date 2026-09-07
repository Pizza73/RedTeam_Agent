"""RFC 6901 secret argument path grammar and resolution tests."""

from __future__ import annotations

import pytest

from redteam_agent.errors import SecretArgumentBindingError
from redteam_agent.tools.secret_argument_path import (
    parse_json_pointer,
    resolve_pointer,
    validate_secret_argument_paths,
)

_ARGS = {"credential": {"secret_version_id": "sv-1"}, "list": [{"secret_version_id": "sv-2"}]}


def test_valid_pointer_parses_and_resolves() -> None:
    tokens = parse_json_pointer("/credential")
    assert resolve_pointer(tokens, _ARGS) == {"secret_version_id": "sv-1"}


def test_array_index_resolves() -> None:
    tokens = parse_json_pointer("/list/0")
    assert resolve_pointer(tokens, _ARGS) == {"secret_version_id": "sv-2"}


def test_empty_root_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        parse_json_pointer("")


def test_missing_leading_slash_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        parse_json_pointer("credential")


def test_wildcard_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        parse_json_pointer("/*")


def test_bad_escape_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        parse_json_pointer("/bad~2escape")


def test_parent_traversal_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        parse_json_pointer("/..")


def test_negative_array_index_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        resolve_pointer(parse_json_pointer("/list/-1"), _ARGS)


def test_ancestor_overlap_rejected() -> None:
    with pytest.raises(SecretArgumentBindingError):
        validate_secret_argument_paths(("/credential", "/credential/secret_version_id"), _ARGS)


def test_leaf_must_be_object() -> None:
    with pytest.raises(SecretArgumentBindingError):
        validate_secret_argument_paths(("/credential/secret_version_id",), _ARGS)


def test_valid_paths_return_tokens() -> None:
    parsed = validate_secret_argument_paths(("/credential",), _ARGS)
    assert parsed == (("credential",),)
