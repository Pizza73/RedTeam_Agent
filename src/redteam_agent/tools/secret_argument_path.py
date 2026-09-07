"""Secret argument path grammar and resolution (SystemDesign §20.1).

``ToolDefinition.secret_argument_paths`` are RFC 6901 JSON Pointers in canonical
form. The empty root pointer, wildcards, JSONPath, regex, negative/append array
indices, parent traversal and non-standard escapes are all rejected. Each
pointer must resolve to exactly one existing leaf in the validated arguments,
and no pointer may be an ancestor of another (no parent/child or alias
overlaps). Any violation is a fail-closed :class:`SecretArgumentBindingError`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from redteam_agent.canonical.json_boundary import CanonicalJsonObject
from redteam_agent.errors import SecretArgumentBindingError

# RFC 6901 array index in canonical ASCII form: "0" or a non-zero-leading run of
# ASCII digits. ``str.isdigit`` accepts Unicode digits, which would alias e.g.
# ASCII "1" and ARABIC-INDIC DIGIT ONE (U+0661) onto the same array leaf; this
# regex forbids that.
_ARRAY_INDEX_RE = re.compile(r"(?a)\A(0|[1-9][0-9]*)\Z")
_SECRET_REFERENCE_FIELDS = frozenset(
    {"credential_type", "secret_version_id", "secret_version", "principal_ref"}
)


def parse_json_pointer(pointer: str) -> tuple[str, ...]:
    """Parse a canonical RFC 6901 JSON Pointer into reference tokens."""
    if pointer == "":
        raise SecretArgumentBindingError("empty root JSON Pointer is not allowed")
    if not pointer.startswith("/"):
        raise SecretArgumentBindingError(f"JSON Pointer must start with '/': {pointer!r}")
    raw_tokens = pointer.split("/")[1:]
    tokens: list[str] = []
    for raw in raw_tokens:
        if "*" in raw:
            raise SecretArgumentBindingError("wildcard is not allowed in a secret path")
        token = _unescape_token(raw)
        if token in ("", ".", ".."):
            raise SecretArgumentBindingError(f"invalid reference token: {raw!r}")
        tokens.append(token)
    return tuple(tokens)


def _unescape_token(raw: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "~":
            if index + 1 >= len(raw) or raw[index + 1] not in ("0", "1"):
                raise SecretArgumentBindingError(f"invalid escape in token: {raw!r}")
            result.append("~" if raw[index + 1] == "0" else "/")
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _is_array_index(token: str) -> bool:
    return _ARRAY_INDEX_RE.match(token) is not None


def resolve_pointer(tokens: tuple[str, ...], arguments: CanonicalJsonObject) -> Any:
    """Resolve tokens against validated arguments, failing closed if absent."""
    current: Any = arguments
    for token in tokens:
        if isinstance(current, Mapping):
            if token not in current:
                raise SecretArgumentBindingError(f"secret path does not resolve: missing key {token!r}")
            current = current[token]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            if not _is_array_index(token):
                raise SecretArgumentBindingError(f"invalid array index token: {token!r}")
            idx = int(token)
            if idx >= len(current):
                raise SecretArgumentBindingError("secret path array index out of range")
            current = current[idx]
        else:
            raise SecretArgumentBindingError("secret path descends into a scalar leaf")
    return current


def validate_secret_argument_paths(
    paths: tuple[str, ...],
    arguments: CanonicalJsonObject,
) -> tuple[tuple[str, ...], ...]:
    """Validate every secret path, returning parsed token tuples.

    Enforces canonical grammar, unique existing leaves, and that no path is an
    ancestor of another.
    """
    parsed: list[tuple[str, ...]] = [parse_json_pointer(path) for path in paths]
    for outer in range(len(parsed)):
        for inner in range(len(parsed)):
            if outer == inner:
                continue
            if _is_ancestor(parsed[outer], parsed[inner]):
                raise SecretArgumentBindingError("secret paths overlap (ancestor/descendant or alias)")
    for tokens in parsed:
        leaf = resolve_pointer(tokens, arguments)
        validate_secret_reference(leaf)
    discovered = frozenset(_discover_secret_reference_paths(arguments))
    if frozenset(parsed) != discovered:
        raise SecretArgumentBindingError("secret paths do not cover every Secret Reference argument")
    return tuple(parsed)


def validate_secret_reference(value: Any) -> None:
    """Require the fixed, closed Secret Reference wire shape."""
    if not isinstance(value, Mapping) or frozenset(value) != _SECRET_REFERENCE_FIELDS:
        raise SecretArgumentBindingError("secret argument leaf must be a closed Secret Reference")
    if any(not isinstance(value[field], str) or not value[field] for field in _SECRET_REFERENCE_FIELDS):
        raise SecretArgumentBindingError("Secret Reference fields must be non-empty strings")


def _discover_secret_reference_paths(
    value: Any, tokens: tuple[str, ...] = ()
) -> tuple[tuple[str, ...], ...]:
    """Enumerate every concrete Secret Reference leaf in validated arguments.

    Static JSON Pointers cannot describe every element of a variable-length
    array.  Runtime enumeration closes that gap without adding wildcard syntax
    or mutable authorization state.
    """
    if isinstance(value, Mapping):
        if frozenset(value) >= _SECRET_REFERENCE_FIELDS:
            return (tokens,)
        found: list[tuple[str, ...]] = []
        for key, child in value.items():
            if isinstance(key, str):
                found.extend(_discover_secret_reference_paths(child, (*tokens, key)))
        return tuple(found)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        found = []
        for index, child in enumerate(value):
            found.extend(_discover_secret_reference_paths(child, (*tokens, str(index))))
        return tuple(found)
    return ()


def _is_ancestor(candidate: tuple[str, ...], other: tuple[str, ...]) -> bool:
    """True if ``candidate`` equals or is a prefix of ``other``."""
    if len(candidate) > len(other):
        return False
    return other[: len(candidate)] == candidate
