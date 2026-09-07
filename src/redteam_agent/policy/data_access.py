"""Data access policy and the versioned ``resource-pattern-v1`` grammar.

Resource patterns are not arbitrary regex/glob. Only two forms exist::

    exact:<canonical-resource-id>
    prefix:<canonical-logical-namespace-prefix>

``exact:`` applies to every resource type; ``prefix:`` applies only to
namespace types (artifact/local_artifact/report/internal_knowledge). Anything
uninterpretable is Default Deny, and prohibited rules win over allowed rules
(SystemDesign §21.2 / §22).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from redteam_agent.errors import DataAccessPatternError
from redteam_agent.models.base import StrictImmutableBoundaryModel

DataAccessOperation = Literal["read", "write", "export", "resolve"]

ResourceType = Literal[
    "artifact",
    "secret_reference",
    "local_artifact",
    "report",
    "internal_knowledge",
]

PATTERN_GRAMMAR_REVISION = "resource-pattern-v1"

_NAMESPACE_TYPES: frozenset[str] = frozenset({"artifact", "local_artifact", "report", "internal_knowledge"})
_META_CHARACTERS = set("*?[]{}()\\^$|+")


class DataAccessRule(StrictImmutableBoundaryModel):
    resource_type: ResourceType
    resource_pattern: str = Field(min_length=1)
    operations: frozenset[DataAccessOperation] = Field(min_length=1)


class DataAccessPolicy(StrictImmutableBoundaryModel):
    allowed: tuple[DataAccessRule, ...]
    prohibited: tuple[DataAccessRule, ...]


@dataclass(frozen=True)
class _ParsedPattern:
    kind: Literal["exact", "prefix"]
    value: str


def parse_resource_pattern(pattern: str, resource_type: str) -> _ParsedPattern:
    """Parse a ``resource-pattern-v1`` pattern, failing closed on anything else."""
    if ":" not in pattern:
        raise DataAccessPatternError(f"pattern missing kind prefix: {pattern!r}")
    kind, _, value = pattern.partition(":")
    if kind not in ("exact", "prefix"):
        raise DataAccessPatternError(f"unknown pattern kind: {kind!r}")
    if value == "":
        raise DataAccessPatternError("empty pattern value")
    if any(char in _META_CHARACTERS for char in value):
        raise DataAccessPatternError(f"pattern value contains meta characters: {value!r}")
    if ".." in value:
        raise DataAccessPatternError("pattern value contains traversal sequence")
    if any(ord(char) < 0x20 for char in value):
        raise DataAccessPatternError("pattern value contains control characters")
    if kind == "prefix" and resource_type not in _NAMESPACE_TYPES:
        raise DataAccessPatternError(f"prefix pattern not allowed for resource type {resource_type!r}")
    return _ParsedPattern(kind=kind, value=value)  # type: ignore[arg-type]


def _pattern_matches(pattern: str, resource_type: str, resource_id: str) -> bool:
    parsed = parse_resource_pattern(pattern, resource_type)
    if parsed.kind == "exact":
        return resource_id == parsed.value
    # prefix: match only at a logical namespace boundary to avoid partial-segment
    # false matches (``prefix:foo`` must not match ``foobar``).
    if resource_id == parsed.value:
        return True
    return resource_id.startswith(parsed.value + "/")


@dataclass(frozen=True)
class DataAccessDecision:
    allowed: bool
    reason_code: str


def evaluate_data_access(
    policy: DataAccessPolicy,
    resource_type: str,
    resource_id: str,
    operation: DataAccessOperation,
) -> DataAccessDecision:
    """Evaluate one data-access request, prohibited-first, Default Deny."""
    try:
        for rule in policy.prohibited:
            if (
                rule.resource_type == resource_type
                and operation in rule.operations
                and _pattern_matches(rule.resource_pattern, resource_type, resource_id)
            ):
                return DataAccessDecision(allowed=False, reason_code="PROHIBITED")
        for rule in policy.allowed:
            if (
                rule.resource_type == resource_type
                and operation in rule.operations
                and _pattern_matches(rule.resource_pattern, resource_type, resource_id)
            ):
                return DataAccessDecision(allowed=True, reason_code="ALLOWED")
    except DataAccessPatternError:
        # An uninterpretable pattern cannot grant access and must not silently
        # pass. Fail closed.
        return DataAccessDecision(allowed=False, reason_code="PATTERN_INDETERMINATE")
    return DataAccessDecision(allowed=False, reason_code="DEFAULT_DENY")


def validate_policy_patterns(policy: DataAccessPolicy) -> None:
    """Raise :class:`DataAccessPatternError` if any pattern is uninterpretable."""
    for rule in (*policy.allowed, *policy.prohibited):
        parse_resource_pattern(rule.resource_pattern, rule.resource_type)
