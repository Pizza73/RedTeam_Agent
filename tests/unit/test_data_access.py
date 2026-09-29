"""Data access policy and resource-pattern-v1 grammar tests."""

from __future__ import annotations

import pytest

from redteam_agent.errors import DataAccessPatternError
from redteam_agent.policy.data_access import (
    DataAccessPolicy,
    DataAccessRule,
    evaluate_data_access,
    parse_resource_pattern,
    validate_policy_patterns,
)


def _policy(allowed=(), prohibited=()) -> DataAccessPolicy:
    return DataAccessPolicy(allowed=allowed, prohibited=prohibited)


def test_exact_allow() -> None:
    policy = _policy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="exact:a1", operations=frozenset({"read"})),)
    )
    assert evaluate_data_access(policy, "artifact", "a1", "read").allowed
    assert not evaluate_data_access(policy, "artifact", "a2", "read").allowed


def test_default_deny() -> None:
    assert not evaluate_data_access(_policy(), "artifact", "a1", "read").allowed


def test_prohibited_precedence() -> None:
    policy = _policy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="prefix:reports", operations=frozenset({"read"})),),
        prohibited=(DataAccessRule(resource_type="artifact", resource_pattern="exact:reports/secret", operations=frozenset({"read"})),),
    )
    assert evaluate_data_access(policy, "artifact", "reports/public", "read").allowed
    assert not evaluate_data_access(policy, "artifact", "reports/secret", "read").allowed


def test_prefix_matches_at_namespace_boundary_only() -> None:
    policy = _policy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="prefix:foo", operations=frozenset({"read"})),)
    )
    assert evaluate_data_access(policy, "artifact", "foo/bar", "read").allowed
    assert evaluate_data_access(policy, "artifact", "foo", "read").allowed
    assert not evaluate_data_access(policy, "artifact", "foobar", "read").allowed


def test_prefix_not_allowed_for_secret_reference() -> None:
    with pytest.raises(DataAccessPatternError):
        parse_resource_pattern("prefix:anything", "secret_reference")


def test_meta_characters_rejected() -> None:
    with pytest.raises(DataAccessPatternError):
        parse_resource_pattern("exact:a*", "artifact")


def test_traversal_rejected() -> None:
    with pytest.raises(DataAccessPatternError):
        parse_resource_pattern("prefix:../etc", "artifact")


def test_unknown_kind_rejected() -> None:
    with pytest.raises(DataAccessPatternError):
        parse_resource_pattern("regex:.*", "artifact")


def test_uninterpretable_pattern_denies_operation() -> None:
    policy = _policy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="glob:*", operations=frozenset({"read"})),)
    )
    decision = evaluate_data_access(policy, "artifact", "a1", "read")
    assert not decision.allowed
    assert decision.reason_code == "PATTERN_INDETERMINATE"


def test_validate_policy_patterns_raises_on_bad_pattern() -> None:
    policy = _policy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="weird", operations=frozenset({"read"})),)
    )
    with pytest.raises(DataAccessPatternError):
        validate_policy_patterns(policy)
