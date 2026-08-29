"""Versioned, prefix-only Data Access Policy evaluation."""

from __future__ import annotations

from redteam_agent.models.context import DataAccessGrant
from redteam_agent.models.scope import DataAccessPolicy, DataAccessRule


def _pattern_matches(pattern: str, resource_id: str) -> bool:
    return resource_id.startswith(pattern[:-1]) if pattern.endswith("*") else resource_id == pattern


class DataAccessEvaluator:
    def allows(self, grant: DataAccessGrant, policy: DataAccessPolicy) -> bool:
        def matches(rule: DataAccessRule) -> bool:
            return (
                rule.resource_type == grant.resource_type
                and _pattern_matches(rule.resource_pattern, grant.resource.resource_id)
                and grant.operations.issubset(rule.operations)
            )

        if any(matches(rule) for rule in policy.prohibited):
            return False
        return any(matches(rule) for rule in policy.allowed)

