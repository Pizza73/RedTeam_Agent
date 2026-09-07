"""Versioned effective-risk and approval policy tests."""

from __future__ import annotations

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.policy.risk_policy import (
    approval_required,
    compute_effective_risk,
    default_risk_policy,
    verify_risk_policy_digests,
)


def _policy() -> tuple[DigestService, object]:
    service = DigestService()
    return service, default_risk_policy(service)


def test_read_only_low_stays_low() -> None:
    _, policy = _policy()
    risk = compute_effective_risk(
        policy=policy, tool_minimum_risk="low", side_effect="read_only",
        normalized_target_count=1, has_secret_resolve=False, privileged_session=False,
    )
    assert risk == "low"


def test_state_change_floor_medium() -> None:
    _, policy = _policy()
    risk = compute_effective_risk(
        policy=policy, tool_minimum_risk="low", side_effect="state_change",
        normalized_target_count=1, has_secret_resolve=False, privileged_session=False,
    )
    assert risk == "medium"


def test_destructive_floor_high() -> None:
    _, policy = _policy()
    risk = compute_effective_risk(
        policy=policy, tool_minimum_risk="low", side_effect="destructive",
        normalized_target_count=1, has_secret_resolve=False, privileged_session=False,
    )
    assert risk == "high"


def test_secret_resolve_floor_medium() -> None:
    _, policy = _policy()
    risk = compute_effective_risk(
        policy=policy, tool_minimum_risk="read", side_effect="read_only",
        normalized_target_count=1, has_secret_resolve=True, privileged_session=False,
    )
    assert risk == "medium"


def test_target_count_floors() -> None:
    _, policy = _policy()
    assert compute_effective_risk(
        policy=policy, tool_minimum_risk="read", side_effect="read_only",
        normalized_target_count=32, has_secret_resolve=False, privileged_session=False,
    ) == "medium"
    assert compute_effective_risk(
        policy=policy, tool_minimum_risk="read", side_effect="read_only",
        normalized_target_count=128, has_secret_resolve=False, privileged_session=False,
    ) == "high"


def test_privileged_state_change_high() -> None:
    _, policy = _policy()
    risk = compute_effective_risk(
        policy=policy, tool_minimum_risk="read", side_effect="state_change",
        normalized_target_count=1, has_secret_resolve=False, privileged_session=True,
    )
    assert risk == "high"


def test_approval_required_for_high_by_global() -> None:
    _, policy = _policy()
    assert approval_required(
        policy=policy, effective_risk="high", side_effect="read_only",
        tool_approval_rule="policy", mission_require_for_risk=frozenset(), mission_require_for_side_effect=frozenset(),
    )


def test_approval_always_rule() -> None:
    _, policy = _policy()
    assert approval_required(
        policy=policy, effective_risk="low", side_effect="read_only",
        tool_approval_rule="always", mission_require_for_risk=frozenset(), mission_require_for_side_effect=frozenset(),
    )


def test_low_read_only_needs_no_approval() -> None:
    _, policy = _policy()
    assert not approval_required(
        policy=policy, effective_risk="low", side_effect="read_only",
        tool_approval_rule="policy", mission_require_for_risk=frozenset(), mission_require_for_side_effect=frozenset(),
    )


def test_determinism() -> None:
    _, policy = _policy()
    args = {
        "policy": policy,
        "tool_minimum_risk": "low",
        "side_effect": "state_change",
        "normalized_target_count": 40,
        "has_secret_resolve": True,
        "privileged_session": False,
    }
    assert compute_effective_risk(**args) == compute_effective_risk(**args)


def test_policy_digests_verify() -> None:
    service, policy = _policy()
    verify_risk_policy_digests(policy, service)  # must not raise
