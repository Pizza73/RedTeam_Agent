"""Versioned effective-risk and global approval policy (SystemDesign §22.1).

Risk and approval requirements are not left to implementer discretion. They are
resolved from a versioned, digest-bound policy table so the same input always
yields the same decision. Risk floors only ever raise risk; no rule lowers it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel

RiskLevel = Literal["read", "low", "medium", "high"]
SideEffect = Literal["read_only", "state_change", "destructive"]

RISK_ORDER: dict[str, int] = {"read": 0, "low": 1, "medium": 2, "high": 3}


def risk_max(*levels: RiskLevel) -> RiskLevel:
    """Return the highest risk level by the fixed ``read<low<medium<high`` order."""
    ordered: list[RiskLevel] = ["read", "low", "medium", "high"]
    best = 0
    for level in levels:
        best = max(best, RISK_ORDER[level])
    return ordered[best]


class GlobalApprovalPolicy(StrictImmutableBoundaryModel):
    policy_revision: str = Field(min_length=1)
    require_for_risk: frozenset[RiskLevel]
    require_for_side_effect: frozenset[SideEffect]
    max_approval_ttl_seconds: int = Field(gt=0)
    policy_digest: str = Field(min_length=1)


class EffectiveRiskPolicy(StrictImmutableBoundaryModel):
    policy_version: str = Field(min_length=1)
    medium_target_count_floor: int = Field(gt=0)
    high_target_count_floor: int = Field(gt=0)
    privileged_state_change_floor: Literal["high"] = "high"
    secret_resolve_floor: Literal["medium", "high"] = "medium"  # noqa: S105 - risk floor name, not a secret
    global_approval_policy: GlobalApprovalPolicy
    policy_digest: str = Field(min_length=1)


def global_approval_policy_payload(policy: GlobalApprovalPolicy) -> dict[str, object]:
    return {
        "policy_revision": policy.policy_revision,
        "require_for_risk": sorted(policy.require_for_risk),
        "require_for_side_effect": sorted(policy.require_for_side_effect),
        "max_approval_ttl_seconds": policy.max_approval_ttl_seconds,
    }


def effective_risk_policy_payload(policy: EffectiveRiskPolicy) -> dict[str, object]:
    return {
        "policy_version": policy.policy_version,
        "medium_target_count_floor": policy.medium_target_count_floor,
        "high_target_count_floor": policy.high_target_count_floor,
        "privileged_state_change_floor": policy.privileged_state_change_floor,
        "secret_resolve_floor": policy.secret_resolve_floor,
        "global_approval_policy_digest": policy.global_approval_policy.policy_digest,
    }


def verify_risk_policy_digests(policy: EffectiveRiskPolicy, digest_service: DigestService) -> None:
    """Recompute and verify the risk policy digests (used on load)."""
    approval = policy.global_approval_policy
    digest_service.verify("policy_digest", global_approval_policy_payload(approval), approval.policy_digest)
    digest_service.verify("policy_digest", effective_risk_policy_payload(policy), policy.policy_digest)


def build_global_approval_policy(
    *,
    policy_revision: str,
    require_for_risk: frozenset[RiskLevel],
    require_for_side_effect: frozenset[SideEffect],
    max_approval_ttl_seconds: int,
    digest_service: DigestService,
) -> GlobalApprovalPolicy:
    stub = GlobalApprovalPolicy(
        policy_revision=policy_revision,
        require_for_risk=require_for_risk,
        require_for_side_effect=require_for_side_effect,
        max_approval_ttl_seconds=max_approval_ttl_seconds,
        policy_digest="pending",
    )
    digest = digest_service.compute("policy_digest", global_approval_policy_payload(stub))
    return GlobalApprovalPolicy(
        policy_revision=policy_revision,
        require_for_risk=require_for_risk,
        require_for_side_effect=require_for_side_effect,
        max_approval_ttl_seconds=max_approval_ttl_seconds,
        policy_digest=digest,
    )


def build_effective_risk_policy(
    *,
    policy_version: str,
    medium_target_count_floor: int,
    high_target_count_floor: int,
    global_approval_policy: GlobalApprovalPolicy,
    digest_service: DigestService,
    secret_resolve_floor: Literal["medium", "high"] = "medium",  # noqa: S107 - risk floor name, not a secret
) -> EffectiveRiskPolicy:
    if not high_target_count_floor > medium_target_count_floor:
        raise ValueError("high_target_count_floor must be greater than medium_target_count_floor")
    stub = EffectiveRiskPolicy(
        policy_version=policy_version,
        medium_target_count_floor=medium_target_count_floor,
        high_target_count_floor=high_target_count_floor,
        secret_resolve_floor=secret_resolve_floor,
        global_approval_policy=global_approval_policy,
        policy_digest="pending",
    )
    digest = digest_service.compute("policy_digest", effective_risk_policy_payload(stub))
    return stub.model_copy(update={"policy_digest": digest})


def default_risk_policy(digest_service: DigestService) -> EffectiveRiskPolicy:
    """Baseline ``risk-policy-v1`` (SystemDesign §22.1)."""
    approval = build_global_approval_policy(
        policy_revision="global-approval-v1",
        require_for_risk=frozenset({"high"}),
        require_for_side_effect=frozenset({"destructive"}),
        max_approval_ttl_seconds=3600,
        digest_service=digest_service,
    )
    return build_effective_risk_policy(
        policy_version="risk-policy-v1",
        medium_target_count_floor=32,
        high_target_count_floor=128,
        global_approval_policy=approval,
        digest_service=digest_service,
    )


def compute_effective_risk(
    *,
    policy: EffectiveRiskPolicy,
    tool_minimum_risk: RiskLevel,
    side_effect: SideEffect,
    normalized_target_count: int,
    has_secret_resolve: bool,
    privileged_session: bool,
    tool_extra_risk_floor: RiskLevel | None = None,
) -> RiskLevel:
    """Effective risk = the maximum of all applicable risk floors."""
    floors: list[RiskLevel] = [tool_minimum_risk]
    if tool_extra_risk_floor is not None:
        floors.append(tool_extra_risk_floor)
    if side_effect == "state_change":
        floors.append("medium")
    elif side_effect == "destructive":
        floors.append("high")
    if has_secret_resolve:
        floors.append(policy.secret_resolve_floor)
    if normalized_target_count >= policy.high_target_count_floor:
        floors.append("high")
    elif normalized_target_count >= policy.medium_target_count_floor:
        floors.append("medium")
    if privileged_session and side_effect != "read_only":
        floors.append("high")
    return risk_max(*floors)


def approval_required(
    *,
    policy: EffectiveRiskPolicy,
    effective_risk: RiskLevel,
    side_effect: SideEffect,
    tool_approval_rule: Literal["policy", "always"],
    mission_require_for_risk: frozenset[RiskLevel],
    mission_require_for_side_effect: frozenset[SideEffect],
) -> bool:
    """Decision-order step 3 (SystemDesign §22.1). Mission may only add."""
    if tool_approval_rule == "always":
        return True
    if effective_risk in policy.global_approval_policy.require_for_risk:
        return True
    if side_effect in policy.global_approval_policy.require_for_side_effect:
        return True
    if effective_risk in mission_require_for_risk:
        return True
    return side_effect in mission_require_for_side_effect
