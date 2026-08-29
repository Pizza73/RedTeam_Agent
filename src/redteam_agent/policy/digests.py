"""Canonical proposal and authorized-intent digest definitions."""

from __future__ import annotations

from redteam_agent.canonical import canonicalize, sha256_digest
from redteam_agent.models.context import DataAccessGrant
from redteam_agent.models.plans import ExecutionPlan, ExecutionPlanProposal
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.models.scope import NormalizedTarget
from redteam_agent.models.tools import ToolDefinition

PROPOSAL_SCHEMA_VERSION = "execution-plan-proposal-v1"


def _sort_payloads(values: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(values, key=canonicalize)


def proposal_payload(proposal: ExecutionPlanProposal) -> dict[str, object]:
    content = proposal.model_dump(mode="python")
    content["requested_targets"] = _sort_payloads(
        [target.model_dump(mode="python") for target in proposal.requested_targets]
    )
    return {"schema_version": PROPOSAL_SCHEMA_VERSION, "proposal": content}


def proposal_digest(proposal: ExecutionPlanProposal) -> str:
    return sha256_digest(proposal_payload(proposal))


def normalized_targets_payload(
    targets: tuple[NormalizedTarget, ...],
) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for target in targets:
        payload = target.model_dump(mode="python")
        payload["resolved_addresses"] = sorted(set(target.resolved_addresses))
        payloads.append(payload)
    return _sort_payloads(payloads)


def data_access_payload(grants: tuple[DataAccessGrant, ...]) -> list[dict[str, object]]:
    payloads = []
    for grant in grants:
        payload = grant.model_dump(mode="python")
        payload["operations"] = sorted(grant.operations)
        payloads.append(payload)
    return _sort_payloads(payloads)


def authorization_intent_payload(
    *,
    plan: ExecutionPlan,
    tool: ToolDefinition,
    normalized_targets: tuple[NormalizedTarget, ...],
    authorized_data_access: tuple[DataAccessGrant, ...],
    effective_risk: str,
    policy_version: str,
    registry_digest: str,
) -> dict[str, object]:
    return {
        "schema_version": "authorized-execution-intent-v1",
        "mission_id": plan.mission_id,
        "mission_revision": plan.mission_revision,
        "authorization_epoch": plan.authorization_epoch,
        "proposal_digest": plan.proposal_digest,
        "tool_ref": plan.proposal.tool_ref.model_dump(mode="python"),
        "resolved_adapter": tool.adapter,
        "resolved_adapter_id": tool.adapter_id,
        "session_id": plan.proposal.session_id,
        "validated_arguments": plan.proposal.arguments.to_dict(),
        "normalized_targets": normalized_targets_payload(normalized_targets),
        "authorized_data_access": data_access_payload(authorized_data_access),
        "effective_risk": effective_risk,
        "side_effect": tool.side_effect,
        "approval_rule": tool.approval_rule,
        "policy_version": policy_version,
        "registry_digest": registry_digest,
        "available_tool_snapshot_id": plan.available_tool_snapshot_id,
        "available_tool_snapshot_digest": plan.available_tool_snapshot_digest,
        "session_security_context_digest": plan.session_security_context_digest,
        "adapter_capabilities_digest": plan.adapter_capabilities_digest,
        "sandbox_capabilities_digest": plan.sandbox_capabilities_digest,
        "remote_mcp_trust_policy_digest": plan.remote_mcp_trust_policy_digest,
    }


def authorization_digest(
    *,
    plan: ExecutionPlan,
    tool: ToolDefinition,
    normalized_targets: tuple[NormalizedTarget, ...],
    authorized_data_access: tuple[DataAccessGrant, ...],
    effective_risk: str,
    policy_version: str,
    registry_digest: str,
) -> str:
    return sha256_digest(
        authorization_intent_payload(
            plan=plan,
            tool=tool,
            normalized_targets=normalized_targets,
            authorized_data_access=authorized_data_access,
            effective_risk=effective_risk,
            policy_version=policy_version,
            registry_digest=registry_digest,
        )
    )


def authorization_digest_from_decision(
    *, plan: ExecutionPlan, tool: ToolDefinition, decision: PolicyDecision
) -> str:
    return authorization_digest(
        plan=plan,
        tool=tool,
        normalized_targets=decision.normalized_targets,
        authorized_data_access=decision.authorized_data_access,
        effective_risk=decision.effective_risk,
        policy_version=decision.policy_version,
        registry_digest=decision.registry_digest,
    )
