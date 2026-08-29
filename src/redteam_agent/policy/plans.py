"""Application-owned plan materialization."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical import stable_id
from redteam_agent.models.mission import Mission
from redteam_agent.models.plans import ExecutionPlan, ExecutionPlanProposal
from redteam_agent.models.tools import AvailableToolSnapshot

from .digests import PROPOSAL_SCHEMA_VERSION, proposal_digest


def create_execution_plan(
    *,
    mission: Mission,
    proposal: ExecutionPlanProposal,
    snapshot: AvailableToolSnapshot,
    created_at: datetime,
) -> ExecutionPlan:
    digest = proposal_digest(proposal)
    identity = {
        "schema_version": "execution-plan-v1",
        "mission_id": mission.mission_id,
        "mission_revision": mission.mission_revision,
        "authorization_epoch": mission.authorization_epoch,
        "proposal_digest": digest,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_digest": snapshot.snapshot_digest,
        "created_at": created_at,
    }
    return ExecutionPlan(
        plan_id=stable_id("plan", identity),
        mission_id=mission.mission_id,
        mission_revision=mission.mission_revision,
        authorization_epoch=mission.authorization_epoch,
        proposal_schema_version=PROPOSAL_SCHEMA_VERSION,
        proposal=proposal,
        proposal_digest=digest,
        available_tool_snapshot_id=snapshot.snapshot_id,
        available_tool_snapshot_digest=snapshot.snapshot_digest,
        session_security_context_digest=snapshot.session_security_context_digest,
        adapter_capabilities_digest=snapshot.adapter_capabilities_digest,
        sandbox_capabilities_digest=snapshot.sandbox_capabilities_digest,
        remote_mcp_trust_policy_digest=snapshot.remote_mcp_trust_policy_digest,
        created_at=created_at,
    )

