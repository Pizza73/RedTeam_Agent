"""Proposal and application-owned plan repositories."""

from __future__ import annotations

from redteam_agent.canonical import stable_id
from redteam_agent.errors import DigestIntegrityError
from redteam_agent.models.plans import ExecutionPlan, ExecutionPlanProposal
from redteam_agent.policy.digests import PROPOSAL_SCHEMA_VERSION, proposal_digest

from .base import ImmutableJsonRepository, model_json
from .tools import AvailableToolSnapshotRepository


class PlanProposalRepository(ImmutableJsonRepository[ExecutionPlanProposal]):
    table = "execution_plan_proposals"
    id_column = "proposal_digest"
    model_type = ExecutionPlanProposal

    def add(self, proposal: ExecutionPlanProposal) -> str:
        calculated_digest = proposal_digest(proposal)
        payload = model_json(proposal)
        self._insert_or_same(
            "INSERT INTO execution_plan_proposals"
            "(proposal_digest, schema_version, payload_json) VALUES (?, ?, ?)",
            (calculated_digest, PROPOSAL_SCHEMA_VERSION, payload),
            payload,
        )
        return calculated_digest

    def get(self, identifier: str | int) -> ExecutionPlanProposal | None:
        proposal = super().get(identifier)
        if proposal is not None:
            row = self.database.connection.execute(
                "SELECT schema_version FROM execution_plan_proposals WHERE proposal_digest = ?",
                (identifier,),
            ).fetchone()
            if (
                proposal_digest(proposal) != identifier
                or row is None
                or row["schema_version"] != PROPOSAL_SCHEMA_VERSION
            ):
                raise DigestIntegrityError("proposal digest or schema binding mismatch")
        return proposal


class PlanRepository(ImmutableJsonRepository[ExecutionPlan]):
    table = "execution_plans"
    id_column = "plan_id"
    model_type = ExecutionPlan

    def verify_integrity(self, model: ExecutionPlan) -> None:
        if proposal_digest(model.proposal) != model.proposal_digest:
            raise DigestIntegrityError("execution plan proposal digest mismatch")
        identity = {
            "schema_version": "execution-plan-v1",
            "mission_id": model.mission_id,
            "mission_revision": model.mission_revision,
            "authorization_epoch": model.authorization_epoch,
            "proposal_digest": model.proposal_digest,
            "snapshot_id": model.available_tool_snapshot_id,
            "snapshot_digest": model.available_tool_snapshot_digest,
            "created_at": model.created_at,
        }
        if model.plan_id != stable_id("plan", identity):
            raise DigestIntegrityError("execution plan ID mismatch")

    def verify_row_binding(self, identifier: str | int, model: ExecutionPlan) -> None:
        row = self.database.connection.execute(
            "SELECT mission_id, mission_revision, authorization_epoch, proposal_digest "
            "FROM execution_plans WHERE plan_id = ?", (identifier,)
        ).fetchone()
        if row is None or not (
            row["mission_id"] == model.mission_id
            and row["mission_revision"] == model.mission_revision
            and row["authorization_epoch"] == model.authorization_epoch
            and row["proposal_digest"] == model.proposal_digest
        ):
            raise DigestIntegrityError("execution plan row binding mismatch")

        self._verify_parent_bindings(model)

    def _verify_parent_bindings(self, plan: ExecutionPlan) -> None:
        stored_proposal = PlanProposalRepository(self.database).get(plan.proposal_digest)
        if stored_proposal != plan.proposal:
            raise DigestIntegrityError("execution plan proposal is not persisted or differs")
        snapshot = AvailableToolSnapshotRepository(self.database).get(
            plan.available_tool_snapshot_id
        )
        if snapshot is None or not (
            snapshot.snapshot_digest == plan.available_tool_snapshot_digest
            and snapshot.mission_id == plan.mission_id
            and snapshot.mission_revision == plan.mission_revision
            and snapshot.authorization_epoch == plan.authorization_epoch
            and snapshot.session_security_context_digest
            == plan.session_security_context_digest
            and snapshot.adapter_capabilities_digest == plan.adapter_capabilities_digest
            and snapshot.sandbox_capabilities_digest == plan.sandbox_capabilities_digest
            and snapshot.remote_mcp_trust_policy_digest
            == plan.remote_mcp_trust_policy_digest
            and any(view.tool_ref == plan.proposal.tool_ref for view in snapshot.tools)
        ):
            raise DigestIntegrityError("execution plan/snapshot binding mismatch")

    def add(self, plan: ExecutionPlan) -> ExecutionPlan:
        self.verify_integrity(plan)
        self._verify_parent_bindings(plan)
        payload = model_json(plan)
        self._insert_or_same(
            "INSERT INTO execution_plans"
            "(plan_id, mission_id, mission_revision, authorization_epoch, proposal_digest, "
            "payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                plan.plan_id,
                plan.mission_id,
                plan.mission_revision,
                plan.authorization_epoch,
                plan.proposal_digest,
                payload,
            ),
            payload,
        )
        return plan
