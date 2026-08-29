"""Immutable PolicyDecision repository and owned DataAccessGrant entries."""

from __future__ import annotations

from redteam_agent.canonical import stable_id, verify_model_digest
from redteam_agent.errors import (
    DigestIntegrityError,
    MissionTTLExceededError,
    PolicyDecisionProvenanceError,
)
from redteam_agent.models.mission import MissionRevision
from redteam_agent.models.policy import PolicyDecision
from redteam_agent.repositories.plans import PlanRepository

from .base import ImmutableJsonRepository, model_json, parse_model_json


class PolicyDecisionRepository(ImmutableJsonRepository[PolicyDecision]):
    table = "policy_decisions"
    id_column = "decision_id"
    model_type = PolicyDecision

    def verify_integrity(self, model: PolicyDecision) -> None:
        verify_model_digest(model, model.decision_digest, exclude={"decision_digest"})
        identity = {
            "authorization_digest": model.authorization_digest,
            "decision": model.decision,
            "issued_at": model.issued_at,
            "expires_at": model.expires_at,
        }
        if model.decision_id != stable_id("decision", identity):
            raise DigestIntegrityError("policy decision ID mismatch")

    def verify_row_binding(self, identifier: str | int, model: PolicyDecision) -> None:
        row = self.database.connection.execute(
            "SELECT decision_digest, mission_id, plan_id, authorization_digest, decision, "
            "expires_at FROM policy_decisions WHERE decision_id = ?", (identifier,)
        ).fetchone()
        if row is None or not (
            row["decision_digest"] == model.decision_digest
            and row["mission_id"] == model.mission_id
            and row["plan_id"] == model.plan_id
            and row["authorization_digest"] == model.authorization_digest
            and row["decision"] == model.decision
            and row["expires_at"] == model.expires_at.isoformat()
        ):
            raise DigestIntegrityError("policy decision row binding mismatch")

    def get(self, identifier: str | int) -> PolicyDecision | None:
        row = self.database.connection.execute(
            "SELECT issuer FROM policy_decisions WHERE decision_id = ?", (identifier,)
        ).fetchone()
        if row is None:
            return None
        if row["issuer"] != "policy_engine_v1":
            raise PolicyDecisionProvenanceError("policy decision issuer is not trusted")
        decision = super().get(identifier)
        if decision is None:
            return None
        rows = self.database.connection.execute(
            "SELECT entry_index, resource_id, resource_version, resource_digest, payload_json "
            "FROM data_access_grants "
            "WHERE owner_type = 'policy' AND owner_id = ? ORDER BY entry_index",
            (decision.decision_id,),
        ).fetchall()
        from redteam_agent.models.context import DataAccessGrant

        persisted = tuple(parse_model_json(DataAccessGrant, row["payload_json"]) for row in rows)
        if persisted != decision.authorized_data_access:
            raise DigestIntegrityError("policy decision child entries differ from envelope")
        for expected_index, (row, entry) in enumerate(zip(rows, persisted, strict=True)):
            if not (
                row["entry_index"] == expected_index
                and row["resource_id"] == entry.resource.resource_id
                and row["resource_version"] == entry.resource.resource_version
                and row["resource_digest"] == entry.resource.resource_digest
            ):
                raise DigestIntegrityError("policy decision child row binding mismatch")
        plan = PlanRepository(self.database).get(decision.plan_id)
        if plan is None or not (
            plan.mission_id == decision.mission_id
            and plan.mission_revision == decision.mission_revision
            and plan.authorization_epoch == decision.authorization_epoch
            and plan.proposal_digest == decision.proposal_digest
            and plan.proposal.tool_ref == decision.tool_ref
        ):
            raise DigestIntegrityError("policy decision/plan binding mismatch")
        return decision

    def _store_issued(self, decision: PolicyDecision, *, issuer_token: object) -> PolicyDecision:
        from redteam_agent.policy.issuance import _POLICY_ENGINE_ISSUER_TOKEN

        if issuer_token is not _POLICY_ENGINE_ISSUER_TOKEN:
            raise PolicyDecisionProvenanceError("only PolicyDecisionIssuanceService may persist")
        self.verify_integrity(decision)
        plan = PlanRepository(self.database).get(decision.plan_id)
        if plan is None or not (
            plan.mission_id == decision.mission_id
            and plan.mission_revision == decision.mission_revision
            and plan.authorization_epoch == decision.authorization_epoch
            and plan.proposal_digest == decision.proposal_digest
            and plan.proposal.tool_ref == decision.tool_ref
        ):
            raise DigestIntegrityError("policy decision/plan binding mismatch")
        row = self.database.connection.execute(
            "SELECT payload_json FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (decision.mission_id, decision.mission_revision),
        ).fetchone()
        if row is None:
            raise MissionTTLExceededError("bound mission revision does not exist")
        mission = parse_model_json(MissionRevision, row["payload_json"])
        if decision.expires_at > mission.valid_until:
            raise MissionTTLExceededError("policy decision outlives mission")
        payload = model_json(decision)
        existing = self._get_payload(decision.decision_id)
        if existing is not None:
            self.ensure_same_payload(existing, payload)
            return decision
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO policy_decisions"
                "(decision_id, decision_digest, mission_id, plan_id, authorization_digest, "
                "decision, expires_at, payload_json, issuer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision.decision_id,
                    decision.decision_digest,
                    decision.mission_id,
                    decision.plan_id,
                    decision.authorization_digest,
                    decision.decision,
                    decision.expires_at.isoformat(),
                    payload,
                    "policy_engine_v1",
                ),
            )
            for index, entry in enumerate(decision.authorized_data_access):
                connection.execute(
                    "INSERT INTO data_access_grants"
                    "(owner_type, owner_id, entry_index, resource_id, resource_version, "
                    "resource_digest, payload_json) VALUES ('policy', ?, ?, ?, ?, ?, ?)",
                    (
                        decision.decision_id,
                        index,
                        entry.resource.resource_id,
                        entry.resource.resource_version,
                        entry.resource.resource_digest,
                        model_json(entry),
                    ),
                )
        return decision
