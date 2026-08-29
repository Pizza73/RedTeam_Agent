"""Separate repositories for human presentation and human decision."""

from __future__ import annotations

from redteam_agent.canonical import sha256_digest, stable_id, verify_model_digest
from redteam_agent.errors import ApprovalBindingError, DigestIntegrityError, MissionTTLExceededError
from redteam_agent.models.approval import ApprovalRecord, ApprovalRequest
from redteam_agent.models.mission import MissionRevision
from redteam_agent.models.policy import PolicyDecision

from .base import ImmutableJsonRepository, model_json, parse_model_json


class ApprovalRequestRepository(ImmutableJsonRepository[ApprovalRequest]):
    table = "approval_requests"
    id_column = "approval_request_id"
    model_type = ApprovalRequest

    def verify_integrity(self, model: ApprovalRequest) -> None:
        verify_model_digest(model, model.request_digest, exclude={"request_digest"})
        presentation_digest = sha256_digest(
            {
                "schema_version": "approval-presentation-v1",
                "presentation": model.presentation,
            }
        )
        if presentation_digest != model.approval_presentation_digest:
            raise DigestIntegrityError("approval presentation digest mismatch")
        identity = {
            "schema_version": "approval-request-v1",
            "policy_decision_id": model.policy_decision_id,
            "authorization_digest": model.authorization_digest,
            "approval_presentation_digest": model.approval_presentation_digest,
            "issued_at": model.issued_at,
            "expires_at": model.expires_at,
        }
        if model.approval_request_id != stable_id("approvalrequest", identity):
            raise DigestIntegrityError("approval request ID mismatch")

    def verify_row_binding(self, identifier: str | int, model: ApprovalRequest) -> None:
        row = self.database.connection.execute(
            "SELECT request_digest, policy_decision_id, expires_at FROM approval_requests "
            "WHERE approval_request_id = ?", (identifier,)
        ).fetchone()
        if row is None or not (
            row["request_digest"] == model.request_digest
            and row["policy_decision_id"] == model.policy_decision_id
            and row["expires_at"] == model.expires_at.isoformat()
        ):
            raise DigestIntegrityError("approval request row binding mismatch")

    def _store_built(self, request: ApprovalRequest, *, builder_token: object) -> ApprovalRequest:
        from redteam_agent.policy.approval import _APPROVAL_BUILDER_TOKEN

        if builder_token is not _APPROVAL_BUILDER_TOKEN:
            raise ApprovalBindingError("approval request must be built by ApprovalService")
        self.verify_integrity(request)
        decision_row = self.database.connection.execute(
            "SELECT payload_json FROM policy_decisions WHERE decision_id = ?",
            (request.policy_decision_id,),
        ).fetchone()
        if decision_row is None:
            raise ApprovalBindingError("policy decision does not exist")
        decision = parse_model_json(PolicyDecision, decision_row["payload_json"])
        mission_row = self.database.connection.execute(
            "SELECT payload_json FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (request.mission_id, request.mission_revision),
        ).fetchone()
        if mission_row is None:
            raise MissionTTLExceededError("bound mission revision does not exist")
        mission = parse_model_json(MissionRevision, mission_row["payload_json"])
        if request.expires_at > mission.valid_until or request.expires_at > decision.expires_at:
            raise MissionTTLExceededError("approval request violates TTL invariant")
        if not (
            request.policy_decision_id == decision.decision_id
            and request.authorization_digest == decision.authorization_digest
            and request.mission_id == decision.mission_id
            and request.mission_revision == decision.mission_revision
            and request.authorization_epoch == decision.authorization_epoch
        ):
            raise ApprovalBindingError("approval request/decision binding mismatch")
        payload = model_json(request)
        self._insert_or_same(
            "INSERT INTO approval_requests"
            "(approval_request_id, request_digest, policy_decision_id, expires_at, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                request.approval_request_id,
                request.request_digest,
                request.policy_decision_id,
                request.expires_at.isoformat(),
                payload,
            ),
            payload,
        )
        return request


class ApprovalRecordRepository(ImmutableJsonRepository[ApprovalRecord]):
    table = "approvals"
    id_column = "approval_id"
    model_type = ApprovalRecord

    def verify_integrity(self, model: ApprovalRecord) -> None:
        verify_model_digest(model, model.record_digest, exclude={"record_digest"})
        identity = {
            "schema_version": "approval-record-v1",
            "approval_request_id": model.approval_request_id,
            "request_digest": model.approval_request_digest,
            "human_decision": model.decision,
            "approver_id": model.approver_id,
            "issued_at": model.issued_at,
        }
        if model.approval_id != stable_id("approval", identity):
            raise DigestIntegrityError("approval record ID mismatch")

    def verify_row_binding(self, identifier: str | int, model: ApprovalRecord) -> None:
        row = self.database.connection.execute(
            "SELECT approval_request_id, policy_decision_id, record_digest, expires_at "
            "FROM approvals WHERE approval_id = ?", (identifier,)
        ).fetchone()
        if row is None or not (
            row["approval_request_id"] == model.approval_request_id
            and row["policy_decision_id"] == model.policy_decision_id
            and row["record_digest"] == model.record_digest
            and row["expires_at"] == model.expires_at.isoformat()
        ):
            raise DigestIntegrityError("approval record row binding mismatch")

    def _store_built(self, record: ApprovalRecord, *, builder_token: object) -> ApprovalRecord:
        from redteam_agent.policy.approval import _APPROVAL_BUILDER_TOKEN

        if builder_token is not _APPROVAL_BUILDER_TOKEN:
            raise ApprovalBindingError("approval record must be built by ApprovalService")
        self.verify_integrity(record)
        request_row = self.database.connection.execute(
            "SELECT payload_json FROM approval_requests WHERE approval_request_id = ?",
            (record.approval_request_id,),
        ).fetchone()
        decision_row = self.database.connection.execute(
            "SELECT payload_json FROM policy_decisions WHERE decision_id = ?",
            (record.policy_decision_id,),
        ).fetchone()
        if request_row is None or decision_row is None:
            raise ApprovalBindingError("approval request or policy decision does not exist")
        request = parse_model_json(ApprovalRequest, request_row["payload_json"])
        decision = parse_model_json(PolicyDecision, decision_row["payload_json"])
        if record.expires_at > request.expires_at or record.expires_at > decision.expires_at:
            raise MissionTTLExceededError("approval record violates TTL invariant")
        if not (
            record.approval_request_digest == request.request_digest
            and record.approval_presentation_digest == request.approval_presentation_digest
            and record.authorization_digest == decision.authorization_digest
            and record.mission_id == request.mission_id == decision.mission_id
            and record.mission_revision == request.mission_revision == decision.mission_revision
            and record.authorization_epoch == request.authorization_epoch == decision.authorization_epoch
        ):
            raise ApprovalBindingError("approval record/request/decision binding mismatch")
        payload = model_json(record)
        self._insert_or_same(
            "INSERT INTO approvals"
            "(approval_id, approval_request_id, policy_decision_id, record_digest, expires_at, "
            "payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record.approval_id,
                record.approval_request_id,
                record.policy_decision_id,
                record.record_digest,
                record.expires_at.isoformat(),
                payload,
            ),
            payload,
        )
        return record
