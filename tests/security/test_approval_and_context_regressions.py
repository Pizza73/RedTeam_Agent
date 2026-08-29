from __future__ import annotations

from datetime import timedelta

import pytest

from redteam_agent.canonical import CanonicalJsonObject, digest_model, sha256_digest, stable_id
from redteam_agent.context import (
    ContextAccessGate,
    ContextAuthorizationApplicationService,
    ContextAuthorizationService,
    ContextSelector,
)
from redteam_agent.context.authorization import _CONTEXT_AUTHORIZER_TOKEN
from redteam_agent.errors import (
    DataAccessDeniedError,
    DigestIntegrityError,
    SessionContextGrantStaleError,
)
from redteam_agent.executor import authorize_execution
from redteam_agent.models.capabilities import SessionSecurityContext
from redteam_agent.models.common import OperationalPhase, RiskLevel, SideEffect
from redteam_agent.models.context import (
    ContextSelectionRequest,
    DataAccessGrant,
    ResourceBinding,
)
from redteam_agent.models.scope import NormalizedTarget
from redteam_agent.policy.approval import _APPROVAL_BUILDER_TOKEN, ApprovalService
from redteam_agent.policy.issuance import PolicyDecisionIssuanceService
from redteam_agent.repositories import (
    AuthorizationRuntimeBindingRepository,
    AvailableToolSnapshotRepository,
    ContextAuthorizationRepository,
    PolicyStateRepository,
    SessionSecurityContextSnapshotRepository,
)
from redteam_agent.repositories.base import model_json
from redteam_agent.repositories.runtime import build_policy_state, build_runtime_binding
from redteam_agent.seeds import FIXED_TIME, mock_context_index
from redteam_agent.storage import Database
from redteam_agent.tools.capability_snapshots import build_session_snapshot
from tests.helpers import build_environment, persist_environment, persisted_gate_kwargs


def _approval_service(kernel) -> ApprovalService:
    return ApprovalService(
        runtime_resolver=kernel.runtime_resolver,
        plans=kernel.plans,
        decisions=kernel.decisions,
        requests=kernel.approval_requests,
        records=kernel.approvals,
    )


def _approval_artifacts(kernel):
    service = _approval_service(kernel)
    request = service.request(
        plan_id=kernel.environment.plan.plan_id,
        policy_decision_id=kernel.decision.decision_id,
        issued_at=FIXED_TIME + timedelta(minutes=2),
        expires_at=FIXED_TIME + timedelta(minutes=10),
    )
    record = service.record(
        approval_request_id=request.approval_request_id,
        human_decision="APPROVED",
        approver_id="operator-1",
        approver_role="lead",
        issued_at=FIXED_TIME + timedelta(minutes=3),
        expires_at=FIXED_TIME + timedelta(minutes=9),
    )
    return request, record


def _forge_request(request, presentation):
    presentation_digest = sha256_digest(
        {"schema_version": "approval-presentation-v1", "presentation": presentation}
    )
    changed = request.model_copy(
        update={
            "presentation": presentation,
            "approval_presentation_digest": presentation_digest,
            "request_digest": "pending",
        }
    )
    identity = {
        "schema_version": "approval-request-v1",
        "policy_decision_id": changed.policy_decision_id,
        "authorization_digest": changed.authorization_digest,
        "approval_presentation_digest": presentation_digest,
        "issued_at": changed.issued_at,
        "expires_at": changed.expires_at,
    }
    changed = changed.model_copy(
        update={"approval_request_id": stable_id("approvalrequest", identity)}
    )
    return changed.model_copy(
        update={"request_digest": digest_model(changed, exclude={"request_digest"})}
    )


def _forge_record(record, request):
    changed = record.model_copy(
        update={
            "approval_request_id": request.approval_request_id,
            "approval_request_digest": request.request_digest,
            "approval_presentation_digest": request.approval_presentation_digest,
            "record_digest": "pending",
        }
    )
    identity = {
        "schema_version": "approval-record-v1",
        "approval_request_id": changed.approval_request_id,
        "request_digest": changed.approval_request_digest,
        "human_decision": changed.decision,
        "approver_id": changed.approver_id,
        "issued_at": changed.issued_at,
    }
    changed = changed.model_copy(update={"approval_id": stable_id("approval", identity)})
    return changed.model_copy(
        update={"record_digest": digest_model(changed, exclude={"record_digest"})}
    )


@pytest.mark.parametrize("mutation", ["target", "arguments", "risk", "side_effect"])
def test_misleading_approval_presentation_is_rejected(mutation: str) -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        request, record = _approval_artifacts(kernel)
        if mutation == "target":
            presentation = request.presentation.model_copy(
                update={
                    "normalized_targets": (
                        NormalizedTarget(
                            type="ip",
                            canonical_value="10.0.0.20",
                            source="plan",
                        ),
                    )
                }
            )
        elif mutation == "arguments":
            presentation = request.presentation.model_copy(
                update={"redacted_arguments": CanonicalJsonObject({"target": "harmless.example"})}
            )
        elif mutation == "risk":
            presentation = request.presentation.model_copy(update={"effective_risk": RiskLevel.LOW})
        else:
            presentation = request.presentation.model_copy(
                update={"side_effect": SideEffect.STATE_CHANGE}
            )
        forged_request = _forge_request(request, presentation)
        forged_record = _forge_record(record, forged_request)
        database.connection.execute("DELETE FROM approvals")
        database.connection.execute("DELETE FROM approval_requests")
        database.connection.execute(
            "INSERT INTO approval_requests"
            "(approval_request_id, request_digest, policy_decision_id, expires_at, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                forged_request.approval_request_id,
                forged_request.request_digest,
                forged_request.policy_decision_id,
                forged_request.expires_at.isoformat(),
                model_json(forged_request),
            ),
        )
        database.connection.execute(
            "INSERT INTO approvals"
            "(approval_id, approval_request_id, policy_decision_id, record_digest, expires_at, "
            "payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                forged_record.approval_id,
                forged_record.approval_request_id,
                forged_record.policy_decision_id,
                forged_record.record_digest,
                forged_record.expires_at.isoformat(),
                model_json(forged_record),
            ),
        )
        kwargs = persisted_gate_kwargs(kernel)
        kwargs.update(
            approval_request_id=forged_request.approval_request_id,
            approval_record_id=forged_record.approval_id,
        )
        assert authorize_execution(**kwargs).status == "INVALID"


def test_wrong_approval_request_record_pair_is_rejected() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        service = _approval_service(kernel)
        first_request = service.request(
            plan_id=kernel.environment.plan.plan_id,
            policy_decision_id=kernel.decision.decision_id,
            issued_at=FIXED_TIME + timedelta(minutes=2),
            expires_at=FIXED_TIME + timedelta(minutes=10),
        )
        second_request = service.request(
            plan_id=kernel.environment.plan.plan_id,
            policy_decision_id=kernel.decision.decision_id,
            issued_at=FIXED_TIME + timedelta(minutes=4),
            expires_at=FIXED_TIME + timedelta(minutes=11),
        )
        second_record = service.record(
            approval_request_id=second_request.approval_request_id,
            human_decision="APPROVED",
            approver_id="operator-1",
            approver_role="lead",
            issued_at=FIXED_TIME + timedelta(minutes=5),
            expires_at=FIXED_TIME + timedelta(minutes=9),
        )
        kwargs = persisted_gate_kwargs(kernel, now=FIXED_TIME + timedelta(minutes=6))
        kwargs.update(
            approval_request_id=first_request.approval_request_id,
            approval_record_id=second_record.approval_id,
        )
        assert authorize_execution(**kwargs).status == "INVALID"


def _context_grant(database: Database):
    kernel = persist_environment(database, build_environment())
    record = mock_context_index(kernel.environment.mission.mission_id)
    kernel.resources.add(record)
    candidates = ContextSelector(kernel.resources).select(
        ContextSelectionRequest(
            mission_id=record.mission_id,
            current_targets=(),
            candidate_session_ids=("session-1",),
            operational_phase=OperationalPhase.DISCOVERY,
        )
    )
    repository = ContextAuthorizationRepository(database)
    grant = ContextAuthorizationApplicationService(
        ContextAuthorizationService(), repository, kernel.runtime_resolver
    ).issue(
        mission_id=record.mission_id,
        service_identity="planner_context",
        candidates=candidates,
        requested_session_ids=("session-1",),
        issued_at=FIXED_TIME,
        expires_at=FIXED_TIME + timedelta(minutes=10),
    )
    return kernel, record, repository, grant


def test_old_policy_version_context_grant_is_rejected() -> None:
    with Database() as database:
        kernel, record, repository, grant = _context_grant(database)
        policies = PolicyStateRepository(database)
        policies.set_current(
            build_policy_state(
                mission_id=record.mission_id,
                state_version=1,
                policy_version="policy-v2",
                updated_at=FIXED_TIME + timedelta(minutes=1),
            )
        )
        gate = ContextAccessGate(kernel.resources, repository, kernel.runtime_resolver)
        with pytest.raises(DataAccessDeniedError):
            gate.authorize_resource(
                grant_id=grant.grant_id,
                mission_id=record.mission_id,
                service_identity="planner_context",
                resource_id=record.binding.resource_id,
                operation="read",
                now=FIXED_TIME + timedelta(minutes=2),
            )


def test_changed_current_session_security_context_rejects_old_grant() -> None:
    with Database() as database:
        kernel, record, repository, grant = _context_grant(database)
        current_runtime = kernel.runtime_resolver.resolve(record.mission_id)
        original = current_runtime.session_snapshot.contexts[0]
        changed_context = SessionSecurityContext(
            **{
                **original.model_dump(mode="python"),
                "current_principal": "uid:0",
                "effective_privilege_context": "uid=0,gid=0",
            }
        )
        changed_session = build_session_snapshot(
            mission_id=record.mission_id,
            contexts=(changed_context,),
            source=current_runtime.session_snapshot.source,
            created_at=FIXED_TIME + timedelta(minutes=1),
        )
        SessionSecurityContextSnapshotRepository(database).add(changed_session)
        calculation = kernel.environment.availability_resolver.calculate(
            mission=current_runtime.mission,
            registry=current_runtime.registry,
            session_snapshot=changed_session,
            adapter_snapshot=current_runtime.adapter_snapshot,
            sandbox_snapshot=current_runtime.sandbox_snapshot,
            remote_trust_snapshot=current_runtime.remote_trust_snapshot,
            policy_version=current_runtime.policy_state.policy_version,
        )
        changed_available = kernel.environment.availability_resolver.persistable_snapshot(
            calculation,
            created_at=FIXED_TIME + timedelta(minutes=1),
            expires_at=FIXED_TIME + timedelta(minutes=30),
            mission_valid_until=current_runtime.mission.valid_until,
        )
        AvailableToolSnapshotRepository(database).add(changed_available)
        AuthorizationRuntimeBindingRepository(database).set_current(
            build_runtime_binding(
                mission_id=record.mission_id,
                binding_version=1,
                mission_revision=current_runtime.mission.mission_revision,
                authorization_epoch=current_runtime.mission.authorization_epoch,
                policy_version=current_runtime.policy_state.policy_version,
                registry_revision=current_runtime.registry.registry_revision,
                registry_digest=current_runtime.registry.registry_digest,
                available_tool_snapshot_id=changed_available.snapshot_id,
                session_security_context_snapshot_id=changed_session.snapshot_id,
                adapter_capability_snapshot_id=current_runtime.adapter_snapshot.snapshot_id,
                sandbox_capability_snapshot_id=current_runtime.sandbox_snapshot.snapshot_id,
                remote_mcp_trust_snapshot_id=current_runtime.remote_trust_snapshot.snapshot_id,
                updated_at=FIXED_TIME + timedelta(minutes=1),
            )
        )
        with pytest.raises(SessionContextGrantStaleError):
            ContextAccessGate(
                kernel.resources, repository, kernel.runtime_resolver
            ).authorize_resource(
                grant_id=grant.grant_id,
                mission_id=record.mission_id,
                service_identity="planner_context",
                resource_id=record.binding.resource_id,
                operation="read",
                now=FIXED_TIME + timedelta(minutes=2),
            )


@pytest.mark.parametrize(
    "binding",
    [
        ResourceBinding(
            resource_id="knowledge:host-1",
            resource_version="2",
            resource_digest="sha256:knowledge-host-1-v1",
        ),
        ResourceBinding(
            resource_id="knowledge:host-1",
            resource_version="1",
            resource_digest="sha256:different",
        ),
    ],
)
def test_resource_version_and_digest_mismatch_each_fail_closed(binding) -> None:
    with Database() as database:
        kernel, record, repository, grant = _context_grant(database)
        changed = record.model_copy(update={"index_id": "changed-index", "binding": binding})
        if binding.resource_version == record.binding.resource_version:
            database.connection.execute(
                "UPDATE context_resource_index SET resource_digest = ?, payload_json = ? "
                "WHERE index_id = ?",
                (binding.resource_digest, model_json(changed), record.index_id),
            )
        else:
            kernel.resources.add(changed)
        with pytest.raises(DataAccessDeniedError):
            ContextAccessGate(
                kernel.resources, repository, kernel.runtime_resolver
            ).authorize_resource(
                grant_id=grant.grant_id,
                mission_id=record.mission_id,
                service_identity="planner_context",
                resource_id=record.binding.resource_id,
                operation="read",
                now=FIXED_TIME + timedelta(minutes=1),
            )


def test_context_and_approval_repositories_reject_invalid_digest_first_insert() -> None:
    with Database() as database:
        _, _, repository, grant = _context_grant(database)
        invalid_grant = grant.model_copy(
            update={"grant_id": "new-invalid-grant", "grant_digest": "sha256:invalid"}
        )
        with pytest.raises(DigestIntegrityError):
            repository._store_issued(invalid_grant, authorizer_token=_CONTEXT_AUTHORIZER_TOKEN)
    with Database() as approval_database:
        approval_kernel = persist_environment(
            approval_database, build_environment(approval_rule="always")
        )
        request, record = _approval_artifacts(approval_kernel)
        with pytest.raises(DigestIntegrityError):
            approval_kernel.approval_requests._store_built(
                request.model_copy(
                    update={"approval_request_id": "new-invalid", "request_digest": "bad"}
                ),
                builder_token=_APPROVAL_BUILDER_TOKEN,
            )
        with pytest.raises(DigestIntegrityError):
            approval_kernel.approvals._store_built(
                record.model_copy(update={"approval_id": "new-invalid", "record_digest": "bad"}),
                builder_token=_APPROVAL_BUILDER_TOKEN,
            )


def test_context_grant_child_row_binding_is_verified_on_read() -> None:
    with Database() as database:
        _, _, repository, grant = _context_grant(database)
        database.connection.execute(
            "UPDATE data_access_grants SET resource_digest = 'sha256:tampered' "
            "WHERE owner_type = 'context' AND owner_id = ?",
            (grant.grant_id,),
        )
        with pytest.raises(DigestIntegrityError):
            repository.get(grant.grant_id)


def test_policy_decision_child_row_binding_is_verified_on_read() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        resource = mock_context_index(kernel.environment.mission.mission_id)
        kernel.resources.add(resource)
        requested = DataAccessGrant(
            resource_type=resource.resource_type,
            resource=resource.binding,
            operations=frozenset({"read"}),
        )
        database.connection.execute(
            "DELETE FROM policy_decisions WHERE decision_id = ?",
            (kernel.decision.decision_id,),
        )
        issued = PolicyDecisionIssuanceService(
            runtime_resolver=kernel.runtime_resolver,
            plans=kernel.plans,
            decisions=kernel.decisions,
            resources=kernel.resources,
        ).issue(
            plan_id=kernel.environment.plan.plan_id,
            requested_data_access=(requested,),
            issued_at=FIXED_TIME + timedelta(minutes=1),
            expires_at=FIXED_TIME + timedelta(minutes=30),
        )
        database.connection.execute(
            "UPDATE data_access_grants SET resource_version = 'tampered' "
            "WHERE owner_type = 'policy' AND owner_id = ?",
            (issued.decision_id,),
        )
        with pytest.raises(DigestIntegrityError):
            kernel.decisions.get(issued.decision_id)
