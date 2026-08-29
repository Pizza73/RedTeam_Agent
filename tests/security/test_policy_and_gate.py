from __future__ import annotations

import inspect
from datetime import timedelta

import pytest

from redteam_agent.canonical import CanonicalJsonObject, digest_model
from redteam_agent.errors import AvailableToolSnapshotStaleError
from redteam_agent.executor import authorize_execution
from redteam_agent.mission import AuthorizationReferenceRegistry, MissionManager
from redteam_agent.models.common import OperationalPhase
from redteam_agent.models.plans import ExecutionPlanProposal
from redteam_agent.models.scope import NamedTargetReference
from redteam_agent.models.tools import ToolRef
from redteam_agent.policy.approval import ApprovalService
from redteam_agent.policy.engine import PolicyEngine
from redteam_agent.policy.plans import create_execution_plan
from redteam_agent.repositories import (
    LLMProfileRepository,
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
)
from redteam_agent.repositories.base import model_json
from redteam_agent.seeds import FIXED_TIME
from redteam_agent.storage import Database
from tests.helpers import build_environment, persist_environment, persisted_gate_kwargs


def test_in_scope_action_is_allowed_and_gate_never_dispatches() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        result = authorize_execution(**persisted_gate_kwargs(kernel))
        assert result.status == "AUTHORIZED"
        assert result.dispatch_performed is False


def test_policy_decision_is_required_from_repository() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        kwargs = persisted_gate_kwargs(kernel)
        kwargs["policy_decision_id"] = "decision_not_issued"
        assert authorize_execution(**kwargs).status == "DENIED"


def test_gate_public_api_cannot_accept_policy_decision_object() -> None:
    parameters = inspect.signature(authorize_execution).parameters
    assert "policy_decision" not in parameters
    assert "execution_plan" not in parameters
    assert "policy_decision_id" in parameters


def test_prohibited_scope_is_denied() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(target="10.0.0.200"))
        assert kernel.decision.decision == "DENY"
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "DENIED"


def test_invalid_or_unimplemented_target_is_denied() -> None:
    environment = build_environment()
    proposal = ExecutionPlanProposal(
        objective="invalid target",
        phase=OperationalPhase.DISCOVERY,
        tool_ref=environment.tool.tool_ref,
        requested_targets=(NamedTargetReference(type="hostname", value="not-implemented.test"),),
        session_id=None,
        arguments=CanonicalJsonObject({"target": "not-an-ip"}),
    )
    plan = create_execution_plan(
        mission=environment.mission,
        proposal=proposal,
        snapshot=environment.snapshot,
        created_at=FIXED_TIME,
    )
    decision = PolicyEngine(
        policy_version="policy-v1", extractors=environment.extractors
    ).authorize(
        mission=environment.mission,
        plan=plan,
        snapshot=environment.snapshot,
        registry=environment.registry,
        issued_at=FIXED_TIME + timedelta(minutes=1),
        expires_at=FIXED_TIME + timedelta(minutes=20),
    )
    assert decision.decision == "DENY"


def test_unregistered_tool_does_not_reach_policy_authorization() -> None:
    environment = build_environment()
    proposal = environment.proposal.model_copy(
        update={"tool_ref": ToolRef(tool_id="unregistered", registry_revision=1)}
    )
    plan = create_execution_plan(
        mission=environment.mission,
        proposal=proposal,
        snapshot=environment.snapshot,
        created_at=FIXED_TIME,
    )
    with pytest.raises(AvailableToolSnapshotStaleError):
        PolicyEngine(policy_version="policy-v1", extractors=environment.extractors).authorize(
            mission=environment.mission,
            plan=plan,
            snapshot=environment.snapshot,
            registry=environment.registry,
            issued_at=FIXED_TIME + timedelta(minutes=1),
            expires_at=FIXED_TIME + timedelta(minutes=20),
        )


def _approval_service(kernel) -> ApprovalService:
    return ApprovalService(
        runtime_resolver=kernel.runtime_resolver,
        plans=kernel.plans,
        decisions=kernel.decisions,
        requests=kernel.approval_requests,
        records=kernel.approvals,
    )


def test_require_approval_predicate_and_policy_decision_remains_immutable() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        assert kernel.decision.decision == "REQUIRE_APPROVAL"
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "WAITING_APPROVAL"
        service = _approval_service(kernel)
        request = service.request(
            plan_id=kernel.environment.plan.plan_id,
            policy_decision_id=kernel.decision.decision_id,
            issued_at=FIXED_TIME + timedelta(minutes=2),
            expires_at=FIXED_TIME + timedelta(minutes=10),
        )
        approved = service.record(
            approval_request_id=request.approval_request_id,
            human_decision="APPROVED",
            approver_id="operator-1",
            approver_role="redteam-lead",
            issued_at=FIXED_TIME + timedelta(minutes=3),
            expires_at=FIXED_TIME + timedelta(minutes=9),
        )
        kwargs = persisted_gate_kwargs(kernel)
        kwargs.update(
            approval_request_id=request.approval_request_id,
            approval_record_id=approved.approval_id,
        )
        assert authorize_execution(**kwargs).status == "AUTHORIZED"
        assert kernel.decisions.get(kernel.decision.decision_id).decision == "REQUIRE_APPROVAL"


def test_rejected_approval_is_denied() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        service = _approval_service(kernel)
        request = service.request(
            plan_id=kernel.environment.plan.plan_id,
            policy_decision_id=kernel.decision.decision_id,
            issued_at=FIXED_TIME + timedelta(minutes=2),
            expires_at=FIXED_TIME + timedelta(minutes=10),
        )
        record = service.record(
            approval_request_id=request.approval_request_id,
            human_decision="REJECTED",
            approver_id="operator-1",
            approver_role="lead",
            issued_at=FIXED_TIME + timedelta(minutes=3),
            expires_at=FIXED_TIME + timedelta(minutes=9),
        )
        kwargs = persisted_gate_kwargs(kernel)
        kwargs.update(
            approval_request_id=request.approval_request_id,
            approval_record_id=record.approval_id,
        )
        assert authorize_execution(**kwargs).status == "DENIED"


def test_old_epoch_is_stale_after_pause() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            LLMProfileRepository(database),
        )
        manager.pause(kernel.environment.mission.mission_id, now=FIXED_TIME + timedelta(minutes=2))
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "STALE"


def test_pre_pause_decision_and_snapshot_cannot_be_reused_after_resume() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            LLMProfileRepository(database),
            authorization_references=AuthorizationReferenceRegistry(
                frozenset({kernel.environment.mission.authorization_reference})
            ),
        )
        manager.pause(kernel.environment.mission.mission_id, now=FIXED_TIME + timedelta(minutes=2))
        manager.resume(kernel.environment.mission.mission_id, now=FIXED_TIME + timedelta(minutes=3))
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "STALE"


def test_pre_pause_approval_cannot_be_reused_after_resume() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        service = _approval_service(kernel)
        request = service.request(
            plan_id=kernel.environment.plan.plan_id,
            policy_decision_id=kernel.decision.decision_id,
            issued_at=FIXED_TIME + timedelta(minutes=1),
            expires_at=FIXED_TIME + timedelta(minutes=10),
        )
        record = service.record(
            approval_request_id=request.approval_request_id,
            human_decision="APPROVED",
            approver_id="operator-1",
            approver_role="lead",
            issued_at=FIXED_TIME + timedelta(minutes=2),
            expires_at=FIXED_TIME + timedelta(minutes=9),
        )
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            LLMProfileRepository(database),
            authorization_references=AuthorizationReferenceRegistry(
                frozenset({kernel.environment.mission.authorization_reference})
            ),
        )
        manager.pause(
            kernel.environment.mission.mission_id,
            now=FIXED_TIME + timedelta(minutes=3),
        )
        manager.resume(
            kernel.environment.mission.mission_id,
            now=FIXED_TIME + timedelta(minutes=4),
        )
        kwargs = persisted_gate_kwargs(kernel, now=FIXED_TIME + timedelta(minutes=5))
        kwargs.update(
            approval_request_id=request.approval_request_id,
            approval_record_id=record.approval_id,
        )
        assert authorize_execution(**kwargs).status == "STALE"


def test_now_equal_expiry_is_expired() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        assert authorize_execution(
            **persisted_gate_kwargs(kernel, now=kernel.decision.expires_at)
        ).status == "STALE"


def test_read_time_corrupted_decision_digest_is_invalid() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        corrupted = kernel.decision.model_copy(update={"authorization_digest": "sha256:bad"})
        database.connection.execute(
            "UPDATE policy_decisions SET payload_json = ? WHERE decision_id = ?",
            (model_json(corrupted), kernel.decision.decision_id),
        )
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "INVALID"


def test_gate_has_no_independent_data_access_bearer_parameter() -> None:
    parameters = inspect.signature(authorize_execution).parameters
    assert "data_access_grant_ids" not in parameters
    assert "data_access_grant" not in parameters
