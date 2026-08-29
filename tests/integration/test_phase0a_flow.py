from __future__ import annotations

from datetime import timedelta

from redteam_agent.context import (
    ContextAuthorizationApplicationService,
    ContextAuthorizationService,
    ContextSelector,
)
from redteam_agent.executor import authorize_execution
from redteam_agent.models.common import OperationalPhase
from redteam_agent.models.context import ContextSelectionRequest
from redteam_agent.policy.approval import ApprovalService
from redteam_agent.repositories import ContextAuthorizationRepository
from redteam_agent.seeds import FIXED_TIME, mock_context_index
from redteam_agent.storage import Database
from tests.helpers import (
    build_environment,
    persist_environment,
    persisted_gate_kwargs,
)


def test_complete_phase0a_repository_flow_without_dispatch() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        result = authorize_execution(**persisted_gate_kwargs(kernel))
        assert result.status == "AUTHORIZED"
        assert result.dispatch_performed is False
        assert kernel.decisions.get(kernel.decision.decision_id) == kernel.decision


def test_context_selection_authorization_and_persistence_flow() -> None:
    with Database() as database:
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
        assert repository.get(grant.grant_id) == grant


def test_sqlite_schema_and_foreign_keys() -> None:
    expected = {
        "missions",
        "mission_revisions",
        "mission_states",
        "policy_states",
        "authorization_runtime_bindings",
        "context_resource_index",
        "context_data_access_grants",
        "data_access_grants",
        "tool_registry_revisions",
        "available_tool_snapshots",
        "session_security_context_snapshots",
        "adapter_capability_snapshots",
        "sandbox_capability_snapshots",
        "remote_mcp_trust_snapshots",
        "execution_plan_proposals",
        "execution_plans",
        "policy_decisions",
        "approval_requests",
        "approvals",
        "llm_profiles",
        "llm_capability_results",
        "audit_logs",
    }
    with Database() as database:
        tables = {
            row["name"]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert expected.issubset(tables)
        assert database.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_approval_request_and_record_are_separate_and_gate_bound() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        service = ApprovalService(
            runtime_resolver=kernel.runtime_resolver,
            plans=kernel.plans,
            decisions=kernel.decisions,
            requests=kernel.approval_requests,
            records=kernel.approvals,
        )
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
        kwargs = persisted_gate_kwargs(kernel)
        kwargs.update(
            approval_request_id=request.approval_request_id,
            approval_record_id=record.approval_id,
        )
        assert authorize_execution(**kwargs).status == "AUTHORIZED"
        assert kernel.decisions.get(kernel.decision.decision_id).decision == "REQUIRE_APPROVAL"
