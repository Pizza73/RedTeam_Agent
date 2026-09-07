"""Generated Phase 1 graph/finalization safety evidence.

The machine drives the public workflow through planning, uncertain recovery,
hard-limit finalization, and durable human-review convergence.  Its invariants
are independent assertions over repository records rather than product state
transition tables.
"""

from __future__ import annotations

import json

from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.agent.mock_agents import MockPlanner
from redteam_agent.agent.models import ActionCandidateSeed
from redteam_agent.agent.workflow import PlanningOperationIds
from redteam_agent.composition.phase1 import build_phase1_kernel
from redteam_agent.errors import AgentLoopError
from redteam_agent.execution.thread import compute_thread_id
from redteam_agent.plan.models import (
    HypothesisCreateProposal,
    PlannerActionOutput,
    PlanThreadUpdateProposal,
)
from redteam_agent.policy.scope_models import IpTargetReference


class Phase1AgentStateMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.kernel = build_phase1_kernel(phase0c=p0c.make_phase0c())
        self.seeded = p0b.seed_authorized(self.kernel.phase0c.phase0b)
        self.mission_id = self.seeded.seeded.revision.mission_id
        head = self.kernel.knowledge_service.initialize_mission(
            mission_id=self.mission_id,
            mission_revision=self.seeded.seeded.revision.mission_revision,
            recorded_at=support.T0,
        )
        goal = self.kernel.goal_service.evaluate(mission_id=self.mission_id)
        grant = self.kernel.phase0c.phase0b.phase0a.context_authorization_service.issue_grant(
            grant_id="state-machine-grant",
            mission_id=self.mission_id,
            service_identity="planner_context",
            candidate_resource_ids=(),
            session_ids=(),
            ttl_seconds=120,
        )
        projection = self.kernel.candidate_projector.build(
            snapshot_id=self.seeded.seeded.snapshot.snapshot_id,
            seeds=(ActionCandidateSeed(
                tool_ref=self.seeded.seeded.tool.tool_ref,
                canonical_target_binding=(
                    IpTargetReference(type="ip", address="10.1.2.3"),
                ),
                satisfied_precondition_refs=(),
                objective_dependency_ids=("mission-objective-0",),
            ),),
            source_version_digests=(goal.evaluation_digest, head.head_digest),
        )
        self.envelope = self.kernel.planner_context_service.build(
            planner_context_id="state-machine-context",
            mission_id=self.mission_id,
            goal_evaluation_id=goal.evaluation_id,
            projection=projection,
            context_grant_id=grant.grant_id,
            available_tool_snapshot_id=self.seeded.seeded.snapshot.snapshot_id,
            iteration=0,
        )
        self.planner = MockPlanner(PlannerActionOutput(
            proposal=support.make_proposal(
                tool=self.seeded.seeded.tool,
                arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
                requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
            ),
            working_state_update=None,
            next_iteration_hints=(),
        ))
        self.execution_created = False
        self.expired = False
        self.operation = 0
        self.run_id = "state-machine-run"
        self.thread_id = compute_thread_id(
            mission_id=self.mission_id,
            mission_revision=self.envelope.mission_revision,
            run_id=self.run_id,
        )
        self.thread = self.kernel.planner_state_manager.apply(
            mission_id=self.mission_id,
            proposal=PlanThreadUpdateProposal(
                operation="replace",
                objective="state machine hypothesis",
                expected_thread_version=None,
                hypothesis_updates=(HypothesisCreateProposal(
                    statement="service may be reachable",
                    basis_reference_ids=(),
                    next_verification_objective="verify",
                ),),
            ),
        )

    def _state(self) -> str:
        current = self.kernel.phase0c.phase0b.phase0a.state_repository.get(self.mission_id)
        assert current is not None
        return current.state

    def _step(self) -> None:
        self.operation += 1
        self.kernel.workflow.run_planning_iteration(
            envelope=self.envelope,
            ids=PlanningOperationIds(
                operation_id=f"state-machine-operation-{self.operation}",
                plan_id="state-machine-plan",
                run_id=self.run_id,
                thread_id=self.thread_id,
                decision_id="state-machine-decision",
                execution_id="state-machine-execution",
                task_id="state-machine-task",
            ),
            invoke_planner=self.planner.invoke,
        )

    @precondition(lambda self: self._state() == "RUNNING" and not self.execution_created)
    @rule()
    def plan_once(self) -> None:
        self._step()
        self.execution_created = True
        self.kernel.phase0c.phase0b.mock_adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]

    @precondition(lambda self: self._state() == "RUNNING" and self.execution_created)
    @rule()
    def reconcile_uncertain_execution(self) -> None:
        self._step()

    @precondition(lambda self: self._state() == "RUNNING")
    @rule()
    def reach_hard_limit(self) -> None:
        self.kernel.phase0c.monotonic_clock.advance(seconds=2 * 24 * 3600 + 1)
        self.expired = True
        if self.execution_created:
            self.kernel.phase0c.phase0b.mock_adapter._reconcile_status = "UNKNOWN"  # type: ignore[attr-defined]
        self._step()

    @precondition(lambda self: self._state() == "FINALIZING")
    @rule()
    def resume_finalization(self) -> None:
        self._step()

    @precondition(lambda self: self._state() == "RUNNING")
    @rule()
    def stale_working_state_update_is_atomic(self) -> None:
        database = self.kernel.phase0c.phase0b.phase0a.database
        before = database.occ_get("plan_thread", self.mission_id)
        try:
            self.kernel.planner_state_manager.apply(
                mission_id=self.mission_id,
                proposal=PlanThreadUpdateProposal(
                    operation="continue",
                    objective="stale update",
                    expected_thread_version=self.thread.thread_version + 1,
                    hypothesis_updates=(),
                ),
            )
        except AgentLoopError:
            pass
        else:
            raise AssertionError("stale working-state update was accepted")
        assert database.occ_get("plan_thread", self.mission_id) == before

    @precondition(
        lambda self: self._state()
        in {"ABORTED", "WAITING_HUMAN_REVIEW", "COMPLETED"}
    )
    @rule()
    def terminal_state_is_stable(self) -> None:
        state_repository = self.kernel.phase0c.phase0b.phase0a.state_repository
        before = state_repository.get(self.mission_id)
        assert state_repository.get(self.mission_id) == before

    @invariant()
    def external_dispatch_is_never_repeated(self) -> None:
        assert self.kernel.phase0c.phase0b.mock_adapter.submit_calls <= 1

    @invariant()
    def recovery_budget_and_human_review_converge(self) -> None:
        rows = self.kernel.phase0c.phase0b.phase0a.database.occ_get_all("agent_retry_budget")
        for _, _, raw in rows:
            assert json.loads(raw)["consumed_attempts"] <= 3
        if self._state() == "WAITING_HUMAN_REVIEW":
            items = self.kernel.unresolved_items.current(self.mission_id)
            assert len(items) == 1
            assert items[0].source_execution_id == "state-machine-execution"
            assert items[0].reason_code == "EXECUTION_RECONCILED"
            assert items[0].status == "OPEN"
            events = self.kernel.phase0c.phase0b.phase0a.database.occ_get_all(
                "unresolved_item_event"
            )
            assert len(events) == 1

    @invariant()
    def graph_checkpoint_contains_only_record_identity_fields(self) -> None:
        checkpoint = self.kernel.controller.checkpoint(self.mission_id)
        if checkpoint is not None:
            assert checkpoint.mission_id == self.mission_id
            assert checkpoint.planner_context_id is None
            assert checkpoint.operation_id.startswith("state-machine-operation-")
        assert self.kernel.workflow.graph.checkpointer is not None
        allowed = {
            "mission_id",
            "operation_id",
            "planner_context_id",
            "goal_evaluation_id",
            "controller_action",
            "controller_reason",
            "planner_output_kind",
        }
        if self.operation:
            checkpointer = self.kernel.workflow.graph.checkpointer
            assert checkpointer is not None
            snapshot = checkpointer.get({
                "configurable": {
                    "thread_id": self.thread_id,
                }
            })
            assert snapshot is not None
            values = snapshot["channel_values"]
            assert set(values) <= allowed
            assert all(isinstance(value, str) for value in values.values())


Phase1AgentStateMachine.TestCase.settings = settings(
    max_examples=8,
    stateful_step_count=7,
    deadline=None,
)

TestPhase1AgentStateMachine = Phase1AgentStateMachine.TestCase
