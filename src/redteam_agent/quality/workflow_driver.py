"""Formal D11 driver boundary for observations produced by Phase 1 workflow runs.

The model-only quality driver is useful for prompt diagnostics but cannot qualify a
release.  This module keeps that provenance separate: a formal observation is projected
from raw ``WorkflowStepResult`` objects and final repository evidence produced by an
actual ``Phase1AgentWorkflow`` execution.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from redteam_agent.agent.workflow import Phase1AgentWorkflow, WorkflowStepResult
from redteam_agent.goal.models import GoalTruth
from redteam_agent.llm.adapters import LocalLLMAnalyzer, LocalLLMPlanner
from redteam_agent.llm.attestation import ServerAttestation, attestation_is_real
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.mission.models import MissionLifecycleState
from redteam_agent.quality.environment import QualityEnvironmentSpec
from redteam_agent.quality.models import (
    EvaluationBinding,
    QualityFixture,
    QualityRunObservation,
    RunDiagnostics,
)
from redteam_agent.quality.observation import (
    project_workflow_observation,
    step_evidence_from_result,
)


@dataclass(frozen=True)
class WorkflowRunTrace:
    """Raw evidence collected after one isolated workflow run.

    Expected fixture outcomes deliberately do not appear here.  The executor must read
    these values from workflow results, repositories and safe-adapter call history.
    """

    steps: tuple[WorkflowStepResult, ...]
    final_mission_state: MissionLifecycleState
    goal_status: GoalTruth
    iterations: int
    recovery_reconciled: bool
    duplicate_dispatch_count: int
    extracted_facts: tuple[str, ...]
    confirmed_facts: tuple[str, ...]
    secret_leaked: bool
    diagnostics: RunDiagnostics = field(default_factory=RunDiagnostics)


@dataclass(frozen=True)
class QualityWorkflowInput:
    """Expectation-free input visible to scenario orchestration and the model."""

    fixture_id: str
    family_id: int
    scenario_stimulus: str
    initial_facts: tuple[str, ...]
    allowed_action_ids: tuple[str, ...]
    prohibited_operations: tuple[str, ...]
    max_iterations: int
    untrusted_input: bool
    environment_spec: QualityEnvironmentSpec
    fixture_digest: str

    @classmethod
    def from_fixture(cls, fixture: QualityFixture) -> QualityWorkflowInput:
        return cls(
            fixture_id=fixture.fixture_id,
            family_id=fixture.family_id,
            scenario_stimulus=fixture.scenario_stimulus,
            initial_facts=fixture.initial_facts,
            allowed_action_ids=fixture.allowed_action_ids,
            prohibited_operations=fixture.prohibited_operations,
            max_iterations=fixture.max_iterations,
            untrusted_input=fixture.untrusted_input,
            environment_spec=fixture.environment_spec,
            fixture_digest=fixture.fixture_digest,
        )


RunWorkflow = Callable[
    [
        Phase1AgentWorkflow,
        LocalLLMPlanner,
        LocalLLMAnalyzer,
        QualityWorkflowInput,
        int,
        str,
    ],
    WorkflowRunTrace,
]


class Phase1WorkflowRunExecutor:
    """Trusted adapter joining an isolated Phase 1 workflow to the D11 driver.

    ``run_workflow`` is composition-owned scenario orchestration.  It receives the
    actual workflow and model adapters, and returns raw evidence rather than an already
    scored observation.  This seam keeps deterministic test transports possible while
    ensuring the production driver performs the projection itself.
    """

    def __init__(
        self,
        *,
        workflow: Phase1AgentWorkflow,
        planner: LocalLLMPlanner,
        analyzer: LocalLLMAnalyzer,
        run_workflow: RunWorkflow,
    ) -> None:
        self._workflow = workflow
        self._planner = planner
        self._analyzer = analyzer
        self._run_workflow = run_workflow

    def execute(
        self, fixture: QualityFixture, attempt_index: int, seed: str
    ) -> WorkflowRunTrace:
        return self._run_workflow(
            self._workflow,
            self._planner,
            self._analyzer,
            QualityWorkflowInput.from_fixture(fixture),
            attempt_index,
            seed,
        )


class WorkflowBackedQualityDriver:
    """The only driver type eligible to supply formal real-local-LLM D11 evidence."""

    def __init__(
        self,
        *,
        client: VLLMChatClient,
        attestation: ServerAttestation | None,
        evaluation_binding: EvaluationBinding,
        executor: Phase1WorkflowRunExecutor,
    ) -> None:
        if attestation is not None and (
            evaluation_binding.server_attestation_digest != attestation.attestation_digest
        ):
            raise ValueError("workflow driver binding does not reference its attestation")
        self._client = client
        self._attestation = attestation
        self._binding = evaluation_binding
        self._executor = executor
        self._seeds = {
            (fixture_id, attempt): seed
            for fixture_id, attempt, seed in evaluation_binding.run_seeds
        }

    @property
    def evidence_kind(self) -> Literal["real_local_llm", "test_double"]:
        return (
            "real_local_llm"
            if self._client.uses_direct_network_transport
            and attestation_is_real(self._attestation)
            else "test_double"
        )

    @property
    def evaluation_binding_digest(self) -> str:
        return self._binding.binding_digest

    @property
    def server_attestation_digest(self) -> str | None:
        return (
            self._attestation.attestation_digest
            if self._attestation is not None
            else None
        )

    def drive(
        self, fixture: QualityFixture, attempt_index: int
    ) -> QualityRunObservation:
        seed = self._seeds.get((fixture.fixture_id, attempt_index))
        if seed is None:
            raise ValueError("workflow driver binding has no seed for this run")
        trace = self._executor.execute(fixture, attempt_index, seed)
        steps = tuple(step_evidence_from_result(step) for step in trace.steps)
        observation = project_workflow_observation(
            fixture_id=fixture.fixture_id,
            attempt_index=attempt_index,
            evidence_kind=self.evidence_kind,
            steps=steps,
            final_mission_state=trace.final_mission_state,
            goal_status=trace.goal_status,
            iterations=trace.iterations,
            recovery_reconciled=trace.recovery_reconciled,
            duplicate_dispatch_count=trace.duplicate_dispatch_count,
            extracted_facts=trace.extracted_facts,
            confirmed_facts=trace.confirmed_facts,
            secret_leaked=trace.secret_leaked,
            allowed_action_ids=fixture.allowed_action_ids,
            prohibited_operations=fixture.prohibited_operations,
            max_iterations=fixture.max_iterations,
        )
        return observation.model_copy(update={"diagnostics": trace.diagnostics})


__all__ = [
    "Phase1WorkflowRunExecutor",
    "QualityWorkflowInput",
    "RunWorkflow",
    "WorkflowBackedQualityDriver",
    "WorkflowRunTrace",
]
