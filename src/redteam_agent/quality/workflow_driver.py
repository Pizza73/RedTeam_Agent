"""Formal D11 driver boundary for observations produced by Phase 1 workflow runs.

The model-only quality driver is useful for prompt diagnostics but cannot qualify a
release.  This module keeps that provenance separate: a formal observation is projected
from raw ``WorkflowStepResult`` objects and final repository evidence produced by an
actual ``Phase1AgentWorkflow`` execution.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Literal

from redteam_agent.agent.workflow import Phase1AgentWorkflow, WorkflowStepResult
from redteam_agent.goal.models import GoalTruth
from redteam_agent.llm.adapters import LocalLLMAnalyzer, LocalLLMPlanner
from redteam_agent.llm.attestation import ServerAttestation, attestation_is_real
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.tokenizer import HuggingFaceTokenCounter, TokenCounter
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

    def execute(self, fixture: QualityFixture, attempt_index: int, seed: str) -> WorkflowRunTrace:
        return self._run_workflow(
            self._workflow,
            self._planner,
            self._analyzer,
            QualityWorkflowInput.from_fixture(fixture),
            attempt_index,
            seed,
        )

    @property
    def is_composition_owned(self) -> bool:
        """The public callback constructor is a test seam, never formal evidence."""
        return False

    def is_bound_to(
        self, *, client: VLLMChatClient, token_counter: TokenCounter, profile_digest: str
    ) -> bool:
        """Whether the actual trace-producing planner/analyzer are bound to this identity.

        The public callback constructor never carries this proof, regardless of what its
        ``run_workflow`` callback happens to close over.
        """
        del client, token_counter, profile_digest
        return False


class IsolatedPhase1WorkflowRunExecutor(Phase1WorkflowRunExecutor):
    """Executor reserved for the product-owned isolated scenario runner."""

    def __init__(self, **kwargs: object) -> None:
        from redteam_agent.quality.scenario_runner import IsolatedPhase1ScenarioRunner

        if type(kwargs.get("run_workflow")) is not IsolatedPhase1ScenarioRunner:
            raise ValueError("formal executor requires the isolated product scenario runner")
        super().__init__(**kwargs)  # type: ignore[arg-type]

    @property
    def is_composition_owned(self) -> bool:
        return True

    def is_bound_to(
        self, *, client: VLLMChatClient, token_counter: TokenCounter, profile_digest: str
    ) -> bool:
        from redteam_agent.quality.scenario_runner import IsolatedPhase1ScenarioRunner

        runner = self._run_workflow
        # Guaranteed by __init__: the constructor rejects any other run_workflow type.
        assert isinstance(runner, IsolatedPhase1ScenarioRunner)
        return runner.is_bound_to(client=client, token_counter=token_counter, profile_digest=profile_digest)


class WorkflowBackedQualityDriver:
    """The only driver type eligible to supply formal real-local-LLM D11 evidence."""

    def __init__(
        self,
        *,
        client: VLLMChatClient,
        attestation: ServerAttestation | None,
        evaluation_binding: EvaluationBinding,
        executor: Phase1WorkflowRunExecutor,
        token_counter: TokenCounter,
        max_parallel_runs: int = 1,
    ) -> None:
        if max_parallel_runs < 1 or max_parallel_runs > 32:
            raise ValueError("max_parallel_runs must be between 1 and 32")
        if attestation is not None and (evaluation_binding.server_attestation_digest != attestation.attestation_digest):
            raise ValueError("workflow driver binding does not reference its attestation")
        self._client = client
        self._attestation = attestation
        self._binding = evaluation_binding
        self._executor = executor
        self._token_counter = token_counter
        self._max_parallel_runs = max_parallel_runs
        self._seeds = {(fixture_id, attempt): seed for fixture_id, attempt, seed in evaluation_binding.run_seeds}

    @property
    def evidence_kind(self) -> Literal["real_local_llm", "test_double"]:
        return (
            "real_local_llm"
            if self._client.uses_direct_network_transport
            and attestation_is_real(self._attestation)
            and type(self._token_counter) is HuggingFaceTokenCounter
            and self._executor.is_composition_owned
            # A composition-owned executor class is not enough on its own: the
            # planner/analyzer that actually produced the trace must be provably
            # bound to *this* client/tokenizer, and to *this* evaluation binding's
            # profile -- never a same-class runner wrapping mismatched or injected
            # inner factories.
            and self._executor.is_bound_to(
                client=self._client,
                token_counter=self._token_counter,
                profile_digest=self._binding.profile_digest,
            )
            else "test_double"
        )

    @property
    def evaluation_binding_digest(self) -> str:
        return self._binding.binding_digest

    @property
    def server_attestation_digest(self) -> str | None:
        return self._attestation.attestation_digest if self._attestation is not None else None

    def drive(self, fixture: QualityFixture, attempt_index: int) -> QualityRunObservation:
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

    def drive_many(
        self, requests: tuple[tuple[QualityFixture, int], ...]
    ) -> tuple[QualityRunObservation | Exception, ...]:
        """Drive an ordered batch through independently isolated kernels.

        Exceptions are returned in their input positions so the runner can preserve
        its fixed 300-record order and convert ordinary model failures into failed
        observations without dropping a run.
        """

        def one(request: tuple[QualityFixture, int]) -> QualityRunObservation | Exception:
            try:
                return self.drive(*request)
            except Exception as exc:  # consumed by QualityRunner under its normal rules
                return exc

        if self._max_parallel_runs == 1:
            return tuple(one(request) for request in requests)
        with ThreadPoolExecutor(max_workers=self._max_parallel_runs) as pool:
            return tuple(pool.map(one, requests))

    def drive_many_completed(
        self, requests: tuple[tuple[QualityFixture, int], ...]
    ) -> Iterator[tuple[int, QualityRunObservation | Exception]]:
        """Yield completed positions promptly so durable evidence is appended incrementally."""
        if self._max_parallel_runs == 1:
            for index, request in enumerate(requests):
                yield index, self.drive_many((request,))[0]
            return
        with ThreadPoolExecutor(max_workers=self._max_parallel_runs) as pool:
            futures = {
                pool.submit(self.drive, fixture, attempt): index
                for index, (fixture, attempt) in enumerate(requests)
            }
            for future in as_completed(futures):
                index = futures[future]
                try:
                    yield index, future.result()
                except Exception as exc:
                    yield index, exc


__all__ = [
    "IsolatedPhase1WorkflowRunExecutor",
    "Phase1WorkflowRunExecutor",
    "QualityWorkflowInput",
    "RunWorkflow",
    "WorkflowBackedQualityDriver",
    "WorkflowRunTrace",
]
